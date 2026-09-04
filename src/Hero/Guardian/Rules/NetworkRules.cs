using System.Net;
using System.Text.RegularExpressions;
using Hero.Interop;

namespace Hero.Guardian.Rules;

/// <summary>
/// A per-snapshot index from PID to sockets.
///
/// Without it every network rule would scan all 143 socket rows for each of ~360 processes on
/// every poll. The index is rebuilt once per snapshot and identified by reference, so it costs one
/// pass over the table per poll rather than one per rule per process.
///
/// Rows owned by PID 0 are dropped: TIME_WAIT entries are commonly attributed to PID 0 on this
/// machine, and they belong to no process. Attributing them would invent a phantom.
/// </summary>
internal static class SocketIndex
{
    private static readonly object Gate = new();
    private static Snapshot? _builtFor;
    private static Dictionary<int, List<Connection>> _map = new();
    private static readonly List<Connection> Empty = new();

    internal static IReadOnlyList<Connection> For(Snapshot snapshot, int pid)
    {
        lock (Gate)
        {
            if (!ReferenceEquals(_builtFor, snapshot))
            {
                var map = new Dictionary<int, List<Connection>>(256);
                foreach (var c in snapshot.Connections)
                {
                    if (c.Pid == 0) continue;
                    if (!map.TryGetValue(c.Pid, out var list)) map[c.Pid] = list = new List<Connection>(4);
                    list.Add(c);
                }
                _map = map;
                _builtFor = snapshot;
            }
            return _map.TryGetValue(pid, out var found) ? found : Empty;
        }
    }
}

/// <summary>
/// Periodic outbound connections with almost no variation in their interval — the shape of a
/// command-and-control beacon.
///
/// The statistics are stated explicitly because a beacon detector with loose thresholds is a
/// machine that cries wolf at npm, cargo, Windows Update, OneDrive, Discord and Steam:
///
/// - Minimum sample count: <see cref="MinIntervals"/> = 8 intervals, i.e. nine observed
///   connections to the same peer. Below that the dispersion statistics are meaningless.
/// - Two statistics must agree: the coefficient of variation (standard deviation over mean) must
///   be at most 0.20, AND the median absolute deviation over the median must be at most 0.25.
///   The MAD test is there because a single missed observation merges two intervals of T into one
///   of 2T, which wrecks the CV precisely when the target is stealthiest; a robust statistic
///   survives one such outlier.
/// - The median interval must fall between 20 and 600 seconds. The lower bound is the poll
///   resolution — HERO samples sockets every 1 to 5 seconds and simply cannot resolve faster
///   periods. The upper bound exists so that eight intervals fit inside the four-hour history
///   window; a 1800-second beacon would need four hours of intervals alone and could never
///   accumulate the minimum sample count.
/// - Only <see cref="Connection.IsExternal"/> peers are considered. Loopback and RFC1918 traffic
///   dominates this machine and is not a beacon by any useful definition.
///
/// Known blind spot, stated rather than papered over: a beacon that rides a single persistent
/// keep-alive connection produces one connection event and is invisible here.
/// </summary>
internal sealed class BeaconingRule : IDetectionRule
{
    public string Id => "net.beaconing";
    public string Description => "Repeated connections to the same internet host at a machine-perfect interval";

    internal const int MinIntervals = 8;
    internal const double MaxCoefficientOfVariation = 0.20;
    internal const double MaxRelativeMad = 0.25;
    internal const double MinMedianSeconds = 20;
    internal const double MaxMedianSeconds = 600;

    private static readonly TimeSpan HistoryWindow = TimeSpan.FromHours(4);
    private const int MaxTrackedProcesses = 512;

    private readonly object _gate = new();
    private readonly Dictionary<(int Pid, long Start), Dictionary<string, List<DateTime>>> _history = new();
    private DateTime _lastIngestedUtc = DateTime.MinValue;

    /// <summary>
    /// Records new outbound connections.
    ///
    /// Called automatically from <see cref="Evaluate"/> on the first subject of each snapshot,
    /// and idempotent by snapshot timestamp so evaluating 360 subjects does not ingest the same
    /// delta 360 times. The engine may also call it directly once per poll, which is cheaper and
    /// makes the ordering explicit; both are safe.
    /// </summary>
    internal void Ingest(SnapshotDelta? delta)
    {
        if (delta is null) return;

        lock (_gate)
        {
            var stamp = delta.Current.TakenUtc;
            if (stamp <= _lastIngestedUtc) return;
            _lastIngestedUtc = stamp;

            foreach (var c in delta.NewConnections)
            {
                if (c.Pid == 0 || c.Protocol != "TCP") continue;
                if (!c.IsExternal) continue;
                if (!delta.Current.ByPid.TryGetValue(c.Pid, out var proc)) continue;
                if (RuleKit.Ignorable(proc)) continue;

                var key = (proc.Pid, proc.StartTimeUtc.Ticks);
                if (!_history.TryGetValue(key, out var peers))
                {
                    if (_history.Count >= MaxTrackedProcesses) continue;   // bounded, never unbounded
                    _history[key] = peers = new Dictionary<string, List<DateTime>>(4);
                }

                if (!peers.TryGetValue(c.PeerKey, out var stamps))
                    peers[c.PeerKey] = stamps = new List<DateTime>(16);

                // The connection start is approximated by the poll that first saw it. That costs
                // up to one poll interval of accuracy, which the 20-second floor absorbs.
                stamps.Add(stamp);
                if (stamps.Count > 256) stamps.RemoveRange(0, stamps.Count - 256);
            }

            Prune(stamp);
        }
    }

    private void Prune(DateTime now)
    {
        var cutoff = now - HistoryWindow;
        var deadProcesses = new List<(int, long)>();

        foreach (var (procKey, peers) in _history)
        {
            var deadPeers = new List<string>();
            foreach (var (peer, stamps) in peers)
            {
                stamps.RemoveAll(t => t < cutoff);
                if (stamps.Count == 0) deadPeers.Add(peer);
            }
            foreach (var peer in deadPeers) peers.Remove(peer);
            if (peers.Count == 0) deadProcesses.Add(procKey);
        }

        foreach (var key in deadProcesses) _history.Remove(key);
    }

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        Ingest(context.Delta);

        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var identity = KnownSoftware.Classify(p.ImagePath);

        // Browsers beacon to everything, all the time, by design.
        if (identity.Class == SoftwareClass.Browser) yield break;

        var sig = context.Signature(p.ImagePath);
        bool validlySigned = sig is { State: SignatureState.Valid };
        bool trustedPublisher = validlySigned && KnownSoftware.IsTrustedPublisher(sig!.Signer);

        // A valid signature from a publisher HERO recognises, on software HERO recognises, is the
        // update-check case: npm, cargo, VS Code, Steam, Discord, OneDrive, Windows Update.
        if (validlySigned && trustedPublisher && identity.IsRecognised) yield break;

        // The statistics are computed under the lock and the results copied out, because a
        // `yield return` may not appear inside a lock: the iterator would hold the mutex for as
        // long as the consumer takes to enumerate, which for a UI-bound consumer is unbounded.
        List<(string Peer, double Median, double Cv, double RelMad, int Samples)> hits = new();
        lock (_gate)
        {
            if (_history.TryGetValue((p.Pid, p.StartTimeUtc.Ticks), out var peers))
            {
                foreach (var (peer, stamps) in peers)
                {
                    if (stamps.Count < MinIntervals + 1) continue;
                    if (!IsPeriodic(stamps, out double median, out double cv, out double relMad)) continue;
                    hits.Add((peer, median, cv, relMad, stamps.Count));
                }
            }
        }

        foreach (var hit in hits)
        {
            double weight = hit.Cv switch
            {
                <= 0.05 => 24,
                <= 0.10 => 20,
                _ => 16,
            };

            // The provenance facts gate this rule rather than adding to it: a beacon from a
            // properly signed binary is worth noting, not acting on.
            if (validlySigned) weight = Math.Min(weight, trustedPublisher ? 4 : 6);
            else if (identity.IsRecognised) weight = Math.Min(weight, 8);

            if (weight < 4) continue;

            yield return RuleKit.Emit(Id, "Clockwork connections to one internet host",
                $"{p.FileName} has connected to {hit.Peer} {hit.Samples} times, every " +
                $"{hit.Median:0} seconds almost to the second. Software that checks for updates does " +
                "this too, but it usually varies; timing this exact is how remote-control tools stay " +
                "in touch with whoever installed them.",
                weight, RuleKit.Families.NetworkTiming,
                weight >= 16 ? Severity.High : Severity.Low,
                $"peer={hit.Peer} n={hit.Samples} median={hit.Median:0.0}s cv={hit.Cv:0.000} mad/median={hit.RelMad:0.000}");
        }
    }

    /// <summary>
    /// Both dispersion statistics, computed over the gaps between successive connections.
    /// Returns false unless every threshold is satisfied, so a caller cannot accidentally act on
    /// a partial match.
    /// </summary>
    internal static bool IsPeriodic(List<DateTime> stamps, out double median, out double cv, out double relMad)
    {
        median = cv = relMad = 0;
        if (stamps.Count < MinIntervals + 1) return false;

        var ordered = stamps.OrderBy(t => t).ToList();
        var gaps = new List<double>(ordered.Count - 1);
        for (int i = 1; i < ordered.Count; i++)
        {
            double seconds = (ordered[i] - ordered[i - 1]).TotalSeconds;
            if (seconds > 0) gaps.Add(seconds);
        }
        if (gaps.Count < MinIntervals) return false;

        double mean = gaps.Average();
        if (mean <= 0) return false;

        double variance = gaps.Sum(g => (g - mean) * (g - mean)) / gaps.Count;
        cv = Math.Sqrt(variance) / mean;

        var sorted = gaps.OrderBy(g => g).ToList();
        double centre = Median(sorted);
        median = centre;
        if (centre <= 0) return false;

        var deviations = gaps.Select(g => Math.Abs(g - centre)).OrderBy(d => d).ToList();
        relMad = Median(deviations) / centre;

        return cv <= MaxCoefficientOfVariation
            && relMad <= MaxRelativeMad
            && median >= MinMedianSeconds
            && median <= MaxMedianSeconds;
    }

    private static double Median(List<double> sorted)
    {
        if (sorted.Count == 0) return 0;
        int mid = sorted.Count / 2;
        return sorted.Count % 2 == 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2.0;
    }
}

/// <summary>
/// An unrecognised, unsigned program talking to the internet.
///
/// Weak by construction. Several of the nine benign unsigned binaries measured running on this
/// machine make outbound connections — the MCP server shims and browser-use tooling do it as
/// their entire purpose — so this exists to give the network family something to contribute when
/// the provenance family has already fired, not to accuse on its own.
/// </summary>
internal sealed class ExternalEgressRule : IDetectionRule
{
    public string Id => "net.external-egress";
    public string Description => "An unrecognised program is sending traffic to the internet";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var identity = KnownSoftware.Classify(p.ImagePath);
        if (identity.IsRecognised) yield break;
        if (!KnownSoftware.IsUserWritable(identity.Location)) yield break;

        var sig = context.Signature(p.ImagePath);
        if (sig is null) yield break;                                   // not verified yet
        if (sig.State == SignatureState.Valid) yield break;

        var peers = SocketIndex.For(context.Snapshot, p.Pid)
            .Where(c => c.IsExternal && c.State == TcpState.Established)
            .Select(c => c.PeerKey)
            .Distinct()
            .Take(5)
            .ToList();

        if (peers.Count == 0) yield break;

        double weight = KnownSoftware.IsVolatile(identity.Location) ? 12 : 6;

        yield return RuleKit.Emit(Id, "Unknown program is on the internet",
            $"{p.FileName} has no valid signature, is running from " +
            $"{UnsignedImageRule.Describe(identity.Location)}, and is connected to " +
            $"{peers.Count} external {(peers.Count == 1 ? "address" : "addresses")}. Plenty of " +
            "developer tools are unsigned and legitimately online, so this only matters alongside " +
            "other evidence.",
            weight, RuleKit.Families.NetworkPeer, Severity.Low, string.Join(", ", peers));
    }
}

/// <summary>
/// A program accepting inbound connections from outside this machine.
///
/// Loopback listeners are ignored entirely: vite, webpack, next, dotnet watch, python -m
/// http.server, adb, Docker and the user's own test harnesses bind localhost constantly and that
/// is simply what a development machine sounds like. What matters is a binding on a real
/// interface by an image with no recognised reason to be reachable.
/// </summary>
internal sealed class UnexpectedListenerRule : IDetectionRule
{
    public string Id => "net.unexpected-listener";
    public string Description => "A program is accepting connections from other machines";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var identity = KnownSoftware.Classify(p.ImagePath);
        if (identity.IsRecognised) yield break;

        var sig = context.Signature(p.ImagePath);
        if (sig is { State: SignatureState.Valid } && KnownSoftware.IsTrustedPublisher(sig.Signer)) yield break;

        var exposed = SocketIndex.For(context.Snapshot, p.Pid)
            .Where(c => c.IsListening && !IPAddress.IsLoopback(c.LocalAddress))
            .Select(c => c.LocalPort)
            .Distinct()
            .ToList();

        if (exposed.Count == 0) yield break;

        var remoteControl = exposed.Where(KnownSoftware.IsRemoteControlPort).ToList();
        double weight = remoteControl.Count > 0 ? 18 : 10;

        yield return RuleKit.Emit(Id,
            remoteControl.Count > 0 ? "Remote-control port is open" : "Program is reachable from the network",
            remoteControl.Count > 0
                ? $"{p.FileName} is listening on port {string.Join(", ", remoteControl)}, which is used " +
                  "for remote desktop and remote support. If you did not set up remote access, someone " +
                  "else may be able to reach this PC."
                : $"{p.FileName} is accepting connections from other machines on port " +
                  $"{string.Join(", ", exposed.Take(4))}. Development servers usually listen only to " +
                  "this PC; listening on the network makes the program reachable from elsewhere.",
            weight, RuleKit.Families.NetworkExposure,
            remoteControl.Count > 0 ? Severity.High : Severity.Medium,
            "listening on " + string.Join(", ", exposed.Take(8)));
    }
}

/// <summary>
/// Remote-management agents and tunnelling clients.
///
/// The intrusion pattern is an RMM agent appearing on a machine whose owner did not install one.
/// The complication is that this machine legitimately runs TeamViewer and Cloudflare WARP, and
/// its owner plausibly wants ngrok or cloudflared for webhook testing. So the discriminators are
/// location and signature, not the name: a properly installed, validly signed agent under Program
/// Files is worth confirming once; the same name running unsigned out of a user folder is not.
/// </summary>
internal sealed class RemoteAccessToolRule : IDetectionRule
{
    public string Id => "net.remote-access-tool";
    public string Description => "Software that lets someone else use or reach this PC is running";

    private static readonly Regex SshForwarding =
        new(@"(?:^|\s)-[RDL]\s*\d", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var identity = KnownSoftware.Classify(p.ImagePath);
        var sig = context.Signature(p.ImagePath);
        bool properlyInstalled = identity.Location is PathClass.ProgramFiles or PathClass.WindowsApps
                                 && sig is { State: SignatureState.Valid };

        if (KnownSoftware.IsRemoteAccessAgent(p.Name, out var product))
        {
            // Gaming and personal remote tools live on a separate list and never accuse.
            if (KnownSoftware.IsUserChosenRemoteTool(p.Name)) yield break;

            double weight = properlyInstalled ? 5 : 16;
            yield return RuleKit.Emit(Id, "Remote-support software is running",
                $"{p.FileName} is remote-support software — it is designed to let another person see " +
                "and control this PC. " +
                (properlyInstalled
                    ? "This copy is properly installed and signed, so confirm once that you meant to install it."
                    : "This copy is not installed the way the vendor ships it, which is how support scams and " +
                      "intruders leave themselves a way back in."),
                weight, RuleKit.Families.RemoteAccess,
                properlyInstalled ? Severity.Low : Severity.High,
                $"{product} · {p.ImagePath}");
            yield break;
        }

        if (!KnownSoftware.IsTunnelClient(p.Name)) yield break;

        bool ssh = KnownSoftware.NameKey(p.Name) is "ssh" or "plink";
        if (ssh && !SshForwarding.IsMatch(p.CommandLine)) yield break;

        bool hasExternal = SocketIndex.For(context.Snapshot, p.Pid).Any(c => c.IsExternal);
        if (!hasExternal) yield break;

        double tunnelWeight = 14;
        if (RuleKit.UserIsAtThisProcess(p, context) || RuleKit.HasDeveloperAncestor(p, context)) tunnelWeight = 5;
        if (properlyInstalled) tunnelWeight = Math.Min(tunnelWeight, 8);

        yield return RuleKit.Emit(Id, "A tunnel to this PC is open",
            $"{p.FileName} creates a tunnel that makes something on this PC reachable from the " +
            "internet, bypassing your router and firewall. Developers use these deliberately for " +
            "webhook testing; started by a script rather than by you, it is how an intruder keeps a " +
            "way in.",
            tunnelWeight, RuleKit.Families.RemoteAccess,
            tunnelWeight >= 14 ? Severity.High : Severity.Low,
            KnownSoftware.Sanitise(p.CommandLine, 200));
    }
}

/// <summary>
/// Cryptocurrency-mining indicators.
///
/// Port evidence alone is close to worthless and is scored accordingly. The pool-port list
/// deliberately excludes 7777 (the Unreal Engine default server port on an Unreal developer's
/// machine) and 8888/9999 (Jupyter and assorted dev APIs). What actually carries the signal is a
/// miner's own name or a stratum-shaped command line, both of which have no benign analogue here.
///
/// This rule is also the mandated corroborator for the hidden-CPU rule, so the pair is capped
/// below anything that could authorise an autonomous action: an overnight simulation must never
/// be terminated because it happened to hold a long connection open.
/// </summary>
internal sealed class MiningIndicatorRule : IDetectionRule
{
    public string Id => "net.mining-indicator";
    public string Description => "Signs of cryptocurrency mining software";

    private static readonly Regex MinerFlags =
        new(@"(?:--donate-level|--rig-id|--nicehash|--coin\b|--cpu-priority|-o\s+stratum\+)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        bool minerName = KnownSoftware.IsMinerImage(p.Name);
        bool minerArgs = KnownSoftware.MentionsMiningPool(p.CommandLine) || MinerFlags.IsMatch(p.CommandLine);

        if (minerName || minerArgs)
        {
            yield return RuleKit.Emit(Id, "Mining software is running",
                $"{p.FileName} is cryptocurrency-mining software, or was started with mining-pool " +
                "settings. If you did not set this up yourself, someone is using your electricity and " +
                "your CPU to earn coins.",
                22, RuleKit.Families.NetworkPeer, Severity.High,
                minerArgs ? KnownSoftware.Sanitise(p.CommandLine, 200) : p.ImagePath);
            yield break;
        }

        var poolPorts = SocketIndex.For(context.Snapshot, p.Pid)
            .Where(c => c.IsExternal && c.Protocol == "TCP" && KnownSoftware.IsMiningPoolPort(c.RemotePort))
            .Select(c => c.PeerKey)
            .Distinct()
            .Take(3)
            .ToList();

        if (poolPorts.Count == 0) yield break;

        var identity = KnownSoftware.Classify(p.ImagePath);
        if (identity.IsRecognised) yield break;

        yield return RuleKit.Emit(Id, "Connection on a port mining pools use",
            $"{p.FileName} is connected to an internet address on a port commonly used by mining " +
            "pools. On its own this proves nothing — plenty of software uses these ports — so HERO " +
            "records it and waits for something else to agree.",
            6, RuleKit.Families.NetworkPeer, Severity.Low, string.Join(", ", poolPorts));
    }
}

/// <summary>
/// A program resolving names through a public DNS provider directly, rather than through Windows.
///
/// HERO has no DNS plane, so "a non-standard resolver" is not observable — what IS observable is a
/// process holding a connection to a well-known public resolver on the DNS-over-HTTPS or
/// DNS-over-TLS port. That matters because it means the process's name lookups never touch the
/// Windows resolver and therefore appear in no local cache, which is exactly how a payload hides
/// where it is calling.
///
/// Browsers do this by default and are excluded outright, as are the VPN and DNS clients on this
/// machine (Cloudflare WARP, Tailscale) whose entire job it is.
/// </summary>
internal sealed class DirectResolverRule : IDetectionRule
{
    public string Id => "net.direct-resolver";
    public string Description => "A program is doing its own encrypted DNS instead of using Windows";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var identity = KnownSoftware.Classify(p.ImagePath);
        if (identity.Class is SoftwareClass.Browser or SoftwareClass.TunnelClient) yield break;
        if (KnownSoftware.IsUserChosenRemoteTool(p.Name)) yield break;
        if (identity.IsRecognised) yield break;

        var resolvers = SocketIndex.For(context.Snapshot, p.Pid)
            .Where(c => c.IsExternal && c.Protocol == "TCP" && c.RemoteAddress is not null)
            .Where(c => c.RemotePort is 443 or 853)
            .Where(c => KnownSoftware.IsPublicDnsResolver(c.RemoteAddress!.ToString()))
            .ToList();

        if (resolvers.Count == 0) yield break;

        bool dot = resolvers.Any(c => c.RemotePort == 853);

        yield return RuleKit.Emit(Id, "Program is bypassing Windows for name lookups",
            $"{p.FileName} is talking straight to a public DNS provider over an encrypted channel " +
            "rather than asking Windows to look names up. Browsers do this on purpose; for anything " +
            "else it means the addresses it contacts leave no trace on this PC.",
            dot ? 12 : 8, RuleKit.Families.NetworkPeer, Severity.Medium,
            string.Join(", ", resolvers.Select(c => c.PeerKey).Distinct().Take(4)));
    }
}
