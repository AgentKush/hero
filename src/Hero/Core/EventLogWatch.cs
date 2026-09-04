using System.Diagnostics.Eventing.Reader;

namespace Hero.Core;

/// <summary>What HERO can currently see on one event channel.</summary>
internal enum EventChannelStatus
{
    /// <summary>Not yet probed.</summary>
    Unknown,
    /// <summary>Subscribed and receiving. Silence from here means genuinely nothing happened.</summary>
    Watching,
    /// <summary>The channel exists but is switched off. Its silence means nothing at all.</summary>
    Disabled,
    /// <summary>Reading it needs rights HERO does not have.</summary>
    AccessDenied,
    /// <summary>No such channel on this machine.</summary>
    NotFound,
    /// <summary>Subscribed once and then broke. HERO is retrying.</summary>
    Failed,
}

/// <summary>Per-channel health, surfaced verbatim in the UI.</summary>
internal sealed record EventChannelHealth
{
    internal required string Channel { get; init; }
    internal required EventChannelStatus Status { get; init; }
    /// <summary>What the channel is watched for, in the user's words.</summary>
    internal required string Purpose { get; init; }
    /// <summary>Why it is in this state, and what it means for coverage.</summary>
    internal required string Detail { get; init; }
    internal DateTime? LastEventUtc { get; init; }
    internal int EventCount { get; init; }
    /// <summary>True when the channel produced more events than HERO would forward.</summary>
    internal bool Throttled { get; init; }

    /// <summary>
    /// True when the absence of events from this channel is meaningful evidence. When false the
    /// UI must not present a quiet channel as a clean one.
    /// </summary>
    internal bool SilenceIsMeaningful => Status == EventChannelStatus.Watching;
}

/// <summary>One event worth telling the detection layer about.</summary>
internal sealed record EventLogSignal
{
    internal required string Channel { get; init; }
    internal required int EventId { get; init; }
    /// <summary>Stable short name, e.g. "service.installed". Rules key on this, not the raw id.</summary>
    internal required string Kind { get; init; }
    internal required DateTime TimeUtc { get; init; }
    internal required string Summary { get; init; }
    internal string ProviderName { get; init; } = "";
    /// <summary>Service name, task name or threat name — whatever the event is about.</summary>
    internal string SubjectName { get; init; } = "";
    /// <summary>The executable or file involved, when one could be resolved from the record.</summary>
    internal string ImagePath { get; init; } = "";
    /// <summary>Raw event properties, in order, for the evidence panel.</summary>
    internal IReadOnlyList<string> Properties { get; init; } = Array.Empty<string>();
}

/// <summary>
/// A live subscription to the Windows event channels HERO can actually read unelevated.
///
/// <para><b>What is watched, and why these channels.</b></para>
/// <list type="bullet">
/// <item><c>System</c> 7045 (a service was installed) and 7040 (a service start type changed).
/// Both are readable at medium integrity and both are real persistence events. Note they fire for
/// every legitimate installer too — Docker, BlueStacks, VPNs and GPU drivers all install services
/// on this machine — so these are corroborating signals, never accusations on their own.</item>
/// <item><c>Microsoft-Windows-Windows Defender/Operational</c> 1116 (threat detected),
/// 1117 (action taken), 5001 (real-time protection disabled) and 5007 (configuration changed).
/// 5001 is the interesting one: something turning Defender off is a strong signal, and it is also
/// exactly what a user does deliberately when a build tool keeps getting quarantined.</item>
/// </list>
///
/// <para><b>What is deliberately NOT relied upon.</b>
/// <c>Microsoft-Windows-TaskScheduler/Operational</c> is DISABLED by default on this machine
/// (measured <c>IsEnabled=False</c>), so subscribing to it would yield permanent silence that a
/// naive design would read as "no tasks were created". It is probed, reported as unavailable, and
/// re-probed periodically in case it is ever turned on. The <c>Security</c> channel — which is
/// where 4688 process creation lives — is denied at medium integrity, so it is listed as requiring
/// elevation and never subscribed to unelevated. In both cases the rule is the same: an unwatched
/// channel is reported as unwatched, never as quiet.</para>
///
/// <para><b>Failure behaviour.</b> Nothing here throws into a caller. The watcher raises on a
/// thread-pool thread, so the handler is wrapped end to end; subscriber exceptions are swallowed
/// so one bad listener cannot take down the process. A cleared log invalidates the subscription's
/// bookmark, which arrives as an exception on the callback rather than as an error return — that
/// is caught, the channel is marked Failed, and a retry timer resubscribes, first from the last
/// bookmark and then, if that is rejected, from now.</para>
/// </summary>
internal sealed class EventLogWatch : IDisposable
{
    /// <summary>Definition of one channel subscription.</summary>
    internal sealed record ChannelSpec
    {
        internal required string Channel { get; init; }
        /// <summary>XPath filter. Keeping it server-side is what makes this cheap.</summary>
        internal required string Query { get; init; }
        internal required string Purpose { get; init; }
        /// <summary>True for channels HERO knows it cannot read at medium integrity.</summary>
        internal bool RequiresElevation { get; init; }
        /// <summary>True for channels expected to be off; their absence is not a fault.</summary>
        internal bool ExpectedUnavailable { get; init; }
    }

    private static readonly ChannelSpec[] Specs =
    {
        new()
        {
            Channel = "System",
            Query = "*[System[(EventID=7045 or EventID=7040)]]",
            Purpose = "Services being installed or reconfigured to start automatically.",
        },
        new()
        {
            Channel = "Microsoft-Windows-Windows Defender/Operational",
            Query = "*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007)]]",
            Purpose = "Windows Defender detections, and Defender itself being turned off or reconfigured.",
        },
        new()
        {
            Channel = "Microsoft-Windows-TaskScheduler/Operational",
            Query = "*[System[(EventID=106 or EventID=140 or EventID=141)]]",
            Purpose = "Scheduled tasks being registered, updated or deleted.",
            ExpectedUnavailable = true,
        },
        new()
        {
            Channel = "Security",
            Query = "*[System[(EventID=4688)]]",
            Purpose = "Process creation with full command lines.",
            RequiresElevation = true,
        },
    };

    /// <summary>Live subscription state for one channel.</summary>
    internal sealed class ChannelWatch
    {
        internal required ChannelSpec Spec { get; init; }
        internal EventLogWatcher? Watcher;
        internal EventBookmark? Bookmark;
        internal EventChannelStatus Status = EventChannelStatus.Unknown;
        internal string Detail = "Not yet checked.";
        internal DateTime? LastEventUtc;
        internal int EventCount;
        internal int ConsecutiveFailures;
        internal DateTime NextAttemptUtc = DateTime.MinValue;

        // Rolling one-minute forwarding budget.
        internal DateTime WindowStartUtc = DateTime.UtcNow;
        internal int WindowCount;
        internal bool Throttled;
    }

    /// <summary>
    /// Ceiling on forwarded events per channel per minute. A normal machine produces a handful of
    /// these a day; sixty in a minute is by definition a storm, and forwarding a storm would let a
    /// noisy channel drive the score all by itself. Events beyond the cap are counted, not lost:
    /// the health record says the channel was throttled.
    /// </summary>
    private const int MaxEventsPerMinute = 60;

    /// <summary>
    /// Identical events inside this window are collapsed. Defender emits 1116 and 1117 for the
    /// same threat, and 5007 arrives in bursts whenever a signature update rewrites configuration.
    /// </summary>
    private static readonly TimeSpan DedupeWindow = TimeSpan.FromSeconds(5);

    private const int RecentCap = 100;
    private static readonly TimeSpan RetryTick = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(5);
    /// <summary>Disabled, missing and denied channels can only change if a human changes them.</summary>
    private static readonly TimeSpan UnavailableRecheck = TimeSpan.FromMinutes(10);

    private readonly List<ChannelWatch> _channels;
    private readonly object _gate = new();
    private readonly List<EventLogSignal> _recent = new();
    private readonly Dictionary<string, DateTime> _dedupe = new(StringComparer.Ordinal);
    private Timer? _retry;
    private bool _disposed;
    /// <summary>
    /// Guards against overlapping retry ticks. The timer has a fixed 30s period, but a connection
    /// attempt against a wedged Event Log service can block for longer than that; two ticks then
    /// run TryConnect on the same ChannelWatch concurrently and the second Teardown reads a
    /// Watcher field the first has already replaced, leaking a live subscription every tick.
    /// </summary>
    private int _ticking;

    internal EventLogWatch()
    {
        _channels = Specs.Select(s => new ChannelWatch { Spec = s }).ToList();
    }

    /// <summary>Raised on a thread-pool thread for every event HERO forwards.</summary>
    internal event Action<EventLogSignal>? Observed;

    /// <summary>Raised whenever a channel's status changes, so the UI can stop claiming coverage.</summary>
    internal event Action<EventChannelHealth>? HealthChanged;

    /// <summary>Current health of every channel, watched or not.</summary>
    internal IReadOnlyList<EventChannelHealth> Health
    {
        get { lock (_gate) return _channels.Select(Snapshot).ToList(); }
    }

    /// <summary>Recently forwarded events, newest first. Bounded.</summary>
    internal IReadOnlyList<EventLogSignal> Recent
    {
        get { lock (_gate) return _recent.ToList(); }
    }

    /// <summary>True when at least one channel is genuinely subscribed.</summary>
    internal bool AnyChannelWatching
    {
        get { lock (_gate) return _channels.Any(c => c.Status == EventChannelStatus.Watching); }
    }

    /// <summary>
    /// Begins watching. Returns immediately: the first connection attempt happens on the retry
    /// timer's first tick, so a slow or wedged Event Log service cannot stall startup.
    /// </summary>
    internal void Start()
    {
        lock (_gate)
        {
            if (_disposed || _retry is not null) return;
            _retry = new Timer(OnRetryTick, null, TimeSpan.Zero, RetryTick);
        }
    }

    /// <summary>Stops watching. Safe to call repeatedly and safe to call from any thread.</summary>
    internal void Stop()
    {
        Timer? timer;
        List<ChannelWatch> channels;
        lock (_gate)
        {
            timer = _retry;
            _retry = null;
            channels = _channels.ToList();
        }

        try { timer?.Dispose(); } catch { }

        foreach (var ch in channels) Teardown(ch);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
        }
        Stop();
    }

    // ------------------------------------------------------------ connection

    private void OnRetryTick(object? _)
    {
        // A tick that arrives while the previous one is still connecting is dropped, not queued:
        // the next one is thirty seconds away and the work is idempotent.
        if (Interlocked.CompareExchange(ref _ticking, 1, 0) != 0) return;

        // This runs on a pool thread on a timer. An escape here would be an unobserved crash in
        // a background thread, so the whole body is guarded.
        try
        {
            List<ChannelWatch> due;
            var now = DateTime.UtcNow;
            lock (_gate)
            {
                if (_disposed) return;
                due = _channels.Where(c => c.Status != EventChannelStatus.Watching && c.NextAttemptUtc <= now).ToList();
            }

            foreach (var ch in due) TryConnect(ch);
        }
        catch { /* never let the retry timer die: it is the reconnection mechanism */ }
        finally { Volatile.Write(ref _ticking, 0); }
    }

    private void TryConnect(ChannelWatch ch)
    {
        // Anything left over from a previous attempt goes first; leaking watchers is how a
        // reconnect loop turns into a handle leak.
        Teardown(ch);

        if (ch.Spec.RequiresElevation && !Elevation.IsElevated)
        {
            SetStatus(ch, EventChannelStatus.AccessDenied,
                $"The {ch.Spec.Channel} log requires administrator rights, so HERO is not watching it. "
                + "Anything it would have shown is not assessable, not clean.",
                UnavailableRecheck);
            return;
        }

        // Stage 1: is the channel even switched on? Reporting a disabled channel's silence as
        // "nothing happened" is the specific failure this check exists to prevent.
        try
        {
            using var config = new EventLogConfiguration(ch.Spec.Channel);
            if (!config.IsEnabled)
            {
                SetStatus(ch, EventChannelStatus.Disabled,
                    $"The {ch.Spec.Channel} log is disabled on this machine, so HERO cannot see "
                    + (ch.Spec.ExpectedUnavailable ? "these events. This is the Windows default. " : "these events. ")
                    + "Turning it on requires administrator rights.",
                    UnavailableRecheck);
                return;
            }
        }
        catch (EventLogNotFoundException)
        {
            SetStatus(ch, EventChannelStatus.NotFound,
                $"The {ch.Spec.Channel} log does not exist on this machine.", UnavailableRecheck);
            return;
        }
        catch (UnauthorizedAccessException)
        {
            SetStatus(ch, EventChannelStatus.AccessDenied,
                $"HERO is not permitted to read the {ch.Spec.Channel} log.", UnavailableRecheck);
            return;
        }
        catch (Exception ex)
        {
            SetStatus(ch, EventChannelStatus.Failed,
                $"The {ch.Spec.Channel} log could not be inspected: {ex.Message}", Backoff(ch));
            return;
        }

        // Stage 2: subscribe. The bookmark is tried first so a brief disconnection does not lose
        // events; after a log clear the bookmark is invalid and rejected, so the retry without one
        // resumes from now. Replaying nothing is correct there — the records are gone.
        if (Subscribe(ch, ch.Bookmark)) return;
        if (ch.Bookmark is not null)
        {
            ch.Bookmark = null;
            if (Subscribe(ch, null)) return;
        }
    }

    private bool Subscribe(ChannelWatch ch, EventBookmark? bookmark)
    {
        try
        {
            var query = new EventLogQuery(ch.Spec.Channel, PathType.LogName, ch.Spec.Query)
            {
                TolerateQueryErrors = true,
            };

            var watcher = bookmark is null
                ? new EventLogWatcher(query)
                : new EventLogWatcher(query, bookmark, readExistingEvents: false);

            watcher.EventRecordWritten += (_, e) => OnRecordWritten(ch, e);
            watcher.Enabled = true;

            ch.Watcher = watcher;
            ch.ConsecutiveFailures = 0;
            SetStatus(ch, EventChannelStatus.Watching,
                $"Watching {ch.Spec.Channel}. {ch.Spec.Purpose}", TimeSpan.Zero);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            SetStatus(ch, EventChannelStatus.AccessDenied,
                $"HERO is not permitted to subscribe to {ch.Spec.Channel}.", UnavailableRecheck);
            return false;
        }
        catch (EventLogNotFoundException)
        {
            SetStatus(ch, EventChannelStatus.NotFound,
                $"The {ch.Spec.Channel} log does not exist on this machine.", UnavailableRecheck);
            return false;
        }
        catch (Exception ex)
        {
            SetStatus(ch, EventChannelStatus.Failed,
                $"HERO could not subscribe to {ch.Spec.Channel}: {ex.Message}. Retrying.", Backoff(ch));
            return false;
        }
    }

    private static void Teardown(ChannelWatch ch)
    {
        var w = ch.Watcher;
        ch.Watcher = null;
        if (w is null) return;
        // Order matters: disabling first stops callbacks arriving mid-dispose.
        try { w.Enabled = false; } catch { }
        try { w.Dispose(); } catch { }
    }

    /// <summary>30s, 1m, 2m, 4m, capped at 5m. Counted per channel.</summary>
    private static TimeSpan Backoff(ChannelWatch ch)
    {
        ch.ConsecutiveFailures = Math.Min(ch.ConsecutiveFailures + 1, 8);
        var seconds = 30d * Math.Pow(2, ch.ConsecutiveFailures - 1);
        var delay = TimeSpan.FromSeconds(seconds);
        return delay > MaxBackoff ? MaxBackoff : delay;
    }

    private void SetStatus(ChannelWatch ch, EventChannelStatus status, string detail, TimeSpan retryIn)
    {
        bool changed;
        EventChannelHealth health;
        lock (_gate)
        {
            changed = ch.Status != status || ch.Detail != detail;
            ch.Status = status;
            ch.Detail = detail;
            ch.NextAttemptUtc = status == EventChannelStatus.Watching
                ? DateTime.MaxValue
                : DateTime.UtcNow + retryIn;
            health = Snapshot(ch);
        }
        if (changed) Raise(HealthChanged, health);
    }

    private static EventChannelHealth Snapshot(ChannelWatch ch) => new()
    {
        Channel = ch.Spec.Channel,
        Status = ch.Status,
        Purpose = ch.Spec.Purpose,
        Detail = ch.Detail,
        LastEventUtc = ch.LastEventUtc,
        EventCount = ch.EventCount,
        Throttled = ch.Throttled,
    };

    // -------------------------------------------------------------- receiving

    private void OnRecordWritten(ChannelWatch ch, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventException is not null)
            {
                // This is how a cleared log, a stopped Event Log service, or a revoked permission
                // arrives. It is not an error return anywhere HERO can check for it, so this
                // branch is the only place a broken subscription becomes visible.
                SetStatus(ch, EventChannelStatus.Failed,
                    $"The {ch.Spec.Channel} subscription stopped ({e.EventException.Message}). "
                    + "HERO is reconnecting; events during the gap were missed.",
                    Backoff(ch));
                return;
            }

            var record = e.EventRecord;
            if (record is null) return;

            EventLogSignal? signal;
            try
            {
                // Grab the bookmark before disposal so a reconnect can resume from here.
                try { ch.Bookmark = record.Bookmark; } catch { }
                signal = Describe(ch.Spec.Channel, record);
            }
            finally
            {
                try { record.Dispose(); } catch { }
            }

            if (signal is null) return;
            if (!Admit(ch, signal)) return;

            Raise(Observed, signal);
        }
        catch
        {
            // The watcher raises on a thread-pool thread. An exception escaping here is an
            // unhandled exception on a pool thread, which terminates the process — precisely the
            // "never throw into the monitor thread" rule this class exists to honour.
        }
    }

    /// <summary>Dedupe and rate-limit. Returns false when the signal should not be forwarded.</summary>
    private bool Admit(ChannelWatch ch, EventLogSignal signal)
    {
        var now = DateTime.UtcNow;
        lock (_gate)
        {
            if (_disposed) return false;

            var key = $"{signal.Channel}|{signal.EventId}|{signal.SubjectName}|{signal.ImagePath}";
            if (_dedupe.TryGetValue(key, out var last) && now - last < DedupeWindow) return false;
            _dedupe[key] = now;
            if (_dedupe.Count > 256)
            {
                // Cheap eviction: drop everything older than the window rather than keeping an LRU
                // for a dictionary that should never grow this large in the first place.
                foreach (var stale in _dedupe.Where(kv => now - kv.Value > DedupeWindow).Select(kv => kv.Key).ToList())
                    _dedupe.Remove(stale);
            }

            if (now - ch.WindowStartUtc > TimeSpan.FromMinutes(1))
            {
                ch.WindowStartUtc = now;
                ch.WindowCount = 0;
                ch.Throttled = false;
            }

            ch.EventCount++;
            ch.LastEventUtc = now;

            if (++ch.WindowCount > MaxEventsPerMinute)
            {
                ch.Throttled = true;
                return false;
            }

            _recent.Insert(0, signal);
            if (_recent.Count > RecentCap) _recent.RemoveRange(RecentCap, _recent.Count - RecentCap);
        }
        return true;
    }

    private static void Raise<T>(Action<T>? handler, T arg)
    {
        if (handler is null) return;
        try { handler(arg); }
        catch { /* a subscriber's bug must not kill the event-log thread */ }
    }

    // ------------------------------------------------------------ description

    /// <summary>
    /// Turns a raw record into something the detection layer can reason about.
    ///
    /// Property indices are used only for the two System events whose layout is stable and
    /// documented; everything else is read positionally with bounds checks and falls back to the
    /// formatted description. A record whose provider metadata is missing throws from
    /// FormatDescription rather than returning null, which is why every read here is guarded.
    /// </summary>
    private static EventLogSignal? Describe(string channel, EventRecord record)
    {
        int id;
        try { id = record.Id; } catch { return null; }

        var props = ReadProperties(record);
        var when = ReadTime(record);
        var provider = ReadProvider(record);
        var formatted = ReadDescription(record);

        string kind, subject = "", image = "", summary;

        switch (id)
        {
            // A service was installed. Documented property order:
            // [0] ServiceName [1] ImagePath [2] ServiceType [3] StartType [4] AccountName.
            case 7045:
                kind = "service.installed";
                subject = At(props, 0);
                image = At(props, 1);
                summary = $"A service named \"{subject}\" was installed"
                        + (image.Length > 0 ? $", running {image}" : "")
                        + (At(props, 3).Length > 0 ? $" ({At(props, 3)} start)" : "") + ".";
                break;

            // A service start type changed. [0] display name [1] previous [2] new [3] short name.
            case 7040:
                kind = "service.starttype-changed";
                subject = At(props, 0);
                summary = $"The start type of \"{subject}\" changed"
                        + (At(props, 1).Length > 0 && At(props, 2).Length > 0
                            ? $" from {At(props, 1)} to {At(props, 2)}" : "") + ".";
                break;

            case 1116:
                kind = "defender.threat-detected";
                image = FindPath(props);
                subject = FindThreatName(props);
                summary = "Windows Defender detected a threat"
                        + (subject.Length > 0 ? $": {subject}" : "")
                        + (image.Length > 0 ? $" in {image}" : "") + ".";
                break;

            case 1117:
                kind = "defender.action-taken";
                image = FindPath(props);
                subject = FindThreatName(props);
                summary = "Windows Defender acted on a threat"
                        + (subject.Length > 0 ? $": {subject}" : "") + ".";
                break;

            case 5001:
                kind = "defender.realtime-disabled";
                summary = "Windows Defender real-time protection was turned off.";
                break;

            case 5007:
                kind = "defender.configuration-changed";
                summary = "Windows Defender configuration was changed.";
                break;

            // TaskScheduler/Operational. Only ever seen if the channel is enabled by hand; kept
            // so that enabling it later needs no code change.
            case 106:
                kind = "task.registered";
                subject = At(props, 0);
                summary = $"A scheduled task was registered: {subject}.";
                break;
            case 140:
                kind = "task.updated";
                subject = At(props, 0);
                summary = $"A scheduled task was updated: {subject}.";
                break;
            case 141:
                kind = "task.deleted";
                subject = At(props, 0);
                summary = $"A scheduled task was deleted: {subject}.";
                break;

            case 4688:
                kind = "process.created";
                image = FindPath(props);
                summary = "A process was created" + (image.Length > 0 ? $": {image}" : "") + ".";
                break;

            default:
                // The XPath filters mean this should be unreachable; forwarding an unrecognised id
                // as Informational is safer than dropping it silently if a filter is ever widened.
                kind = "eventlog.other";
                summary = formatted ?? $"Event {id} on {channel}.";
                break;
        }

        // The formatted description is far better prose than anything assembled from properties,
        // when the provider metadata is present to produce it.
        if (formatted is { Length: > 0 } && id is 1116 or 1117 or 5001 or 5007)
            summary = Collapse(formatted);

        return new EventLogSignal
        {
            Channel = channel,
            EventId = id,
            Kind = kind,
            TimeUtc = when,
            Summary = summary,
            ProviderName = provider,
            SubjectName = subject,
            ImagePath = image,
            Properties = props,
        };
    }

    private static string At(IReadOnlyList<string> props, int i) =>
        i >= 0 && i < props.Count ? props[i] : "";

    /// <summary>
    /// Defender's property layout varies by platform version, so the path is found by shape
    /// rather than by index: the first property that looks like a rooted Windows path. Heuristic
    /// and openly so — a miss costs a blank field, never a wrong attribution.
    /// </summary>
    private static string FindPath(IReadOnlyList<string> props)
    {
        foreach (var p in props)
        {
            if (p.Length < 4) continue;
            var s = p;
            // Defender prefixes with a scan-source tag such as "file:_C:\path\to\thing.exe".
            int marker = s.IndexOf(":_", StringComparison.Ordinal);
            if (marker >= 0 && marker + 2 < s.Length) s = s[(marker + 2)..];
            if (s.Length > 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') && char.IsLetter(s[0]))
                return s;
        }
        return "";
    }

    /// <summary>
    /// Defender threat names follow a recognisable shape (Category:Platform/Family). Matching on
    /// the shape avoids depending on a property index that moves between platform versions.
    /// </summary>
    private static string FindThreatName(IReadOnlyList<string> props)
    {
        foreach (var p in props)
        {
            if (p.Length is < 5 or > 200) continue;
            if (p.Contains(':') && p.Contains('/') && !p.Contains('\\')) return p;
        }
        return "";
    }

    private static IReadOnlyList<string> ReadProperties(EventRecord record)
    {
        try
        {
            var list = new List<string>(8);
            foreach (var p in record.Properties)
                list.Add(p.Value?.ToString() ?? "");
            return list;
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static DateTime ReadTime(EventRecord record)
    {
        try { return record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow; }
        catch { return DateTime.UtcNow; }
    }

    private static string ReadProvider(EventRecord record)
    {
        try { return record.ProviderName ?? ""; }
        catch { return ""; }
    }

    private static string? ReadDescription(EventRecord record)
    {
        // Throws EventLogException when the provider's message resource is not installed, which
        // happens for third-party providers and for events written by a since-removed product.
        try { return record.FormatDescription(); }
        catch { return null; }
    }

    /// <summary>Event descriptions are multi-line and padded; the UI wants one line.</summary>
    private static string Collapse(string text)
    {
        var flat = string.Join(' ', text.Split('\r', '\n')
                                        .Select(l => l.Trim())
                                        .Where(l => l.Length > 0));
        return flat.Length > 400 ? flat[..400] + "…" : flat;
    }
}
