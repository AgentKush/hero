using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Hero.Core;
using Hero.Interop;

namespace Hero.Guardian;

/// <summary>
/// How well HERO knows an entity. Ordered, so <c>state &gt;= EntityState.Familiar</c> reads
/// naturally; Blocked is negative so it never satisfies such a test.
/// </summary>
internal enum EntityState
{
    /// <summary>The user killed this. It never earns trust again without an explicit reset.</summary>
    Blocked = -1,
    New = 0,
    Observed = 1,
    Familiar = 2,
    Known = 3,
    Trusted = 4,
}

/// <summary>
/// What happened when a known path turned out to hold different bytes. The whole point of this
/// enum is that "the file changed" is not one event: an OBS update and a signer break need
/// opposite responses, and conflating them produces either an alert storm or a blind spot.
/// </summary>
internal enum ChangeKind
{
    /// <summary>Same bytes as last time.</summary>
    None,
    /// <summary>First time this path has ever been seen.</summary>
    FirstSight,
    /// <summary>Same signer, still valid, new bytes. Silent by design — this is 99% of changes.</summary>
    VersionRollover,
    /// <summary>Same signer but the binary lives somewhere the user can write. Quietly re-watched.</summary>
    RollingUserWritable,
    /// <summary>Was signed, now unsigned or signed by someone else, or the signature broke.</summary>
    SignerBreak,
    /// <summary>Unsigned before, unsigned now. Weak evidence; a build output looks exactly like this.</summary>
    UnsignedRewrite,
}

/// <summary>
/// What a user's "this is fine" actually covers. Deliberately three narrow scopes rather than
/// one broad one: a path-only allowlist is a persistence primitive, because an attacker who can
/// replace the file inherits the approval.
/// </summary>
internal enum AllowScope
{
    /// <summary>These exact bytes at this path. Dies the moment the file changes.</summary>
    Hash,
    /// <summary>This publisher at this path. Survives updates, dies on a signer change.</summary>
    PathAndSigner,
    /// <summary>One rule, for one entity. The narrowest and the default for "stop telling me this".</summary>
    RuleForEntity,
}

/// <summary>
/// Identity of the bytes behind a path.
///
/// Size plus last-write time is the cheap identity used everywhere on the hot path: it costs one
/// stat call, and it is exactly the key the signature cache already uses. A SHA-256 is filled in
/// only where a real content commitment is required (a hash-scoped allowlist entry), because
/// hashing a 900 MB Unreal binary on every process start is not affordable.
/// </summary>
internal readonly record struct ContentIdentity(long Size, long WriteTicks, string? Sha256)
{
    internal bool IsEmpty => Size == 0 && WriteTicks == 0 && Sha256 is null;

    /// <summary>Stable string form, stored in entity and allowlist records.</summary>
    internal string Token => Sha256 is { Length: > 0 } h ? "h:" + h : $"s:{Size:x}.{WriteTicks:x}";

    internal static ContentIdentity For(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return default;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return default;
            return new ContentIdentity(fi.Length, fi.LastWriteTimeUtc.Ticks, null);
        }
        catch { return default; }
    }

    /// <summary>
    /// Full content hash, or null when the file is absent, locked or too large.
    ///
    /// FileShare.ReadWrite|Delete is not optional: without it every running executable and every
    /// binary a compiler is mid-write on fails to open, and the caller mints a spurious
    /// "cannot verify" event on every build.
    /// </summary>
    internal static string? TryHash(string? path, long maxBytes = 64L * 1024 * 1024)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length > maxBytes) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
        }
        catch { return null; }
    }

    /// <summary>
    /// True when both identities describe the same bytes. A hash on both sides is decisive; a
    /// hash on one side only cannot prove equality, so size+mtime is used as the fallback.
    /// </summary>
    internal bool Matches(in ContentIdentity other)
    {
        if (Sha256 is { Length: > 0 } a && other.Sha256 is { Length: > 0 } b)
            return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        return Size == other.Size && WriteTicks == other.WriteTicks;
    }
}

/// <summary>
/// Welford sufficient statistics over ln(1+x).
///
/// Resource channels are heavy-tailed — a process that normally uses 0.5% CPU and occasionally
/// uses 40% is not lognormal-tailed by accident — so the log transform is what makes a z-score
/// mean anything at all. Only {n, mean, m2} are stored, which is 24 bytes rather than a history.
/// </summary>
internal sealed class EnvelopeStat
{
    [JsonPropertyName("n")] public double N { get; set; }
    [JsonPropertyName("mu")] public double Mean { get; set; }
    [JsonPropertyName("m2")] public double M2 { get; set; }
    [JsonPropertyName("max")] public double Max { get; set; }
    /// <summary>Sigma as of the last daily checkpoint. See <see cref="CappedSigma"/>.</summary>
    [JsonPropertyName("sg0")] public double SigmaCheckpoint { get; set; }
    [JsonPropertyName("cp")] public DateTime CheckpointUtc { get; set; }

    internal void Add(double raw, double sigmaFloor, DateTime nowUtc)
    {
        double x = Math.Log(1 + Math.Max(0, raw));
        N += 1;
        double d = x - Mean;
        Mean += d / N;
        M2 += d * (x - Mean);
        if (raw > Max) Max = raw;

        // The daily checkpoint is what rate-limits envelope growth (see CappedSigma). It is
        // taken at most once every 24h so that a burst of observations cannot walk it upward.
        if (CheckpointUtc == default)
        {
            CheckpointUtc = nowUtc;
            SigmaCheckpoint = RawSigma(sigmaFloor);
        }
        else if ((nowUtc - CheckpointUtc).TotalDays >= 1.0)
        {
            SigmaCheckpoint = RawSigma(sigmaFloor);
            CheckpointUtc = nowUtc;
        }
    }

    internal double RawSigma(double floor)
        => N >= 2 ? Math.Max(Math.Sqrt(Math.Max(0, M2 / (N - 1))), floor) : floor;

    /// <summary>
    /// Sigma, but forbidden from growing more than 15% past yesterday's value.
    ///
    /// This is the anti-poisoning interlock. The standard attack on any behavioural baseline is
    /// to ramp the malicious behaviour slowly enough that the envelope widens to accommodate it.
    /// Capping variance growth means a fortnight-long ramp from 1% to 60% CPU still produces a
    /// z-score spike, because the model is not permitted to keep up.
    ///
    /// It is applied on read rather than by mutating m2, so no information is destroyed and the
    /// cap can be retuned without re-learning.
    /// </summary>
    internal double CappedSigma(double floor)
    {
        double s = RawSigma(floor);
        return SigmaCheckpoint > 0 ? Math.Min(s, SigmaCheckpoint * 1.15) : s;
    }

    /// <summary>One-sided z. A process using LESS of something than usual is not a threat.</summary>
    internal double ZScore(double raw, double floor)
    {
        if (N < 12) return 0;   // you cannot deviate from an envelope you have not learned
        double x = Math.Log(1 + Math.Max(0, raw));
        double z = (x - Mean) / CappedSigma(floor);
        return z > 0 ? z : 0;
    }

    internal void Decay(double lambda)
    {
        // Decay the sufficient statistics but NOT the mean: this is the exponentially-weighted
        // moment trick. A gradual drift in resource use is tracked, while a step change still
        // spikes, because the variance has not had time to widen to meet it.
        N *= lambda;
        M2 *= lambda;
    }
}

/// <summary>One distinct set of bytes that has occupied an entity's path.</summary>
internal sealed class ContentRecord
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("sz")] public long Size { get; set; }
    [JsonPropertyName("fv")] public string Version { get; set; } = "";
    [JsonPropertyName("fs")] public DateTime FirstSeenUtc { get; set; }
    [JsonPropertyName("ls")] public DateTime LastSeenUtc { get; set; }
    [JsonPropertyName("n")] public double Count { get; set; }
}

/// <summary>Per-publisher reputation earned on THIS host. No shipped publisher list.</summary>
internal sealed class SignerRecord
{
    [JsonPropertyName("cn")] public string Name { get; set; } = "";
    [JsonPropertyName("k")] public int KnownEntities { get; set; }
    [JsonPropertyName("d")] public int Denies { get; set; }
    [JsonPropertyName("fs")] public DateTime FirstSeenUtc { get; set; }
    /// <summary>When <see cref="KnownEntities"/> was last recounted. See the note there.</summary>
    [JsonPropertyName("cnt")] public DateTime CountedUtc { get; set; }
}

/// <summary>An autorun HERO has seen before. Novelty of the WRITE is the interesting part.</summary>
internal sealed class PersistenceRecord
{
    [JsonPropertyName("t")] public string Target { get; set; } = "";
    [JsonPropertyName("fs")] public DateTime FirstSeenUtc { get; set; }
    [JsonPropertyName("ls")] public DateTime LastSeenUtc { get; set; }
    [JsonPropertyName("n")] public int Sightings { get; set; }
}

/// <summary>One user approval. Re-proved on every use; never trusted because it exists.</summary>
internal sealed class AllowlistEntry
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("sc")] public AllowScope Scope { get; set; }
    [JsonPropertyName("k")] public string EntityKey { get; set; } = "";
    [JsonPropertyName("p")] public string Path { get; set; } = "";
    /// <summary>Content identity token at approval time. A change revokes Hash-scoped entries.</summary>
    [JsonPropertyName("cid")] public string Identity { get; set; } = "";
    /// <summary>
    /// Cheap size+last-write stamp. Checked first so the common case costs one stat call; only a
    /// stamp mismatch justifies re-hashing, which is what keeps a 900 MB binary off the hot path.
    /// </summary>
    [JsonPropertyName("stp")] public string Stamp { get; set; } = "";
    [JsonPropertyName("cn")] public string Signer { get; set; } = "";
    [JsonPropertyName("ss")] public int SignerState { get; set; }
    [JsonPropertyName("r")] public string RuleId { get; set; } = "";
    [JsonPropertyName("ts")] public DateTime CreatedUtc { get; set; }
    [JsonPropertyName("exp")] public DateTime ExpiresUtc { get; set; }
    [JsonPropertyName("lh")] public DateTime LastHitUtc { get; set; }
    [JsonPropertyName("h")] public int Hits { get; set; }
    [JsonPropertyName("rv")] public bool Revoked { get; set; }
    [JsonPropertyName("rr")] public string RevokedReason { get; set; } = "";

    [JsonIgnore] internal bool Live => !Revoked && ExpiresUtc > DateTime.UtcNow;
}

/// <summary>Everything HERO has learned about one executable path on this machine.</summary>
internal sealed class BaselineEntity
{
    [JsonPropertyName("k")] public string Key { get; set; } = "";
    /// <summary>Tokenised path — stable across app updates and profile moves.</summary>
    [JsonPropertyName("p")] public string Path { get; set; } = "";
    /// <summary>Last literal path observed. Also detects a tokenised-key collision.</summary>
    [JsonPropertyName("rp")] public string RealPath { get; set; } = "";
    [JsonPropertyName("nm")] public string Name { get; set; } = "";

    [JsonPropertyName("fs")] public DateTime FirstSeenUtc { get; set; }
    [JsonPropertyName("ls")] public DateTime LastSeenUtc { get; set; }
    /// <summary>Decayed execution count.</summary>
    [JsonPropertyName("n")] public double Count { get; set; }
    /// <summary>Of which are provisional — struck from the record if the user later kills it.</summary>
    [JsonPropertyName("pv")] public double Provisional { get; set; }
    /// <summary>Bitmask of the last 32 days on which this ran. Bit 0 is <see cref="DayAnchor"/>.</summary>
    [JsonPropertyName("dm")] public uint DayMask { get; set; }
    [JsonPropertyName("da")] public int DayAnchor { get; set; }
    [JsonPropertyName("bt")] public int Boots { get; set; }
    [JsonPropertyName("lb")] public int LastBootSeen { get; set; } = -1;
    [JsonPropertyName("dec")] public DateTime DecayedUtc { get; set; }

    [JsonPropertyName("ids")] public List<ContentRecord> Identities { get; set; } = new();
    [JsonPropertyName("cn")] public string Signer { get; set; } = "";
    [JsonPropertyName("ss")] public int SignerState { get; set; }
    [JsonPropertyName("sk")] public int SignerKind { get; set; }
    /// <summary>
    /// This path has held a validly signed binary at least once. Sticky, and deliberately so:
    /// "was it signed before?" must not be answerable by the most recent reading alone, because a
    /// locked or unreadable file yields a transient non-verdict, and an attacker who can arrange
    /// one reading of "unsigned" would otherwise erase the fact that a signer break ever happened.
    /// </summary>
    [JsonPropertyName("sgv")] public bool EverSigned { get; set; }

    [JsonPropertyName("par")] public Dictionary<string, double> Parents { get; set; } = new();
    /// <summary>External peer prefixes: IPv4 /16, IPv6 /48. /24 is far too tight for a CDN.</summary>
    [JsonPropertyName("net")] public Dictionary<string, double> Peers { get; set; } = new();
    [JsonPropertyName("prt")] public Dictionary<string, double> Ports { get; set; } = new();
    [JsonPropertyName("hr")] public double[] Hours { get; set; } = new double[24];

    [JsonPropertyName("cpu")] public EnvelopeStat Cpu { get; set; } = new();
    [JsonPropertyName("mem")] public EnvelopeStat Memory { get; set; } = new();
    [JsonPropertyName("thr")] public EnvelopeStat Threads { get; set; } = new();
    [JsonPropertyName("env")] public DateTime LastEnvelopeUtc { get; set; }

    [JsonPropertyName("st")] public EntityState State { get; set; } = EntityState.New;
    [JsonPropertyName("ua")] public bool UserAllowed { get; set; }
    [JsonPropertyName("bl")] public bool Blocked { get; set; }
    [JsonPropertyName("al")] public int Allows { get; set; }
    [JsonPropertyName("dn")] public int Denies { get; set; }
    /// <summary>Rarity is forced to zero until this time — the silent window after an update.</summary>
    [JsonPropertyName("grc")] public DateTime UpdateGraceUntilUtc { get; set; }
    /// <summary>Behaviour deviation thresholds are halved until this time after a risky update.</summary>
    [JsonPropertyName("wch")] public DateTime WatchUntilUtc { get; set; }
    [JsonPropertyName("sgc")] public bool SignerChanged { get; set; }
    /// <summary>Referenced by an autorun. Exempt from pruning: an autorun can outlive its target.</summary>
    [JsonPropertyName("per")] public bool Persistent { get; set; }

    /// <summary>
    /// Fields written by a newer build survive a round-trip through an older one. Without this a
    /// downgrade silently destroys everything the newer schema learned.
    /// </summary>
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }

    [JsonIgnore] internal int DistinctDays => BitOperations.PopCount(DayMask);
    [JsonIgnore] internal ContentRecord? Current => Identities.Count == 0 ? null : Identities[^1];
}

/// <summary>Outcome of feeding one observation into the model.</summary>
internal sealed record ObservationResult(BaselineEntity Entity, ChangeKind Change, string? BurstId, int BurstSize)
{
    /// <summary>True when this change is part of a coalesced multi-file update.</summary>
    internal bool IsBurst => BurstId is not null && BurstSize > 1;
}

/// <summary>
/// Path tokenisation and static path trust.
///
/// Tokenisation is what makes an entity key stable: keying on the literal path would mint a new
/// zero-history entity on every MSIX version bump and every uv cache refresh, and a machine full
/// of zero-history entities is a machine full of false positives.
/// </summary>
internal static class PathModel
{
    private static readonly (string Prefix, string Token)[] Prefixes = BuildPrefixes();

    private static readonly Regex GuidSegment = new(
        @"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    // Microsoft.WidgetsPlatformRuntime_1.0.0.0_x64__8wekyb3d8bbwe -> keep name and publisher,
    // discard version and architecture. Every Store app update changes those two.
    private static readonly Regex MsixSegment = new(
        @"^(?<p>[^_]+)_[^_]+_[^_]+__(?<u>[^_]+)$", RegexOptions.CultureInvariant);

    private static (string, string)[] BuildPrefixes()
    {
        var list = new List<(string, string)>();
        void Add(string? path, string token)
        {
            // The token is lowercased with the rest of the path. Tokenise lowercases the whole
            // string and then splices the token in, so an uppercase token would be the ONLY
            // uppercase run in the output — and every consumer below compares the result against
            // lowercase literals with StringComparison.Ordinal. Getting this wrong silently
            // disables the entire static path-trust table: every path falls through to the 0.45
            // "ordinary fixed drive" tier, which charges System32 as though it were a project
            // folder and halves the penalty on %TEMP% and Downloads.
            if (!string.IsNullOrWhiteSpace(path))
                list.Add((path.TrimEnd('\\').ToLowerInvariant(), token.ToLowerInvariant()));
        }

        Add(Path.GetTempPath(), "%TEMP%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.System), "%SYS32%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "%SYSWOW%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "%WINDIR%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "%PF86%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "%PF%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "%PROGRAMDATA%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "%LOCALAPPDATA%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "%APPDATA%");
        Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "%USERPROFILE%");

        // Longest first, so %TEMP% (which lives inside %LOCALAPPDATA%) wins over its own parent.
        return list.Where(t => t.Item1.Length > 0)
                   .OrderByDescending(t => t.Item1.Length)
                   .ToArray();
    }

    /// <summary>Canonical, machine-independent form of a path.</summary>
    internal static string Tokenise(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        string p = path.Trim();
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        p = p.ToLowerInvariant();

        foreach (var (prefix, token) in Prefixes)
        {
            if (p.Length >= prefix.Length && p.StartsWith(prefix, StringComparison.Ordinal) &&
                (p.Length == prefix.Length || p[prefix.Length] == '\\'))
            {
                p = token + p[prefix.Length..];
                break;
            }
        }

        var parts = p.Split('\\');
        for (int i = 0; i < parts.Length; i++)
        {
            var s = parts[i];
            if (s.Length == 0) continue;
            if (GuidSegment.IsMatch(s)) { parts[i] = "{guid}"; continue; }

            var m = MsixSegment.Match(s);
            if (m.Success) { parts[i] = m.Groups["p"].Value + "_*__" + m.Groups["u"].Value; continue; }

            // Only intermediate directories are collapsed; the leaf is the binary's own name and
            // collapsing it would merge genuinely different executables.
            if (i < parts.Length - 1 && LooksOpaque(s)) parts[i] = "{id}";
        }
        return string.Join('\\', parts);
    }

    /// <summary>
    /// A cache/content-addressed directory name: long, alphanumeric, mixed digits and letters.
    ///
    /// Erring toward collapsing is deliberate. A wrongly-collapsed segment merely merges two
    /// entities living in the same cache tree, which costs nothing; a wrongly-preserved one mints
    /// a brand-new zero-history entity every time uv, npm or pip refreshes its cache, which is an
    /// alert storm. This machine runs uv, whose archive-v0 directories are exactly this shape.
    /// </summary>
    private static bool LooksOpaque(string segment)
    {
        if (segment.Length < 16) return false;
        int digits = 0, letters = 0;
        foreach (char c in segment)
        {
            if (char.IsAsciiDigit(c)) digits++;
            else if (char.IsAsciiLetter(c)) letters++;
            else if (c is '-' or '_') { /* tolerated inside opaque ids */ }
            else return false;
        }
        return digits >= 4 && letters >= 4;
    }

    /// <summary>Stable entity key. 64 bits of SHA-256 over the tokenised path.</summary>
    internal static string KeyFor(string? path)
    {
        string t = Tokenise(path);
        if (t.Length == 0) return "";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(t));
        return "p:" + Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
    }

    /// <summary>
    /// Static path trust Pt in [0,1]. Higher is more trustworthy; the score uses (1 - Pt).
    ///
    /// Two corrections against the naive table matter on this machine:
    ///   * There is NO "path longer than 200 characters is pathological" rule. node_modules and
    ///     Unreal Intermediate trees routinely exceed it, and that rule would permanently charge
    ///     every esbuild/swc/Unreal binary the maximum path penalty.
    ///   * Ordinary paths on a non-system fixed drive get 0.45 rather than falling through to 0.
    ///     Every project this user owns lives on D:, and a table with no entry for D: makes the
    ///     user's entire working life look pathological.
    /// </summary>
    internal static double BaseTrust(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return 0.30;

        // Trim before the pathology test, exactly as Tokenise does. Registry-derived targets and
        // shortcut resolutions routinely carry a trailing space, and without this the trailing-
        // space check below would charge an ordinary autorun the full 3-point path penalty
        // reserved for genuine deception.
        path = path.Trim();
        if (IsPathological(path)) return 0.00;

        string t = Tokenise(path);

        if (t.StartsWith("%sys32%", StringComparison.Ordinal) ||
            t.StartsWith("%syswow%", StringComparison.Ordinal) ||
            t.StartsWith(@"%windir%\winsxs", StringComparison.Ordinal) ||
            t.StartsWith(@"%windir%\servicing", StringComparison.Ordinal))
            return 1.00;

        if (t.StartsWith("%pf%", StringComparison.Ordinal) ||
            t.StartsWith("%pf86%", StringComparison.Ordinal) ||
            t.StartsWith("%windir%", StringComparison.Ordinal) ||
            t.Contains(@"\windowsapps\", StringComparison.Ordinal) ||
            t.StartsWith(@"%programdata%\package cache", StringComparison.Ordinal))
            return 0.85;

        if (t.StartsWith(@"%localappdata%\programs", StringComparison.Ordinal) ||
            t.StartsWith("%programdata%", StringComparison.Ordinal))
            return 0.55;

        if (t.StartsWith("%temp%", StringComparison.Ordinal) ||
            t.StartsWith(@"%userprofile%\downloads", StringComparison.Ordinal) ||
            t.Contains(@"\$recycle.bin\", StringComparison.Ordinal))
            return 0.10;

        if (t.StartsWith("%localappdata%", StringComparison.Ordinal) ||
            t.StartsWith("%appdata%", StringComparison.Ordinal))
            return 0.30;

        if (t.StartsWith(@"\\", StringComparison.Ordinal)) return 0.10;   // UNC

        try
        {
            string? root = Path.GetPathRoot(path);
            if (!string.IsNullOrEmpty(root))
            {
                var drive = new DriveInfo(root);
                if (drive.DriveType is DriveType.Removable or DriveType.CDRom or DriveType.Network)
                    return 0.10;
            }
        }
        catch { /* an unreadable drive is not evidence of anything */ }

        if (t.StartsWith("%userprofile%", StringComparison.Ordinal)) return 0.30;

        // Ordinary path on a fixed drive: D:\My projects, C:\dev, a game install outside PF.
        return 0.45;
    }

    /// <summary>
    /// Genuinely pathological path shapes. Deliberately narrow: only the checks with real signal.
    /// Bidi overrides and trailing dots exist to deceive a human reader; an alternate data stream
    /// as an executable image has no legitimate use.
    /// </summary>
    internal static bool IsPathological(string path)
    {
        // ':' is legitimate at index 1 ("C:\"); anywhere later it is an ADS.
        int colon = path.IndexOf(':', 2);
        if (colon >= 0) return true;

        foreach (char c in path)
        {
            if (char.IsControl(c)) return true;
            var cat = System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c);
            if (cat == System.Globalization.UnicodeCategory.Format) return true;   // RLO/LRO et al
        }

        foreach (var segment in path.Split('\\'))
        {
            if (segment.Length == 0) continue;
            char last = segment[^1];
            if (last == ' ' || (last == '.' && segment != "." && segment != "..")) return true;
        }
        return false;
    }

    /// <summary>Directory used for earned-trust and update-burst grouping.</summary>
    internal static string DirectoryKey(string? path)
    {
        string t = Tokenise(path);
        int i = t.LastIndexOf('\\');
        return i > 0 ? t[..i] : t;
    }

    /// <summary>IPv4 /16, IPv6 /48. A /24 is far too tight for Cloudflare, Akamai or Azure.</summary>
    internal static string PeerPrefix(IPAddress? address)
    {
        if (address is null) return "";
        var b = address.GetAddressBytes();
        if (b.Length == 4) return $"4:{b[0]}.{b[1]}";
        if (b.Length >= 6) return $"6:{b[0]:x2}{b[1]:x2}:{b[2]:x2}{b[3]:x2}:{b[4]:x2}{b[5]:x2}";
        return "";
    }
}

/// <summary>
/// The learned model of THIS machine.
///
/// Design rule that everything else follows from: the store holds only OBSERVATIONS, never
/// scores. Retuning a weight or a threshold is therefore a code change with no data migration
/// and nothing to re-learn — which matters, because every constant in the scorer is a starting
/// estimate that has to be validated against a fortnight of this user's real work.
///
/// Persisted as one JSON document under <see cref="HeroPaths.Baseline"/>. One file rather than
/// sharded: at the entity counts this machine actually produces a shard set would rewrite over
/// half its files on every flush, which is more NTFS metadata churn than it saves.
/// </summary>
internal sealed class Baseline
{
    // ---------------------------------------------------------------- tunables (one place)

    internal const int CurrentSchema = 1;
    /// <summary>Scoring-model version. Bump to invalidate cached derived state; no migration.</summary>
    internal const int CurrentEpoch = 1;

    // Decay half-lives in days. Network behaviour churns fastest; execution history is the
    // slowest because it is the evidence a dropper cannot fabricate.
    private const double HalfLifeCount = 90;
    private const double HalfLifeHours = 45;
    private const double HalfLifeParents = 60;
    private const double HalfLifeNetwork = 30;

    // Bounded top-K maps. Rare categories are dropped rather than kept forever; the cost is that
    // an evicted category looks new again, which is why the counts are generous.
    private const int MaxParents = 12;
    private const int MaxPeers = 32;
    private const int MaxPorts = 16;
    private const int MaxIdentities = 4;

    internal const int MaxEntities = 6000;
    private const int MaxBytes = 8 * 1024 * 1024;

    // Earned directory trust. Deliberately reachable at Familiar rather than Known: build artefacts
    // are pruned long before 14 days and 7 distinct days, so a Known threshold would only ever
    // promote toolchain directories, which already live in Program Files and do not need it.
    private const int EarnedDirectoryEntities = 8;
    private const double EarnedDirectoryTrust = 0.55;

    /// <summary>Provisional observations are struck from the record if the user later kills it.</summary>
    private const double ProvisionalCount = 12;

    internal static readonly double[] SigmaFloors = { 0.35, 0.20, 0.25 };   // cpu, memory, threads

    // ---------------------------------------------------------------- persisted state

    [JsonPropertyName("schema")] public int Schema { get; set; } = CurrentSchema;
    [JsonPropertyName("epoch")] public int Epoch { get; set; } = CurrentEpoch;
    [JsonPropertyName("host")] public string HostId { get; set; } = "";
    [JsonPropertyName("created")] public DateTime CreatedUtc { get; set; }
    [JsonPropertyName("saved")] public DateTime SavedUtc { get; set; }

    /// <summary>Hours HERO has actually been watching. Not uptime — a machine left on while
    /// HERO is not running teaches it nothing.</summary>
    [JsonPropertyName("watch")] public double ObservedHours { get; set; }
    [JsonPropertyName("boots")] public int BootSessions { get; set; }
    /// <summary>Last <see cref="Environment.TickCount64"/> seen. See <see cref="BeginSession"/>.</summary>
    [JsonPropertyName("tick")] public long LastTickCount { get; set; }
    [JsonPropertyName("beat")] public DateTime LastHeartbeatUtc { get; set; }
    /// <summary>Count of implausible wall-clock jumps. A clock moved backwards resets nothing.</summary>
    [JsonPropertyName("clk")] public int ClockAnomalies { get; set; }

    [JsonPropertyName("ents")] public Dictionary<string, BaselineEntity> Entities { get; set; } = new();
    [JsonPropertyName("sgn")] public Dictionary<string, SignerRecord> Signers { get; set; } = new();
    [JsonPropertyName("per")] public Dictionary<string, PersistenceRecord> Persistence { get; set; } = new();
    [JsonPropertyName("allow")] public List<AllowlistEntry> Allowlist { get; set; } = new();
    /// <summary>Directories whose earned trust the user has eroded by killing something in them.</summary>
    [JsonPropertyName("dpen")] public Dictionary<string, double> DirectoryPenalties { get; set; } = new();

    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }

    // ---------------------------------------------------------------- runtime-only state

    [JsonIgnore] private readonly object _gate = new();
    [JsonIgnore] private readonly Dictionary<string, double> _dirTrust = new(StringComparer.Ordinal);
    /// <summary>False when <see cref="_dirTrust"/> must be rebuilt. See <see cref="PathTrust"/>.</summary>
    [JsonIgnore] private bool _dirTrustValid;
    [JsonIgnore] private readonly List<UpdateBurst> _bursts = new();
    [JsonIgnore] private readonly HashSet<string> _frozen = new(StringComparer.Ordinal);
    [JsonIgnore] private bool _dirty;
    [JsonIgnore] private DateTime _lastSaveUtc;

    [JsonIgnore] internal string FilePath { get; set; } = "";
    [JsonIgnore] internal bool IsDirty { get { lock (_gate) return _dirty; } }
    [JsonIgnore] internal int EntityCount { get { lock (_gate) return Entities.Count; } }

    private sealed class UpdateBurst
    {
        internal string Id = "";
        internal string Root = "";
        internal string Signer = "";
        internal DateTime FirstUtc;
        internal DateTime LastUtc;
        internal int Count;
    }

    // ---------------------------------------------------------------- bootstrap

    /// <summary>
    /// The quiet period. HERO is learning and deliberately near-silent.
    ///
    /// Three conditions rather than a wall-clock timer, because a user who installs HERO on a
    /// Friday evening and does not touch the machine until Monday would otherwise leave bootstrap
    /// with a baseline built entirely from idle-time background tasks — and then alert on every
    /// single application they open on Monday morning.
    ///
    /// The entity count is reached within about an hour of ordinary use on this machine, so in
    /// practice the binding constraints are the 72 watched hours and 3 boots: enough to have seen
    /// a weekend and a couple of cold-boot autorun cascades.
    /// </summary>
    [JsonIgnore]
    internal bool IsBootstrapping
    {
        get
        {
            lock (_gate)
            {
                if (CreatedUtc != default && (DateTime.UtcNow - CreatedUtc).TotalDays >= 14) return false;
                return !(ObservedHours >= 72 && BootSessions >= 3 && Entities.Count >= 300);
            }
        }
    }

    /// <summary>0..1 across the three bootstrap conditions, for an honest progress element.</summary>
    [JsonIgnore]
    internal double BootstrapProgress
    {
        get
        {
            lock (_gate)
            {
                double a = Math.Min(1, ObservedHours / 72.0);
                double b = Math.Min(1, BootSessions / 3.0);
                double c = Math.Min(1, Entities.Count / 300.0);
                return Math.Clamp((a + b + c) / 3.0, 0, 1);
            }
        }
    }

    [JsonIgnore] internal string LearnState => IsBootstrapping ? "learning" : "steady";

    [JsonIgnore]
    internal double HistoryDays
    {
        get { lock (_gate) return CreatedUtc == default ? 0 : Math.Max(0, (DateTime.UtcNow - CreatedUtc).TotalDays); }
    }

    // ---------------------------------------------------------------- lifecycle

    internal static Baseline Load(string? path = null)
    {
        string file = path ?? HeroPaths.Baseline;
        var b = TryRead(file) ?? TryRead(file + ".bak") ?? new Baseline();
        b.FilePath = file;
        b.AfterLoad();
        return b;
    }

    private static Baseline? TryRead(string file)
    {
        try
        {
            if (!File.Exists(file)) return null;
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return JsonSerializer.Deserialize<Baseline>(fs, JsonOptions);
        }
        catch
        {
            // A corrupt baseline is a nuisance, never a crash: HERO re-learns rather than dies.
            return null;
        }
    }

    private void AfterLoad()
    {
        Entities ??= new();
        Signers ??= new();
        Persistence ??= new();
        Allowlist ??= new();
        DirectoryPenalties ??= new();

        if (CreatedUtc == default) CreatedUtc = DateTime.UtcNow;

        // A store written by a NEWER build must not be half-parsed into nonsense. Start again
        // rather than mangle it; the old file is left in place under a dated name.
        if (Schema > CurrentSchema)
        {
            try
            {
                if (File.Exists(FilePath))
                    File.Move(FilePath, FilePath + $".newer-{DateTime.UtcNow:yyyyMMddHHmmss}", true);
            }
            catch { /* best effort */ }
            Entities.Clear(); Signers.Clear(); Persistence.Clear();
            Schema = CurrentSchema;
            Epoch = CurrentEpoch;
            CreatedUtc = DateTime.UtcNow;
            ObservedHours = 0; BootSessions = 0;
        }

        bool epochChanged = Epoch != CurrentEpoch;
        Epoch = CurrentEpoch;

        foreach (var (key, e) in Entities)
        {
            e.Key = key;
            e.Identities ??= new();
            e.Parents ??= new();
            e.Peers ??= new();
            e.Ports ??= new();
            e.Cpu ??= new();
            e.Memory ??= new();
            e.Threads ??= new();
            if (e.Hours is null || e.Hours.Length != 24) e.Hours = new double[24];
            // The stored state is a cache for UI speed. On an epoch bump it is recomputed,
            // because a changed model must not inherit the previous model's conclusions.
            if (epochChanged) e.State = Evaluate(e, DateTime.UtcNow);
        }

        if (string.IsNullOrEmpty(HostId)) HostId = ComputeHostId();
    }

    private static string ComputeHostId()
    {
        try
        {
            var seed = Environment.MachineName + "|" + Environment.UserName;
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(seed)), 0, 8).ToLowerInvariant();
        }
        catch { return "unknown"; }
    }

    /// <summary>
    /// Called once at startup. Detects a reboot and accrues the boot-session counter.
    ///
    /// Reboot detection compares the persisted tick count with the current one. TickCount64 only
    /// resets at boot, so a value lower than the one we stored means the machine restarted. The
    /// obvious alternative — deriving a boot time as UtcNow minus TickCount64 — is wrong, because
    /// GetTickCount64 excludes time spent asleep, so on a desktop that sleeps the derived boot
    /// time drifts forward and every service start looks like a fresh boot. That inflates the
    /// counter and lets bootstrap complete on a baseline built from a single boot.
    /// </summary>
    internal void BeginSession(DateTime nowUtc)
    {
        lock (_gate)
        {
            long tick = Environment.TickCount64;
            bool rebooted = LastTickCount > 0 && tick < LastTickCount;
            if (LastTickCount == 0 || rebooted) BootSessions++;
            LastTickCount = tick;
            LastHeartbeatUtc = nowUtc;
            if (CreatedUtc == default) CreatedUtc = nowUtc;
            _dirty = true;
        }
    }

    /// <summary>
    /// Accrues watched time. Call from the monitor loop. The per-call cap means a suspended or
    /// hibernated process cannot credit itself with hours it did not actually watch.
    /// </summary>
    internal void Heartbeat(DateTime nowUtc)
    {
        lock (_gate)
        {
            if (LastHeartbeatUtc == default) { LastHeartbeatUtc = nowUtc; return; }
            double minutes = (nowUtc - LastHeartbeatUtc).TotalMinutes;
            if (minutes < 0) { ClockAnomalies++; LastHeartbeatUtc = nowUtc; return; }
            ObservedHours += Math.Min(minutes, 5.0) / 60.0;
            LastHeartbeatUtc = nowUtc;
            LastTickCount = Environment.TickCount64;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
    };

    /// <summary>Writes if dirty and the interval has elapsed. Returns true when it wrote.</summary>
    internal bool SaveIfDue(TimeSpan interval)
    {
        lock (_gate)
        {
            if (!_dirty) return false;
            if (_lastSaveUtc != default && DateTime.UtcNow - _lastSaveUtc < interval) return false;
        }
        Save();
        return true;
    }

    /// <summary>
    /// Persists the model. Crash-safe: the new document is written to a temp file, flushed all
    /// the way to the platter, and only then swapped in. A power cut can lose the last minute of
    /// learning; it can never leave a half-written baseline that fails to parse on next boot.
    /// </summary>
    internal void Save()
    {
        string json;
        lock (_gate)
        {
            Prune(DateTime.UtcNow);

            json = JsonSerializer.Serialize(this, JsonOptions);
            // Hard byte cap. Eviction is by ascending value-to-keep, and it is bounded so a
            // pathological document cannot spin here.
            for (int pass = 0; pass < 8 && json.Length > MaxBytes; pass++)
            {
                EvictLowestValue(Math.Max(64, Entities.Count / 10));
                json = JsonSerializer.Serialize(this, JsonOptions);
            }

            SavedUtc = DateTime.UtcNow;
            _lastSaveUtc = SavedUtc;
            _dirty = false;
        }

        try
        {
            WriteAtomic(string.IsNullOrEmpty(FilePath) ? HeroPaths.Baseline : FilePath, json);
        }
        catch
        {
            lock (_gate) _dirty = true;   // failed write must not look like a successful one
        }
    }

    private static void WriteAtomic(string target, string content)
    {
        string dir = Path.GetDirectoryName(target) ?? ".";
        Directory.CreateDirectory(dir);
        string tmp = target + ".tmp";

        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var bytes = Encoding.UTF8.GetBytes(content);
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(flushToDisk: true);
        }

        for (int attempt = 0; ; attempt++)
        {
            try
            {
                // File.Replace requires the destination to already exist and throws
                // FileNotFoundException otherwise — which is exactly the first-run case, on every
                // machine, every time. Move covers it.
                if (File.Exists(target)) File.Replace(tmp, target, target + ".bak", true);
                else File.Move(tmp, target);
                return;
            }
            catch (Exception ex) when (attempt < 3 && (ex is IOException or UnauthorizedAccessException))
            {
                // A reader holding the file open (the dashboard, a backup agent) is transient.
                Thread.Sleep(50 * (attempt + 1));
            }
        }
    }

    // ---------------------------------------------------------------- observation

    /// <summary>
    /// Feeds one poll into the model: newly started processes and their connections.
    /// This is the single call the guardian service needs to wire up.
    /// </summary>
    internal void Ingest(SnapshotDelta delta, DetectionContext context)
    {
        var now = delta.Current.TakenUtc;
        Heartbeat(now);

        foreach (var p in delta.StartedProcesses)
        {
            if (p.PathUnavailable) continue;
            if (HeroPaths.IsOwnState(p.ImagePath)) continue;   // never learn from, or about, ourselves

            string? parent = delta.Current.ByPid.TryGetValue(p.ParentPid, out var par) ? par.FileName : null;
            Observe(p, context.Signature(p.ImagePath), parent, now);
        }

        foreach (var c in delta.NewConnections)
        {
            if (!c.IsExternal) continue;
            if (!delta.Current.ByPid.TryGetValue(c.Pid, out var owner) || owner.PathUnavailable) continue;
            var e = Find(owner.ImagePath);
            if (e is not null) ObserveConnection(e, c, now);
        }
    }

    /// <summary>Records one execution of a process and classifies any change to its bytes.</summary>
    internal ObservationResult Observe(ProcessRecord process, SignatureInfo? signature,
                                       string? parentName, DateTime nowUtc)
    {
        lock (_gate)
        {
            string key = PathModel.KeyFor(process.ImagePath);
            if (key.Length == 0)
                return new ObservationResult(new BaselineEntity { Name = process.Name }, ChangeKind.None, null, 0);

            if (!Entities.TryGetValue(key, out var e) || e is null)
            {
                e = new BaselineEntity
                {
                    Key = key,
                    Path = PathModel.Tokenise(process.ImagePath),
                    RealPath = process.ImagePath,
                    Name = process.FileName,
                    FirstSeenUtc = nowUtc,
                    DecayedUtc = nowUtc,
                    DayAnchor = DayIndex(nowUtc),
                };
                Entities[key] = e;
                // No InvalidateDirectoryTrust here: a brand-new entity is State.New and so counts
                // toward no directory. If Evaluate below fast-tracks it to Familiar, the boundary
                // test at the end of this method catches it.
            }

            // Anti-poisoning interlock 1: nothing inside an open incident is learned from.
            // Observations still reach the event log for forensics; they never widen a model.
            if (_frozen.Contains(key)) return new ObservationResult(e, ChangeKind.None, null, 0);

            EnsureDecayed(e, nowUtc);

            var change = ClassifyChange(e, process, signature, nowUtc, out string? burstId, out int burstSize);

            // Anti-poisoning interlock 2: a file whose signature is present but INVALID is never
            // learned from at all. Nobody accidentally ships a corrupt signature.
            if (signature is { State: SignatureState.Invalid })
                return new ObservationResult(e, change, burstId, burstSize);

            e.RealPath = process.ImagePath;
            e.Name = process.FileName;
            e.LastSeenUtc = nowUtc;
            e.Count += 1;
            if (e.Count <= ProvisionalCount) e.Provisional = e.Count;

            if (e.LastBootSeen != BootSessions) { e.LastBootSeen = BootSessions; e.Boots++; }
            TouchDay(e, nowUtc);
            e.Hours[nowUtc.ToLocalTime().Hour] += 1;

            if (!string.IsNullOrEmpty(parentName))
                Bump(e.Parents, parentName.ToLowerInvariant(), MaxParents);

            if (process.ThreadCount > 0 && ShouldSampleEnvelope(e, nowUtc))
            {
                e.Threads.Add(process.ThreadCount, SigmaFloors[2], nowUtc);
                e.LastEnvelopeUtc = nowUtc;
            }

            if (signature is not null) RecordSigner(e, signature, nowUtc);

            var before = e.State;
            e.State = Evaluate(e, nowUtc);
            // Only a transition ACROSS the Familiar boundary can change a directory's count, and
            // this runs on every process start — on this machine, hundreds a minute during a build.
            if ((before >= EntityState.Familiar) != (e.State >= EntityState.Familiar))
                InvalidateDirectoryTrust();

            _dirty = true;
            return new ObservationResult(e, change, burstId, burstSize);
        }
    }

    /// <summary>
    /// One envelope observation per entity per 10 minutes.
    ///
    /// Recording every sample would let a ten-hour Unreal build contribute thousands of
    /// observations while a three-second CLI tool contributes one, which destroys any
    /// comparability between entities and lets a long-lived process wash out its own envelope.
    /// </summary>
    private static bool ShouldSampleEnvelope(BaselineEntity e, DateTime nowUtc)
        => e.LastEnvelopeUtc == default || (nowUtc - e.LastEnvelopeUtc).TotalMinutes >= 10;

    /// <summary>Records a resource sample. CPU percent is whole-machine, memory is private MB.</summary>
    internal void ObserveResources(BaselineEntity entity, double? cpuPercent, double? privateMb,
                                   int? threads, DateTime nowUtc)
    {
        lock (_gate)
        {
            if (_frozen.Contains(entity.Key)) return;
            if (!ShouldSampleEnvelope(entity, nowUtc)) return;
            EnsureDecayed(entity, nowUtc);

            if (cpuPercent is { } cpu) entity.Cpu.Add(cpu, SigmaFloors[0], nowUtc);
            if (privateMb is { } mem) entity.Memory.Add(mem, SigmaFloors[1], nowUtc);
            if (threads is { } thr) entity.Threads.Add(thr, SigmaFloors[2], nowUtc);
            entity.LastEnvelopeUtc = nowUtc;
            _dirty = true;
        }
    }

    /// <summary>Records one external peer. Loopback and RFC1918 are never learned or scored.</summary>
    internal void ObserveConnection(BaselineEntity entity, Connection connection, DateTime nowUtc)
    {
        if (!connection.IsExternal) return;
        lock (_gate)
        {
            if (_frozen.Contains(entity.Key)) return;
            EnsureDecayed(entity, nowUtc);
            var prefix = PathModel.PeerPrefix(connection.RemoteAddress);
            if (prefix.Length > 0) Bump(entity.Peers, prefix, MaxPeers);
            if (connection.RemotePort > 0)
                Bump(entity.Ports, connection.RemotePort.ToString(System.Globalization.CultureInfo.InvariantCulture), MaxPorts);
            _dirty = true;
        }
    }

    /// <summary>Records an autorun sighting. Returns true if HERO has never seen this one before.</summary>
    internal bool ObservePersistence(PersistenceEntry entry, DateTime nowUtc)
    {
        lock (_gate)
        {
            bool isNew = false;
            if (!Persistence.TryGetValue(entry.Key, out var rec) || rec is null)
            {
                isNew = true;
                rec = new PersistenceRecord { FirstSeenUtc = nowUtc, Target = entry.Target };
                Persistence[entry.Key] = rec;
            }
            else if (!string.Equals(rec.Target, entry.Target, StringComparison.OrdinalIgnoreCase))
            {
                // A modified autorun is a different event from a new one, and a more interesting
                // one: the value changed under an entry the user already lives with.
                rec.Target = entry.Target;
                isNew = true;
            }

            rec.LastSeenUtc = nowUtc;
            rec.Sightings++;

            if (!string.IsNullOrEmpty(entry.ImagePath))
            {
                var e = FindLocked(entry.ImagePath);
                if (e is not null) e.Persistent = true;
            }

            _dirty = true;
            // During bootstrap the whole autorun set is new by definition, so nothing here is
            // novel: the census is a triage list, not an alert stream.
            return isNew && !IsBootstrapping;
        }
    }

    private static void Bump(Dictionary<string, double> map, string key, int cap)
    {
        map[key] = map.TryGetValue(key, out var v) ? v + 1 : 1;
        if (map.Count <= cap) return;

        // Evict the rarest. The cost is that an evicted category looks brand-new if it returns,
        // so the caps are set generously rather than tightly.
        string? weakest = null;
        double lowest = double.MaxValue;
        foreach (var (candidate, count) in map)
            if (count < lowest) { lowest = count; weakest = candidate; }
        if (weakest is not null) map.Remove(weakest);
    }

    private static int DayIndex(DateTime utc) => (int)(utc.Date - new DateTime(2020, 1, 1)).TotalDays;

    private static void TouchDay(BaselineEntity e, DateTime nowUtc)
    {
        int day = DayIndex(nowUtc);
        int delta = day - e.DayAnchor;
        if (delta > 0)
        {
            e.DayMask = delta >= 32 ? 0u : e.DayMask << delta;
            e.DayAnchor = day;
        }
        else if (delta < 0)
        {
            // Clock moved backwards. Credit the day without rewriting the anchor.
            if (-delta < 32) { e.DayMask |= 1u << -delta; return; }
            return;
        }
        e.DayMask |= 1u;
    }

    // ---------------------------------------------------------------- change classification

    /// <summary>
    /// Decides what a new set of bytes at a known path MEANS. This is the single highest-value
    /// false-positive control in the whole engine: without it, the first Windows cumulative
    /// update after install generates thousands of events.
    /// </summary>
    private ChangeKind ClassifyChange(BaselineEntity e, ProcessRecord process, SignatureInfo? sig,
                                      DateTime nowUtc, out string? burstId, out int burstSize)
    {
        burstId = null;
        burstSize = 0;

        var identity = ContentIdentity.For(process.ImagePath);
        if (identity.IsEmpty) return ChangeKind.None;

        var current = e.Current;
        string token = identity.Token;

        if (current is not null && string.Equals(current.Id, token, StringComparison.Ordinal))
        {
            current.LastSeenUtc = nowUtc;
            current.Count += 1;
            return ChangeKind.None;
        }

        var record = new ContentRecord
        {
            Id = token,
            Size = identity.Size,
            Version = ReadVersion(process.ImagePath),
            FirstSeenUtc = nowUtc,
            LastSeenUtc = nowUtc,
            Count = 1,
        };
        e.Identities.Add(record);
        while (e.Identities.Count > MaxIdentities) e.Identities.RemoveAt(0);

        if (current is null) return ChangeKind.FirstSight;

        // "Was this signed?" is answered from the whole history, not the last reading. Once a path
        // has held a validly signed binary, an unsigned one appearing there is a break — forever.
        bool wasSigned = e.EverSigned || e.SignerState == (int)SignatureState.Valid;
        bool nowValid = sig is { State: SignatureState.Valid };
        bool sameSigner = nowValid && !string.IsNullOrEmpty(e.Signer) &&
                          string.Equals(e.Signer, sig!.Signer, StringComparison.OrdinalIgnoreCase);

        ChangeKind kind;
        if (nowValid && (sameSigner || string.IsNullOrEmpty(e.Signer)))
        {
            double pt = PathModel.BaseTrust(process.ImagePath);
            if (pt >= 0.55)
            {
                // Case A: same publisher, trusted location. Inherit every statistic, keep the
                // state, and suppress rarity for a day. Zero alerts. This must be silent — it is
                // what happens every time Chrome, VS Code or the dotnet SDK updates.
                kind = ChangeKind.VersionRollover;
                e.UpdateGraceUntilUtc = nowUtc.AddHours(24);
            }
            else
            {
                // Case B: same publisher, but the user (or anything running as them) can write
                // here. Roll over, but re-arm behaviour watching for a day.
                kind = ChangeKind.RollingUserWritable;
                e.UpdateGraceUntilUtc = nowUtc.AddHours(12);
                e.WatchUntilUtc = nowUtc.AddHours(24);
            }
        }
        else if (wasSigned && !nowValid)
        {
            // Case C: it was signed and now it is not, or the signature broke, or someone else
            // signed it. Statistics are retained but the entity loses its earned standing.
            kind = ChangeKind.SignerBreak;
            e.SignerChanged = true;
            e.State = EntityState.Observed;
            e.UpdateGraceUntilUtc = default;
            e.WatchUntilUtc = nowUtc.AddHours(48);
        }
        else
        {
            // Case D: unsigned before, unsigned now. Every build output on this machine looks
            // exactly like this, which is why it is weak evidence and never more.
            kind = ChangeKind.UnsignedRewrite;
            e.WatchUntilUtc = nowUtc.AddHours(6);
        }

        var burst = JoinBurst(process.ImagePath, sig?.Signer ?? "", nowUtc);
        burstId = burst.Item1;
        burstSize = burst.Item2;
        return kind;
    }

    /// <summary>
    /// Coalesces a multi-file update into one event.
    ///
    /// Two windows, because the two updates that matter most have opposite shapes. A signed
    /// application update rewrites a directory in seconds, so 15 minutes is generous. An Unreal
    /// or Steam update rewrites gigabytes of UNSIGNED content sharing no publisher over an hour
    /// or more; a same-signer rule would never coalesce it and would produce exactly the storm
    /// the mechanism exists to prevent.
    /// </summary>
    private (string?, int) JoinBurst(string imagePath, string signer, DateTime nowUtc)
    {
        string root = PathModel.DirectoryKey(imagePath);
        if (root.Length == 0) return (null, 0);

        double window = string.IsNullOrEmpty(signer) ? 120 : 15;
        _bursts.RemoveAll(b => (nowUtc - b.LastUtc).TotalMinutes > 120);

        var burst = _bursts.FirstOrDefault(b =>
            string.Equals(b.Root, root, StringComparison.Ordinal) &&
            string.Equals(b.Signer, signer, StringComparison.OrdinalIgnoreCase) &&
            (nowUtc - b.LastUtc).TotalMinutes <= window);

        if (burst is null)
        {
            burst = new UpdateBurst
            {
                Id = "upd_" + Convert.ToHexString(SHA256.HashData(
                        Encoding.UTF8.GetBytes(root + "|" + signer + "|" + nowUtc.Ticks)), 0, 6).ToLowerInvariant(),
                Root = root,
                Signer = signer,
                FirstUtc = nowUtc,
            };
            _bursts.Add(burst);
            if (_bursts.Count > 32) _bursts.RemoveAt(0);
        }

        burst.LastUtc = nowUtc;
        burst.Count++;
        return (burst.Id, burst.Count);
    }

    private static string ReadVersion(string path)
    {
        try { return FileVersionInfo.GetVersionInfo(path).FileVersion ?? ""; }
        catch { return ""; }
    }

    private void RecordSigner(BaselineEntity e, SignatureInfo sig, DateTime nowUtc)
    {
        // Unknown and Unreadable are non-verdicts — a locked file, a deleted file, an unelevated
        // read that failed. They must never overwrite a real one, or a single transient failure
        // silently erases what HERO knew about this binary's publisher.
        if (sig.State is SignatureState.Unknown or SignatureState.Unreadable) return;

        e.SignerState = (int)sig.State;
        e.SignerKind = (int)sig.Kind;
        if (sig.State == SignatureState.Valid) e.EverSigned = true;
        if (string.IsNullOrEmpty(sig.Signer)) return;
        e.Signer = sig.Signer;

        if (sig.State != SignatureState.Valid) return;
        if (!Signers.TryGetValue(sig.Signer, out var rec) || rec is null)
        {
            rec = new SignerRecord { Name = sig.Signer, FirstSeenUtc = nowUtc };
            Signers[sig.Signer] = rec;
        }
        // Recounted at most every six hours. It is a full scan of the entity table, and this runs
        // on every process start: on a machine that spawns hundreds of build processes a minute,
        // recounting each time would be the single most expensive thing the baseline does. Nothing
        // depends on it being fresher than that — promotion to a reputable publisher also requires
        // 30 days of history.
        if ((nowUtc - rec.CountedUtc).TotalHours >= 6)
        {
            rec.CountedUtc = nowUtc;
            rec.KnownEntities = Entities.Values.Count(x =>
                x.State >= EntityState.Known &&
                string.Equals(x.Signer, sig.Signer, StringComparison.OrdinalIgnoreCase));
        }
    }

    // ---------------------------------------------------------------- decay

    /// <summary>
    /// Applies time decay. Called at the top of every read and write path so that no code path
    /// can forget it — the failure mode of decay-at-call-sites is a model that is silently stale
    /// in some paths and current in others.
    /// </summary>
    internal void EnsureDecayed(BaselineEntity e, DateTime nowUtc)
    {
        if (e.DecayedUtc == default) { e.DecayedUtc = nowUtc; return; }
        double days = (nowUtc - e.DecayedUtc).TotalDays;
        if (days < 1.0)
        {
            if (days < -1.0) { ClockAnomalies++; e.DecayedUtc = nowUtc; }   // clock moved back
            return;
        }
        if (days > 3650) days = 3650;   // clock jumped forward: clamp rather than annihilate

        double lc = Math.Pow(0.5, days / HalfLifeCount);
        double lh = Math.Pow(0.5, days / HalfLifeHours);
        double lp = Math.Pow(0.5, days / HalfLifeParents);
        double ln = Math.Pow(0.5, days / HalfLifeNetwork);

        e.Count *= lc;
        e.Provisional = Math.Min(e.Provisional, e.Count);
        for (int i = 0; i < e.Hours.Length; i++) e.Hours[i] *= lh;
        DecayMap(e.Parents, lp);
        DecayMap(e.Peers, ln);
        DecayMap(e.Ports, ln);
        e.Cpu.Decay(lc);
        e.Memory.Decay(lc);
        e.Threads.Decay(lc);

        // FirstSeen is deliberately NOT decayed. Age is the strongest single piece of evidence
        // that something is not a fresh dropper, and decaying it would make software the user has
        // had installed for a year periodically re-alert.
        e.DecayedUtc = nowUtc;
        _dirty = true;
    }

    private static void DecayMap(Dictionary<string, double> map, double lambda)
    {
        if (map.Count == 0) return;
        List<string>? dead = null;
        foreach (var key in map.Keys.ToList())
        {
            double v = map[key] * lambda;
            if (v < 0.5) (dead ??= new()).Add(key);
            else map[key] = v;
        }
        if (dead is not null) foreach (var k in dead) map.Remove(k);
    }

    // ---------------------------------------------------------------- graduation

    /// <summary>
    /// Which rung of the trust ladder an entity is on. Always derived, never authoritative on
    /// disk — the stored value is a cache so the dashboard does not recompute 6,000 of these.
    ///
    /// The day-diversity clause is what stops a build script that runs an executable 400 times in
    /// one afternoon from graduating it to "known" on day one.
    /// </summary>
    internal EntityState Evaluate(BaselineEntity e, DateTime nowUtc)
    {
        if (e.Blocked) return EntityState.Blocked;

        double n = e.Count;
        double ageDays = e.FirstSeenUtc == default ? 0 : Math.Max(0, (nowUtc - e.FirstSeenUtc).TotalDays);
        int days = e.DistinctDays;
        double sg = SignerTrust((SignatureState)e.SignerState, (SignatureKind)e.SignerKind, e.Signer);
        double pt = PathModel.BaseTrust(e.RealPath);   // static tier only: the earned tier reads
                                                      // cached states and would recurse into here

        var state = EntityState.New;
        if (n >= 3 && e.Boots >= 2) state = EntityState.Observed;
        if (n >= 8 && ageDays >= 3 && days >= 3) state = EntityState.Familiar;
        if (n >= 15 && ageDays >= 14 && days >= 7 && (sg >= 0.55 || e.UserAllowed || pt >= 0.85))
            state = EntityState.Known;
        if (state == EntityState.Known && sg >= 0.80 && ageDays >= 45)
            state = EntityState.Trusted;

        // FAST TRACK, expressed as a FLOOR rather than a shortcut. A catalog-signed Windows
        // component in a system directory, or anything signed by a publisher that already owns
        // several known entities on this host, is never below Familiar. Installing a new Microsoft
        // or NVIDIA component therefore produces no alert at all, while a brand-new unsigned binary
        // in %APPDATA% still starts at New with no history.
        //
        // A floor and not a first-observation special case: as a special case it would apply at
        // n=1 and stop applying at n=2, so the entity would go Familiar -> New on its second run
        // and the second run would score as MORE novel than the first.
        if (((sg >= 1.0 && pt >= 0.85) || sg >= 0.80) && state < EntityState.Familiar)
            state = EntityState.Familiar;

        // A signer break costs earned standing outright, and it outranks the fast-track floor:
        // "signed by a publisher I trust" is exactly what a signer break has just disproved.
        // Everything else about this ladder is gradual; this is not.
        if (e.SignerChanged && state > EntityState.Observed) state = EntityState.Observed;
        return state;
    }

    // ---------------------------------------------------------------- lookups and trust

    internal BaselineEntity? Find(string? imagePath)
    {
        lock (_gate) return FindLocked(imagePath);
    }

    private BaselineEntity? FindLocked(string? imagePath)
    {
        string key = PathModel.KeyFor(imagePath);
        if (key.Length == 0) return null;
        if (!Entities.TryGetValue(key, out var e) || e is null) return null;
        EnsureDecayed(e, DateTime.UtcNow);
        return e;
    }

    /// <summary>Entity for a subject, or null when HERO has never seen it.</summary>
    internal BaselineEntity? Find(Subject subject) => Find(PathOf(subject));

    internal static string? PathOf(Subject subject) => subject switch
    {
        ProcessSubject p => p.Process.PathUnavailable ? null : p.Process.ImagePath,
        PersistenceSubject e => string.IsNullOrEmpty(e.Entry.ImagePath) ? null : e.Entry.ImagePath,
        _ => null,
    };

    /// <summary>
    /// Rarity R in [0,1]: how surprising it is that this ran at all.
    ///
    /// R = exp(-0.11667*n - 0.03*ageDays). Reference points, which are regression fixtures:
    ///   n=0,  age=0   -> 1.000     never seen before
    ///   n=1,  age=0   -> 0.890
    ///   n=3,  age=1   -> 0.683
    ///   n=8,  age=5   -> 0.339
    ///   n=15, age=14  -> 0.114     roughly where an entity becomes "known"
    ///   n=30, age=60  -> 0.005
    /// The execution count carries more weight than age because a dropper can backdate a file
    /// trivially but cannot fabricate execution history inside HERO's own store.
    /// </summary>
    internal double Novelty(BaselineEntity? entity, DateTime nowUtc)
    {
        bool boot = IsBootstrapping;
        if (entity is null) return boot ? 0.65 : 1.0;

        lock (_gate)
        {
            EnsureDecayed(entity, nowUtc);
            if (nowUtc < entity.UpdateGraceUntilUtc) return 0.0;   // silent window after an update

            double ageDays = entity.FirstSeenUtc == default ? 0 : Math.Max(0, (nowUtc - entity.FirstSeenUtc).TotalDays);
            double r = Math.Exp(-0.11667 * entity.Count - 0.03 * ageDays);
            if (entity.UserAllowed) r *= 0.5;
            r = Math.Clamp(r, 0, 1);

            // On day two literally everything is rare, so an unclamped R would put every process
            // on the machine at the top of the scale and mean nothing.
            return boot ? Math.Min(r, 0.65) : r;
        }
    }

    /// <summary>
    /// Signer trust Sg. The score uses (1 - Sg), so this ranges from a 1.35-point penalty for a
    /// broken signature to a 0-point charge for a Windows component.
    ///
    ///   1.00  catalog-signed, or Microsoft-signed: a genuine platform component
    ///   0.80  valid, and this publisher already owns 3+ known entities on THIS host
    ///   0.55  valid Authenticode, publisher not yet established here
    ///   0.00  unsigned  — nine unsigned binaries are running on this machine right now and
    ///                     every one is benign, so this is a weak contribution by construction
    ///  -0.35  signature present but INVALID: strictly worse than unsigned, because nobody
    ///         accidentally ships a corrupt signature
    /// </summary>
    internal double SignerTrust(SignatureState state, SignatureKind kind, string signer)
    {
        switch (state)
        {
            case SignatureState.Invalid:
                return -0.35;
            case SignatureState.Valid:
                break;
            default:
                // Unknown and Unreadable are treated as unsigned, not as suspicious. An
                // unverifiable file is an access limitation on an unelevated tool, not evidence.
                return 0.00;
        }

        lock (_gate)
        {
            if (!string.IsNullOrEmpty(signer) &&
                Signers.TryGetValue(signer, out var rec) && rec is not null && rec.Denies >= 2)
                return 0.00;   // the user has killed this publisher's software twice; no promotion

            if (kind == SignatureKind.Catalog) return 1.00;
            if (signer.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase)) return 1.00;

            if (!string.IsNullOrEmpty(signer) && Signers.TryGetValue(signer, out var r2) && r2 is not null &&
                r2.KnownEntities >= 3 && (DateTime.UtcNow - r2.FirstSeenUtc).TotalDays >= 30)
                return 0.80;   // earned on this host, with no shipped publisher list

            return 0.55;
        }
    }

    /// <summary>
    /// Reads one categorical channel under the store's own lock.
    ///
    /// The scorer runs on whichever thread asked for a verdict while the monitor loop is writing
    /// observations on another. Enumerating a Dictionary mid-write throws, so the read happens in
    /// here rather than in the scorer — a crash in the guardian is worse than any false positive.
    /// </summary>
    internal (double Total, int Distinct, bool Known) ChannelStats(Dictionary<string, double> channel, string category)
    {
        lock (_gate)
        {
            double total = 0;
            foreach (var v in channel.Values) total += v;
            return (total, channel.Count, category.Length > 0 && channel.ContainsKey(category));
        }
    }

    internal double SignerTrust(SignatureInfo? sig)
        => sig is null ? 0.00 : SignerTrust(sig.State, sig.Kind, sig.Signer);

    internal double SignerTrust(BaselineEntity? e)
        => e is null ? 0.00 : SignerTrust((SignatureState)e.SignerState, (SignatureKind)e.SignerKind, e.Signer);

    /// <summary>
    /// Path trust Pt, including the earned-directory promotion.
    ///
    /// The earned tier is essential on this machine and it is deliberately reachable: a directory
    /// containing 8 entities at Familiar or better is promoted to 0.55. Requiring "known" (14 days
    /// and 7 distinct days) would be unreachable for build output, because build artefacts are
    /// pruned long before they get there — so the tier would only ever promote toolchain
    /// directories, which already live in Program Files and do not need it.
    /// </summary>
    internal double PathTrust(string? path)
    {
        double baseTrust = PathModel.BaseTrust(path);
        if (string.IsNullOrWhiteSpace(path)) return baseTrust;

        string dir = PathModel.DirectoryKey(path);
        if (dir.Length == 0) return baseTrust;

        lock (_gate)
        {
            if (!_dirTrustValid) RebuildDirectoryTrust();
            double earned = _dirTrust.GetValueOrDefault(dir);

            // A directory the user has killed something in loses its earned bonus. It can never
            // drop below the static tier: a penalty is not a second path-trust system.
            if (DirectoryPenalties.TryGetValue(dir, out double penalty)) earned = Math.Max(0, earned - penalty);
            return Math.Max(baseTrust, earned);
        }
    }

    /// <summary>
    /// Recomputes earned directory trust for every directory in one pass.
    ///
    /// Whole-map rather than per-directory memoisation, because the per-directory form degenerates
    /// badly here: a miss costs a full scan of up to <see cref="MaxEntities"/> entities, each one
    /// re-tokenising a path (a lowercase, a split and two regex matches per segment), and the cache
    /// is invalidated whenever an entity crosses the Familiar boundary. During a build — dozens of
    /// short-lived processes a second, every one of them scored — that is tens of milliseconds per
    /// verdict spent inside the store's global lock, which is where the monitor loop also wants to
    /// be. One pass per invalidation instead of one pass per miss keeps it off the hot path.
    /// </summary>
    private void RebuildDirectoryTrust()
    {
        _dirTrust.Clear();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var e in Entities.Values)
        {
            if (e.State < EntityState.Familiar) continue;
            string dir = PathModel.DirectoryKey(e.RealPath);
            if (dir.Length == 0) continue;
            int n = counts.TryGetValue(dir, out int prev) ? prev + 1 : 1;
            counts[dir] = n;
            if (n == EarnedDirectoryEntities) _dirTrust[dir] = EarnedDirectoryTrust;
        }
        _dirTrustValid = true;
    }

    /// <summary>Marks earned directory trust stale. Only a change that can alter a directory's
    /// count of Familiar-or-better entities needs to call this.</summary>
    private void InvalidateDirectoryTrust()
    {
        _dirTrust.Clear();
        _dirTrustValid = false;
    }

    // ---------------------------------------------------------------- freeze / feedback

    /// <summary>
    /// Stops learning from an entity while an incident about it is open. Without this, an
    /// attacker's dwell time IS training data.
    /// </summary>
    internal void Freeze(string entityKey)
    {
        if (string.IsNullOrEmpty(entityKey)) return;
        lock (_gate) _frozen.Add(entityKey);
    }

    internal void Unfreeze(string entityKey)
    {
        lock (_gate) _frozen.Remove(entityKey);
    }

    internal bool IsFrozen(string entityKey)
    {
        lock (_gate) return _frozen.Contains(entityKey);
    }

    /// <summary>
    /// Records a user approval against the model.
    ///
    /// Note what this does NOT do: it never injects pseudo-observations at the observed extreme
    /// values. That trick is attractive — feedback flowing into the same model rather than into a
    /// bypass list — but it writes a large single-step variance widening that the daily sigma
    /// checkpoint cannot rate-limit, so one mis-clicked approval would permanently widen the
    /// entity's envelope. Approval halves the rarity term and nothing else.
    /// </summary>
    internal void MarkUserAllowed(BaselineEntity entity)
    {
        lock (_gate)
        {
            entity.UserAllowed = true;
            entity.Allows++;
            entity.Blocked = false;
            entity.State = Evaluate(entity, DateTime.UtcNow);
            InvalidateDirectoryTrust();   // an approval can lift the entity across Familiar
            _dirty = true;
        }
    }

    /// <summary>Records a kill verdict: block, strike the provisional training data, penalise.</summary>
    internal void MarkUserDenied(BaselineEntity entity)
    {
        lock (_gate)
        {
            entity.Blocked = true;
            entity.UserAllowed = false;
            entity.Denies++;

            // The attacker's own training data dies with the attacker: the first dozen
            // observations of any entity are provisional precisely so this is possible.
            entity.Count = Math.Max(0, entity.Count - entity.Provisional);
            entity.Provisional = 0;
            entity.State = EntityState.Blocked;

            if (!string.IsNullOrEmpty(entity.Signer) &&
                Signers.TryGetValue(entity.Signer, out var rec) && rec is not null)
            {
                rec.Denies++;
            }

            string dir = PathModel.DirectoryKey(entity.RealPath);
            if (dir.Length > 0)
                DirectoryPenalties[dir] = Math.Min(0.55, DirectoryPenalties.GetValueOrDefault(dir) + 0.15);

            InvalidateDirectoryTrust();
            _dirty = true;
        }
    }

    internal void AddAllowlistEntry(AllowlistEntry entry)
    {
        lock (_gate)
        {
            Allowlist.Add(entry);
            if (Allowlist.Count > 512) Allowlist.RemoveAll(a => a.Revoked || a.ExpiresUtc < DateTime.UtcNow);
            _dirty = true;
        }
    }

    internal void MarkDirty()
    {
        lock (_gate) _dirty = true;
    }

    /// <summary>
    /// Retires an allowlist entry. A tombstone rather than a deletion: an approval that silently
    /// vanishes is indistinguishable from one that was never made, and the trust-review panel
    /// needs to be able to say what happened and when.
    /// </summary>
    internal void RevokeAllowlist(AllowlistEntry entry, string reason)
    {
        lock (_gate)
        {
            entry.Revoked = true;
            entry.RevokedReason = reason;
            _dirty = true;
        }
    }

    /// <summary>Approvals created in the last <paramref name="window"/>. Feeds the trust rate limit.</summary>
    internal int AllowlistCreatedSince(TimeSpan window)
    {
        var cutoff = DateTime.UtcNow - window;
        lock (_gate) return Allowlist.Count(a => a.CreatedUtc >= cutoff);
    }

    /// <summary>Live allowlist entries for an entity, newest first.</summary>
    internal List<AllowlistEntry> AllowlistFor(string entityKey)
    {
        lock (_gate)
            return Allowlist.Where(a => a.Live && string.Equals(a.EntityKey, entityKey, StringComparison.Ordinal))
                            .OrderByDescending(a => a.CreatedUtc)
                            .ToList();
    }

    // ---------------------------------------------------------------- pruning

    /// <summary>
    /// Nightly-ish housekeeping. Called from Save so it cannot be forgotten.
    /// Never prunes anything an allowlist entry, an autorun or a block references.
    /// </summary>
    internal void Prune(DateTime nowUtc)
    {
        var referenced = new HashSet<string>(
            Allowlist.Where(a => a.Live).Select(a => a.EntityKey), StringComparer.Ordinal);

        var doomed = new List<string>();
        foreach (var (key, e) in Entities)
        {
            if (referenced.Contains(key) || e.Persistent || e.Blocked || e.UserAllowed) continue;
            double idle = e.LastSeenUtc == default ? 0 : (nowUtc - e.LastSeenUtc).TotalDays;

            // Build artefacts: this machine produces tens to hundreds a week. They are not
            // installed software and keeping them would balloon the store for no benefit.
            bool transient = e.Count < 3 && idle > 7 && PathModel.BaseTrust(e.RealPath) < 0.85;

            if (idle > 365 || (idle > 120 && e.Count < 5) || transient) doomed.Add(key);
        }

        foreach (var key in doomed) Entities.Remove(key);

        Allowlist.RemoveAll(a => a.Revoked && (nowUtc - a.CreatedUtc).TotalDays > 400);
        if (Entities.Count > MaxEntities) EvictLowestValue(Entities.Count - MaxEntities);
        if (doomed.Count > 0) InvalidateDirectoryTrust();
    }

    /// <summary>
    /// Evicts the least valuable entities. keepScore weights execution history most heavily,
    /// then recency, then signer standing — the same ordering as the rarity term, so eviction
    /// never removes the entities whose absence would create a false positive.
    /// </summary>
    private void EvictLowestValue(int count)
    {
        if (count <= 0 || Entities.Count == 0) return;
        var now = DateTime.UtcNow;

        var ranked = Entities
            .Where(kv => !kv.Value.Persistent && !kv.Value.Blocked && !kv.Value.UserAllowed)
            .Select(kv => (kv.Key, Score:
                0.5 * Math.Log(1 + kv.Value.Count) +
                0.3 * (1 - Math.Min(1, (now - kv.Value.LastSeenUtc).TotalDays / 365.0)) +
                0.2 * Math.Max(0, SignerTrust(kv.Value))))
            .OrderBy(t => t.Score)
            .Take(count)
            .Select(t => t.Key)
            .ToList();

        foreach (var key in ranked) Entities.Remove(key);
        InvalidateDirectoryTrust();
    }
}
