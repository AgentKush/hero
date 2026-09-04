using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
using Hero.Interop;

namespace Hero.Guardian.Rules;

/// <summary>
/// Shared vocabulary for the process rules.
///
/// Two decisions live here rather than in each rule, because getting them inconsistent is how a
/// detection set drifts into false positives:
///
/// 1. <see cref="Ignorable"/> — what HERO refuses to accuse at all. A process whose image path
///    could not be read is an ACCESS limitation, not evidence: 132 of 358 processes on this
///    machine deny it unelevated, and treating that as suspicion would flag a third of Windows.
///
/// 2. <see cref="Families"/> — the correlation groups. Signature state, path class, file age and
///    "did it delete itself" are four ways of describing one observation about one file, so they
///    all report the same family and the scorer counts only the strongest. Without that, an
///    ordinary unsigned build output accumulates four independent-looking accusations from a
///    single fact.
/// </summary>
internal static class RuleKit
{
    internal static class Families
    {
        /// <summary>Everything derived from the file on disk: signature, location, age, existence.</summary>
        internal const string Provenance = "provenance";
        /// <summary>A Windows image name used somewhere it does not belong.</summary>
        internal const string Masquerade = "masquerade";
        /// <summary>Parent/child relationships.</summary>
        internal const string Lineage = "lineage";
        /// <summary>Content of the command line.</summary>
        internal const string CommandLine = "command-line";
        /// <summary>Token privilege and integrity level.</summary>
        internal const string Privilege = "privilege";
        /// <summary>CPU and other resource consumption.</summary>
        internal const string Resource = "resource";
        /// <summary>Timing structure of outbound connections.</summary>
        internal const string NetworkTiming = "network-timing";
        /// <summary>Who the process talks to.</summary>
        internal const string NetworkPeer = "network-peer";
        /// <summary>What the process makes reachable from outside.</summary>
        internal const string NetworkExposure = "network-exposure";
        /// <summary>Remote-control and tunnelling software.</summary>
        internal const string RemoteAccess = "remote-access";
        /// <summary>How something arranged to run again later.</summary>
        internal const string PersistenceTechnique = "persistence-technique";
        /// <summary>When the persistence appeared.</summary>
        internal const string PersistenceAge = "persistence-age";
        /// <summary>Interference with security tooling or with the audit trail.</summary>
        internal const string Evasion = "evasion";
        /// <summary>Advisory only. Weak weights, never part of an accusation.</summary>
        internal const string Hardening = "hardening";
        /// <summary>Zero-weight explanatory notes shown alongside a verdict.</summary>
        internal const string Context = "context";
    }

    /// <summary>
    /// The ceiling on any one signal.
    ///
    /// Chosen so that no pair of families can reach the auto-action band on its own: the strongest
    /// signal here is 28, the strongest realistic pair sums to ~54, and three genuinely independent
    /// families are needed before autonomous action becomes arithmetically possible. The scorer
    /// owns the band boundaries; this constant only guarantees the rules cannot defeat them.
    /// </summary>
    internal const double MaxSingleSignalWeight = 28;

    /// <summary>Processes HERO will not accuse, for reasons that are not about behaviour.</summary>
    internal static bool Ignorable(ProcessRecord p)
    {
        if (p.Pid <= 4) return true;                             // System / Idle
        if (p.Pid == Environment.ProcessId) return true;         // never accuse ourselves
        if (p.PathUnavailable) return true;                      // access limitation, not evidence
        if (Core.HeroPaths.IsOwnState(p.ImagePath)) return true; // HERO's own state directory
        return false;
    }

    /// <summary>The process this subject is about, or null when the subject is not a process or
    /// is one HERO refuses to accuse.</summary>
    internal static ProcessRecord? ProcessOf(Subject subject) =>
        subject is ProcessSubject ps && !Ignorable(ps.Process) ? ps.Process : null;

    /// <summary>The persistence entry this subject is about, or null.</summary>
    internal static PersistenceEntry? PersistenceOf(Subject subject) =>
        subject is PersistenceSubject ps ? ps.Entry : null;

    /// <summary>
    /// True when the user is plainly present at this process — it owns the foreground window, or
    /// an ancestor terminal does.
    ///
    /// This is only ever allowed to soften a signal toward "ask the user", never to suppress one.
    /// GetLastInputInfo is a session-global timestamp any process can refresh with SendInput, and
    /// it cannot say which window received the input, so it is not evidence of consent.
    /// </summary>
    internal static bool UserIsAtThisProcess(ProcessRecord p, DetectionContext ctx)
    {
        int fg = ctx.Snapshot.ForegroundPid;
        if (fg == 0) return false;
        if (fg == p.Pid) return true;

        foreach (var ancestor in ctx.Snapshot.Ancestry(p))
            if (ancestor.Pid == fg) return true;

        return false;
    }

    /// <summary>True when a build system or IDE is somewhere in this process's ancestry.</summary>
    internal static bool HasDeveloperAncestor(ProcessRecord p, DetectionContext ctx)
    {
        foreach (var ancestor in ctx.Snapshot.Ancestry(p))
        {
            if (KnownSoftware.IsDeveloperTool(ancestor.Name)) return true;
            if (KnownSoftware.IsTerminal(ancestor.Name)) return true;
            if (KnownSoftware.Classify(ancestor.ImagePath).IsDeveloperTooling) return true;
        }
        return false;
    }

    /// <summary>Convenience constructor so every signal reads the same way at the call site.</summary>
    internal static Signal Emit(string id, string title, string explanation, double weight,
                                string family, Severity severity, string evidence = "") => new()
    {
        RuleId = id,
        Title = title,
        Explanation = explanation,
        Weight = Math.Min(weight, MaxSingleSignalWeight),
        Family = family,
        Severity = severity,
        Evidence = KnownSoftware.Sanitise(evidence),
    };
}

// ---------------------------------------------------------------------------- provenance

/// <summary>
/// An image with no signature at all, running from somewhere the user can write.
///
/// This is deliberately the weakest rule in the set. Measured on this machine: nine unsigned
/// binaries are running right now and all nine are benign — uv.exe, uvx.exe, Python shims from
/// the uv cache, MCP virtual-environment entry points, and Microsoft's own WidgetService. Several
/// also make outbound connections. Unsigned-ness in a user directory is therefore the base rate
/// of a developer machine, not an anomaly, and it may only ever act as a gate on something else.
/// </summary>
internal sealed class UnsignedImageRule : IDetectionRule
{
    public string Id => "proc.unsigned-image";
    public string Description => "Running program has no digital signature and lives where you can write";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        // A missing cache entry means "not verified yet", not "unsigned". Treating the two the
        // same would accuse every process during the first seconds after HERO starts.
        var sig = context.Signature(p.ImagePath);
        if (sig is null || sig.State != SignatureState.Unsigned) yield break;

        var id = KnownSoftware.Classify(p.ImagePath);
        if (!KnownSoftware.IsUserWritable(id.Location)) yield break;

        if (id.IsRecognised)
        {
            yield return RuleKit.Emit(Id, "Unsigned, but recognised software",
                $"{p.FileName} has no digital signature. That is normal for {id.Label} — many " +
                "developer tools ship unsigned. Noted for context only.",
                0, RuleKit.Families.Context, Severity.Safe, p.ImagePath);
            yield break;
        }

        double weight = id.Location switch
        {
            PathClass.RecycleBin => 24,
            PathClass.Public => 18,
            PathClass.Downloads => 16,
            PathClass.Temp => 16,
            PathClass.Removable => 12,
            PathClass.Network => 12,
            _ => 10,
        };

        yield return RuleKit.Emit(Id, "Unsigned program in a writable location",
            $"{p.FileName} carries no digital signature and is running from {Describe(id.Location)}. " +
            "On its own this is weak — much developer tooling is unsigned — so HERO will not act " +
            "on it unless other, unrelated evidence agrees.",
            weight, RuleKit.Families.Provenance,
            weight >= 16 ? Severity.Medium : Severity.Low, p.ImagePath);
    }

    internal static string Describe(PathClass c) => c switch
    {
        PathClass.Temp => "a temporary folder",
        PathClass.Downloads => "your Downloads folder",
        PathClass.Public => "the Public folder",
        PathClass.RecycleBin => "inside the Recycle Bin",
        PathClass.Removable => "removable media",
        PathClass.Network => "a network location",
        PathClass.UserData => "your user profile",
        PathClass.UserPrograms => "a per-user program folder",
        PathClass.ProgramData => "the shared ProgramData folder",
        PathClass.DevWorkspace => "one of your project folders",
        _ => "a folder you can write to",
    };
}

/// <summary>
/// A signature that exists and fails. Strictly worse than no signature: it means the file was
/// modified after it was signed, or its certificate is revoked or untrusted.
///
/// The single most important exception on this machine is BlueStacks. The user's own notes record
/// that HD-Player is patched for root after every auto-update, which permanently and deliberately
/// breaks its digest. Scoring that at full strength would give HERO a recurring high-severity
/// anchor against software the user maintains on purpose, and it would fight them forever.
/// </summary>
internal sealed class InvalidSignatureRule : IDetectionRule
{
    public string Id => "proc.signature-invalid";
    public string Description => "Program is signed, but the signature does not validate";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var sig = context.Signature(p.ImagePath);
        if (sig is null || sig.State != SignatureState.Invalid) yield break;

        var id = KnownSoftware.Classify(p.ImagePath);

        if (id.Class == SoftwareClass.AndroidEmulator)
        {
            yield return RuleKit.Emit(Id, "Patched emulator binary",
                $"{p.FileName} is signed but the signature no longer matches the file. For " +
                "BlueStacks this is expected if you have patched it for root — the patch changes " +
                "the file after signing. Worth confirming once, then dismissing.",
                6, RuleKit.Families.Provenance, Severity.Low, sig.Describe());
            yield break;
        }

        // An expired certificate is not tampering. Measured on this machine: Git for Windows ships
        // C:\Program Files\Git\usr\bin\bash.exe with a certificate outside its validity period, and
        // WinVerifyTrust reports that as a failure. Scoring it like a bad digest would put a core
        // developer tool into the watch band permanently, for a housekeeping fact.
        bool expired = sig.HResult == Native.CERT_E_EXPIRED;

        // An untrusted root is the self-signed / test-signed case, which developers produce
        // routinely. A bad digest on a binary claiming a major publisher is the real signal.
        bool untrustedRoot = sig.HResult == Native.CERT_E_UNTRUSTEDROOT || sig.HResult == Native.CERT_E_CHAINING;
        bool claimsMajorPublisher = KnownSoftware.IsTrustedPublisher(sig.Signer);
        bool properlyInstalled = id.Location is PathClass.ProgramFiles or PathClass.SystemProtected
                                 or PathClass.WindowsApps or PathClass.DriverStore;

        double weight = expired ? 3
                      : untrustedRoot ? 8
                      : id.IsRecognised && properlyInstalled ? 10
                      : claimsMajorPublisher ? 25
                      : 18;

        string explanation = expired
            ? $"{p.FileName} is properly signed, but the signing certificate has since expired. That " +
              "is ordinary for older software and is not a sign of tampering."
            : untrustedRoot
                ? $"{p.FileName} is signed by a certificate this PC does not trust. That is normal " +
                  "for self-signed or test-signed builds, including ones you make yourself."
                : $"{p.FileName} claims to be signed{(sig.Signer.Length > 0 ? " by " + sig.Signer : "")}, " +
                  "but the file no longer matches its signature. Something changed the file after " +
                  "it was published — that is either an update mechanism that patches in place, or tampering.";

        yield return RuleKit.Emit(Id, expired ? "Expired signing certificate" : "Broken digital signature",
            explanation, weight, RuleKit.Families.Provenance,
            weight >= 18 ? Severity.High : weight >= 10 ? Severity.Medium : Severity.Low,
            $"{sig.Describe()} · {p.ImagePath}");
    }
}

/// <summary>
/// Execution from a folder that exists for transient content.
///
/// Installers run from %TEMP% constantly, so the weights are graded by how little business a
/// long-lived program has being there. The Recycle Bin is the outlier: nothing legitimate
/// executes from it.
/// </summary>
internal sealed class VolatileLocationRule : IDetectionRule
{
    public string Id => "proc.volatile-location";
    public string Description => "Program is running from a temporary, download or public folder";

    private static readonly string[] InstallerNameHints =
        { "setup", "install", "update", "unins", "vcredist", "msi", "patch", "bootstrap" };

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var id = KnownSoftware.Classify(p.ImagePath);
        if (!KnownSoftware.IsVolatile(id.Location)) yield break;

        // A build tree that happens to sit under a temp path is still a build tree.
        if (id.Location != PathClass.RecycleBin && KnownSoftware.LooksLikeDevelopmentOutput(p.ImagePath)) yield break;

        double weight = id.Location switch
        {
            PathClass.RecycleBin => 24,
            PathClass.Public => 16,
            PathClass.Downloads => 14,
            _ => 10,
        };

        var name = KnownSoftware.NameKey(p.FileName);
        bool looksLikeInstaller = InstallerNameHints.Any(h => name.Contains(h, StringComparison.Ordinal));
        if (looksLikeInstaller && id.Location != PathClass.RecycleBin) weight /= 2;

        // A build tool's child extracting and running in %TEMP% is a build, not an intrusion.
        if (RuleKit.HasDeveloperAncestor(p, context)) weight /= 2;

        var sig = context.Signature(p.ImagePath);
        if (sig is { State: SignatureState.Valid }) weight /= 2;

        if (weight < 4) yield break;

        yield return RuleKit.Emit(Id, "Running from a temporary location",
            $"{p.FileName} is running from {UnsignedImageRule.Describe(id.Location)}. Programs you " +
            "install normally live in Program Files or a per-user program folder; running from here " +
            "is common for installers and rare for anything that stays running.",
            weight, RuleKit.Families.Provenance,
            weight >= 16 ? Severity.Medium : Severity.Low, p.ImagePath);
    }
}

/// <summary>
/// The image was written to disk moments before it started.
///
/// Write-then-execute is what a dropper does and also what every build on this machine does all
/// day: cargo run, dotnet run, npm test, Unreal hot reload, PyInstaller output. The rule is
/// therefore suppressed entirely inside project trees and for children of build tools, and its
/// weight is low enough that it can only ever be corroboration.
/// </summary>
internal sealed class RecentlyWrittenImageRule : IDetectionRule
{
    public string Id => "proc.image-written-recently";
    public string Description => "The program file was created or modified just before it ran";

    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null || p.StartTimeUtc == default) yield break;

        var id = KnownSoftware.Classify(p.ImagePath);
        if (!KnownSoftware.IsUserWritable(id.Location)) yield break;
        if (id.Location == PathClass.DevWorkspace || id.IsRecognised) yield break;
        if (RuleKit.HasDeveloperAncestor(p, context)) yield break;

        var fact = KnownSoftware.Stat(p.ImagePath);
        if (!fact.Exists || fact.LastWriteUtc == default) yield break;

        var gap = p.StartTimeUtc - fact.LastWriteUtc;
        if (gap < TimeSpan.Zero || gap > Window) yield break;

        yield return RuleKit.Emit(Id, "Program appeared and ran immediately",
            $"{p.FileName} was written to disk {(int)gap.TotalSeconds} seconds before it started, in " +
            $"{UnsignedImageRule.Describe(id.Location)}. Software you install is normally written once " +
            "and run much later.",
            12, RuleKit.Families.Provenance, Severity.Medium,
            $"written {fact.LastWriteUtc:u}, started {p.StartTimeUtc:u}");
    }
}

/// <summary>
/// The program is still running but its file is gone — the self-deleting stager pattern.
///
/// Guarded twice against the obvious mistake: an unreadable file is not a missing one, and the
/// containing directory must still exist, otherwise an unmounted volume or a path HERO resolved
/// wrongly reads as evidence.
/// </summary>
internal sealed class DeletedImageRule : IDetectionRule
{
    public string Id => "proc.image-deleted";
    public string Description => "The running program has deleted its own file from disk";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var id = KnownSoftware.Classify(p.ImagePath);
        if (!KnownSoftware.IsUserWritable(id.Location)) yield break;

        var fact = KnownSoftware.Stat(p.ImagePath);
        if (fact.Exists) yield break;

        var dir = p.Directory;
        if (string.IsNullOrEmpty(dir)) yield break;

        bool directoryStillThere;
        try { directoryStillThere = Directory.Exists(dir); } catch { directoryStillThere = false; }
        if (!directoryStillThere) yield break;

        yield return RuleKit.Emit(Id, "Program deleted itself but is still running",
            $"{p.FileName} is running from memory, but the file it was launched from no longer " +
            "exists on disk. Legitimate software has no reason to erase itself while running; " +
            "installers that clean up their own temporary copies usually exit first.",
            24, RuleKit.Families.Provenance, Severity.High, p.ImagePath);
    }
}

// ---------------------------------------------------------------------------- masquerade

/// <summary>
/// A Windows image name running from somewhere that name has no business being.
///
/// The canonical location is looked up per image, never as a shared directory set, because
/// explorer.exe does not live in System32 — it is C:\WINDOWS\Explorer.EXE. A shared rule would
/// score the user's own desktop shell as the strongest signal in the product on every boot.
/// </summary>
internal sealed class MasqueradingImageRule : IDetectionRule
{
    public string Id => "proc.system-name-out-of-place";
    public string Description => "A program is using a Windows system name from the wrong folder";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        if (KnownSoftware.IsSystemImageOutOfPlace(p.ImagePath, out var expected))
        {
            yield return RuleKit.Emit(Id, "Windows system name in the wrong place",
                $"A program called {p.FileName} is running from {p.Directory}. The real {p.FileName} " +
                $"lives in {expected}. Copying a Windows name is one of the oldest ways to hide in a " +
                "process list.",
                28, RuleKit.Families.Masquerade, Severity.Critical, p.ImagePath);
            yield break;
        }

        // Near-miss names only matter where a non-administrator could have put the file. A sweep of
        // the 7069 executables installed on this machine produced exactly three one-edit names and
        // all three are legitimate software in Program Files: the JDK's jcmd.exe (one edit from
        // cmd.exe) and two copies of Google Play Games' Service.exe (one edit from services.exe).
        // Program Files needs administrator rights to write, so a lookalike there is a publisher's
        // naming choice far more often than a disguise — and the exact-name branch above still
        // covers a genuine impostor that does reach a protected directory.
        var id = KnownSoftware.Classify(p.ImagePath);
        if (!KnownSoftware.IsUserWritable(id.Location)) yield break;

        // A valid Authenticode signature is the same argument again: an attacker who can sign is
        // not reduced to misspelling a filename.
        if (context.Signature(p.ImagePath) is { State: SignatureState.Valid }) yield break;

        if (KnownSoftware.IsNearMissOfSystemImage(p.FileName, out var lookalike))
        {
            yield return RuleKit.Emit(Id, "Name looks like a Windows file, but is not",
                $"{p.FileName} is one letter — or one swapped pair of letters — away from the Windows " +
                $"file {lookalike}, and it is running from {UnsignedImageRule.Describe(id.Location)}. " +
                "That is a deliberate disguise technique, not a coincidence worth ignoring.",
                20, RuleKit.Families.Masquerade, Severity.High, p.ImagePath);
        }
    }
}

// ---------------------------------------------------------------------------- lineage

/// <summary>
/// A Windows service host with the wrong parent.
///
/// Lineage on Windows is a reported value, not a fact: any process can nominate an arbitrary
/// parent with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, and Windows itself re-parents every
/// UAC-elevated launch onto the AppInfo service host. The rule therefore fires only when the
/// claimed parent is present, started first, and is demonstrably the wrong one — and it declines
/// entirely when the parent is svchost, which is how "Run as administrator" always looks.
/// </summary>
internal sealed class UnexpectedParentRule : IDetectionRule
{
    public string Id => "proc.unexpected-parent";
    public string Description => "A Windows system process was started by something unexpected";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        if (!context.Snapshot.ByPid.TryGetValue(p.ParentPid, out var parent)) yield break;
        if (parent.StartTimeUtc == default || p.StartTimeUtc == default) yield break;
        if (parent.StartTimeUtc > p.StartTimeUtc) yield break;   // recycled PID, lineage unknown

        // The elevation broker. Every elevated launch on this machine shows this parent.
        if (KnownSoftware.NameKey(parent.Name) == "svchost" && KnownSoftware.NameKey(p.Name) != "svchost")
            yield break;

        if (KnownSoftware.HasExpectedParent(p.Name, parent.Name, out var expected)) yield break;
        if (expected.Length == 0) yield break;

        var parentSig = parent.PathUnavailable ? null : context.Signature(parent.ImagePath);
        double weight = parentSig is { State: SignatureState.Valid } ? 8 : 12;

        yield return RuleKit.Emit(Id, "System process started by the wrong program",
            $"{p.FileName} is normally started by {expected}, but this copy was started by " +
            $"{parent.FileName}. Windows re-parents processes in several legitimate situations, so " +
            "this is a hint rather than a conclusion.",
            weight, RuleKit.Families.Lineage, Severity.Medium,
            $"{parent.FileName} (pid {parent.Pid}) -> {p.FileName} (pid {p.Pid})");
    }
}

/// <summary>
/// A document reader, browser or archiver spawning a script host or a living-off-the-land binary.
///
/// This is the classic initial-access chain, and it is also a minefield on this machine. Three
/// suppressions are mandatory and each is grounded in something the user actually does:
///
/// - msiexec launched from a browser is opening a downloaded installer, the single most ordinary
///   software-installation action on Windows. It is not in the high-risk child set at all.
/// - "conhost --headless" is the ConPTY mechanism behind every terminal session, so conhost is
///   never a child of interest.
/// - msbuild, installutil and regasm are first-class tools here, not LOLBins, whenever a build
///   system or IDE is anywhere in the ancestry.
/// </summary>
internal sealed class SuspiciousChildRule : IDetectionRule
{
    public string Id => "proc.suspicious-child";
    public string Description => "A document, browser or archive opened a scripting or system tool";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var childKey = KnownSoftware.NameKey(p.Name);
        bool interesting = KnownSoftware.IsHighRiskLolBin(childKey) || KnownSoftware.IsScriptHost(childKey);
        if (!interesting) yield break;
        if (childKey is "conhost") yield break;

        if (!context.Snapshot.ByPid.TryGetValue(p.ParentPid, out var parent)) yield break;
        if (parent.StartTimeUtc != default && p.StartTimeUtc != default && parent.StartTimeUtc > p.StartTimeUtc)
            yield break;

        var parentKey = KnownSoftware.NameKey(parent.Name);
        bool documentParent = KnownSoftware.IsDocumentApp(parentKey);
        bool browserParent = KnownSoftware.IsBrowser(parentKey);
        bool archiveParent = KnownSoftware.IsArchiver(parentKey)
                             || (!parent.PathUnavailable && IsArchiveExtractionDir(parent.ImagePath));

        if (!documentParent && !browserParent && !archiveParent) yield break;
        if (RuleKit.HasDeveloperAncestor(p, context)) yield break;

        // A browser or archiver handing off to a script host is worse than a document reader
        // doing it only because documents are not opened much on this machine; the ordering here
        // reflects base rates, not tradecraft.
        double weight = documentParent ? 18 : 14;

        // Whether the process's own image carries an argument that fetches or executes content is
        // the discriminator that separates "user double-clicked something" from a loader chain.
        bool hasPayloadShape = CommandLinePatterns.LooksLikeFetchAndRun(p.CommandLine);
        if (hasPayloadShape) weight = 18; else weight -= 4;

        if (RuleKit.UserIsAtThisProcess(p, context)) weight /= 2;
        if (weight < 4) yield break;

        yield return RuleKit.Emit(Id, "Unexpected program launched from a document or browser",
            $"{parent.FileName} started {p.FileName}. That combination is how malicious documents " +
            "and archives get their first foothold. If you just opened an attachment or extracted " +
            "an archive, this is the moment to be sure of where it came from.",
            weight, RuleKit.Families.Lineage, Severity.High,
            $"{parent.FileName} -> {p.FileName} {KnownSoftware.Sanitise(p.CommandLine, 200)}");
    }

    private static bool IsArchiveExtractionDir(string path) =>
        path.Contains(@"\Temp\Rar$", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\Temp\7z", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\Temp\Temp1_", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\Temp\BNZ.", StringComparison.OrdinalIgnoreCase);
}

// ---------------------------------------------------------------------------- command line

/// <summary>
/// The shared command-line lexicon.
///
/// Deliberately excludes every Defender cmdlet. Add-MpPreference and Set-MpPreference are owned
/// by the Defender rule in <c>EvasionRules</c> and nowhere else: the user typing
/// <c>Add-MpPreference -ExclusionPath 'D:\My projects'</c> in an elevated terminal is a real and
/// common developer action, and two rules scoring one keystroke sequence in two families is
/// exactly how a corroboration requirement gets defeated by a single deliberate act.
/// </summary>
internal static class CommandLinePatterns
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    /// <summary>A base64 blob handed to PowerShell. Any unambiguous prefix of -EncodedCommand works.</summary>
    internal static readonly Regex Encoded =
        new(@"(?:^|\s)[-/](?:e|en|enc|enco|encod|encode|encoded|encodedcommand|ec)\s+([A-Za-z0-9+/=]{20,})", Opts);

    /// <summary>Fetch-and-run in one line: the loader signature.</summary>
    internal static readonly Regex[] FetchAndRun =
    {
        new(@"(?:invoke-restmethod|irm|invoke-webrequest|iwr|curl(?:\.exe)?|wget)\b[^\r\n|]{0,300}\|\s*(?:iex|invoke-expression|powershell|pwsh|cmd|bash|sh)\b", Opts),
        new(@"(?:new-object\s+(?:system\.)?net\.webclient|\[(?:system\.)?net\.webclient\])[^\r\n]{0,200}download(?:string|file|data)", Opts),
        new(@"regsvr32(?:\.exe)?[^\r\n]{0,160}/i:\s*https?://", Opts),
        new(@"mshta(?:\.exe)?[^\r\n]{0,160}(?:https?://|javascript:|vbscript:)", Opts),
        new(@"rundll32(?:\.exe)?[^\r\n]{0,160}javascript:", Opts),
        new(@"msiexec(?:\.exe)?[^\r\n]{0,160}https?://", Opts),
        new(@"certutil(?:\.exe)?[^\r\n]{0,160}(?:[-/]urlcache|[-/]decode)", Opts),
    };

    /// <summary>Fetching alone. Half of every install script on this machine looks like this.</summary>
    internal static readonly Regex[] FetchOnly =
    {
        new(@"(?:invoke-webrequest|iwr|curl(?:\.exe)?|wget)\b[^\r\n]{0,200}\s[-/](?:outfile|o)\b", Opts),
        new(@"start-bitstransfer\b", Opts),
        new(@"bitsadmin(?:\.exe)?[^\r\n]{0,160}/transfer", Opts),
        new(@"(?:urlretrieve|urlopen|requests\.get)\s*\(", Opts),
    };

    /// <summary>Hidden, profile-less, policy-bypassing execution. Individually near-worthless —
    /// every CI runner and VS Code task uses these — so they are only ever counted together.</summary>
    internal static readonly Regex StealthFlags =
        new(@"(?:^|\s)[-/](?:w(?:indowstyle)?\s+h(?:idden)?|nop|noprofile|noni|noninteractive|ep\s+bypass|executionpolicy\s+(?:bypass|unrestricted))\b", Opts);

    internal static bool LooksLikeFetchAndRun(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return false;
        foreach (var r in FetchAndRun) if (r.IsMatch(commandLine)) return true;
        return false;
    }

    internal static bool LooksLikeFetch(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return false;
        foreach (var r in FetchOnly) if (r.IsMatch(commandLine)) return true;
        return false;
    }

    /// <summary>Decodes an -EncodedCommand payload. PowerShell encodes UTF-16LE; anything that
    /// does not decode cleanly is reported as undecodable rather than guessed at.</summary>
    internal static string? TryDecode(string base64)
    {
        try
        {
            var trimmed = base64.Trim();
            int pad = trimmed.Length % 4;
            if (pad != 0) trimmed = trimmed.PadRight(trimmed.Length + (4 - pad), '=');
            var bytes = Convert.FromBase64String(trimmed);
            if (bytes.Length < 4) return null;
            var text = Encoding.Unicode.GetString(bytes);
            // A UTF-16LE decode of non-UTF-16 data produces mostly unprintable characters.
            int printable = text.Count(c => !char.IsControl(c) || c is '\n' or '\r' or '\t');
            return printable > text.Length * 0.8 ? text : null;
        }
        catch { return null; }
    }

    /// <summary>Shannon entropy in bits per character.</summary>
    internal static double Entropy(string s)
    {
        if (s.Length == 0) return 0;
        Span<int> counts = stackalloc int[128];
        int counted = 0;
        foreach (char c in s)
        {
            if (c < 128) { counts[c]++; counted++; }
        }
        if (counted == 0) return 0;

        double h = 0;
        for (int i = 0; i < 128; i++)
        {
            if (counts[i] == 0) continue;
            double pr = (double)counts[i] / counted;
            h -= pr * Math.Log2(pr);
        }
        return h;
    }

    /// <summary>
    /// The share of the line occupied by things that look like file paths. Compiler invocations,
    /// UnrealBuildTool argument blocks and cargo flag soups are long and punctuation-dense purely
    /// because they are lists of paths, and they must not read as obfuscation.
    /// </summary>
    internal static double PathTokenRatio(string commandLine)
    {
        if (commandLine.Length == 0) return 0;
        int pathChars = 0;
        foreach (var token in commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            bool pathish = (token.Contains('\\') || token.Contains('/')) && token.Contains('.');
            if (pathish) pathChars += token.Length;
        }
        return (double)pathChars / commandLine.Length;
    }
}

/// <summary>
/// A base64 payload passed to PowerShell.
///
/// The decoded content is the discriminator, not the encoding: Chocolatey, some installers and CI
/// runners genuinely use -EncodedCommand to survive quoting. So the payload is decoded, re-scanned
/// with the same fetch/run patterns, and attached to the evidence so the prompt can show the user
/// exactly what would have run.
/// </summary>
internal sealed class EncodedCommandRule : IDetectionRule
{
    public string Id => "proc.encoded-command";
    public string Description => "A command was passed in encoded form rather than as readable text";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null || p.CommandLine.Length == 0) yield break;

        var match = CommandLinePatterns.Encoded.Match(p.CommandLine);
        if (!match.Success) yield break;

        var decoded = CommandLinePatterns.TryDecode(match.Groups[1].Value);

        // -EncodedCommand is a PowerShell switch, and the abbreviation set that makes the pattern
        // catch "-e" also catches an ordinary "-e VALUE". Verified: "docker run -e
        // POSTGRESPASSWORDVERYLONGVALUE=... image" matches, and because that payload is not base64
        // it lands in the "could not decode" branch — the HIGHEST-weight outcome of the three.
        // Requiring either a PowerShell host or a payload that actually decodes closes that
        // without opening a hole: a renamed copy of powershell.exe still carries real base64.
        bool powershellHost = KnownSoftware.NameKey(p.Name) is "powershell" or "pwsh" or "powershell_ise";
        if (!powershellHost && decoded is null) yield break;

        double weight;
        string explanation;
        if (decoded is null)
        {
            weight = 12;
            explanation = $"{p.FileName} was started with an encoded command that HERO could not decode. " +
                          "Encoding is occasionally used by installers to survive quoting, but it also " +
                          "hides what is about to run.";
        }
        else if (CommandLinePatterns.LooksLikeFetchAndRun(decoded) || CommandLinePatterns.LooksLikeFetch(decoded))
        {
            weight = 22;
            explanation = $"{p.FileName} was started with an encoded command that, once decoded, " +
                          "downloads something and runs it. That is the standard shape of a loader.";
        }
        else
        {
            weight = 8;
            explanation = $"{p.FileName} was started with an encoded command. The decoded text looks " +
                          "ordinary, so this is recorded for context rather than treated as a problem.";
        }

        if (RuleKit.UserIsAtThisProcess(p, context) && weight > 8) weight -= 4;

        yield return RuleKit.Emit(Id, "Encoded command line", explanation,
            weight, RuleKit.Families.CommandLine,
            weight >= 18 ? Severity.High : Severity.Medium,
            decoded is null ? match.Groups[1].Value : "decoded: " + decoded);
    }
}

/// <summary>
/// Download-and-execute in a single command line.
///
/// This user installs software this way — <c>irm https://astral.sh/uv/install.ps1 | iex</c> is the
/// documented install path for uv, and rustup, scoop, pnpm, bun and Chocolatey all publish the
/// same pattern. So a well-known installer host damps the score heavily; it does not clear it,
/// because a lookalike domain is a genuine technique.
/// </summary>
internal sealed class DownloadCradleRule : IDetectionRule
{
    public string Id => "proc.download-cradle";
    public string Description => "A command downloads something from the internet and runs it";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null || p.CommandLine.Length == 0) yield break;

        bool fetchAndRun = CommandLinePatterns.LooksLikeFetchAndRun(p.CommandLine);
        bool fetchOnly = !fetchAndRun && CommandLinePatterns.LooksLikeFetch(p.CommandLine);
        if (!fetchAndRun && !fetchOnly) yield break;

        double weight = fetchAndRun ? 22 : 10;

        bool knownHost = KnownSoftware.MentionsKnownInstallerHost(p.CommandLine);
        if (knownHost) weight = fetchAndRun ? 8 : 4;

        // Present at the keyboard means "ask", never "ignore".
        if (RuleKit.UserIsAtThisProcess(p, context)) weight = Math.Min(weight, 10);
        if (weight < 4) yield break;

        yield return RuleKit.Emit(Id,
            fetchAndRun ? "Command downloads and runs code" : "Command downloads a file",
            fetchAndRun
                ? $"{p.FileName} was told to fetch something from the internet and execute it in one " +
                  (knownHost
                      ? "step. The address is a well-known installer host, which is how several tools you use are installed — worth a glance, not an alarm."
                      : "step. That is how most installers arrive, and also how most malware does. Check that you started this.")
                : $"{p.FileName} is downloading a file to disk. Recorded so it can be correlated with " +
                  "what runs next.",
            weight, RuleKit.Families.CommandLine,
            weight >= 18 ? Severity.High : Severity.Low,
            p.CommandLine);
    }
}

/// <summary>
/// Deliberately obfuscated command lines.
///
/// The first version of this rule scored entropy and punctuation density and was measured against
/// this machine's live process table. It fired on two things, both benign, and both instructive:
///
///   pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "try { ... } catch {}; ..."
///   claude.exe --type=renderer --gpu-preferences=SAAAAAAAAADgAAAEAAAA... --field-trial-handle=...
///
/// Inline PowerShell is punctuation by nature, and Chromium helper processes carry base64 blobs as
/// ordinary arguments. Generic density therefore measures the language, not the intent.
///
/// So the rule now demands a STRUCTURAL indicator — backtick or caret padding, ${} name
/// obfuscation, character-code or -join reassembly, or one enormous unbroken token — which is
/// something an author does only to defeat reading. Entropy and density remain, but only as
/// supporting evidence that cannot fire on their own.
/// </summary>
internal sealed class ObfuscatedCommandRule : IDetectionRule
{
    public string Id => "proc.obfuscated-command";
    public string Description => "A command line looks deliberately scrambled";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var cmd = p.CommandLine;
        if (cmd.Length < 200) yield break;

        var id = KnownSoftware.Classify(p.ImagePath);
        if (id.IsDeveloperTooling || id.Trust == TrustHint.SystemManaged) yield break;
        if (KnownSoftware.IsDeveloperTool(p.Name)) yield break;
        if (KnownSoftware.IsChromiumChild(cmd)) yield break;
        if (RuleKit.HasDeveloperAncestor(p, context)) yield break;
        if (CommandLinePatterns.PathTokenRatio(cmd) > 0.40) yield break;

        var structural = new List<string>(4);
        if (cmd.Count(c => c == '`') > 8) structural.Add("escape-character padding");
        if (cmd.Count(c => c == '^') > 8) structural.Add("caret escaping");
        if (CountOccurrences(cmd, "${") > 3) structural.Add("variable-name obfuscation");
        if (CountOccurrences(cmd, "[char]") > 3) structural.Add("character-code reassembly");
        if (CountOccurrences(cmd, "-join") > 1) structural.Add("string reassembly");
        if (LongestToken(cmd) > 400) structural.Add("one enormous unbroken argument");

        if (structural.Count == 0) yield break;

        var supporting = new List<string>(3);
        if (CommandLinePatterns.Entropy(cmd) > 4.8) supporting.Add("high character entropy");

        int nonAlnum = cmd.Count(c => !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c));
        if ((double)nonAlnum / cmd.Length > 0.45) supporting.Add("mostly punctuation");
        if (cmd.Length > 1500) supporting.Add("extreme length");

        if (structural.Count + supporting.Count < 2) yield break;

        double weight = KnownSoftware.IsLolBin(p.Name) ? 12 : 8;

        yield return RuleKit.Emit(Id, "Scrambled command line",
            $"The command that started {p.FileName} is written to be hard to read " +
            $"({string.Join(", ", structural.Concat(supporting))}). Ordinary software has no reason " +
            "to hide what it is doing.",
            weight, RuleKit.Families.CommandLine, Severity.Medium, cmd);
    }

    private static int LongestToken(string cmd)
    {
        int longest = 0, run = 0;
        foreach (char c in cmd)
        {
            if (char.IsWhiteSpace(c)) { run = 0; continue; }
            if (++run > longest) longest = run;
        }
        return longest;
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        int count = 0, i = 0;
        while ((i = haystack.IndexOf(needle, i, StringComparison.OrdinalIgnoreCase)) >= 0) { count++; i += needle.Length; }
        return count;
    }
}

// ---------------------------------------------------------------------------- privilege

/// <summary>
/// Integrity-level anomalies.
///
/// Measured distribution on this machine: Medium 174, Unknown 132, Untrusted 34, Low 15, High 3.
/// Untrusted is the normal state of sandboxed browser and AppContainer content processes and is
/// never a signal. Elevated developer tooling is also normal here, so the only shapes scored are
/// an unrecognised unsigned binary holding High/System rights, and a sandboxed process spawning an
/// unsandboxed child.
/// </summary>
internal sealed class IntegrityAnomalyRule : IDetectionRule
{
    public string Id => "proc.integrity-anomaly";
    public string Description => "A program holds more privilege than its origin justifies";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        var id = KnownSoftware.Classify(p.ImagePath);
        var sig = context.Signature(p.ImagePath);

        if (p.Integrity is IntegrityLevel.High or IntegrityLevel.System
            && KnownSoftware.IsUserWritable(id.Location)
            && !id.IsRecognised
            && sig is { State: SignatureState.Unsigned or SignatureState.Invalid })
        {
            yield return RuleKit.Emit(Id, "Unsigned program running with administrator rights",
                $"{p.FileName} is running with elevated privileges from " +
                $"{UnsignedImageRule.Describe(id.Location)} and carries no valid signature. If you did " +
                "not approve an administrator prompt for this, it should not have those rights.",
                16, RuleKit.Families.Privilege, Severity.High,
                $"integrity={p.Integrity}, {sig.Describe()}");
        }

        // A sandbox escape: a Low/Untrusted process (a browser renderer, an AppContainer app)
        // producing a Medium-or-higher child.
        if (context.Snapshot.ByPid.TryGetValue(p.ParentPid, out var parent)
            && parent.Integrity is IntegrityLevel.Low or IntegrityLevel.Untrusted
            && p.Integrity is IntegrityLevel.Medium or IntegrityLevel.High or IntegrityLevel.System
            && (parent.StartTimeUtc == default || p.StartTimeUtc == default || parent.StartTimeUtc <= p.StartTimeUtc))
        {
            yield return RuleKit.Emit(Id, "Sandboxed program escaped its sandbox",
                $"{parent.FileName} runs in a restricted sandbox, but it started {p.FileName} with " +
                "ordinary user rights. Content processes are sandboxed precisely so that they cannot " +
                "do this.",
                20, RuleKit.Families.Privilege, Severity.High,
                $"{parent.FileName} ({parent.Integrity}) -> {p.FileName} ({p.Integrity})");
        }
    }
}

// ---------------------------------------------------------------------------- resource

/// <summary>
/// A windowless program burning CPU while the machine is idle.
///
/// This is the highest-risk false positive HERO can produce on this machine and it is tuned
/// accordingly. The user runs slot-math Monte Carlo simulations that saturate all 24 threads for
/// hours with no window, plus Unreal shader compilation, Blender Cycles renders, cargo and MSVC
/// builds, and ffmpeg encodes — all windowless, all overnight, all indistinguishable from a miner
/// on CPU shape alone. So:
///
/// - the weight is capped far below anything that could anchor an action;
/// - recognised toolchains, project trees and signed binaries never qualify as candidates;
/// - sampling only ever touches the handful of processes that pass the candidate gate, because
///   opening a Process object per PID per poll is itself a handle leak and a cost the budget
///   cannot absorb.
///
/// Presence of a visible window is remembered permanently once seen, so a program that showed a
/// window earlier can never later be described as hidden.
/// </summary>
internal sealed class HiddenCpuBurnerRule : IDetectionRule
{
    public string Id => "proc.hidden-cpu-burn";
    public string Description => "A hidden program is using heavy CPU while you are away";

    private const double CoresThreshold = 0.60;                 // fraction of one core, averaged
    private const int MinObservationSeconds = 600;              // ten minutes of evidence
    private const int MinIdleSeconds = 300;                     // the user has been away five minutes
    private const int SampleIntervalMs = 30_000;

    private sealed class Track
    {
        internal DateTime FirstUtc;
        internal TimeSpan FirstCpu;
        internal DateTime LastUtc;
        internal TimeSpan LastCpu;
        internal long LastSampleTicks;
        internal bool EverHadWindow;
    }

    private readonly ConcurrentDictionary<(int Pid, long Start), Track> _tracks = new();

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null || p.StartTimeUtc == default) yield break;

        if (_tracks.Count > 256) Prune();

        // Candidate gate. Everything below this line costs a handle, so almost nothing reaches it.
        var id = KnownSoftware.Classify(p.ImagePath);
        if (id.IsRecognised) yield break;
        if (id.Location == PathClass.DevWorkspace) yield break;
        if (RuleKit.HasDeveloperAncestor(p, context)) yield break;

        var sig = context.Signature(p.ImagePath);
        if (sig is { State: SignatureState.Valid } && KnownSoftware.IsTrustedPublisher(sig.Signer)) yield break;

        var runFor = DateTime.UtcNow - p.StartTimeUtc;
        if (runFor.TotalSeconds < MinObservationSeconds) yield break;
        if (p.ThreadCount < 3) yield break;

        var track = Sample(p);
        if (track is null || track.EverHadWindow) yield break;

        var span = (track.LastUtc - track.FirstUtc).TotalSeconds;
        if (span < MinObservationSeconds) yield break;

        double cores = (track.LastCpu - track.FirstCpu).TotalSeconds / span;
        if (cores < CoresThreshold) yield break;
        if (context.Snapshot.IdleSeconds < MinIdleSeconds) yield break;

        yield return RuleKit.Emit(Id, "Hidden program using heavy CPU",
            $"{p.FileName} has averaged {cores:0.0} CPU cores for {(int)(span / 60)} minutes with no " +
            "window on screen, while you have been away. Long background jobs look exactly like this — " +
            "if this is one of your simulations, builds or renders, mark it as yours and HERO will stop " +
            "asking.",
            12, RuleKit.Families.Resource, Severity.Medium,
            $"{cores:0.00} cores over {(int)span}s, threads={p.ThreadCount}");
    }

    private Track? Sample(ProcessRecord p)
    {
        var key = (p.Pid, p.StartTimeUtc.Ticks);
        var track = _tracks.GetOrAdd(key, _ => new Track());

        long now = Environment.TickCount64;
        if (track.LastSampleTicks != 0 && now - track.LastSampleTicks < SampleIntervalMs)
            return track.FirstUtc == default ? null : track;

        try
        {
            using var proc = Process.GetProcessById(p.Pid);
            var cpu = proc.TotalProcessorTime;
            var stamp = DateTime.UtcNow;

            if (proc.MainWindowHandle != IntPtr.Zero) track.EverHadWindow = true;

            if (track.FirstUtc == default) { track.FirstUtc = stamp; track.FirstCpu = cpu; }
            track.LastUtc = stamp;
            track.LastCpu = cpu;
            track.LastSampleTicks = now;
        }
        catch
        {
            // Exited, protected, or refusing the query. Silence here is correct: HERO cannot
            // measure the process, so it must not describe it.
            track.LastSampleTicks = now;
            return null;
        }

        return track.FirstUtc == default ? null : track;
    }

    private void Prune()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-30);
        foreach (var kv in _tracks)
            if (kv.Value.LastUtc < cutoff) _tracks.TryRemove(kv.Key, out _);
    }
}

// ---------------------------------------------------------------------------- catalogue

/// <summary>
/// Every rule HERO ships, in one place.
///
/// Several rules carry bounded internal state (connection interval histories, CPU samples, the
/// set of persistence entries seen at first scan). The catalogue is therefore built once and
/// reused: constructing fresh rules per evaluation would silently reset every statistic that
/// needs multiple observations, and the beacon detector in particular would then never reach its
/// minimum sample count.
/// </summary>
internal static class RuleCatalogue
{
    private static readonly Lazy<IReadOnlyList<IDetectionRule>> Instance = new(Build, isThreadSafe: true);

    public static IReadOnlyList<IDetectionRule> All() => Instance.Value;

    private static IReadOnlyList<IDetectionRule> Build() => new List<IDetectionRule>
    {
        // Provenance — one family, so four descriptions of one file cannot stack.
        new UnsignedImageRule(),
        new InvalidSignatureRule(),
        new VolatileLocationRule(),
        new RecentlyWrittenImageRule(),
        new DeletedImageRule(),

        // Identity and lineage.
        new MasqueradingImageRule(),
        new UnexpectedParentRule(),
        new SuspiciousChildRule(),

        // What was asked of it.
        new EncodedCommandRule(),
        new DownloadCradleRule(),
        new ObfuscatedCommandRule(),

        new IntegrityAnomalyRule(),
        new HiddenCpuBurnerRule(),

        // Network.
        new BeaconingRule(),
        new ExternalEgressRule(),
        new UnexpectedListenerRule(),
        new RemoteAccessToolRule(),
        new MiningIndicatorRule(),
        new DirectResolverRule(),

        // Persistence.
        new UnsignedPersistenceRule(),
        new PersistenceLocationRule(),
        new LolBinPersistenceRule(),
        new RunOncePrefixRule(),
        new IfeoDebuggerRule(),
        new AppInitDllRule(),
        new WinlogonHijackRule(),
        new UnquotedServicePathRule(),
        new NewPersistenceRule(),

        // Evasion, driven by the Windows event logs.
        new DefenderTamperRule(),
        new EventLogClearedRule(),
        new ServiceStartTypeRule(),
        new ServiceInstalledRule(),
    }.AsReadOnly();
}
