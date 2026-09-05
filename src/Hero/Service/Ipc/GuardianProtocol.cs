using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hero.Service.Ipc;

/// <summary>
/// The wire contract between the HERO tray application and the guardian service.
///
/// Newline-delimited JSON over a named pipe. Both halves ship in the same binary, so this could
/// have been anything; it is plain text on purpose, because the failure mode that actually costs
/// hours is an IPC channel you cannot inspect. A person can attach to this pipe and read what the
/// two halves are saying to each other.
///
/// Framing is a single '\n' between messages, which is safe because <see cref="Serialise"/> never
/// writes indented JSON and JSON string escaping turns any embedded newline into "\\n".
/// </summary>
internal static class GuardianProtocol
{
    /// <summary>
    /// Not \\.\pipe\HERO: the name is versioned so that a new tray app talking to an old service
    /// left behind by a failed upgrade fails to connect rather than silently misreading it.
    /// </summary>
    internal const string PipeName = "HERO.guardian.v1";

    /// <summary>
    /// How many pipe instances the service will keep. One of these is the listener, so this is
    /// also the number of simultaneous clients.
    ///
    /// Four was too few to be safe. The accept loop creates the next listening instance only after
    /// the current one is taken, so four clients holding connections open leave nothing listening
    /// and the pipe stops answering — for everyone, including the dashboard's own once-a-second
    /// state poll. A dashboard that goes blind is the failure mode this project keeps rediscovering
    /// (see docs/PLATFORM-FACTS.md sections 20 and 25), and it should not also be available on
    /// request to anything that can open four handles.
    ///
    /// Raising it is only half the fix — a hostile client can hold sixteen as easily as four — so
    /// the server also drops a connection that connects and then says nothing. See
    /// <c>GuardianPipeServer.IdleTimeout</c>.
    /// </summary>
    internal const int MaxServerInstances = 16;

    internal static readonly JsonSerializerOptions Json = InternalTypes.Configure(new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    });

    internal static string Serialise<T>(T value) => JsonSerializer.Serialize(value, Json);

    // ---- operations

    /// <summary>Liveness and identity. The one call every client makes first.</summary>
    internal const string OpPing = "ping";

    /// <summary>What the service knows about its own integrity.</summary>
    internal const string OpIntegrity = "integrity";

    /// <summary>
    /// Everything the dashboard renders, in one message.
    ///
    /// One fat call rather than nine per-page ones because the pages already work this way: they
    /// all read from a single engine snapshot on a timer. Nine calls would take nine inconsistent
    /// slices of a machine that changes every second, and the Processes page would disagree with
    /// the Network page about which processes exist.
    /// </summary>
    internal const string OpState = "state";

    /// <summary>
    /// Asks the service to verify these image paths.
    ///
    /// The first operation that is not a read, and it exists because of a bug that looked like a
    /// transport failure: the Network page calls RequestVerification for the owners of live
    /// connections, and in remote mode that queued work into the DASHBOARD's verifier, which
    /// nothing reads. The service was never told to look, so it answered "unknown" for every
    /// user application, forever, and every row read "still checking…". The service is the only
    /// verifier now, so the request has to reach it.
    /// </summary>
    internal const string OpVerify = "verify";

    // ---- commands
    //
    // THE RULE FOR EVERY ONE OF THESE: a command names its target by SUBJECT KEY, and the service
    // resolves that key against the verdicts it currently holds. It never accepts a path, a pid or
    // a registry location from the client and acts on it directly.
    //
    // This is not defensive tidiness, it is the difference between a guardian and a weapon. HERO
    // now runs as LocalSystem, and any interactive user can open this pipe. A command surface that
    // took arbitrary targets would be a general-purpose "terminate any process, quarantine any
    // file, delete any registry value as SYSTEM" service — a privilege escalation shipped as a
    // feature. Resolving through the verdict set means the only things HERO can be asked to act on
    // are the things HERO itself has independently decided are worth acting on.

    internal const string OpDismiss = "dismiss";
    internal const string OpUndismiss = "undismiss";
    internal const string OpAllow = "allow";
    internal const string OpRecheck = "recheck";
    internal const string OpAct = "act";
    internal const string OpSaveSettings = "settings.save";
    internal const string OpSaveRawSetting = "settings.raw";
    internal const string OpVaultRestore = "vault.restore";
    internal const string OpVaultDelete = "vault.delete";
    internal const string OpRescanPersistence = "persistence.rescan";

    /// <summary>
    /// What HERO has concluded from the user's corrections, and the request to forget it.
    ///
    /// A read and a reset rather than any way to SET an influence value, which is the whole design:
    /// the numbers are derived by replaying a ledger of things that actually happened, and a command
    /// that could write one directly would be a command that could soften any rule without ever
    /// having been right about anything.
    /// </summary>
    internal const string OpLearning = "learning";
    internal const string OpLearningReset = "learning.reset";

    // ---- maintenance
    //
    // The same rule, stated for a different noun: these name a CLEANUP TARGET BY ID, and the
    // service resolves that id against its own catalogue. A path never crosses the pipe. HERO's
    // targets are compile-time declarations in its own source, so the worst an attacker can ask
    // for is one of the things HERO would have offered the user anyway.
    //
    // They exist because the dashboard runs unelevated and six targets on this machine could not
    // even be MEASURED from it, let alone cleaned — roughly 11.5 GB of Windows Update cache, setup
    // logs, Delivery Optimization, font cache and crash dumps sat behind "needs admin" forever.
    // HERO already holds the rights: the guardian service is LocalSystem, from boot. It simply was
    // never asked. Routing the work there is what makes those rows work with no UAC prompt at all,
    // and it is strictly better than the alternative of elevating the dashboard, which would put an
    // always-on high-integrity UI process on the machine to save asking a service that is already
    // running.
    //
    // Clean is asynchronous — it starts a job and returns an id — because a target can hold
    // 734,915 files and holding one of the four pipe instances open for the minutes that takes
    // would deny the pipe to everything else, including the guardian's own state polling.

    // ---- authorisation

    /// <summary>What a caller must hold before an operation is dispatched.</summary>
    internal enum OpAccess
    {
        /// <summary>Any caller the pipe's ACL admits — that is, a signed-in interactive user.</summary>
        Interactive,

        /// <summary>An elevated administrator token, proved by impersonating the client.</summary>
        Elevated,
    }

    /// <summary>
    /// The authorisation table. One place, consulted by the dispatcher before anything runs.
    ///
    /// THIS REPLACES A PER-ARM CONVENTION THAT WAS APPLIED IN ONE DIRECTION ONLY. The command
    /// surface's own doc comment names the problem exactly — "the pipe made 'the user' mean
    /// 'anyone signed in'" — and that insight was then applied solely to the containment-REVERSAL
    /// arms. resume, undo and vault.restore demanded an elevated caller; suspend, blocknetwork,
    /// killtree, quarantine and removepersistence did not.
    ///
    /// The asymmetry was worse than either half alone. Suspend ungated and resume gated means any
    /// signed-in account could freeze a process and then could not thaw it: not merely an
    /// escalation but a denial of service with no way back, performed by LocalSystem on the
    /// caller's behalf.
    ///
    /// So the rule is the pairing, stated once: A CALLER WHO CAN BREAK SOMETHING MUST BE ABLE TO
    /// UNBREAK IT. Containment and its reversal sit at the same level, and because the reversals
    /// were already elevated, the containments join them rather than the reversals being lowered.
    /// Lowering them would have meant an unprivileged caller directing SYSTEM to terminate process
    /// trees and move executables, which is the escalation HERO exists to detect.
    ///
    /// An unknown operation is Elevated, not Interactive. A table that fails open is not a table.
    /// </summary>
    internal static OpAccess AccessFor(string op) => op switch
    {
        // Read-only. These tell the caller about their own machine and change nothing.
        OpPing or OpIntegrity or OpState or OpVerify => OpAccess.Interactive,

        // HERO's own view of a finding: dismissing, un-dismissing, re-checking. Reversible by the
        // same caller, and confined to what HERO displays rather than to what the machine does.
        OpDismiss or OpUndismiss or OpRecheck => OpAccess.Interactive,

        // Reads. Learning counts are the user's own responses to their own findings.
        OpLearning or OpMaintenanceStatus => OpAccess.Interactive,

        // Only ever makes HERO stricter, which is a direction an attacker has no use for.
        OpLearningReset => OpAccess.Interactive,

        // Two cosmetic-to-personal preferences, and the arm applies its own directional rule:
        // switching the reverse-DNS lookup OFF is always allowed, switching it ON is not. Gating
        // the whole operation would have demanded administrator rights to turn animations off.
        OpSaveRawSetting => OpAccess.Interactive,

        // Costs work but changes nothing, and the ten-minute sweep would do it anyway.
        OpRescanPersistence => OpAccess.Interactive,

        // Measuring reads sizes; cleaning deletes files. Only one of those is a question.
        OpMaintenanceMeasure => OpAccess.Interactive,

        // Everything below either alters the machine, weakens the guardian, or destroys data.
        // OpAct is listed here for the op itself; the individual actions are checked again by
        // GuardianCommands.Perform, because "act" covers both halves of every pair.
        _ => OpAccess.Elevated,
    };

    internal const string OpMaintenanceMeasure = "maintenance.measure";
    internal const string OpMaintenanceClean = "maintenance.clean";
    internal const string OpMaintenanceStatus = "maintenance.status";

    /// <summary>
    /// Stable identity for one connection, used to key the peer verdict table. Matches the
    /// grouping the Network page already does, so a row and its verdict cannot come apart.
    /// </summary>
    internal static string ConnectionKey(Interop.Connection c)
        => $"{c.Pid}|{c.RemoteAddress}|{c.RemotePort}|{c.IsListening}";
}

/// <summary>
/// One consistent view of the guardian, assembled under the service's own locks.
///
/// Signatures and peer verdicts are included as lookup tables rather than left for the UI to
/// compute. In the old in-process design each page recomputed them per row on the UI thread;
/// across the pipe that would mean shipping the whole signature cache and the entire learned
/// baseline just so the client could redo work the service has already done.
/// </summary>
internal sealed class StateReply
{
    public Guardian.Snapshot? Snapshot { get; set; }
    public List<Guardian.Verdict> Verdicts { get; set; } = new();

    /// <summary>
    /// Omitted entirely when the client already has this version.
    ///
    /// Measured before this existed: the persistence inventory was 24.3% of a 500 KB poll and is
    /// rescanned every ten minutes, so it was transmitted 600 times per change; recent starts was
    /// another 14.8%, largely duplicating records the same message carries under `processes`.
    /// Null means "unchanged, keep what you have" — NOT "empty", which is why these are nullable
    /// rather than defaulting to an empty list a careless client would render as nothing.
    /// </summary>
    public List<Guardian.PersistenceEntry>? Persistence { get; set; }
    public List<Interop.ProcessRecord>? RecentStarts { get; set; }

    /// <summary>Versions of the two gated sections, whether or not they were sent this time.</summary>
    public int PersistenceVersion { get; set; }
    public int RecentStartsVersion { get; set; }

    public DateTime? PersistenceScannedUtc { get; set; }

    /// <summary>Image path to its verified signature, for the paths in this snapshot only.</summary>
    public Dictionary<string, Interop.SignatureInfo> Signatures { get; set; } = new();

    /// <summary>
    /// The service's assessment of each connection, in the SAME ORDER as
    /// <see cref="Snapshot"/>.Connections.
    ///
    /// Positional rather than keyed, and that is the fix for a real bug. The first version sent a
    /// dictionary keyed by a server-formatted string — "pid|address|port|listening" — and the
    /// client rebuilt that string to look the verdict up. Every row on the Network page came back
    /// "checking…", because a key formatted on one side and reconstructed on the other is a
    /// contract nobody is checking: any difference in how an address or a bool renders silently
    /// becomes a miss. An index cannot be misformatted.
    /// </summary>
    public List<Guardian.PeerAssessment> ConnectionVerdicts { get; set; } = new();
}

internal sealed record IpcRequest
{
    public int Id { get; init; }
    public string Op { get; init; } = "";
    public JsonElement? Args { get; init; }
}

internal sealed record IpcResponse
{
    public int Id { get; init; }
    public bool Ok { get; init; }
    public JsonElement? Data { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// What a command changed. Deliberately uniform across every command so the UI has one shape to
/// render and one place to decide whether to say "done" or "refused".
/// </summary>
internal sealed class CommandReply
{
    public bool Acted { get; set; }
    public bool Refused { get; set; }
    public string Rung { get; set; } = "";
    public string Message { get; set; } = "";
    public string Outcome { get; set; } = "";

    /// <summary>Set by <see cref="GuardianProtocol.OpRecheck"/>: the entry as it now stands.</summary>
    public Guardian.PersistenceEntry? Entry { get; set; }

    /// <summary>True when the recheck found the entry gone entirely.</summary>
    public bool EntryGone { get; set; }
}

/// <summary>
/// Answer to <see cref="GuardianProtocol.OpMaintenanceMeasure"/>: what the service can see at a
/// target the dashboard could not read.
///
/// Flattened rather than sending <c>Measurement</c> itself. The state pipe has already been taken
/// down once by a type that would not cross it (see docs/PLATFORM-FACTS.md section 25), and a
/// record of primitives cannot repeat that.
/// </summary>
internal sealed record MaintenanceMeasureReply
{
    public string TargetId { get; init; } = "";
    public bool Found { get; init; }
    public long Bytes { get; init; }
    public long Files { get; init; }
    /// <summary>The <c>AccessState</c> name, so the client renders the same words either way.</summary>
    public string State { get; init; } = "";
}

/// <summary>
/// Answer to <see cref="GuardianProtocol.OpMaintenanceClean"/> and
/// <see cref="GuardianProtocol.OpMaintenanceStatus"/>.
///
/// One shape for both: starting a job and asking after it differ only in whether the numbers have
/// moved yet, and giving them separate records would mean two things to keep in step.
/// </summary>
internal sealed record MaintenanceJobReply
{
    public string JobId { get; init; } = "";
    public string TargetId { get; init; } = "";
    public bool Accepted { get; init; }
    public bool Running { get; init; }
    public bool Finished { get; init; }
    public long BytesDeleted { get; init; }
    public long FilesDeleted { get; init; }
    public long FilesPlanned { get; init; }
    public string CurrentPath { get; init; } = "";
    public string Message { get; init; } = "";
}

/// <summary>
/// Answer to <see cref="GuardianProtocol.OpLearning"/>: what HERO has made of its own track record.
///
/// Carries the raw tallies alongside the softenings on purpose. A multiplier on its own is a number
/// the user has no way to argue with; "you have told me this was wrong about four programs, so I
/// count it for 0.90 here" is a claim they can check against their own memory.
/// </summary>
internal sealed record LearningReply
{
    /// <summary>
    /// Whether the ledger is actually out of the signed-in user's reach.
    ///
    /// False means nothing has been learned and nothing will be, however long the list of tallies —
    /// see OutcomeStore.InfluenceFor. The UI says so rather than showing an empty list that looks
    /// like "you have never corrected me".
    /// </summary>
    public bool Sealed { get; init; }

    public List<LearnedRule> Rules { get; init; } = new();
}

/// <summary>One rule's record on this machine.</summary>
internal sealed record LearnedRule
{
    public string RuleId { get; init; } = "";
    public string Description { get; init; } = "";

    /// <summary>1.0 unless HERO has decided to count this rule for less here.</summary>
    public double Influence { get; init; } = 1.0;

    /// <summary>Distinct programs the user has said this rule is wrong about.</summary>
    public int Programs { get; init; }

    public int Allows { get; init; }
    public int Acts { get; init; }
    public int Dismisses { get; init; }
}

/// <summary>Answer to <see cref="GuardianProtocol.OpPing"/>.</summary>
internal sealed record PingReply
{
    public string Version { get; init; } = "";
    public int Pid { get; init; }
    public string Identity { get; init; } = "";
    public double UptimeSeconds { get; init; }
    public string InstallDirectory { get; init; } = "";
    public string StateDirectory { get; init; } = "";
}

/// <summary>Answer to <see cref="GuardianProtocol.OpIntegrity"/>.</summary>
internal sealed record IntegrityReply
{
    public bool ManifestPresent { get; init; }
    public int FileCount { get; init; }
    public DateTime? RecordedUtc { get; init; }
    public DateTime? LastCheckedUtc { get; init; }
    public List<string> Changes { get; init; } = new();
}
