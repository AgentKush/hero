using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Hero.Core;
using Hero.Interop;
using Microsoft.Win32;

namespace Hero.Guardian;

/// <summary>
/// The escalation ladder.
///
/// The rungs are ordered by EXECUTION DEPENDENCY, not by reversibility — suspend must happen
/// before the forensic capture (a dump of a running process tears), and both must happen before
/// the kill. Reversibility does not follow that order at all: <see cref="KillTree"/> is the one
/// genuinely irreversible rung, while <see cref="Quarantine"/>, which comes after it, is fully
/// reversible through the vault.
/// </summary>
internal enum ResponseRung
{
    /// <summary>Record it. Change nothing, tell nobody.</summary>
    Observe = 0,
    /// <summary>Surface it to the user. Still change nothing.</summary>
    Notify = 1,
    /// <summary>Freeze the process. Fully reversible, and stops exfiltration in flight.</summary>
    Suspend = 2,
    /// <summary>Firewall block. Reversible, but only prevents NEW connections — see the remarks on the method.</summary>
    BlockNetwork = 3,
    /// <summary>Terminate the process tree. Irreversible.</summary>
    KillTree = 4,
    /// <summary>Move the file to the vault. Reversible.</summary>
    Quarantine = 5,
    /// <summary>Remove or disable an autorun. Reversible only through its undo record.</summary>
    RemovePersistence = 6,
}

internal enum ActionOutcome
{
    /// <summary>Nothing was done because the rung was Observe/Notify.</summary>
    NotApplicable,
    /// <summary>Dry run: HERO reported what it would have done and did nothing.</summary>
    DryRun,
    /// <summary>The action completed and was verified.</summary>
    Performed,
    /// <summary>Some of the action completed. The message names what did not.</summary>
    PartiallyPerformed,
    /// <summary>Refused by the protected set.</summary>
    RefusedProtected,
    /// <summary>The autonomy gate was not satisfied. Waiting on the user.</summary>
    RefusedGate,
    /// <summary>The circuit breaker has tripped; HERO is in ask-only mode.</summary>
    RefusedCircuitBreaker,
    /// <summary>Needs administrator rights HERO does not have.</summary>
    RefusedNeedsElevation,
    /// <summary>Windows refused the operation. Never retried, never escalated.</summary>
    RefusedByOs,
    /// <summary>The user declined the elevation prompt or the confirmation.</summary>
    Declined,
    /// <summary>Something went wrong. Fail-safe direction is always "did not act".</summary>
    Failed,
}

/// <summary>The result of one attempted rung.</summary>
internal sealed record ResponseResult
{
    internal required ResponseRung Rung { get; init; }
    internal required ActionOutcome Outcome { get; init; }
    /// <summary>One sentence the user can act on. Never a raw HRESULT on its own.</summary>
    internal required string Message { get; init; }

    internal string ActionId { get; init; } = "";
    internal string IncidentId { get; init; } = "";
    internal string Target { get; init; } = "";
    internal string UndoRecordPath { get; init; } = "";
    internal string ForensicSnapshotPath { get; init; } = "";
    internal bool Autonomous { get; init; }
    internal IReadOnlyList<string> Details { get; init; } = Array.Empty<string>();

    internal bool Acted => Outcome is ActionOutcome.Performed or ActionOutcome.PartiallyPerformed;
    internal bool Refused => Outcome is ActionOutcome.RefusedProtected or ActionOutcome.RefusedGate
                                     or ActionOutcome.RefusedCircuitBreaker or ActionOutcome.RefusedNeedsElevation
                                     or ActionOutcome.RefusedByOs;
    internal bool Undoable => UndoRecordPath.Length > 0 && Acted;
}

/// <summary>What the ladder decided for one verdict, and what came of it.</summary>
internal sealed record ResponsePlan
{
    internal required string IncidentId { get; init; }
    internal required ResponseRung Ceiling { get; init; }
    /// <summary>True when HERO actually acted without asking.</summary>
    internal required bool Autonomous { get; init; }

    /// <summary>
    /// True when the EVIDENCE alone cleared the bar, regardless of whether the master switches
    /// allowed HERO to act on it. This is what the shakedown report is built from: during the
    /// first week the user needs to see "HERO would have acted here", not "automatic action is
    /// switched off", or the report says nothing about the quality of the detection.
    /// </summary>
    internal required bool MeetsAutonomyBar { get; init; }

    internal required bool DryRun { get; init; }

    /// <summary>Why autonomy was or was not granted, in the user's words.</summary>
    internal required string GateExplanation { get; init; }
    internal required IReadOnlyList<ResponseResult> Results { get; init; }

    /// <summary>True when HERO stopped short and is waiting for the user to decide.</summary>
    internal bool AwaitingUser => !Autonomous && Ceiling >= ResponseRung.Suspend;
}

/// <summary>
/// A capability token. Its private constructor is the enforcement point: no destructive method in
/// this file will run without one, and <see cref="Mint"/> is the only way to obtain one.
///
/// The invariant is deliberately shaped differently for the reversible and irreversible rungs,
/// because pretending kill has an undo record would make the guarantee decorative:
///
///   * every rung requires a completed forensic snapshot ON DISK;
///   * reversible rungs additionally require a materialised undo record ON DISK;
///   * <see cref="ResponseRung.KillTree"/> has no undo record and never will, so instead it
///     requires that the same target was already suspended — which is what preserves the
///     evidence and stops the activity while the decision is still reversible.
/// </summary>
internal sealed class ActionAuthorisation
{
    internal ResponseRung Rung { get; }
    internal string IncidentId { get; }
    internal string ActionId { get; }
    internal bool UserInitiated { get; }
    internal string ForensicSnapshotPath { get; }
    internal string UndoRecordPath { get; }
    internal string Justification { get; }

    private ActionAuthorisation(ResponseRung rung, string incidentId, string actionId, bool userInitiated,
                                string snapshotPath, string undoPath, string justification)
    {
        Rung = rung;
        IncidentId = incidentId;
        ActionId = actionId;
        UserInitiated = userInitiated;
        ForensicSnapshotPath = snapshotPath;
        UndoRecordPath = undoPath;
        Justification = justification;
    }

    internal static ActionAuthorisation? Mint(
        ResponseRung rung, string incidentId, string actionId, bool userInitiated,
        string forensicSnapshotPath, string undoRecordPath, bool targetAlreadySuspended,
        string justification, out string refusal)
    {
        refusal = "";

        if (rung <= ResponseRung.Notify)
        {
            refusal = "Observe and Notify change nothing and need no authorisation.";
            return null;
        }

        if (string.IsNullOrEmpty(forensicSnapshotPath) || !File.Exists(forensicSnapshotPath))
        {
            refusal = "No forensic snapshot was written, so there would be no way to explain or contest this action afterwards. Refusing.";
            return null;
        }

        if (rung == ResponseRung.KillTree)
        {
            if (!targetAlreadySuspended)
            {
                refusal = "A kill has no undo record, so HERO only performs one after the target has been suspended and its state captured. The suspend did not complete.";
                return null;
            }
        }
        else if (string.IsNullOrEmpty(undoRecordPath) || !File.Exists(undoRecordPath))
        {
            refusal = "No undo record was captured. HERO does not perform a reversible action it cannot actually reverse.";
            return null;
        }

        return new ActionAuthorisation(rung, incidentId, actionId, userInitiated,
                                       forensicSnapshotPath, undoRecordPath, justification);
    }
}

// ------------------------------------------------------------------ undo records

/// <summary>
/// Everything needed to put one change back. Written and flushed BEFORE the change, for the same
/// reason a database writes ahead: a crash between the mutation and the record leaves a change
/// nobody can attribute and nobody can reverse.
///
/// Properties are public because System.Text.Json ignores internal members; the types themselves
/// stay internal.
/// </summary>
internal sealed class UndoRecord
{
    public string ActionId { get; set; } = "";
    public string IncidentId { get; set; } = "";
    public DateTime CapturedUtc { get; set; }
    /// <summary>registry-value | scheduled-task | service-config | quarantine | firewall-rule | suspend</summary>
    public string Kind { get; set; } = "";
    public string Description { get; set; } = "";
    public string TargetKey { get; set; } = "";
    public string Reason { get; set; } = "";

    /// <summary>False when some part of the original state could not be captured.</summary>
    public bool Complete { get; set; } = true;
    /// <summary>What could not be captured, and why. Empty when Complete.</summary>
    public string Incomplete { get; set; } = "";

    /// <summary>pending until the change succeeds, then committed; undone once reversed.</summary>
    public string State { get; set; } = "pending";

    public RegistryUndo? Registry { get; set; }
    public TaskUndo? Task { get; set; }
    public ServiceUndo? Service { get; set; }
    public FirewallUndo? Firewall { get; set; }
    public SuspendUndo? Suspend { get; set; }
    /// <summary>Vault id when the change routed through <see cref="QuarantineVault"/>.</summary>
    public string QuarantineId { get; set; } = "";
}

internal sealed class RegistryUndo
{
    public string Hive { get; set; } = "";
    public string SubKey { get; set; } = "";
    public string ValueName { get; set; } = "";
    /// <summary>The raw REG_* type code, preserved exactly.</summary>
    public uint ValueKind { get; set; }
    /// <summary>
    /// The raw value bytes. Captured through RegQueryValueExW rather than RegistryKey.GetValue,
    /// which hands back a managed string for REG_SZ/REG_EXPAND_SZ and therefore loses embedded
    /// nulls, non-standard terminators and trailing bytes — and silently expands
    /// "%USERPROFILE%\..." into "C:\Users\finla\...", so a naive undo writes different data.
    /// </summary>
    public string ValueBase64 { get; set; } = "";
    /// <summary>True when the value was read through the WOW64 32-bit view.</summary>
    public bool Wow6432 { get; set; }

    /// <summary>
    /// The companion StartupApproved blob, which carries the Task Manager enabled/disabled state
    /// for this entry. Restoring the Run value without it produces a subtly different startup
    /// state than the user had.
    /// </summary>
    public string StartupApprovedBase64 { get; set; } = "";
    public uint StartupApprovedKind { get; set; }
    public string StartupApprovedSubKey { get; set; } = "";
}

internal sealed class TaskUndo
{
    public string TaskName { get; set; } = "";
    /// <summary>The complete task definition. Round-trips exactly through schtasks /create /xml.</summary>
    public string Xml { get; set; } = "";
    public bool WasEnabled { get; set; }
    /// <summary>True when the task runs with a stored password or S4U and therefore cannot be recreated.</summary>
    public bool RequiresStoredCredential { get; set; }
    /// <summary>disable | delete</summary>
    public string Operation { get; set; } = "disable";
}

internal sealed class ServiceUndo
{
    public string ServiceName { get; set; } = "";
    public string RegistryPath { get; set; } = "";
    /// <summary>Every value under the service key, as name -> "kind:base64".</summary>
    public Dictionary<string, string> Values { get; set; } = new();
    /// <summary>Values under Parameters, where a svchost-hosted service's real payload (ServiceDll) lives.</summary>
    public Dictionary<string, string> ParameterValues { get; set; } = new();
}

internal sealed class FirewallUndo
{
    public string DisplayName { get; set; } = "";
    public string IncidentId { get; set; } = "";
    public string Group { get; set; } = "";
    public string Direction { get; set; } = "";
    public string Program { get; set; } = "";
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public DateTime CreatedUtc { get; set; }
    public DateTime TtlUtc { get; set; }
}

internal sealed class SuspendUndo
{
    public int Pid { get; set; }
    public long StartTicks { get; set; }
    public string Name { get; set; } = "";
    public string ImagePath { get; set; } = "";
    public DateTime SuspendedUtc { get; set; }
    public DateTime AutoResumeUtc { get; set; }
}

/// <summary>A currently frozen process, for the tray indicator. A mysterious hang must never be unexplained.</summary>
internal sealed record SuspendedProcess(int Pid, long StartTicks, string Name, string ImagePath,
                                        DateTime SuspendedUtc, DateTime AutoResumeUtc, string IncidentId);

// ------------------------------------------------------------------- the ledger

/// <summary>One line of the append-only action log.</summary>
internal sealed class ResponseLedgerEntry
{
    public string ActionId { get; set; } = "";
    public string IncidentId { get; set; } = "";
    public DateTime Utc { get; set; }
    public string Rung { get; set; } = "";
    public string Outcome { get; set; } = "";
    public string Target { get; set; } = "";
    public string Message { get; set; } = "";
    public bool Autonomous { get; set; }
    public bool DryRun { get; set; }
    public string UndoRecordPath { get; set; } = "";
    public string ForensicSnapshotPath { get; set; } = "";
    public string PrevHash { get; set; } = "";
    public string Hash { get; set; } = "";
}

// ------------------------------------------------------------- circuit breaker

internal sealed class AutonomyStamp
{
    public DateTime Utc { get; set; }
    public string Rung { get; set; } = "";
    public string Target { get; set; } = "";
}

internal sealed class AutonomyState
{
    public List<AutonomyStamp> Recent { get; set; } = new();
    public bool Tripped { get; set; }
    public string TripReason { get; set; } = "";
    public DateTime? TrippedUtc { get; set; }
    public int TotalAutonomousActions { get; set; }
}

/// <summary>
/// The hard cap that turns an unbounded failure into a bounded one.
///
/// A single over-tuned rule loose on this machine would not act once — it would act across the
/// ~28 claude.exe, ~23 cmd.exe and ~22 node.exe processes running concurrently. The budget below
/// is sized for the shape of a genuine incident, not for the shape of a bad rule:
///
///   * <b>3 autonomous actions per 10 minutes.</b> One real incident needs at most a suspend, a
///     network block and a kill against a single subject — three. A fourth autonomous action
///     inside ten minutes is far more likely to be a rule misfiring across a process cohort than
///     a second genuine intrusion, and the cost of pausing for the user in the rare real case is
///     one notification, while the cost of not pausing in the common false case is unbounded.
///   * <b>8 per 24 hours</b>, which allows two full incidents plus slack and still bounds a slow
///     leak that never trips the ten-minute window.
///   * <b>More than 2 distinct targets in 60 seconds trips immediately.</b> A real outbreak
///     converges on one program; a broken rule sprays across many.
///
/// Counters are persisted, because a crash-restart loop that reset the budget would disable the
/// cap in exactly the scenario the cap exists for. Re-arming is always an explicit user gesture,
/// never a timer.
/// </summary>
internal sealed class CircuitBreaker
{
    internal const int MaxPer10Minutes = 3;
    internal const int MaxPer24Hours = 8;
    internal const int MaxDistinctTargetsPer60Seconds = 2;
    internal static readonly TimeSpan MinPersistenceRemovalInterval = TimeSpan.FromHours(1);

    /// <summary>
    /// The user's rolling-hour cap, from settings. Sits alongside the fixed windows above rather
    /// than replacing them: those are the engine's own structural limits and are not the user's to
    /// widen, while this is the number the Settings page shows and the README quotes.
    ///
    /// The two encodings disagreed and only one was enforced. Settings persisted
    /// maxAutoActionsPerHour = 5 and maxAutoActionsPerSweep = 2, merged them across the IPC
    /// boundary, clamped them defensively against a hostile settings file, and described them in
    /// the UI — and nothing ever read either one. The README told the user HERO was "capped at
    /// five actions an hour and two per sweep" while the only limits with teeth were the three
    /// constants above.
    /// </summary>
    internal int MaxPerHour { get; set; } = 5;

    /// <summary>The user's per-sweep cap. Refuses without tripping — see <see cref="BeginSweep"/>.</summary>
    internal int MaxPerSweep { get; set; } = 2;

    private int _thisSweep;

    /// <summary>
    /// Starts a new sweep's budget.
    ///
    /// Deliberately NOT persisted, unlike the rolling windows. A sweep is a unit of work inside one
    /// run; a restart ends it by definition, and carrying a partial sweep's count across a restart
    /// would make the first sweep after a crash stricter than it should be for no stated reason.
    /// The rolling hour and the 24-hour ceiling are the limits that survive restarts, and they are
    /// persisted precisely because a crash-restart loop must not reset them.
    /// </summary>
    internal void BeginSweep()
    {
        lock (_sync) _thisSweep = 0;
    }

    private readonly string _statePath = Path.Combine(HeroPaths.Root, "autonomy.json");
    private readonly object _sync = new();
    private AutonomyState _state = new();

    internal event Action<string>? Disarmed;

    internal CircuitBreaker() => Load();

    internal bool Tripped { get { lock (_sync) return _state.Tripped; } }
    internal string TripReason { get { lock (_sync) return _state.TripReason; } }
    internal DateTime? TrippedUtc { get { lock (_sync) return _state.TrippedUtc; } }
    internal int TotalAutonomousActions { get { lock (_sync) return _state.TotalAutonomousActions; } }

    /// <summary>
    /// Checks and, if allowed, consumes budget for one autonomous action.
    ///
    /// The limiter caps AUTONOMY only. A user clicking "quarantine this" must always work
    /// regardless of counter state, so callers pass user-initiated actions straight past this.
    /// </summary>
    internal bool TryConsume(ResponseRung rung, string target, out string refusal)
    {
        lock (_sync)
        {
            Prune();

            if (_state.Tripped)
            {
                refusal = $"HERO is in ask-only mode: {_state.TripReason} Nothing will be actioned automatically until you re-arm it.";
                return false;
            }

            var now = DateTime.UtcNow;

            // The per-sweep cap refuses; it does not trip. Hitting it means "that is enough for one
            // pass", not "something is wrong with HERO" — the next sweep starts with a full budget,
            // and the rolling windows below are what catch a rule that keeps coming back.
            if (MaxPerSweep >= 0 && _thisSweep >= MaxPerSweep)
            {
                refusal = $"HERO has already taken {_thisSweep} automatic action(s) in this sweep, which is its per-sweep limit. " +
                          "Anything further in this pass waits for you.";
                return false;
            }

            // The user's rolling-hour cap. Distinct from the ten-minute window: that one catches a
            // rule misfiring across a cohort in a burst, this one catches a slow drip that never
            // fills a ten-minute bucket.
            int lastHour = _state.Recent.Count(s => now - s.Utc <= TimeSpan.FromHours(1));
            if (MaxPerHour >= 0 && lastHour >= MaxPerHour)
            {
                TripLocked($"{MaxPerHour} automatic actions have already fired in the last hour, which is the limit set in Settings.");
                refusal = _state.TripReason;
                return false;
            }

            int last10 = _state.Recent.Count(s => now - s.Utc <= TimeSpan.FromMinutes(10));
            if (last10 >= MaxPer10Minutes)
            {
                TripLocked($"{MaxPer10Minutes} automatic actions already fired in the last ten minutes, which is more like a rule misfiring across similar processes than a real outbreak.");
                refusal = _state.TripReason;
                return false;
            }

            if (_state.Recent.Count >= MaxPer24Hours)
            {
                TripLocked($"{MaxPer24Hours} automatic actions have fired in the last 24 hours, which is the daily ceiling.");
                refusal = _state.TripReason;
                return false;
            }

            var recentTargets = _state.Recent
                .Where(s => now - s.Utc <= TimeSpan.FromSeconds(60))
                .Select(s => s.Target)
                .Append(target)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            if (recentTargets > MaxDistinctTargetsPer60Seconds)
            {
                TripLocked($"{recentTargets} different programs would have been actioned within a minute. A genuine incident converges on one program, so HERO has stopped rather than spread.");
                refusal = _state.TripReason;
                return false;
            }

            if (rung == ResponseRung.RemovePersistence)
            {
                DateTime? lastRemoval = null;
                foreach (var s in _state.Recent)
                {
                    if (s.Rung != nameof(ResponseRung.RemovePersistence)) continue;
                    if (lastRemoval is null || s.Utc > lastRemoval.Value) lastRemoval = s.Utc;
                }
                if (lastRemoval is { } t && now - t < MinPersistenceRemovalInterval)
                {
                    refusal = "HERO removes at most one startup entry automatically per hour. This one is waiting for you.";
                    return false;
                }
            }

            _state.Recent.Add(new AutonomyStamp { Utc = now, Rung = rung.ToString(), Target = target });
            _state.TotalAutonomousActions++;
            _thisSweep++;
            Save();
            refusal = "";
            return true;
        }
    }

    /// <summary>Disarms autonomy immediately. Used for trip conditions detected outside TryConsume.</summary>
    internal void Trip(string reason)
    {
        lock (_sync) TripLocked(reason);
    }

    private void TripLocked(string reason)
    {
        if (_state.Tripped) return;
        _state.Tripped = true;
        _state.TripReason = reason;
        _state.TrippedUtc = DateTime.UtcNow;
        Save();
        try { Disarmed?.Invoke(reason); } catch { }
    }

    /// <summary>Re-arms autonomy. Only ever called from an explicit user gesture.</summary>
    internal void ReArm()
    {
        lock (_sync)
        {
            _state.Tripped = false;
            _state.TripReason = "";
            _state.TrippedUtc = null;
            _state.Recent.Clear();
            Save();
        }
    }

    private void Prune()
    {
        var cutoff = DateTime.UtcNow - TimeSpan.FromHours(24);
        _state.Recent.RemoveAll(s => s.Utc < cutoff);
    }

    private void Load()
    {
        try
        {
            if (File.Exists(_statePath))
                _state = JsonSerializer.Deserialize<AutonomyState>(File.ReadAllText(_statePath)) ?? new AutonomyState();
        }
        catch { _state = new AutonomyState(); }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(HeroPaths.Root);
            File.WriteAllText(_statePath, JsonSerializer.Serialize(_state, ResponseEngine.Json));
        }
        catch
        {
            // A breaker that cannot persist its counters is a breaker that resets on every crash.
            // Refusing to act is the only safe interpretation, so trip in memory at least.
            _state.Tripped = true;
            _state.TripReason = "HERO could not save its autonomy counters to disk, so it cannot guarantee the limit holds across a restart.";
        }
    }
}

// ------------------------------------------------------------------ the engine

/// <summary>
/// Containment.
///
/// Every rung is gated, and the gates are deliberately harsher than the detection side, because
/// the two failure modes are not symmetric: a missed detection costs a slower response, while a
/// false positive that kills the user's editor or moves a file out of System32 costs work that
/// no undo record returns.
///
/// Four properties are structural rather than advisory:
///
///   1. <see cref="ProtectedSet"/> is consulted FIRST, on every path, and its refusal is recorded
///      in the ledger. A refusal at this point is also a scoring defect worth surfacing — the
///      scorer should not have proposed it.
///   2. Nothing destructive runs without an <see cref="ActionAuthorisation"/>, and one cannot be
///      minted without the forensic snapshot (and, for reversible rungs, the undo record) already
///      on disk.
///   3. Suspension precedes the kill, both because it stops the activity while the decision is
///      still reversible and because it is what makes the captured evidence coherent.
///   4. The circuit breaker converts a bad rule from an unbounded event into a bounded one and
///      then falls back to ask-only until the user says otherwise.
///
/// Autonomous actions never trigger a UAC prompt. A tray app that raises consent dialogs the user
/// did not ask for teaches them to click through consent dialogs, which is a net security loss
/// (PLATFORM-FACTS §6). Elevation is requested only from an explicit user gesture, once.
/// </summary>
internal sealed class ResponseEngine : IDisposable
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    private static readonly JsonSerializerOptions JsonCompact = new() { WriteIndented = false };

    /// <summary>The literal firewall group. Never an "@dll,-123" indirect resource string, which
    /// only resolves for registered resources and renders as garbage otherwise.</summary>
    internal const string FirewallGroup = "HERO Containment";
    /// <summary>Distinctive rule-name prefix so HERO can find and remove exactly its own rules.</summary>
    internal const string FirewallNamePrefix = "HERO-Block";

    private readonly ProtectedSet _protected;
    private readonly QuarantineVault _vault;
    private readonly CircuitBreaker _breaker;

    private readonly ConcurrentDictionary<int, SuspendedProcess> _suspended = new();
    private readonly ConcurrentDictionary<int, System.Threading.Timer> _resumeTimers = new();
    private readonly object _ledgerLock = new();

    /// <summary>
    /// Dry run. Ships ON: this machine's normal process topology — a supervisor spawning dozens
    /// of children which spawn shells which spawn console hosts — is behaviourally identical to a
    /// RAT, so the first week's job is to show the user what HERO WOULD have done against their
    /// real workload before it is trusted to act.
    /// </summary>
    internal bool DryRun { get; set; } = true;

    /// <summary>
    /// Asked, at the moment of every autonomy decision, whether HERO may act without asking — and
    /// if not, why not, in words the user will read.
    ///
    /// THIS REPLACED A PLAIN BOOL, and the bool is why HERO could not act at all. `AutonomyEnabled`
    /// was read here and assigned NOWHERE in the product: <c>GuardianService.ApplyAutonomy</c>, the
    /// single bridge from settings to engine, set <see cref="DryRun"/> and nothing else. So the
    /// autonomy level the user picked in Settings reached the dry-run flag and stopped, the gate
    /// below always fell to "automatic action is switched off", and the four safety limits behind
    /// it — the 72-hour observation window, the post-crash pause, quiet hours and the caps — were
    /// never consulted because the thing they exist to limit never ran.
    ///
    /// A DELEGATE RATHER THAN A FLAG, because the answer changes with the clock and not with the
    /// settings. The observation window expires, quiet hours begin and end, the post-crash pause
    /// lifts. A value captured when settings last changed would be stale within the hour, and
    /// stale in the permissive direction, which is the wrong way for this particular value to be
    /// wrong.
    ///
    /// Null means not configured, and not configured means NO. A response engine with no policy
    /// attached is one nobody has told what it is allowed to do.
    /// </summary>
    internal Func<(bool Permitted, string Reason)>? AutonomyPolicy { get; set; }

    /// <summary>
    /// The autonomy half of the gate. Fails closed on a null policy and on a throwing one: this
    /// answers "may HERO terminate something without asking", so the only safe reading of "I could
    /// not work it out" is no.
    /// </summary>
    private bool AutonomyPermitted(out string reason)
    {
        if (AutonomyPolicy is null)
        {
            reason = "automatic action is not configured.";
            return false;
        }

        try
        {
            var (permitted, why) = AutonomyPolicy();
            reason = permitted ? "" : (why.Length > 0 ? why : "automatic action is switched off.");
            return permitted;
        }
        catch
        {
            reason = "HERO could not determine whether it is allowed to act, so it did not.";
            return false;
        }
    }

    /// <summary>
    /// The user's cap on autonomous actions in a rolling hour. Settings owns the number; the
    /// breaker enforces it. See <see cref="CircuitBreaker.MaxPerHour"/>.
    /// </summary>
    internal int MaxAutoActionsPerHour
    {
        get => _breaker.MaxPerHour;
        set => _breaker.MaxPerHour = value;
    }

    /// <summary>The user's cap on autonomous actions within a single sweep.</summary>
    internal int MaxAutoActionsPerSweep
    {
        get => _breaker.MaxPerSweep;
        set => _breaker.MaxPerSweep = value;
    }

    /// <summary>
    /// Marks the start of a detection sweep, resetting the per-sweep budget.
    ///
    /// Called by the guardian at the top of each sweep. Without a boundary the "per sweep" cap has
    /// no meaning, which is why it went unenforced while being persisted, merged over IPC and
    /// advertised in the README.
    /// </summary>
    internal void BeginSweep() => _breaker.BeginSweep();

    /// <summary>
    /// Autonomous removal of a startup entry. Off, and it stays off on this machine: System
    /// Restore has zero restore points with VSS and sppsvc stopped, so the OS-level rollback the
    /// design would otherwise lean on for registry, task and service changes does not exist.
    /// Without it, every persistence removal is confirmed by the user.
    /// </summary>
    internal bool AllowAutonomousPersistenceRemoval { get; set; }

    /// <summary>Whether a user-initiated action may raise one UAC prompt. Never applies to autonomy.</summary>
    internal bool AllowElevationPrompt { get; set; } = true;

    /// <summary>
    /// Score at or above which a verdict is eligible for autonomous action.
    ///
    /// Expressed in the scorer's own units, NOT as a percentage. <see cref="Verdict.Score"/> is
    /// produced by <see cref="ScorerModel"/> on a roughly 0-25 scale — Informational below 4, Low
    /// below 10, Medium below 15, Critical at 22 — so an 0-to-100-shaped threshold such as 85 is
    /// not merely strict, it is unreachable: every verdict this machine can produce sits below it,
    /// and the engine would sit inert for ever without saying so.
    ///
    /// The default is <see cref="ScorerModel.HighScore"/>, which is exactly the score at which the
    /// scorer's own confidence mapping first permits <see cref="Confidence.High"/>. That is the
    /// point of pairing the two conditions in <see cref="MeetsAutonomyBar"/>: they are computed by
    /// different parts of the scorer and are required to AGREE, so a High confidence arriving with
    /// a sub-High score is a scorer defect and the gate stays shut.
    /// </summary>
    internal double AutonomyScoreThreshold { get; set; } = ScorerModel.HighScore;

    /// <summary>How long a suspension survives without adjudication before it self-heals.</summary>
    internal TimeSpan AutoResumeAfter { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>How long a firewall containment rule lives before the reaper removes it.</summary>
    internal TimeSpan FirewallRuleTtl { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Vault ceiling. Quarantine is refused rather than evicting an older entry.</summary>
    internal long VaultQuotaBytes { get; set; } = 5L * 1024 * 1024 * 1024;

    internal CircuitBreaker Breaker => _breaker;
    internal ProtectedSet Protection => _protected;
    internal IReadOnlyCollection<SuspendedProcess> CurrentlySuspended => _suspended.Values.ToArray();

    /// <summary>Raised for every ledgered action, including refusals.</summary>
    internal event Action<ResponseResult>? ActionRecorded;

    /// <summary>
    /// Raised when the scorer proposed something the protected set refused. That is not a normal
    /// event: it means detection targeted something it should have excluded, and it is worth
    /// surfacing as a defect rather than swallowing as a routine refusal.
    /// </summary>
    internal event Action<ResponseResult>? ScoringDefectSuspected;

    internal ResponseEngine(ProtectedSet? protectedSet = null, QuarantineVault? vault = null)
    {
        _protected = protectedSet ?? ProtectedSet.Shared;
        _vault = vault ?? new QuarantineVault();
        _breaker = new CircuitBreaker();
        HeroPaths.EnsureCreated();

        // Continue the ledger's hash chain across restarts. Starting a fresh chain every session
        // would make an ordinary restart indistinguishable from someone truncating the log.
        try
        {
            if (File.Exists(LedgerPath))
            {
                foreach (var line in File.ReadLines(LedgerPath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var previous = JsonSerializer.Deserialize<ResponseLedgerEntry>(line);
                    if (previous is not null) _prevHash = previous.Hash;
                }
            }
        }
        catch { /* a fresh chain is the fallback; the ledger is still appended to */ }
    }

    // =====================================================================
    //  Orchestration
    // =====================================================================

    /// <summary>
    /// Runs the ladder for one verdict.
    ///
    /// The gate is stated once and applies to EVERY rung, not just the destructive ones: a verdict
    /// that cannot justify a kill cannot justify an autonomous suspend either. Suspension is
    /// reversible, but a mystery freeze on the user's build is still a failure.
    /// </summary>
    internal ResponsePlan Respond(Verdict verdict, Snapshot? snapshot = null, bool userInitiated = false)
    {
        string incidentId = NewId("inc");
        var results = new List<ResponseResult>();

        // Recomputed per incident, not once at boot: intermediate parents die, and a stale chain
        // protects the wrong PIDs.
        _protected.RefreshLineage(snapshot);

        var ceiling = ChooseCeiling(verdict);
        var protection = ClassifySubject(verdict.Subject);

        // The evidence bar and the master switches are evaluated separately and reported
        // separately. Collapsing them would make the shakedown report useless: every entry would
        // read "automatic action is switched off" instead of saying whether the detection was
        // actually good enough to act on.
        string gateWhy;
        bool meetsBar;
        bool autonomous = false;

        if (ceiling < ResponseRung.Suspend)
        {
            meetsBar = false;
            gateWhy = "Nothing here warrants an action.";
        }
        else
        {
            meetsBar = MeetsAutonomyBar(verdict, protection, out gateWhy);

            if (userInitiated) gateWhy = "Requested by you.";
            else if (!meetsBar) { /* gateWhy already names the failing condition */ }
            else if (DryRun)
                gateWhy = $"Dry run — HERO would have acted on its own here. {BuildGrantExplanation(verdict)}";
            else if (!AutonomyPermitted(out string denial))
                gateWhy = $"HERO would have acted on its own here ({BuildGrantExplanation(verdict)}), but {denial}";
            else if (_breaker.Tripped)
                gateWhy = $"Ask-only mode: {_breaker.TripReason}";
            else
            {
                autonomous = true;
                gateWhy = BuildGrantExplanation(verdict);
            }
        }

        if (ceiling <= ResponseRung.Notify)
        {
            results.Add(Record(new ResponseResult
            {
                Rung = ceiling,
                Outcome = ActionOutcome.NotApplicable,
                Message = ceiling == ResponseRung.Observe
                    ? "Recorded for the timeline. Nothing about this warrants telling you yet."
                    : $"{verdict.Subject.Display}: {verdict.Headline?.Explanation ?? "worth a look"}",
                IncidentId = incidentId,
                Target = verdict.Subject.Display,
            }));
            return new ResponsePlan
            {
                IncidentId = incidentId,
                Ceiling = ceiling,
                Autonomous = false,
                MeetsAutonomyBar = meetsBar,
                DryRun = DryRun,
                GateExplanation = gateWhy,
                Results = results,
            };
        }

        switch (verdict.Subject)
        {
            case ProcessSubject ps:
            {
                var process = ps.Process;

                // Rung 2 first, always. It is the only fully reversible way to stop exfiltration
                // or encryption in flight, and the kill rung will not authorise without it.
                var suspend = Suspend(process, incidentId, ReasonFor(verdict), userInitiated, autonomous, verdict);
                results.Add(suspend);

                // Rung 3. Note this only prevents NEW connections: a firewall rule is evaluated at
                // connection establishment, so it does nothing to a socket that is already open.
                // That is exactly why it never stands alone here — the suspend above is what stops
                // an exfiltration already in progress.
                if (ceiling >= ResponseRung.BlockNetwork && HasExternalConnections(process, snapshot))
                    results.Add(BlockNetwork(process, incidentId, ReasonFor(verdict), userInitiated, autonomous, snapshot));

                // Rung 4. Only when the suspend actually took: killing without the freeze loses the
                // evidence that would prove or disprove the detection.
                if (ceiling >= ResponseRung.KillTree)
                    results.Add(KillTree(process, incidentId, ReasonFor(verdict), userInitiated, autonomous,
                                         snapshot, verdict, suspendCompleted: suspend.Acted));

                // Rung 5.
                if (ceiling >= ResponseRung.Quarantine && !process.PathUnavailable)
                    results.Add(Quarantine(process.ImagePath, incidentId, ReasonFor(verdict), userInitiated, autonomous));
                break;
            }

            case PersistenceSubject pe:
                results.Add(RemovePersistence(pe.Entry, incidentId, ReasonFor(verdict), userInitiated, autonomous));
                break;

            default:
                results.Add(Record(new ResponseResult
                {
                    Rung = ResponseRung.Notify,
                    Outcome = ActionOutcome.NotApplicable,
                    Message = $"HERO has no containment path for {verdict.Subject.Display}; reporting only.",
                    IncidentId = incidentId,
                    Target = verdict.Subject.Display,
                }));
                break;
        }

        return new ResponsePlan
        {
            IncidentId = incidentId,
            Ceiling = ceiling,
            Autonomous = autonomous,
            MeetsAutonomyBar = meetsBar,
            DryRun = DryRun,
            GateExplanation = gateWhy,
            Results = results,
        };
    }

    /// <summary>
    /// Maps a score onto the highest rung HERO will consider. Bands are contiguous so no score
    /// falls into a gap.
    ///
    /// The boundaries are the scorer's OWN tier constants rather than numbers restated here.
    /// Restating them is precisely what produced the defect this replaces: the bands were written
    /// on an 0-to-100 scale while <see cref="ScorerModel"/> emits roughly 0-25, so every verdict
    /// this machine can produce — a Critical one included — fell under the first boundary and the
    /// entire ladder silently collapsed to Observe. Two copies of a threshold is one copy too
    /// many; referencing the model means a retune moves these with it or fails to compile.
    /// </summary>
    private ResponseRung ChooseCeiling(Verdict verdict)
    {
        double s = verdict.Score;
        if (s < ScorerModel.LowScore) return ResponseRung.Observe;
        if (s < ScorerModel.MediumScore) return ResponseRung.Notify;

        // Persistence has no suspend and no network rung — removing or disabling the autorun is
        // the only containment that exists for it — so its ceiling is that rung from the middle
        // band upwards. The autonomy gate, not the ceiling, is what keeps it prompt-only until the
        // score also reaches the scorer's High tier.
        if (verdict.Subject is PersistenceSubject) return ResponseRung.RemovePersistence;

        if (s < ScorerModel.HighScore) return ResponseRung.BlockNetwork;   // suspend and net-block, prompt-only
        return ResponseRung.Quarantine;
    }

    /// <summary>
    /// The evidence half of the autonomy gate, stated once and applied to EVERY rung — a verdict
    /// that cannot justify a kill cannot justify an autonomous suspend either. Suspension is
    /// reversible, but a mystery freeze on the user's build is still a failure.
    ///
    /// Two independently computed fields are required to agree (score AND confidence tier) because
    /// they are produced by different parts of the scorer, so a single arithmetic bug cannot open
    /// the gate on its own. The two-signal-family requirement is the main precision lever: most
    /// real false positives are one over-tuned rule, not two unrelated rules agreeing.
    ///
    /// The master switches (dry run, autonomy enabled, circuit breaker) are deliberately NOT
    /// checked here — see <see cref="ResponsePlan.MeetsAutonomyBar"/>.
    /// </summary>
    private bool MeetsAutonomyBar(Verdict verdict, ProtectionResult protection, out string why)
    {
        if (protection.BlocksAutonomy)
        {
            why = protection.Reason;
            return false;
        }
        if (verdict.Score < AutonomyScoreThreshold)
        {
            // One decimal, not zero. On the scorer's 0-25 scale a rounded-to-integer score prints
            // the self-contradicting sentence "Score 15 is below the 15 needed" for a 14.6.
            why = $"Score {verdict.Score:0.0} is below the {AutonomyScoreThreshold:0.0} needed to act without asking.";
            return false;
        }
        if (verdict.Confidence != Confidence.High)
        {
            why = $"Confidence is {verdict.Confidence}, not High.";
            return false;
        }
        if (verdict.CorroboratingFamilies < 2)
        {
            why = "Only one kind of evidence supports this. HERO needs at least two unrelated kinds before it acts on its own — nine unsigned binaries are running on this machine right now and every one of them is benign.";
            return false;
        }

        why = "";
        return true;
    }

    private static string BuildGrantExplanation(Verdict verdict) =>
        $"Score {verdict.Score:0.0}, {verdict.CorroboratingFamilies} independent kinds of evidence, nothing protected in the way.";

    /// <summary>
    /// Whether this call has any authority to change anything at all.
    ///
    /// There are exactly two sources of authority — the user asked, or the autonomy gate opened —
    /// and an action needs one of them. Before this existed, <c>autonomous</c> was threaded through
    /// every rung purely as an annotation for the ledger: nothing actually required it. The result
    /// was that <see cref="Respond"/> with autonomy switched OFF and dry run switched OFF reached
    /// the mutating code with neither source of authority behind it, and froze, firewalled, killed
    /// and quarantined on its own — while <c>autonomous</c> being false also skipped the circuit
    /// breaker, so that configuration was less bounded than autonomy proper, not more. That is the
    /// configuration the shakedown screen tells the user is the cautious one.
    ///
    /// When authority is absent the rung still runs its whole evidence path and reports what it
    /// would have done; it simply stops short of the change. That is what keeps the shakedown
    /// report informative instead of empty.
    /// </summary>
    private static bool Authorised(bool userInitiated, bool autonomous) => userInitiated || autonomous;

    private ProtectionResult ClassifySubject(Subject subject) => subject switch
    {
        ProcessSubject ps => _protected.Classify(ps.Process),
        PersistenceSubject pe => _protected.Classify(pe.Entry),
        _ => ProtectionResult.Clear,
    };

    private static string ReasonFor(Verdict v) =>
        v.Headline is { } h ? $"{h.Title}: {h.Explanation}" : $"Score {v.Score:0.0}";

    private static bool HasExternalConnections(ProcessRecord p, Snapshot? snapshot) =>
        snapshot?.Connections.Any(c => c.Pid == p.Pid && c.IsExternal) ?? false;

    // =====================================================================
    //  Rung 2 — suspend
    // =====================================================================

    /// <summary>
    /// Freezes a process.
    ///
    /// This is the highest-value rung and the one that makes the ladder safe. It stops
    /// exfiltration and encryption immediately, it is 100% reversible, and it is what lets the
    /// evidence be captured coherently instead of torn across a running address space.
    ///
    /// The suspension is journalled to disk BEFORE the freeze. Without that, a HERO crash — the
    /// first thing a RAT would attempt — leaves every suspended process frozen forever with
    /// nothing on disk to reconcile from.
    /// </summary>
    internal ResponseResult Suspend(ProcessRecord process, string incidentId, string reason,
                                   bool userInitiated, bool autonomous = false, Verdict? verdict = null)
    {
        string actionId = NewId("act");
        string target = process.FileName;
        bool describeOnly = DryRun || !Authorised(userInitiated, autonomous);

        // 1. Protected set first, always.
        var live = _protected.ProbeLive(process);
        if (live.BlocksEverything || (!userInitiated && live.BlocksAutonomy))
            return RecordRefusal(ResponseRung.Suspend, actionId, incidentId, target, live, autonomous);

        if (_protected.IsSuspendForbidden(process, out string suspendWhy))
            return RecordRefusal(ResponseRung.Suspend, actionId, incidentId, target,
                                 new ProtectionResult(ProtectionTier.NeverSuspend, suspendWhy), autonomous);

        // 2. Budget.
        if (autonomous && !_breaker.TryConsume(ResponseRung.Suspend, target, out string refusal))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Suspend, Outcome = ActionOutcome.RefusedCircuitBreaker,
                Message = refusal, ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        // 3. Evidence before action.
        string snapshotPath = WriteForensicSnapshot(incidentId, verdict, process, new[] { process }, null, "suspend");

        var undo = new UndoRecord
        {
            ActionId = actionId,
            IncidentId = incidentId,
            CapturedUtc = DateTime.UtcNow,
            Kind = "suspend",
            Description = $"Freeze {target} (PID {process.Pid})",
            TargetKey = $"{process.Pid}:{process.StartTimeUtc.Ticks}",
            Reason = reason,
            Suspend = new SuspendUndo
            {
                Pid = process.Pid,
                StartTicks = process.StartTimeUtc.Ticks,
                Name = process.Name,
                ImagePath = process.ImagePath,
                SuspendedUtc = DateTime.UtcNow,
                AutoResumeUtc = DateTime.UtcNow + AutoResumeAfter,
            },
        };
        string undoPath = WriteUndoRecord(undo);

        if (describeOnly)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Suspend,
                Outcome = DryRun ? ActionOutcome.DryRun : ActionOutcome.RefusedGate,
                Message = (DryRun ? "" : "Waiting for you. ") +
                    $"Would freeze {target} (PID {process.Pid}) and resume it automatically after {AutoResumeAfter.TotalMinutes:0} minutes if nothing else happened.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
            });

        var auth = ActionAuthorisation.Mint(ResponseRung.Suspend, incidentId, actionId, userInitiated,
                                            snapshotPath, undoPath, false, reason, out string mintRefusal);
        if (auth is null)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Suspend, Outcome = ActionOutcome.Failed, Message = mintRefusal,
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        // 4. Act.
        IntPtr h = Native.OpenProcess(Native.PROCESS_SUSPEND_RESUME, false, process.Pid);
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Suspend,
                Outcome = err == ErrorAccessDenied ? ActionOutcome.RefusedByOs : ActionOutcome.Failed,
                Message = err == ErrorAccessDenied
                    ? $"Windows refused HERO permission to freeze {target}. That only happens for protected or higher-privileged processes, so HERO has stopped rather than trying to force it."
                    : $"Could not open {target} to freeze it (error {err}).",
                ActionId = actionId, IncidentId = incidentId, Target = target,
                ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
            });
        }

        try
        {
            int status = Native.NtSuspendProcess(h);
            if (status != 0)
                return Record(new ResponseResult
                {
                    Rung = ResponseRung.Suspend, Outcome = ActionOutcome.Failed,
                    Message = $"Windows would not freeze {target} (NTSTATUS 0x{status:X8}).",
                    ActionId = actionId, IncidentId = incidentId, Target = target,
                    ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
                });
        }
        finally { Native.CloseHandle(h); }

        undo.State = "committed";
        WriteUndoRecord(undo);
        AppendJournal(SuspendJournalPath, new { op = "suspend", pid = process.Pid,
            startTicks = process.StartTimeUtc.Ticks, name = process.Name, path = process.ImagePath,
            utc = DateTime.UtcNow, incidentId, actionId });

        var record = new SuspendedProcess(process.Pid, process.StartTimeUtc.Ticks, target,
            process.ImagePath, DateTime.UtcNow, DateTime.UtcNow + AutoResumeAfter, incidentId);
        _suspended[process.Pid] = record;
        ArmAutoResume(record);

        return Record(new ResponseResult
        {
            Rung = ResponseRung.Suspend, Outcome = ActionOutcome.Performed,
            Message = $"Froze {target} (PID {process.Pid}). It is not running and not sending anything. HERO will thaw it automatically in {AutoResumeAfter.TotalMinutes:0} minutes unless you decide otherwise.",
            ActionId = actionId, IncidentId = incidentId, Target = target,
            UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
        });
    }

    /// <summary>Thaws a frozen process. Always allowed — undoing containment is never gated.</summary>
    internal ResponseResult Resume(int pid)
    {
        string actionId = NewId("act");
        _suspended.TryGetValue(pid, out var known);

        if (DryRun && known is not null)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Suspend, Outcome = ActionOutcome.DryRun,
                Message = $"Would thaw {known.Name} (PID {pid}).",
                ActionId = actionId, IncidentId = known.IncidentId, Target = known.Name,
            });

        IntPtr h = Native.OpenProcess(Native.PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero)
        {
            // The process exited while frozen, which is a perfectly normal end state.
            _suspended.TryRemove(pid, out _);
            DisarmAutoResume(pid);
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Suspend, Outcome = ActionOutcome.NotApplicable,
                Message = $"PID {pid} is gone; nothing to thaw.",
                ActionId = actionId, Target = known?.Name ?? pid.ToString(CultureInfo.InvariantCulture),
            });
        }

        int status;
        try { status = Native.NtResumeProcess(h); }
        finally { Native.CloseHandle(h); }

        _suspended.TryRemove(pid, out _);
        DisarmAutoResume(pid);
        AppendJournal(SuspendJournalPath, new { op = "resume", pid, utc = DateTime.UtcNow });

        return Record(new ResponseResult
        {
            Rung = ResponseRung.Suspend,
            Outcome = status == 0 ? ActionOutcome.Performed : ActionOutcome.Failed,
            Message = status == 0
                ? $"Thawed {known?.Name ?? "PID " + pid}."
                : $"Could not thaw PID {pid} (NTSTATUS 0x{status:X8}).",
            ActionId = actionId, Target = known?.Name ?? pid.ToString(CultureInfo.InvariantCulture),
        });
    }

    private void ArmAutoResume(SuspendedProcess record)
    {
        DisarmAutoResume(record.Pid);
        var due = record.AutoResumeUtc - DateTime.UtcNow;
        if (due < TimeSpan.Zero) due = TimeSpan.Zero;
        var timer = new System.Threading.Timer(_ =>
        {
            try { Resume(record.Pid); } catch { }
        }, null, due, Timeout.InfiniteTimeSpan);
        _resumeTimers[record.Pid] = timer;
    }

    private void DisarmAutoResume(int pid)
    {
        if (_resumeTimers.TryRemove(pid, out var t)) t.Dispose();
    }

    // =====================================================================
    //  Rung 3 — network containment
    // =====================================================================

    /// <summary>
    /// Blocks a program's network access with a Windows Firewall rule.
    ///
    /// IMPORTANT AND OFTEN GOT WRONG: a firewall rule is evaluated when a connection is
    /// established, so adding one does NOT tear down or re-authorise a socket that is already
    /// open. Against exfiltration already in progress it does nothing — which is why this rung is
    /// only ever offered alongside a suspend, never as an equivalent alternative to one.
    ///
    /// Rules are PATH-based, not PID-based, so the protected set refuses any image under %WINDIR%
    /// or inside a developer root before we get here.
    /// </summary>
    internal ResponseResult BlockNetwork(ProcessRecord process, string incidentId, string reason,
                                         bool userInitiated, bool autonomous = false, Snapshot? snapshot = null)
    {
        string actionId = NewId("act");
        string target = process.FileName;
        bool describeOnly = DryRun || !Authorised(userInitiated, autonomous);

        if (process.PathUnavailable)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.BlockNetwork, Outcome = ActionOutcome.RefusedProtected,
                Message = $"HERO cannot read the image path for {process.Name}, and a firewall rule needs an exact path or it blocks the wrong program.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        var protection = _protected.Classify(process);
        if (protection.BlocksEverything || (!userInitiated && protection.BlocksAutonomy))
            return RecordRefusal(ResponseRung.BlockNetwork, actionId, incidentId, target, protection, autonomous);

        if (_protected.IsFirewallTargetForbidden(process.ImagePath, out string fwWhy))
            return RecordRefusal(ResponseRung.BlockNetwork, actionId, incidentId, target,
                                 new ProtectionResult(ProtectionTier.Essential, fwWhy), autonomous);

        if (autonomous && !_breaker.TryConsume(ResponseRung.BlockNetwork, target, out string refusal))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.BlockNetwork, Outcome = ActionOutcome.RefusedCircuitBreaker,
                Message = refusal, ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        string canonical = ProtectedSet.Canonicalise(process.ImagePath);
        var created = DateTime.UtcNow;
        var ttl = created + FirewallRuleTtl;

        var rules = new[]
        {
            new FirewallUndo
            {
                DisplayName = $"{FirewallNamePrefix} {incidentId} out", IncidentId = incidentId,
                Group = FirewallGroup, Direction = "Outbound", Program = canonical,
                CreatedUtc = created, TtlUtc = ttl,
            },
            new FirewallUndo
            {
                DisplayName = $"{FirewallNamePrefix} {incidentId} in", IncidentId = incidentId,
                Group = FirewallGroup, Direction = "Inbound", Program = canonical,
                CreatedUtc = created, TtlUtc = ttl,
            },
        };

        string snapshotPath = WriteForensicSnapshot(incidentId, null, process, new[] { process }, snapshot, "block-network");

        var undo = new UndoRecord
        {
            ActionId = actionId, IncidentId = incidentId, CapturedUtc = created,
            Kind = "firewall-rule",
            Description = $"Block inbound and outbound network for {canonical}",
            TargetKey = canonical, Reason = reason, Firewall = rules[0],
        };
        string undoPath = WriteUndoRecord(undo);

        if (describeOnly)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.BlockNetwork,
                Outcome = DryRun ? ActionOutcome.DryRun : ActionOutcome.RefusedGate,
                Message = (DryRun ? "" : "Waiting for you. ") +
                    $"Would add two firewall rules blocking {canonical} in and out for {FirewallRuleTtl.TotalHours:0} hours. Note this would only stop NEW connections — anything already connected keeps its socket until the process is frozen or killed.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
                Details = rules.Select(r => BuildAddRuleCommand(r, reason)).ToArray(),
            });

        if (!IsElevated())
        {
            // Honest degradation: the user is told exactly what was not done and what would do it.
            // Autonomy never raises a UAC prompt, so an autonomous incident stops here and the
            // suspend from the previous rung remains the containment.
            if (!userInitiated || !AllowElevationPrompt)
                return Record(new ResponseResult
                {
                    Rung = ResponseRung.BlockNetwork, Outcome = ActionOutcome.RefusedNeedsElevation,
                    Message = "Adding a firewall rule needs administrator rights, which HERO does not have. The process is still frozen, which stops traffic more completely than a firewall rule would. Run the command below from an elevated terminal to add the block yourself.",
                    ActionId = actionId, IncidentId = incidentId, Target = target,
                    UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
                    Details = rules.Select(r => BuildAddRuleCommand(r, reason)).ToArray(),
                });
        }

        var auth = ActionAuthorisation.Mint(ResponseRung.BlockNetwork, incidentId, actionId, userInitiated,
                                            snapshotPath, undoPath, false, reason, out string mintRefusal);
        if (auth is null)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.BlockNetwork, Outcome = ActionOutcome.Failed, Message = mintRefusal,
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        // The journal is written and flushed BEFORE the rules are added, so a crash between the two
        // still leaves a trace the startup reaper can find. A forgotten block on a common binary
        // produces baffling connectivity failures weeks later; nothing HERO adds may outlive it.
        // It is written HERE rather than earlier so a dry run, a refused gate or a missing-rights
        // refusal does not seed the reaper's journal with rules that were never created.
        foreach (var r in rules)
            AppendJournal(FirewallJournalPath, new { op = "add", r.DisplayName, r.Group, r.Direction,
                r.Program, createdUtc = created, ttlUtc = ttl, incidentId, actionId });

        // Both rules go in ONE PowerShell invocation. Two invocations meant two consecutive UAC
        // prompts for a single user gesture, which is exactly the click-through training the
        // elevation policy exists to avoid. -ErrorAction Stop on each means a failure on the
        // outbound rule aborts before the inbound one, and the journal above lets the reaper
        // remove whichever did land.
        var failures = new List<string>();
        string addScript = string.Join(Environment.NewLine, rules.Select(r => BuildAddRuleCommand(r, reason)));
        if (!RunPowerShell(addScript, elevate: !IsElevated(), out string addError))
            foreach (var r in rules) failures.Add($"{r.DisplayName}: {addError}");

        if (failures.Count == rules.Length)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.BlockNetwork, Outcome = ActionOutcome.Failed,
                Message = "The firewall rules could not be added.", Details = failures,
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
            });

        undo.State = "committed";
        WriteUndoRecord(undo);

        return Record(new ResponseResult
        {
            Rung = ResponseRung.BlockNetwork,
            Outcome = failures.Count == 0 ? ActionOutcome.Performed : ActionOutcome.PartiallyPerformed,
            Message = $"Blocked {target} from the network for {FirewallRuleTtl.TotalHours:0} hours. Existing connections are unaffected by a firewall rule, so the freeze is what stopped anything already in flight.",
            Details = failures,
            ActionId = actionId, IncidentId = incidentId, Target = target,
            UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
        });
    }

    private string BuildAddRuleCommand(FirewallUndo rule, string reason)
    {
        string description = JsonSerializer.Serialize(new
        {
            hero = 1,
            incidentId = rule.IncidentId,
            rule = rule.DisplayName,
            createdUtc = rule.CreatedUtc.ToString("O", CultureInfo.InvariantCulture),
            ttlUtc = rule.TtlUtc.ToString("O", CultureInfo.InvariantCulture),
            reason,
            version = "1.0.0",
        }, JsonCompact);

        var sb = new StringBuilder();
        sb.Append("New-NetFirewallRule -DisplayName ").Append(PsQuote(rule.DisplayName));
        sb.Append(" -Group ").Append(PsQuote(rule.Group));
        sb.Append(" -Direction ").Append(rule.Direction);
        sb.Append(" -Action Block -Profile Any -Enabled True");
        if (!string.IsNullOrEmpty(rule.Program))
            sb.Append(" -Program ").Append(PsQuote(rule.Program));
        if (!string.IsNullOrEmpty(rule.RemoteAddress))
        {
            sb.Append(" -RemoteAddress ").Append(PsQuote(rule.RemoteAddress));
            if (rule.RemotePort > 0) sb.Append(" -Protocol TCP -RemotePort ").Append(rule.RemotePort);
        }
        sb.Append(" -Description ").Append(PsQuote(description));
        sb.Append(" -ErrorAction Stop | Out-Null");
        return sb.ToString();
    }

    /// <summary>Removes one HERO rule by its display name.</summary>
    internal ResponseResult RemoveFirewallRule(string displayName)
    {
        string actionId = NewId("act");
        if (!displayName.StartsWith(FirewallNamePrefix, StringComparison.Ordinal))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.BlockNetwork, Outcome = ActionOutcome.RefusedProtected,
                Message = $"\"{displayName}\" is not a HERO rule. HERO only ever removes rules it created.",
                ActionId = actionId, Target = displayName,
            });

        string cmd = $"Get-NetFirewallRule -Group {PsQuote(FirewallGroup)} -ErrorAction SilentlyContinue | " +
                     $"Where-Object {{ $_.DisplayName -eq {PsQuote(displayName)} }} | Remove-NetFirewallRule -ErrorAction Stop";

        if (DryRun)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.BlockNetwork, Outcome = ActionOutcome.DryRun,
                Message = $"Would remove firewall rule \"{displayName}\".",
                ActionId = actionId, Target = displayName, Details = new[] { cmd },
            });

        bool ok = RunPowerShell(cmd, elevate: !IsElevated(), out string err);
        AppendJournal(FirewallJournalPath, new { op = "remove", displayName, utc = DateTime.UtcNow, ok });

        return Record(new ResponseResult
        {
            Rung = ResponseRung.BlockNetwork,
            Outcome = ok ? ActionOutcome.Performed : ActionOutcome.Failed,
            Message = ok ? $"Removed firewall rule \"{displayName}\"." : $"Could not remove \"{displayName}\": {err}",
            ActionId = actionId, Target = displayName,
            Details = ok ? Array.Empty<string>() : new[] { cmd },
        });
    }

    /// <summary>
    /// Deletes every expired HERO rule.
    ///
    /// The description-parses-as-HERO-JSON check matters: other software already writes the
    /// Grouping field on this machine (there are rules grouped as "Claude" and as bare GUIDs), so
    /// matching on the group alone would eventually remove somebody else's rules.
    /// </summary>
    internal void ReapExpiredFirewallRules()
    {
        if (DryRun || !IsElevated()) return;

        string script =
            "$now=[DateTime]::UtcNow; " +
            $"Get-NetFirewallRule -Group {PsQuote(FirewallGroup)} -ErrorAction SilentlyContinue | ForEach-Object {{ " +
            "  $d=$_.Description; " +
            "  if ($d -and $d.StartsWith('{\"hero\"')) { " +
            "    try { $j=$d | ConvertFrom-Json; if ([DateTime]::Parse($j.ttlUtc).ToUniversalTime() -lt $now) { " +
            "      Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue } } catch { } } }";

        RunPowerShell(script, elevate: false, out _);
    }

    // =====================================================================
    //  Rung 4 — kill tree
    // =====================================================================

    /// <summary>
    /// The largest tree HERO will end without asking.
    ///
    /// Stated plainly rather than dressed up: on this machine an ordinary
    /// pwsh -> claude -> node -> cmd -> conhost chain routinely exceeds four processes, so
    /// autonomous multi-process tree kills will essentially never fire here. That is the intended
    /// outcome, not an oversight. A large tree is far more likely to be the user's toolchain than
    /// a RAT, and the user is a better judge of which than any heuristic HERO can run.
    /// </summary>
    internal const int MaxAutonomousTreeSize = 4;

    /// <summary>Beyond this HERO refuses outright, even for the user, and asks them to narrow it down.</summary>
    internal const int MaxTreeSize = 24;

    /// <summary>
    /// Terminates a process and its descendants, children first.
    ///
    /// Ordering is not cosmetic. Killing the parent first lets a supervisor respawn its children,
    /// so termination runs leaves-to-root. Every parent-child edge is validated against creation
    /// times, and every PID is re-validated immediately before termination, because the kernel
    /// recycles PIDs from a bitmap and gives no ordering guarantee between enumeration and
    /// termination — a recycled PID here means killing an innocent process, potentially a
    /// boot-critical one.
    /// </summary>
    internal ResponseResult KillTree(ProcessRecord root, string incidentId, string reason,
                                     bool userInitiated, bool autonomous = false, Snapshot? snapshot = null,
                                     Verdict? verdict = null, bool suspendCompleted = false)
    {
        string actionId = NewId("act");
        string target = root.FileName;
        bool describeOnly = DryRun || !Authorised(userInitiated, autonomous);

        var live = _protected.ProbeLive(root);
        if (live.BlocksEverything || (!userInitiated && live.BlocksAutonomy))
            return RecordRefusal(ResponseRung.KillTree, actionId, incidentId, target, live, autonomous);

        // Build and validate the tree.
        var members = BuildValidatedTree(root, snapshot, out string treeNote);
        if (members.Count > MaxTreeSize)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.KillTree, Outcome = ActionOutcome.RefusedProtected,
                Message = $"That would terminate {members.Count} processes. A tree that size on this machine is almost certainly a build or toolchain rather than one program, so HERO refuses and asks you to point at a narrower target.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        // A protected member anywhere in the tree means the walk reached somewhere it should not
        // have. Refuse the whole operation rather than killing a partial tree.
        foreach (var m in members)
        {
            var mp = _protected.Classify(m);
            if (!mp.BlocksEverything) continue;
            return RecordRefusal(ResponseRung.KillTree, actionId, incidentId, target,
                new ProtectionResult(mp.Tier,
                    $"The process tree under {target} reaches {m.FileName}, which HERO must never terminate. {mp.Reason} Refusing the whole operation rather than killing part of the tree."),
                autonomous);
        }

        if (autonomous && members.Count > MaxAutonomousTreeSize)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.KillTree, Outcome = ActionOutcome.RefusedGate,
                Message = $"{members.Count} processes would be terminated, above the {MaxAutonomousTreeSize} HERO will end without asking. Waiting for you.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        if (autonomous && !_breaker.TryConsume(ResponseRung.KillTree, target, out string refusal))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.KillTree, Outcome = ActionOutcome.RefusedCircuitBreaker,
                Message = refusal, ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        // Freeze the whole tree before capturing evidence. A dump or module walk of a running
        // process tears; a frozen one is coherent. This also stops the supervisor respawning
        // while the capture is in flight.
        var frozen = new List<int>();
        if (!describeOnly)
        {
            foreach (var m in members)
            {
                IntPtr sh = Native.OpenProcess(Native.PROCESS_SUSPEND_RESUME, false, m.Pid);
                if (sh == IntPtr.Zero) continue;
                try { if (Native.NtSuspendProcess(sh) == 0) frozen.Add(m.Pid); }
                finally { Native.CloseHandle(sh); }
            }
            foreach (int pid in frozen)
                AppendJournal(SuspendJournalPath, new { op = "suspend", pid, utc = DateTime.UtcNow, incidentId, actionId });
        }

        string snapshotPath = WriteForensicSnapshot(incidentId, verdict, root, members, snapshot, "kill-tree");

        if (describeOnly)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.KillTree,
                Outcome = DryRun ? ActionOutcome.DryRun : ActionOutcome.RefusedGate,
                Message = ((DryRun ? "" : "Waiting for you. ") +
                    $"Would end {members.Count} process{(members.Count == 1 ? "" : "es")} starting from {target} (PID {root.Pid}), children first. {treeNote}").Trim(),
                ActionId = actionId, IncidentId = incidentId, Target = target,
                ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
                Details = members.Select(m => $"PID {m.Pid} {m.FileName} — {m.CommandLine}").ToArray(),
            });

        // A kill has no undo record, so the token demands the suspend instead.
        bool suspendHeld = suspendCompleted || frozen.Contains(root.Pid) || _suspended.ContainsKey(root.Pid);
        var auth = ActionAuthorisation.Mint(ResponseRung.KillTree, incidentId, actionId, userInitiated,
                                            snapshotPath, "", suspendHeld, reason, out string mintRefusal);
        if (auth is null)
        {
            ResumeAll(frozen);
            return Record(new ResponseResult
            {
                Rung = ResponseRung.KillTree, Outcome = ActionOutcome.Failed, Message = mintRefusal,
                ActionId = actionId, IncidentId = incidentId, Target = target,
                ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
            });
        }

        // Leaves first. BuildValidatedTree returns breadth-first from the root, so reversing it
        // yields deepest-first.
        var order = members.AsEnumerable().Reverse().ToList();
        var killed = new List<string>();
        var survived = new List<string>();
        var denied = new List<string>();

        foreach (var m in order)
        {
            var outcome = TerminateVerified(m, out string detail);
            switch (outcome)
            {
                case ActionOutcome.Performed: killed.Add($"PID {m.Pid} {m.FileName}"); break;
                case ActionOutcome.RefusedByOs: denied.Add($"PID {m.Pid} {m.FileName}: {detail}"); break;
                default: survived.Add($"PID {m.Pid} {m.FileName}: {detail}"); break;
            }
        }

        // Anything that survived stays frozen: an escaped member of a tree HERO decided to end is
        // better contained than running, and the suspension is journalled so it self-heals.
        foreach (int pid in frozen.Where(p => survived.Any(s => s.StartsWith($"PID {p} ", StringComparison.Ordinal))))
        {
            if (!_suspended.ContainsKey(pid))
            {
                var rec = new SuspendedProcess(pid, 0, "(survived kill)", "", DateTime.UtcNow,
                                               DateTime.UtcNow + AutoResumeAfter, incidentId);
                _suspended[pid] = rec;
                ArmAutoResume(rec);
            }
        }

        if (denied.Count > 0)
        {
            // A denied kill means the scorer targeted something it should have excluded. Never
            // retried, never escalated to an elevated attempt, never a driver — surfaced as a
            // defect instead.
            var defect = new ResponseResult
            {
                Rung = ResponseRung.KillTree, Outcome = ActionOutcome.RefusedByOs,
                Message = $"Windows refused to end {denied.Count} of the {members.Count} processes. That refusal only happens for protected processes, which means HERO should not have selected them — this is a defect in its own scoring, not something to retry with more privilege.",
                Details = denied, ActionId = actionId, IncidentId = incidentId, Target = target,
                ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
            };
            try { ScoringDefectSuspected?.Invoke(defect); } catch { }
        }

        var result = new ResponseResult
        {
            Rung = ResponseRung.KillTree,
            Outcome = killed.Count == members.Count ? ActionOutcome.Performed
                    : killed.Count > 0 ? ActionOutcome.PartiallyPerformed
                    : ActionOutcome.Failed,
            Message = killed.Count == members.Count
                ? $"Ended {killed.Count} process{(killed.Count == 1 ? "" : "es")} under {target}. Everything about them was written to the incident record first, so this is explainable and contestable afterwards."
                : $"Ended {killed.Count} of {members.Count} processes under {target}. The rest are named below and remain frozen.",
            Details = killed.Concat(denied).Concat(survived).ToArray(),
            ActionId = actionId, IncidentId = incidentId, Target = target,
            ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
        };
        return Record(result);
    }

    /// <summary>
    /// Terminates one process and verifies it actually died, rather than assuming TerminateProcess
    /// succeeding means the process is gone. Termination is asynchronous; the wait is the proof.
    /// </summary>
    private static ActionOutcome TerminateVerified(ProcessRecord p, out string detail)
    {
        detail = "";
        IntPtr h = Native.OpenProcess(PROCESS_TERMINATE_SYNCHRONIZE, false, p.Pid);
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == ErrorInvalidParameter) { detail = "already gone"; return ActionOutcome.Performed; }
            if (err == ErrorAccessDenied) { detail = "access denied — protected process"; return ActionOutcome.RefusedByOs; }
            detail = $"could not open (error {err})";
            return ActionOutcome.Failed;
        }

        try
        {
            // Re-validate identity on the handle we are about to terminate through. This is the
            // last possible moment a recycled PID could be caught.
            if (Native.GetProcessTimes(h, out long creation, out long exit, out _, out _))
            {
                if (exit != 0) { detail = "already exited"; return ActionOutcome.Performed; }
                DateTime live;
                try { live = DateTime.FromFileTimeUtc(creation); } catch { live = default; }
                if (live != default && p.StartTimeUtc != default &&
                    Math.Abs((live - p.StartTimeUtc).TotalMilliseconds) > 50)
                {
                    detail = "PID was recycled onto a different process between selection and action — not terminated";
                    return ActionOutcome.Failed;
                }
            }

            if (!Native.TerminateProcess(h, 1))
            {
                int err = Marshal.GetLastWin32Error();
                if (err == ErrorInvalidHandle) { detail = "exited during the call"; return ActionOutcome.Performed; }
                if (err == ErrorAccessDenied) { detail = "access denied — protected process"; return ActionOutcome.RefusedByOs; }
                detail = $"terminate failed (error {err})";
                return ActionOutcome.Failed;
            }

            uint wait = WaitForSingleObject(h, 5000);
            if (wait == WAIT_OBJECT_0) return ActionOutcome.Performed;
            detail = "terminate was accepted but the process had not exited five seconds later";
            return ActionOutcome.Failed;
        }
        finally { Native.CloseHandle(h); }
    }

    private void ResumeAll(IEnumerable<int> pids)
    {
        foreach (int pid in pids)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_SUSPEND_RESUME, false, pid);
            if (h == IntPtr.Zero) continue;
            try { Native.NtResumeProcess(h); } finally { Native.CloseHandle(h); }
            AppendJournal(SuspendJournalPath, new { op = "resume", pid, utc = DateTime.UtcNow });
        }
    }

    /// <summary>
    /// Breadth-first walk from the root, discarding any parent-child edge whose child started
    /// before its claimed parent — that edge means the parent PID has been recycled and the child
    /// belongs to something else entirely.
    /// </summary>
    private List<ProcessRecord> BuildValidatedTree(ProcessRecord root, Snapshot? snapshot, out string note)
    {
        note = "";
        List<ProcessRecord> all;
        try { all = snapshot?.Processes.ToList() ?? ProcessProbe.Snapshot(false); }
        catch { all = new List<ProcessRecord> { root }; }

        var byParent = new Dictionary<int, List<ProcessRecord>>();
        foreach (var p in all)
        {
            if (!byParent.TryGetValue(p.ParentPid, out var list))
                byParent[p.ParentPid] = list = new List<ProcessRecord>();
            list.Add(p);
        }

        var ordered = new List<ProcessRecord> { root };
        var seen = new HashSet<int> { root.Pid };
        var queue = new Queue<ProcessRecord>();
        queue.Enqueue(root);
        int discarded = 0;

        while (queue.Count > 0 && ordered.Count < MaxTreeSize + 1)
        {
            var parent = queue.Dequeue();
            if (!byParent.TryGetValue(parent.Pid, out var children)) continue;

            foreach (var child in children)
            {
                if (!seen.Add(child.Pid)) continue;

                if (child.StartTimeUtc == default || parent.StartTimeUtc == default ||
                    child.StartTimeUtc < parent.StartTimeUtc)
                {
                    discarded++;
                    continue;
                }

                ordered.Add(child);
                queue.Enqueue(child);
            }
        }

        if (discarded > 0)
            note = $"{discarded} claimed child process{(discarded == 1 ? " was" : "es were")} discarded because its start time proves the parent PID had been recycled.";
        return ordered;
    }

    // =====================================================================
    //  Rung 5 — quarantine
    // =====================================================================

    /// <summary>
    /// Moves a file into the vault. Reversible, and the vault already handles the two cases that
    /// matter most — antivirus holding every handle to the file, and restoring metadata on the
    /// way back — so nothing here reimplements it.
    /// </summary>
    internal ResponseResult Quarantine(string path, string incidentId, string reason,
                                       bool userInitiated, bool autonomous = false)
    {
        string actionId = NewId("act");
        string target = string.IsNullOrEmpty(path) ? "(no path)" : Path.GetFileName(path);
        bool describeOnly = DryRun || !Authorised(userInitiated, autonomous);

        var protection = _protected.ClassifyPath(path);
        if (protection.BlocksEverything || (!userInitiated && protection.BlocksAutonomy))
            return RecordRefusal(ResponseRung.Quarantine, actionId, incidentId, target, protection, autonomous);

        if (!File.Exists(path))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Quarantine, Outcome = ActionOutcome.NotApplicable,
                Message = $"{path} is no longer there.", ActionId = actionId,
                IncidentId = incidentId, Target = target,
            });

        // Vault-full policy: refuse, never evict. Evicting the oldest entry would silently destroy
        // the user's only copy of an earlier false positive.
        if (!VaultHasRoom(path, out string quotaWhy))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Quarantine, Outcome = ActionOutcome.Failed,
                Message = quotaWhy + " HERO will not delete an older quarantined file to make room — that could be the only copy of something you wanted back.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        if (autonomous && !_breaker.TryConsume(ResponseRung.Quarantine, target, out string refusal))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Quarantine, Outcome = ActionOutcome.RefusedCircuitBreaker,
                Message = refusal, ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        string snapshotPath = WriteForensicSnapshot(incidentId, null, null, Array.Empty<ProcessRecord>(), null, "quarantine");

        var undo = new UndoRecord
        {
            ActionId = actionId, IncidentId = incidentId, CapturedUtc = DateTime.UtcNow,
            Kind = "quarantine", Description = $"Quarantine {path}",
            TargetKey = path, Reason = reason,
        };
        string undoPath = WriteUndoRecord(undo);

        if (describeOnly)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Quarantine,
                Outcome = DryRun ? ActionOutcome.DryRun : ActionOutcome.RefusedGate,
                Message = (DryRun ? "" : "Waiting for you. ") +
                    $"Would move {path} into the vault, where it cannot run, and keep a manifest complete enough to put it back byte-for-byte.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
            });

        var auth = ActionAuthorisation.Mint(ResponseRung.Quarantine, incidentId, actionId, userInitiated,
                                            snapshotPath, undoPath, false, reason, out string mintRefusal);
        if (auth is null)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Quarantine, Outcome = ActionOutcome.Failed, Message = mintRefusal,
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        var vaulted = _vault.Quarantine(path, reason);
        if (!vaulted.Success)
        {
            string message = vaulted.Message;
            if (IsControlledFolderPath(path))
                message += " Windows Defender's Controlled Folder Access is switched on and guards Desktop, Documents, Pictures, Videos, Music and Favourites. A quarantine is a move, and the move's first half is a delete from that folder, so Defender blocks it — that is Defender working correctly, not a HERO fault. To let HERO work there, add it under Windows Security > Virus & threat protection > Ransomware protection > Allow an app through Controlled folder access.";

            return Record(new ResponseResult
            {
                Rung = ResponseRung.Quarantine, Outcome = ActionOutcome.Failed, Message = message,
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
            });
        }

        undo.QuarantineId = vaulted.Manifest?.Id ?? "";
        undo.State = "committed";
        WriteUndoRecord(undo);

        return Record(new ResponseResult
        {
            Rung = ResponseRung.Quarantine, Outcome = ActionOutcome.Performed,
            Message = $"Moved {target} to the vault. {vaulted.Message} Nothing was deleted — one click puts it back exactly as it was.",
            ActionId = actionId, IncidentId = incidentId, Target = target,
            UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
        });
    }

    private bool VaultHasRoom(string sourcePath, out string why)
    {
        why = "";
        try
        {
            long incoming = new FileInfo(sourcePath).Length;
            long used = 0;
            if (Directory.Exists(HeroPaths.VaultDir))
                foreach (var f in Directory.EnumerateFiles(HeroPaths.VaultDir))
                {
                    try { used += new FileInfo(f).Length; } catch { }
                }

            if (used + incoming > VaultQuotaBytes)
            {
                why = $"The quarantine vault would exceed its {VaultQuotaBytes / (1024 * 1024 * 1024)} GB limit.";
                return false;
            }

            var drive = new DriveInfo(Path.GetPathRoot(HeroPaths.VaultDir) ?? "C:\\");
            if (drive.IsReady && incoming > drive.AvailableFreeSpace / 4)
            {
                why = "Quarantining this file would use more than a quarter of the free space on the vault's drive.";
                return false;
            }
            return true;
        }
        catch
        {
            // Fail-safe direction: if HERO cannot tell whether there is room, it does not move the
            // file. A half-copied quarantine is worse than a file left in place.
            why = "HERO could not confirm there is room in the vault.";
            return false;
        }
    }

    /// <summary>The six folders Controlled Folder Access guards. Verified enabled on this machine.</summary>
    private static bool IsControlledFolderPath(string path)
    {
        var guarded = new[]
        {
            Environment.SpecialFolder.Desktop, Environment.SpecialFolder.MyDocuments,
            Environment.SpecialFolder.MyPictures, Environment.SpecialFolder.MyVideos,
            Environment.SpecialFolder.MyMusic, Environment.SpecialFolder.Favorites,
        };
        string canonical = ProtectedSet.Canonicalise(path);
        foreach (var f in guarded)
        {
            string dir;
            try { dir = Environment.GetFolderPath(f); } catch { continue; }
            if (ProtectedSet.Under(canonical, dir)) return true;
        }
        return false;
    }

    // =====================================================================
    //  Rung 6 — persistence removal
    // =====================================================================

    /// <summary>
    /// Removes or disables one autorun, having first captured an undo record complete enough to
    /// recreate it exactly.
    ///
    /// The reversible operation is always preferred over the destructive one: a scheduled task is
    /// disabled rather than deleted, and a Winlogon value is repaired rather than removed. This
    /// rung is never autonomous by default on this machine, because System Restore has zero
    /// restore points with VSS and sppsvc stopped — there is no OS-level rollback behind it, so
    /// the undo record is the only safety net and the user should know before it is used.
    /// </summary>
    internal ResponseResult RemovePersistence(PersistenceEntry entry, string incidentId, string reason,
                                              bool userInitiated, bool autonomous = false)
    {
        string actionId = NewId("act");
        string target = $"{entry.Category}: {entry.Name}";

        var protection = _protected.Classify(entry);
        if (protection.BlocksEverything || (!userInitiated && protection.BlocksAutonomy))
            return RecordRefusal(ResponseRung.RemovePersistence, actionId, incidentId, target, protection, autonomous);

        if (autonomous && !AllowAutonomousPersistenceRemoval)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.RefusedGate,
                Message = "HERO does not remove startup entries on its own. System Restore on this machine has no restore points and its supporting services are stopped, so there is no operating-system rollback behind this change — only HERO's own undo record. That is worth a confirmation.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        if (autonomous && !_breaker.TryConsume(ResponseRung.RemovePersistence, target, out string refusal))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.RefusedCircuitBreaker,
                Message = refusal, ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        return entry.Category switch
        {
            PersistenceCategory.StartupFolder =>
                // A .lnk is just a file, so it routes through the vault wholesale. That gives
                // byte-identical restore for free, including the shortcut's link-tracker data,
                // which reconstructing from parsed properties would silently lose.
                Quarantine(entry.Target, incidentId, reason, userInitiated, autonomous),

            PersistenceCategory.ScheduledTask =>
                RemoveScheduledTask(entry, actionId, incidentId, reason, userInitiated, autonomous),

            PersistenceCategory.Service =>
                CaptureServiceOnly(entry, actionId, incidentId, reason, autonomous),

            _ => RemoveRegistryValue(entry, actionId, incidentId, reason, userInitiated, autonomous),
        };
    }

    // ------------------------------------------------------- registry values

    private ResponseResult RemoveRegistryValue(PersistenceEntry entry, string actionId, string incidentId,
                                               string reason, bool userInitiated, bool autonomous)
    {
        string target = $"{entry.Location}\\{entry.Name}";
        bool describeOnly = DryRun || !Authorised(userInitiated, autonomous);

        if (!TryParseRegistryLocation(entry.Location, out IntPtr hive, out string hiveName,
                                      out string subKey, out bool wow32))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.Failed,
                Message = $"HERO could not work out which registry key \"{entry.Location}\" refers to, so it will not touch it.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        if (!TryReadRawValue(hive, subKey, entry.Name, wow32, out uint kind, out byte[] data, out int readErr))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence,
                Outcome = readErr == ErrorAccessDenied ? ActionOutcome.RefusedNeedsElevation : ActionOutcome.Failed,
                Message = readErr == ErrorAccessDenied
                    ? $"Reading {target} needs administrator rights. Without the original bytes there is no undo record, and without an undo record HERO does not act."
                    : $"HERO could not read the current value of {target} (error {readErr}), so it cannot guarantee it could put it back.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        var registryUndo = new RegistryUndo
        {
            Hive = hiveName, SubKey = subKey, ValueName = entry.Name,
            ValueKind = kind, ValueBase64 = Convert.ToBase64String(data), Wow6432 = wow32,
        };

        // The StartupApproved companion carries this entry's Task Manager enabled/disabled state.
        // Putting the Run value back without it produces a subtly different startup state.
        if (subKey.EndsWith(@"CurrentVersion\Run", StringComparison.OrdinalIgnoreCase))
        {
            const string approved = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
            if (TryReadRawValue(hive, approved, entry.Name, false, out uint aKind, out byte[] aData, out _))
            {
                registryUndo.StartupApprovedSubKey = approved;
                registryUndo.StartupApprovedKind = aKind;
                registryUndo.StartupApprovedBase64 = Convert.ToBase64String(aData);
            }
        }

        var undo = new UndoRecord
        {
            ActionId = actionId, IncidentId = incidentId, CapturedUtc = DateTime.UtcNow,
            Kind = "registry-value", Description = $"Remove {target}",
            TargetKey = target, Reason = reason, Registry = registryUndo,
        };
        string undoPath = WriteUndoRecord(undo);

        string snapshotPath = WriteForensicSnapshot(incidentId, null, null, Array.Empty<ProcessRecord>(), null, "remove-persistence");

        if (describeOnly)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence,
                Outcome = DryRun ? ActionOutcome.DryRun : ActionOutcome.RefusedGate,
                Message = (DryRun ? "" : "Waiting for you. ") +
                    $"Would delete {target} (currently \"{entry.Target}\"), after saving its exact raw value so it can be recreated byte-for-byte.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
            });

        // userInitiated, not !autonomous. "Not autonomous" does not mean "the user asked" — it also
        // covers the plan-only path, and asserting the user's consent on their behalf is the one
        // claim this token must never make.
        var auth = ActionAuthorisation.Mint(ResponseRung.RemovePersistence, incidentId, actionId, userInitiated,
                                            snapshotPath, undoPath, false, reason, out string mintRefusal);
        if (auth is null)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.Failed, Message = mintRefusal,
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        int err = DeleteValue(hive, subKey, entry.Name, wow32);
        if (err != 0)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence,
                Outcome = err == ErrorAccessDenied ? ActionOutcome.RefusedNeedsElevation : ActionOutcome.Failed,
                Message = err == ErrorAccessDenied
                    ? $"Deleting {target} needs administrator rights. HERO has saved the undo record; run it again from an elevated session, or use the command below."
                    : $"Could not delete {target} (error {err}).",
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
                Details = new[] { $"reg delete \"{hiveName}\\{subKey}\" /v \"{entry.Name}\" /f" },
            });

        // Remove the StartupApproved companion too, otherwise a stale entry lingers there.
        if (registryUndo.StartupApprovedSubKey.Length > 0)
            DeleteValue(hive, registryUndo.StartupApprovedSubKey, entry.Name, false);

        undo.State = "committed";
        WriteUndoRecord(undo);

        return Record(new ResponseResult
        {
            Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.Performed,
            Message = $"Removed the startup entry {entry.Name}. It will not run at logon any more, and HERO kept its exact original value so you can put it back.",
            ActionId = actionId, IncidentId = incidentId, Target = target,
            UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
        });
    }

    // ------------------------------------------------------ scheduled tasks

    private ResponseResult RemoveScheduledTask(PersistenceEntry entry, string actionId, string incidentId,
                                               string reason, bool userInitiated, bool autonomous)
    {
        string target = entry.Name;
        bool describeOnly = DryRun || !Authorised(userInitiated, autonomous);

        // The complete definition, which round-trips exactly through schtasks /create /xml.
        string xml = RunCapture("schtasks.exe", $"/query /tn \"{entry.Name}\" /xml ONE", out int queryExit);
        bool haveXml = queryExit == 0 && xml.Contains("<Task", StringComparison.OrdinalIgnoreCase);

        // A task registered with a stored password or S4U cannot be recreated from its XML without
        // that password, so a delete-then-restore silently produces a task that never runs again.
        bool storedCredential = haveXml &&
            (xml.Contains("<LogonType>Password</LogonType>", StringComparison.OrdinalIgnoreCase) ||
             xml.Contains("<LogonType>S4U</LogonType>", StringComparison.OrdinalIgnoreCase) ||
             xml.Contains("InteractiveTokenOrPassword", StringComparison.OrdinalIgnoreCase));

        var undo = new UndoRecord
        {
            ActionId = actionId, IncidentId = incidentId, CapturedUtc = DateTime.UtcNow,
            Kind = "scheduled-task", Description = $"Disable scheduled task {entry.Name}",
            TargetKey = entry.Name, Reason = reason,
            Complete = haveXml && !storedCredential,
            Incomplete = !haveXml
                ? "The task definition could not be exported, so HERO cannot promise to recreate it."
                : storedCredential
                    ? "This task runs with a stored password. Windows does not hand that password back, so a deleted task cannot be fully restored — only disabled and re-enabled."
                    : "",
            Task = new TaskUndo
            {
                TaskName = entry.Name, Xml = haveXml ? xml : "",
                WasEnabled = entry.Enabled, RequiresStoredCredential = storedCredential,
                Operation = "disable",
            },
        };
        string undoPath = WriteUndoRecord(undo);
        string snapshotPath = WriteForensicSnapshot(incidentId, null, null, Array.Empty<ProcessRecord>(), null, "remove-persistence");

        if (describeOnly)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence,
                Outcome = DryRun ? ActionOutcome.DryRun : ActionOutcome.RefusedGate,
                Message = (DryRun ? "" : "Waiting for you. ") +
                          $"Would DISABLE the scheduled task {entry.Name} rather than delete it — disabling is completely reversible and stops it running just as effectively." +
                          (storedCredential ? " Note this task runs with a stored password, so deleting it could never be fully undone." : ""),
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
                Details = new[] { $"schtasks /change /tn \"{entry.Name}\" /disable" },
            });

        if (!haveXml)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.Failed,
                Message = $"HERO could not export the definition of {entry.Name}, so it has no way to put it back and will not change it.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath,
            });

        var auth = ActionAuthorisation.Mint(ResponseRung.RemovePersistence, incidentId, actionId, userInitiated,
                                            snapshotPath, undoPath, false, reason, out string mintRefusal);
        if (auth is null)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.Failed, Message = mintRefusal,
                ActionId = actionId, IncidentId = incidentId, Target = target,
            });

        RunCapture("schtasks.exe", $"/change /tn \"{entry.Name}\" /disable", out int exit);
        if (exit != 0)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence,
                Outcome = ActionOutcome.RefusedNeedsElevation,
                Message = $"Disabling {entry.Name} did not succeed (schtasks exit code {exit}). Tasks in the root folder and machine-scope tasks need administrator rights.",
                ActionId = actionId, IncidentId = incidentId, Target = target,
                UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
                Details = new[] { $"schtasks /change /tn \"{entry.Name}\" /disable" },
            });

        undo.State = "committed";
        WriteUndoRecord(undo);

        return Record(new ResponseResult
        {
            Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.Performed,
            Message = $"Disabled the scheduled task {entry.Name}. It still exists and is unchanged otherwise, so re-enabling it is a single click.",
            ActionId = actionId, IncidentId = incidentId, Target = target,
            UndoRecordPath = undoPath, ForensicSnapshotPath = snapshotPath, Autonomous = autonomous,
        });
    }

    // ------------------------------------------------------------- services

    /// <summary>
    /// Captures a service's full configuration and then stops.
    ///
    /// Service create/delete/config is administrator-only in every case, and the undo surface is
    /// the largest of any persistence class — a dozen config fields, a registry subtree, and a
    /// security descriptor, all of which must round-trip or the restored service exists but
    /// misbehaves. HERO captures what it can read unelevated and hands the user an exact command
    /// rather than pretending it did something.
    /// </summary>
    private ResponseResult CaptureServiceOnly(PersistenceEntry entry, string actionId, string incidentId,
                                              string reason, bool autonomous)
    {
        string target = $"Service: {entry.Name}";
        string keyPath = $@"System\CurrentControlSet\Services\{entry.Name}";

        var serviceUndo = new ServiceUndo { ServiceName = entry.Name, RegistryPath = $@"HKLM\{keyPath}" };
        bool captured = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key is not null)
            {
                foreach (var name in key.GetValueNames())
                {
                    if (TryReadRawValue(HKEY_LOCAL_MACHINE, keyPath, name, false, out uint k, out byte[] d, out _))
                        serviceUndo.Values[name] = $"{k}:{Convert.ToBase64String(d)}";
                }
                // The real payload of a svchost-hosted service is ServiceDll under Parameters,
                // not ImagePath. Capturing only the service config would lose the reference.
                using var parameters = key.OpenSubKey("Parameters");
                if (parameters is not null)
                {
                    foreach (var name in parameters.GetValueNames())
                    {
                        if (TryReadRawValue(HKEY_LOCAL_MACHINE, keyPath + @"\Parameters", name, false,
                                            out uint k, out byte[] d, out _))
                            serviceUndo.ParameterValues[name] = $"{k}:{Convert.ToBase64String(d)}";
                    }
                }
                captured = true;
            }
        }
        catch { }

        var undo = new UndoRecord
        {
            ActionId = actionId, IncidentId = incidentId, CapturedUtc = DateTime.UtcNow,
            Kind = "service-config", Description = $"Disable service {entry.Name}",
            TargetKey = entry.Name, Reason = reason, Service = serviceUndo,
            Complete = false,
            Incomplete = "Service security descriptors, failure actions and trigger configuration cannot be read without administrator rights, so this record can restore the service's registry state but not every field of its configuration.",
            State = captured ? "captured" : "incomplete",
        };
        string undoPath = WriteUndoRecord(undo);

        return Record(new ResponseResult
        {
            Rung = ResponseRung.RemovePersistence,
            Outcome = DryRun ? ActionOutcome.DryRun : ActionOutcome.RefusedNeedsElevation,
            Message = DryRun
                ? $"Would DISABLE the service {entry.Name} rather than delete it, which needs administrator rights. HERO has saved everything it can read of the service's configuration first."
                : $"Changing the service {entry.Name} needs administrator rights, which HERO does not have. Its configuration has been saved so the change can be undone; run the command below from an elevated terminal to disable it.",
            ActionId = actionId, IncidentId = incidentId, Target = target,
            UndoRecordPath = undoPath, Autonomous = autonomous,
            Details = new[]
            {
                $"sc.exe config \"{entry.Name}\" start= disabled",
                $"sc.exe stop \"{entry.Name}\"",
            },
        });
    }

    // =====================================================================
    //  Undo
    // =====================================================================

    /// <summary>
    /// Reverses one previously recorded action. Every undo is itself ledgered as a new entry, so
    /// the history is appended to and never rewritten.
    /// </summary>
    internal ResponseResult Undo(string actionId)
    {
        // The id names a file, and it arrives over a pipe that any interactive user may open,
        // into a service running as LocalSystem. Path.Combine discards UndoDir entirely if this
        // string is rooted, so an unchecked id is that user handing SYSTEM an arbitrary JSON
        // document to deserialise — and an UndoRecord chooses its own effect: writing an HKLM
        // value, creating a scheduled task, or moving a file back out of the vault.
        if (!HeroPaths.IsSafeStateId(actionId))
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Observe, Outcome = ActionOutcome.Failed,
                Message = "That is not a valid action id.", ActionId = "",
            });

        string path = Path.Combine(HeroPaths.UndoDir, actionId + ".json");
        UndoRecord? undo = null;
        try
        {
            if (File.Exists(path)) undo = JsonSerializer.Deserialize<UndoRecord>(File.ReadAllText(path), Json);
        }
        catch { }

        if (undo is null)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Observe, Outcome = ActionOutcome.Failed,
                Message = $"There is no undo record for {actionId}.", ActionId = actionId,
            });

        string newId = NewId("undo");

        if (DryRun)
            return Record(new ResponseResult
            {
                Rung = ResponseRung.Observe, Outcome = ActionOutcome.DryRun,
                Message = $"Would reverse: {undo.Description}.",
                ActionId = newId, IncidentId = undo.IncidentId, Target = undo.TargetKey,
            });

        ResponseResult result = undo.Kind switch
        {
            "suspend" => Resume(undo.Suspend?.Pid ?? 0),
            "registry-value" => UndoRegistry(undo, newId),
            "scheduled-task" => UndoTask(undo, newId),
            "quarantine" => UndoQuarantine(undo, newId),
            "firewall-rule" => RemoveFirewallRule(undo.Firewall?.DisplayName ?? ""),
            "service-config" => new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.RefusedNeedsElevation,
                Message = $"Restoring the service {undo.Service?.ServiceName} needs administrator rights. Its saved configuration is in {path}.",
                ActionId = newId, IncidentId = undo.IncidentId, Target = undo.TargetKey,
            },
            _ => new ResponseResult
            {
                Rung = ResponseRung.Observe, Outcome = ActionOutcome.Failed,
                Message = $"HERO does not know how to reverse a \"{undo.Kind}\" action.",
                ActionId = newId, IncidentId = undo.IncidentId, Target = undo.TargetKey,
            },
        };

        if (result.Acted)
        {
            undo.State = "undone";
            WriteUndoRecord(undo);
        }
        return result;
    }

    private ResponseResult UndoRegistry(UndoRecord undo, string actionId)
    {
        var r = undo.Registry;
        if (r is null)
            return new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.Failed,
                Message = "The undo record has no registry data in it.", ActionId = actionId,
            };

        IntPtr hive = r.Hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase)
            ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
        byte[] data = Convert.FromBase64String(r.ValueBase64);

        int err = WriteRawValue(hive, r.SubKey, r.ValueName, r.ValueKind, data, r.Wow6432);
        if (err == 0 && r.StartupApprovedBase64.Length > 0)
            WriteRawValue(hive, r.StartupApprovedSubKey, r.ValueName, r.StartupApprovedKind,
                          Convert.FromBase64String(r.StartupApprovedBase64), false);

        return Record(new ResponseResult
        {
            Rung = ResponseRung.RemovePersistence,
            Outcome = err == 0 ? ActionOutcome.Performed
                    : err == ErrorAccessDenied ? ActionOutcome.RefusedNeedsElevation : ActionOutcome.Failed,
            Message = err == 0
                ? $"Put {r.Hive}\\{r.SubKey}\\{r.ValueName} back exactly as it was, including its original value type."
                : err == ErrorAccessDenied
                    ? $"Restoring {r.Hive}\\{r.SubKey}\\{r.ValueName} needs administrator rights."
                    : $"Could not restore {r.ValueName} (error {err}).",
            ActionId = actionId, IncidentId = undo.IncidentId, Target = undo.TargetKey,
        });
    }

    private ResponseResult UndoTask(UndoRecord undo, string actionId)
    {
        var t = undo.Task;
        if (t is null)
            return new ResponseResult
            {
                Rung = ResponseRung.RemovePersistence, Outcome = ActionOutcome.Failed,
                Message = "The undo record has no task data in it.", ActionId = actionId,
            };

        int exit;
        if (t.Operation == "disable")
        {
            RunCapture("schtasks.exe", $"/change /tn \"{t.TaskName}\" /enable", out exit);
        }
        else
        {
            string tmp = Path.Combine(HeroPaths.UndoDir, actionId + ".task.xml");
            File.WriteAllText(tmp, t.Xml, Encoding.Unicode);
            RunCapture("schtasks.exe", $"/create /tn \"{t.TaskName}\" /xml \"{tmp}\" /f", out exit);
        }

        return Record(new ResponseResult
        {
            Rung = ResponseRung.RemovePersistence,
            Outcome = exit == 0 ? ActionOutcome.Performed : ActionOutcome.Failed,
            Message = exit == 0
                ? $"Re-enabled the scheduled task {t.TaskName}."
                : $"Could not restore {t.TaskName} (schtasks exit code {exit})." +
                  (t.RequiresStoredCredential ? " This task runs with a stored password, which Windows never hands back, so it has to be re-created by hand." : ""),
            ActionId = actionId, IncidentId = undo.IncidentId, Target = undo.TargetKey,
        });
    }

    private ResponseResult UndoQuarantine(UndoRecord undo, string actionId)
    {
        if (string.IsNullOrEmpty(undo.QuarantineId))
            return new ResponseResult
            {
                Rung = ResponseRung.Quarantine, Outcome = ActionOutcome.Failed,
                Message = "The undo record does not name a vault entry.", ActionId = actionId,
            };

        var restored = _vault.Restore(undo.QuarantineId);
        return Record(new ResponseResult
        {
            Rung = ResponseRung.Quarantine,
            Outcome = restored.Success ? ActionOutcome.Performed : ActionOutcome.Failed,
            Message = restored.Message, ActionId = actionId,
            IncidentId = undo.IncidentId, Target = undo.TargetKey,
        });
    }

    // =====================================================================
    //  Startup reconciliation
    // =====================================================================

    /// <summary>
    /// Puts the machine back to a coherent state after HERO restarts.
    ///
    /// A suspension that outlived the process which created it has no adjudication path left, so
    /// it is resumed rather than left frozen. A HERO that is killed — the first thing a RAT would
    /// attempt — must not leave the user's applications frozen forever with nothing on disk to
    /// explain it.
    /// </summary>
    internal ResponseResult ReconcileOnStart()
    {
        var resumed = new List<string>();
        try
        {
            if (File.Exists(SuspendJournalPath))
            {
                var outstanding = new Dictionary<int, string>();
                foreach (var line in File.ReadLines(SuspendJournalPath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        var root = doc.RootElement;
                        if (!root.TryGetProperty("op", out var op)) continue;
                        if (!root.TryGetProperty("pid", out var pidEl)) continue;
                        int pid = pidEl.GetInt32();
                        if (op.GetString() == "suspend")
                            outstanding[pid] = root.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                        else
                            outstanding.Remove(pid);
                    }
                    catch { /* one malformed line must not abort reconciliation */ }
                }

                foreach (var (pid, name) in outstanding)
                {
                    IntPtr h = Native.OpenProcess(Native.PROCESS_SUSPEND_RESUME, false, pid);
                    if (h == IntPtr.Zero) continue;
                    try { if (Native.NtResumeProcess(h) == 0) resumed.Add($"PID {pid} {name}"); }
                    finally { Native.CloseHandle(h); }
                    AppendJournal(SuspendJournalPath, new { op = "resume", pid, utc = DateTime.UtcNow, note = "startup reconciliation" });
                }
            }
        }
        catch { }

        ReapExpiredFirewallRules();

        return Record(new ResponseResult
        {
            Rung = ResponseRung.Observe, Outcome = ActionOutcome.Performed,
            Message = resumed.Count == 0
                ? "Nothing was left frozen or blocked from a previous session."
                : $"Thawed {resumed.Count} process{(resumed.Count == 1 ? "" : "es")} left frozen when HERO last stopped, and swept any expired firewall blocks.",
            Details = resumed, ActionId = NewId("act"),
        });
    }

    // =====================================================================
    //  Forensic snapshot
    // =====================================================================

    private sealed class ForensicRecord
    {
        public string IncidentId { get; set; } = "";
        public string Trigger { get; set; } = "";
        public DateTime CapturedUtc { get; set; }
        public bool DryRun { get; set; }
        public bool Elevated { get; set; }
        public string HeroVersion { get; set; } = "1.0.0";
        public string? VerdictSummary { get; set; }
        public double Score { get; set; }
        public string Confidence { get; set; } = "";
        public List<ForensicSignal> Signals { get; set; } = new();
        public List<ForensicProcess> Processes { get; set; } = new();
        public List<ForensicConnection> Connections { get; set; } = new();
        public List<string> CaptureNotes { get; set; } = new();
    }

    private sealed class ForensicSignal
    {
        public string RuleId { get; set; } = "";
        public string Title { get; set; } = "";
        public string Explanation { get; set; } = "";
        public string Family { get; set; } = "";
        public double Weight { get; set; }
        public string Severity { get; set; } = "";
        public string Evidence { get; set; } = "";
    }

    private sealed class ForensicProcess
    {
        public int Pid { get; set; }
        public int ParentPid { get; set; }
        public string Name { get; set; } = "";
        public string ImagePath { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public DateTime StartTimeUtc { get; set; }
        public string Integrity { get; set; } = "";
        public int ThreadCount { get; set; }
        public string Role { get; set; } = "";
        public List<string> LoadedModules { get; set; } = new();
        /// <summary>Null, with a note, when the command line could not be read — distinguishable from an empty one.</summary>
        public string? CommandLineCaptureFailed { get; set; }
    }

    private sealed class ForensicConnection
    {
        public int Pid { get; set; }
        public string Protocol { get; set; } = "";
        public string Local { get; set; } = "";
        public string Remote { get; set; } = "";
        public string State { get; set; } = "";
        public bool External { get; set; }
    }

    /// <summary>
    /// Writes everything HERO knew, before it changes anything.
    ///
    /// This serves two purposes and the second is the more important one: it lets the user contest
    /// a false positive after the fact, and it makes the detection reviewable so scoring bugs get
    /// found instead of accumulating.
    ///
    /// Collection runs on a time budget. Module enumeration on a hostile process is a documented
    /// hang, so it happens on a worker thread that is abandoned on timeout rather than waited on —
    /// snapshot collection must never be able to block the containment path at the moment it
    /// matters. No memory dump is taken: a full-memory dump of the user's own applications would
    /// contain browser cookies, password-manager memory and SSH keys in plaintext, and that is an
    /// opt-in the user makes per incident, not a default.
    /// </summary>
    private string WriteForensicSnapshot(string incidentId, Verdict? verdict, ProcessRecord? target,
                                         IReadOnlyList<ProcessRecord> tree, Snapshot? snapshot, string trigger)
    {
        try
        {
            string dir = Path.Combine(HeroPaths.EventsDir, incidentId);
            Directory.CreateDirectory(dir);

            // Before a single byte is written into it. What goes in here is the target's full
            // command line and process ancestry, which is the most sensitive thing HERO records,
            // and the directory would otherwise inherit the state root's read grant to Users.
            HeroPaths.ProtectIncidentDirectory(dir);
            string file = Path.Combine(dir, $"snapshot-{trigger}-{DateTime.UtcNow:HHmmssfff}.json");

            var record = new ForensicRecord
            {
                IncidentId = incidentId,
                Trigger = trigger,
                CapturedUtc = DateTime.UtcNow,
                DryRun = DryRun,
                Elevated = IsElevated(),
                VerdictSummary = verdict?.Headline?.Title,
                Score = verdict?.Score ?? 0,
                Confidence = verdict?.Confidence.ToString() ?? "",
            };

            if (verdict is not null)
                foreach (var s in verdict.Signals)
                    record.Signals.Add(new ForensicSignal
                    {
                        RuleId = s.RuleId, Title = s.Title, Explanation = s.Explanation,
                        Family = s.Family, Weight = s.Weight, Severity = s.Severity.ToString(),
                        Evidence = s.Evidence,
                    });

            var wanted = new List<(ProcessRecord Record, string Role)>();
            if (target is not null) wanted.Add((target, "target"));
            foreach (var m in tree)
                if (target is null || m.Pid != target.Pid) wanted.Add((m, "tree"));
            if (snapshot is not null && target is not null)
                foreach (var a in snapshot.Ancestry(target))
                    wanted.Add((a, "ancestor"));

            int moduleBudget = 8;
            foreach (var (p, role) in wanted.DistinctBy(w => w.Record.Pid))
            {
                var fp = new ForensicProcess
                {
                    Pid = p.Pid, ParentPid = p.ParentPid, Name = p.Name, ImagePath = p.ImagePath,
                    CommandLine = p.CommandLine, StartTimeUtc = p.StartTimeUtc,
                    Integrity = p.Integrity.ToString(), ThreadCount = p.ThreadCount, Role = role,
                };
                if (string.IsNullOrEmpty(p.CommandLine))
                    fp.CommandLineCaptureFailed =
                        "Reading another user's or a higher-integrity process's command line needs administrator rights.";
                if (moduleBudget-- > 0) fp.LoadedModules = ModulesOf(p.Pid, 1500);
                record.Processes.Add(fp);
            }

            var pids = record.Processes.Select(p => p.Pid).ToHashSet();
            IReadOnlyList<Connection> connections = snapshot?.Connections ?? SafeConnections();
            foreach (var c in connections.Where(x => pids.Contains(x.Pid)))
                record.Connections.Add(new ForensicConnection
                {
                    Pid = c.Pid, Protocol = c.Protocol,
                    Local = $"{c.LocalAddress}:{c.LocalPort}",
                    Remote = c.RemoteAddress is null ? "" : $"{c.RemoteAddress}:{c.RemotePort}",
                    State = c.State.ToString(), External = c.IsExternal,
                });

            if (!record.Elevated)
                record.CaptureNotes.Add("HERO was not running as administrator, so command lines and image paths for higher-integrity processes are missing from this record.");

            // WriteThrough: the whole point is that this survives a crash between here and the
            // action it authorises.
            using (var fs = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.Read,
                                           4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(fs, record, Json);
                fs.Flush(true);
            }
            return file;
        }
        catch
        {
            // No snapshot means no authorisation can be minted, which means nothing destructive
            // runs. That is the fail-safe direction and needs no separate handling.
            return "";
        }
    }

    private static List<Connection> SafeConnections()
    {
        try { return NetworkProbe.Snapshot(); } catch { return new List<Connection>(); }
    }

    private static List<string> ModulesOf(int pid, int timeoutMs)
    {
        var task = System.Threading.Tasks.Task.Run(() =>
        {
            var list = new List<string>();
            try
            {
                using var p = Process.GetProcessById(pid);
                foreach (ProcessModule m in p.Modules)
                {
                    list.Add(m.FileName ?? m.ModuleName ?? "");
                    if (list.Count >= 200) break;
                }
            }
            catch (Exception ex) { list.Add($"(modules unavailable: {ex.GetType().Name})"); }
            return list;
        });

        // Wait on the task, not on the thread: on timeout the worker is abandoned and the
        // containment path continues. Blocking here would let a hostile process stall the response.
        return task.Wait(timeoutMs) ? task.Result : new List<string> { "(module enumeration timed out)" };
    }

    // =====================================================================
    //  Ledger, journals and undo storage
    // =====================================================================

    private static string LedgerPath => Path.Combine(HeroPaths.EventsDir, "ledger.jsonl");
    private static string SuspendJournalPath => Path.Combine(HeroPaths.UndoDir, "suspensions.jsonl");
    private static string FirewallJournalPath => Path.Combine(HeroPaths.UndoDir, "firewall.jsonl");

    private string _prevHash = "";

    /// <summary>
    /// Appends to the action ledger and raises the UI event.
    ///
    /// The chain is honest about what it is: it detects accidental corruption and truncation. It
    /// is NOT tamper-evidence against the adversary this product names, because the ledger is
    /// created by a medium-integrity process running as the user, whose owner retains WRITE_DAC —
    /// same-user malware can rewrite the file and recompute the chain. Claiming otherwise would be
    /// worse than not claiming it.
    /// </summary>
    private ResponseResult Record(ResponseResult result)
    {
        var entry = new ResponseLedgerEntry
        {
            ActionId = result.ActionId, IncidentId = result.IncidentId, Utc = DateTime.UtcNow,
            Rung = result.Rung.ToString(), Outcome = result.Outcome.ToString(),
            Target = result.Target, Message = result.Message, Autonomous = result.Autonomous,
            DryRun = DryRun, UndoRecordPath = result.UndoRecordPath,
            ForensicSnapshotPath = result.ForensicSnapshotPath,
        };

        try
        {
            lock (_ledgerLock)
            {
                entry.PrevHash = _prevHash;
                entry.Hash = Hash($"{entry.PrevHash}|{entry.ActionId}|{entry.Utc:O}|{entry.Rung}|{entry.Outcome}|{entry.Target}");
                _prevHash = entry.Hash;

                Directory.CreateDirectory(HeroPaths.EventsDir);
                File.AppendAllText(LedgerPath, JsonSerializer.Serialize(entry, JsonCompact) + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            // A failing ledger means HERO can no longer explain what it did, so autonomy stops.
            _breaker.Trip($"HERO could not write to its own action log ({ex.GetType().Name}), so it can no longer guarantee it can tell you what it has done.");
        }

        try { ActionRecorded?.Invoke(result); } catch { }
        return result;
    }

    private ResponseResult RecordRefusal(ResponseRung rung, string actionId, string incidentId,
                                         string target, ProtectionResult protection, bool autonomous)
    {
        var result = new ResponseResult
        {
            Rung = rung, Outcome = ActionOutcome.RefusedProtected,
            Message = protection.Reason, ActionId = actionId, IncidentId = incidentId,
            Target = target, Autonomous = autonomous,
        };

        // Reaching a protected-set refusal from an autonomous path means the scorer proposed
        // something it should have excluded. That is a defect, not routine.
        if (autonomous && protection.BlocksEverything)
        {
            try { ScoringDefectSuspected?.Invoke(result); } catch { }
            _breaker.Trip($"HERO was about to act automatically on something it must never touch ({target}). It has stopped acting automatically until you have looked at why.");
        }

        return Record(result);
    }

    private static string WriteUndoRecord(UndoRecord undo)
    {
        try
        {
            Directory.CreateDirectory(HeroPaths.UndoDir);
            string path = Path.Combine(HeroPaths.UndoDir, undo.ActionId + ".json");
            using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read,
                                          4096, FileOptions.WriteThrough);
            JsonSerializer.Serialize(fs, undo, Json);
            fs.Flush(true);
            return path;
        }
        catch { return ""; }
    }

    private static void AppendJournal(string path, object entry)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.AppendAllText(path, JsonSerializer.Serialize(entry, JsonCompact) + Environment.NewLine);
        }
        catch { }
    }

    private static string Hash(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

    private static string NewId(string prefix) =>
        $"{prefix}-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("n")[..6]}";

    // =====================================================================
    //  Process launching
    // =====================================================================

    internal static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>
    /// Runs a PowerShell command.
    ///
    /// The script is passed as -EncodedCommand so no amount of quoting in a path or a JSON
    /// description can break the command line or, worse, inject into it. windowspowershell (5.1)
    /// is used rather than pwsh because it is always present.
    /// </summary>
    private static bool RunPowerShell(string script, bool elevate, out string error)
    {
        error = "";
        try
        {
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}");

            if (elevate)
            {
                // Exactly one prompt, from an explicit user gesture. Never retried in a loop:
                // a tray app that repeatedly raises UAC teaches the user to click through it.
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WindowStyle = ProcessWindowStyle.Hidden;
            }
            else
            {
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
            }

            using var p = Process.Start(psi);
            if (p is null) { error = "PowerShell would not start."; return false; }

            if (!elevate) error = p.StandardError.ReadToEnd().Trim();
            if (!p.WaitForExit(30000)) { error = "PowerShell did not finish within 30 seconds."; return false; }
            if (p.ExitCode != 0 && error.Length == 0) error = $"exit code {p.ExitCode}";
            return p.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            error = "You declined the administrator prompt.";
            return false;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private static string RunCapture(string exe, string args, out int exitCode)
    {
        exitCode = -1;
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            using var p = Process.Start(psi);
            if (p is null) return "";
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(20000);
            exitCode = p.HasExited ? p.ExitCode : -1;
            return output;
        }
        catch { return ""; }
    }

    /// <summary>Single-quotes a string for PowerShell, doubling embedded single quotes.</summary>
    private static string PsQuote(string s) => "'" + s.Replace("'", "''") + "'";

    // =====================================================================
    //  Raw registry access
    // =====================================================================

    private static bool TryParseRegistryLocation(string location, out IntPtr hive, out string hiveName,
                                                 out string subKey, out bool wow32)
    {
        hive = IntPtr.Zero;
        hiveName = "";
        subKey = "";
        wow32 = location.Contains("(WOW64)", StringComparison.OrdinalIgnoreCase);

        string cleaned = location.Replace(" (WOW64)", "", StringComparison.OrdinalIgnoreCase).Trim();
        int slash = cleaned.IndexOf('\\');
        if (slash <= 0) return false;

        hiveName = cleaned[..slash];
        subKey = cleaned[(slash + 1)..];

        if (hiveName.Equals("HKCU", StringComparison.OrdinalIgnoreCase)) hive = HKEY_CURRENT_USER;
        else if (hiveName.Equals("HKLM", StringComparison.OrdinalIgnoreCase)) hive = HKEY_LOCAL_MACHINE;
        else return false;

        return subKey.Length > 0;
    }

    /// <summary>
    /// Reads a value as raw bytes plus its exact type.
    ///
    /// RegistryKey.GetValue cannot do this: even with DoNotExpandEnvironmentNames it returns a
    /// managed string for REG_SZ/REG_EXPAND_SZ and a string[] for REG_MULTI_SZ, so a value with an
    /// unusual terminator, embedded nulls or trailing bytes does not round-trip — and the whole
    /// claim of this undo record is that it does.
    /// </summary>
    private static bool TryReadRawValue(IntPtr hive, string subKey, string valueName, bool wow32,
                                        out uint kind, out byte[] data, out int error)
    {
        kind = 0;
        data = Array.Empty<byte>();
        uint sam = KEY_READ | (wow32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);

        error = RegOpenKeyExW(hive, subKey, 0, sam, out IntPtr key);
        if (error != 0) return false;

        try
        {
            uint size = 0;
            error = RegQueryValueExW(key, valueName, IntPtr.Zero, out kind, null, ref size);
            if (error != 0) return false;

            var buffer = new byte[size];
            error = RegQueryValueExW(key, valueName, IntPtr.Zero, out kind, buffer, ref size);
            if (error != 0) return false;

            data = size == buffer.Length ? buffer : buffer.AsSpan(0, (int)size).ToArray();
            return true;
        }
        finally { RegCloseKey(key); }
    }

    private static int WriteRawValue(IntPtr hive, string subKey, string valueName, uint kind,
                                     byte[] data, bool wow32)
    {
        uint sam = KEY_SET_VALUE | (wow32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);
        int err = RegOpenKeyExW(hive, subKey, 0, sam, out IntPtr key);
        if (err != 0) return err;
        try { return RegSetValueExW(key, valueName, 0, kind, data, (uint)data.Length); }
        finally { RegCloseKey(key); }
    }

    private static int DeleteValue(IntPtr hive, string subKey, string valueName, bool wow32)
    {
        uint sam = KEY_SET_VALUE | (wow32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);
        int err = RegOpenKeyExW(hive, subKey, 0, sam, out IntPtr key);
        if (err != 0) return err;
        try { return RegDeleteValueW(key, valueName); }
        finally { RegCloseKey(key); }
    }

    public void Dispose()
    {
        foreach (var t in _resumeTimers.Values) t.Dispose();
        _resumeTimers.Clear();
    }

    // =====================================================================
    //  P/Invoke — declared privately so they cannot collide with Hero.Interop.Native
    // =====================================================================

    private const int ErrorAccessDenied = 5;
    private const int ErrorInvalidHandle = 6;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorCancelled = 1223;   // the user dismissed the UAC prompt

    private const uint PROCESS_TERMINATE_SYNCHRONIZE = 0x0001 | 0x00100000;
    private const uint WAIT_OBJECT_0 = 0;

    private static readonly IntPtr HKEY_CURRENT_USER = new(unchecked((int)0x80000001));
    private static readonly IntPtr HKEY_LOCAL_MACHINE = new(unchecked((int)0x80000002));

    private const uint KEY_READ = 0x20019;
    private const uint KEY_SET_VALUE = 0x0002;
    private const uint KEY_WOW64_64KEY = 0x0100;
    private const uint KEY_WOW64_32KEY = 0x0200;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions,
        uint samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int RegQueryValueExW(IntPtr hKey, string lpValueName, IntPtr lpReserved,
        out uint lpType, byte[]? lpData, ref uint lpcbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int RegSetValueExW(IntPtr hKey, string lpValueName, uint Reserved,
        uint dwType, byte[] lpData, uint cbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int RegDeleteValueW(IntPtr hKey, string lpValueName);

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern int RegCloseKey(IntPtr hKey);
}
