using Hero.Core;
using Hero.Guardian.Rules;
using Hero.Interop;

namespace Hero.Guardian;

/// <summary>
/// The always-on core of HERO. Owns the monitor loop, the signature verifier, the learned
/// baseline, the scorer and the detection rules.
///
/// This deliberately does NOT live on MainWindow. An earlier revision started the engine from the
/// window's Loaded event, which meant launching with --tray — the way HERO starts at logon — never
/// began monitoring at all, because Loaded never fires for a window that is never shown. Measured
/// idle CPU looked wonderful precisely because nothing was running.
///
/// The window is a view onto this service. The service outlives every window.
/// </summary>
internal sealed class GuardianService : IAsyncDisposable
{
    internal static GuardianService Current { get; } = new();

    internal MonitorEngine Engine { get; } = new();
    internal SignatureVerifier Verifier { get; } = new();
    internal QuarantineVault Vault { get; } = new();

    /// <summary>Findings the user has told HERO to stop showing, and until when.</summary>
    internal DismissalStore Dismissals { get; } = new();

    /// <summary>Shared so the hostname-resolution setting reaches every view.</summary>
    internal PeerAssessor Peers { get; } = new();
    internal HeroSettings Settings { get; private set; } = HeroSettings.Load();

    /// <summary>
    /// Containment. Starts in dry-run and is only armed by the autonomy setting, so the default
    /// build detects and explains without touching anything.
    /// </summary>
    internal ResponseEngine Response { get; private set; } = null!;

    /// <summary>The most recent plan produced for each verdict, keyed by subject.</summary>
    internal IReadOnlyDictionary<string, ResponsePlan> Plans
    {
        get { lock (_planLock) return new Dictionary<string, ResponsePlan>(_plans); }
    }

    private readonly Dictionary<string, ResponsePlan> _plans = new();
    private readonly object _planLock = new();

    internal Baseline Baseline { get; private set; } = null!;
    private Scorer _scorer = null!;
    private IReadOnlyList<IDetectionRule> _rules = Array.Empty<IDetectionRule>();

    /// <summary>Raised for every poll, on a background thread.</summary>
    internal event Action<SnapshotDelta>? Observed;

    /// <summary>Raised when a subject is judged worth showing the user.</summary>
    internal event Action<Verdict>? VerdictRaised;

    /// <summary>Recently started processes, newest first. Bounded.</summary>
    internal IReadOnlyList<ProcessRecord> RecentStarts
    {
        get { lock (_recentLock) return _recentStarts.ToList(); }
    }

    /// <summary>Current verdicts worth attention, strongest first.</summary>
    internal IReadOnlyList<Verdict> Verdicts
    {
        get { lock (_verdictLock) return _verdicts.Values.OrderByDescending(v => v.Score).ToList(); }
    }

    /// <summary>The most recent persistence inventory, refreshed on a slow cadence.</summary>
    internal IReadOnlyList<PersistenceEntry> Persistence
    {
        get { lock (_persistLock) return _persistence; }
    }

    internal DateTime? PersistenceScannedUtc { get; private set; }

    /// <summary>
    /// Bumped whenever the persistence inventory or the recent-starts list is replaced.
    ///
    /// These exist so the state poll can skip sections that have not changed. Measured: the
    /// persistence inventory is a quarter of every 500 KB poll and is rescanned every TEN MINUTES,
    /// so it was being re-sent 600 times per actual change; recent starts was another 15%, and is
    /// mostly process records the same message already carries under `processes`.
    ///
    /// A counter rather than a hash: the client only needs to know THAT it changed, and hashing
    /// 400 entries every second to answer that question would cost more than the bytes saved.
    /// </summary>
    internal int PersistenceVersion { get; private set; }

    internal int RecentStartsVersion { get; private set; }

    private readonly List<ProcessRecord> _recentStarts = new();
    private readonly object _recentLock = new();
    private const int RecentCap = 60;

    private readonly Dictionary<string, Verdict> _verdicts = new();
    private readonly object _verdictLock = new();

    private List<PersistenceEntry> _persistence = new();
    private readonly object _persistLock = new();

    private readonly SemaphoreSlim _verifyGate = new(1, 1);
    private readonly HashSet<string> _verifyQueued = new(StringComparer.OrdinalIgnoreCase);

    private DateTime _lastPersistenceScan = DateTime.MinValue;
    private bool _started;

    /// <summary>
    /// Persistence enumeration costs seconds, not milliseconds — a full scan of this machine
    /// measured about 4s, dominated by the schtasks subprocess. It therefore runs on its own slow
    /// cadence rather than inside the one-second poll.
    /// </summary>
    private static readonly TimeSpan PersistenceInterval = TimeSpan.FromMinutes(10);

    /// <summary>
    /// True when this instance is a VIEW of a guardian running in the service rather than a
    /// guardian itself. Set once at startup and never afterwards: a facade that changed its mind
    /// about where its data came from would be impossible to reason about.
    /// </summary>
    internal bool IsRemote { get; private set; }

    /// <summary>
    /// True when this process is running the guardian in-process but cannot write its state
    /// directory, so nothing it observes is being recorded.
    ///
    /// Reachable only in one configuration: HERO is installed (so %ProgramData%\HERO is closed to
    /// the signed-in user) but the service is not answering. The dashboard is still worth having
    /// there — live processes, connections and persistence are read straight from the machine —
    /// but the ledger, the baseline and the vault are not being written, and the UI has to say so
    /// rather than let the user believe a record is accumulating.
    /// </summary>
    internal bool PersistenceBlocked { get; set; }

    /// <summary>How often the dashboard asks the service for a fresh view.</summary>
    private static readonly TimeSpan RemotePollInterval = TimeSpan.FromSeconds(1);

    private CancellationTokenSource? _remotePolling;
    private bool _loggedRemoteShape;

    /// <summary>
    /// Versions of the gated sections this process currently holds. -1 means "nothing", which is
    /// also what they return to if the service restarts with fresh counters — the service sends
    /// the full section whenever the numbers disagree, so a counter reset is self-correcting
    /// rather than a stale view nobody notices.
    /// </summary>
    private int _havePersistenceVersion = -1;
    private int _haveRecentVersion = -1;

    /// <summary>
    /// Runs the dashboard against the guardian service instead of starting an engine here.
    ///
    /// The engine is NOT started in this mode, which is the entire point: two engines would mean
    /// two baselines and two writers on a hash-chained ledger. Every page keeps reading the same
    /// properties it always did — <see cref="Engine"/>.Latest, <see cref="Verdicts"/>,
    /// <see cref="Persistence"/> — and the poller below fills them from the wire.
    /// </summary>
    internal void StartRemote()
    {
        if (_started) return;
        _started = true;
        IsRemote = true;

        _rules = RuleCatalogue.All();
        Baseline = new Baseline();          // unused when remote, but pages may still touch it
        _scorer = new Scorer(Baseline);
        Response = new ResponseEngine(vault: Vault);

        _remotePolling = new CancellationTokenSource();
        _ = Task.Run(() => RemotePollLoopAsync(_remotePolling.Token));
    }

    private async Task RemotePollLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                // Tell the service which versions of the gated sections we already hold, so it
                // can leave them out. On the first poll these are -1 and everything arrives.
                var state = await Service.Ipc.GuardianClient
                    .StateAsync(_havePersistenceVersion, _haveRecentVersion, token)
                    .ConfigureAwait(false);

                if (state is not null) ApplyRemote(state);
            }
            catch { /* the service may be restarting; the next tick will find it */ }

            try { await Task.Delay(RemotePollInterval, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Copies one wire view into the fields the pages read.</summary>
    private void ApplyRemote(Service.Ipc.StateReply state)
    {
        var delta = state.Snapshot is not null ? Engine.AcceptRemote(state.Snapshot) : null;

        lock (_verdictLock)
        {
            _verdicts.Clear();
            foreach (var verdict in state.Verdicts) _verdicts[verdict.Subject.Key] = verdict;
        }

        // A null section means "unchanged, keep what you have" — never "empty". Replacing on null
        // would blank the Persistence page every second, which is precisely the failure the
        // nullable type is there to make hard to write by accident.
        if (state.Persistence is { } persistence)
        {
            lock (_persistLock) _persistence = persistence;
        }
        _havePersistenceVersion = state.PersistenceVersion;

        PersistenceScannedUtc = state.PersistenceScannedUtc;

        if (state.RecentStarts is { } recent)
        {
            lock (_recentLock)
            {
                _recentStarts.Clear();
                foreach (var process in recent) _recentStarts.Add(process);
            }
        }
        _haveRecentVersion = state.RecentStartsVersion;

        // The signature cache and the peer verdicts are answers the service already computed.
        // Publishing them into the same lookups the pages use keeps every call site identical.
        Verifier.AcceptRemote(state.Signatures);

        // Keys are generated HERE, from the connections this process just deserialised, using the
        // same method the lookup will use. That is the point: both sides of the comparison are
        // produced by one piece of code running on one set of objects, so a formatting difference
        // cannot put them out of step the way a server-formatted key did.
        var connections = state.Snapshot?.Connections;
        if (connections is not null && connections.Count == state.ConnectionVerdicts.Count)
        {
            var byConnection = new Dictionary<string, PeerAssessment>(connections.Count);
            for (int i = 0; i < connections.Count; i++)
                byConnection[Service.Ipc.GuardianProtocol.ConnectionKey(connections[i])] = state.ConnectionVerdicts[i];

            Peers.AcceptRemote(byConnection);
        }

        // Raised LAST, once every section above has been published, so a page refreshing in
        // response sees one consistent view rather than a half-applied one.
        //
        // Without this the dashboard was frozen. Observed is the only thing that calls the
        // window's RefreshCurrent, the local poll loop is the only place that ever raised it, and
        // that loop does not run when the guardian lives in the service — so since detection moved
        // out of process, every page rendered once on navigation and then never again. It looked
        // like work that had stalled ("Still checking signatures: 265 of 344") when the service had
        // in fact answered long before; navigating away and back was enough to show the real state.
        if (delta is not null) Observed?.Invoke(delta);

        if (!_loggedRemoteShape)
        {
            _loggedRemoteShape = true;
            try
            {
                // Per-user: this runs in the dashboard, as the signed-in user, and the guardian's
                // state directory is closed to that user.
                Core.HeroPaths.WriteUserLog("ipc.log",
                    $"{DateTime.UtcNow:u} first state applied: " +
                    $"processes={state.Snapshot?.Processes.Count ?? -1} " +
                    $"connections={state.Snapshot?.Connections.Count ?? -1} " +
                    $"persistence={state.Persistence?.Count.ToString() ?? "unchanged"} " +
                    $"signatures={state.Signatures.Count} " +
                    $"connectionVerdicts={state.ConnectionVerdicts.Count}{Environment.NewLine}");
            }
            catch { }
        }
    }

    internal void Start()
    {
        if (_started) return;
        _started = true;

        Settings.NoteStart(DateTime.UtcNow);
        Baseline = Baseline.Load();
        _scorer = new Scorer(Baseline);
        _rules = RuleCatalogue.All();

        Response = new ResponseEngine(vault: Vault);
        Peers.ResolveHostnames = ReadResolveHostnames();
        ApplyAutonomy();

        // Anything suspended when HERO last exited must be accounted for on start, or a process
        // frozen for triage stays frozen forever because the app that froze it is gone.
        try { Response.ReconcileOnStart(); } catch { }

        // Bring the logon registration back in line with the setting. This is what heals a stale
        // Run key after the executable is moved or rebuilt elsewhere: without it the key keeps
        // pointing at a path that no longer exists, and HERO silently stops starting at logon —
        // discovered at the next reboot, which is precisely when nobody is watching. Off the
        // startup path because it touches the registry and the Task Scheduler COM API, and
        // nothing here depends on the result.
        // NOT WHEN THIS ENGINE IS THE SERVICE. Every mechanism StartupRegistration touches is
        // per-user — the Run key under HKCU, the StartupApproved tombstone beside it, the Startup
        // folder shortcut, the per-user scheduled task — and under LocalSystem all four resolve to
        // the service account. Reconcile there wrote a run-at-logon entry for an account that never
        // logs on, and left the user's real entry untouched; DisableAll had the mirror fault, so
        // turning "start with Windows" OFF deleted nothing the user would ever see.
        //
        // The healing this exists for still happens, and happens in the right place: the tray app
        // reconciles at its own startup, which is the process the Run key launches, running as the
        // person the entry belongs to. See App.OnStartup.
        if (!RunningAsSystem())
        {
            _ = Task.Run(() =>
            {
                try { Core.StartupRegistration.Reconcile(Settings); } catch { }
            });
        }

        Engine.Observed += OnObserved;
        Engine.Faulted += OnEngineFaulted;
        Engine.Start();

        // Warm the signature cache and take the first persistence inventory off the poll thread.
        _ = Task.Run(WarmAsync);
    }

    /// <summary>
    /// Sends a command to the guardian service and waits for the answer.
    ///
    /// Synchronous on purpose. Every caller is a button the user just pressed, and the alternative
    /// — making Dismiss, Allow and Recheck async — would have rippled through page code that is
    /// otherwise untouched by the move to a service. The client's own timeout bounds the wait, and
    /// an unreachable service comes back as a refusal rather than an exception.
    /// </summary>
    private static Service.Ipc.CommandReply Remote(string op, object args)
        => Service.Ipc.GuardianClient.CommandAsync(op, args).GetAwaiter().GetResult();

    /// <summary>
    /// Performs a response action against a finding the service still holds.
    ///
    /// Answers with the engine's own <see cref="ResponseResult"/> — incident id, undo record path,
    /// forensic snapshot path and all — so the Threats page renders the outcome exactly as it did
    /// when the engine was in this process.
    /// </summary>
    internal async Task<ResponseResult> ActAsync(string subjectKey, string action, string reason,
                                                 string incident, string? actionId = null)
    {
        var result = await Service.Ipc.GuardianClient.ActAsync(
            new { subjectKey, action, reason, incident, actionId }).ConfigureAwait(true);

        return result ?? new ResponseResult
        {
            Rung = ResponseRung.Observe,
            Outcome = ActionOutcome.RefusedByOs,
            Message = "The HERO guardian service did not respond, so nothing was changed.",
        };
    }

    /// <summary>Restores a quarantined file. Routed to the service, which owns the vault.</summary>
    internal Service.Ipc.CommandReply VaultRestore(string id)
        => IsRemote
            ? Remote(Service.Ipc.GuardianProtocol.OpVaultRestore, new { id })
            : Convert(Vault.Restore(id));

    /// <summary>Permanently deletes a quarantined file.</summary>
    internal Service.Ipc.CommandReply VaultDelete(string id)
        => IsRemote
            ? Remote(Service.Ipc.GuardianProtocol.OpVaultDelete, new { id })
            : Convert(Vault.Delete(id));

    /// <summary>The vault''s own result shape, mapped to the reply the dashboard renders.</summary>
    private static Service.Ipc.CommandReply Convert(QuarantineResult result) => new()
    {
        Acted = result.Success,
        Refused = !result.Success,
        Rung = "Quarantine",
        Message = result.Message,
        Outcome = result.Success ? "Performed" : "RefusedByOs",
    };

    /// <summary>
    /// Persists settings.
    ///
    /// In remote mode the service writes the file, because it owns %ProgramData%\HERO. What stays
    /// local is the HKCU startup registration: a LocalSystem service writing HKCU would write into
    /// SYSTEM's hive, not the signed-in user's, and the entry would never run.
    /// </summary>
    internal Service.Ipc.CommandReply SaveSettings(Core.HeroSettings settings)
    {
        if (!IsRemote)
        {
            settings.SaveSafe();
            ReloadSettings();
            return new Service.Ipc.CommandReply { Acted = true, Message = "Settings saved." };
        }

        var reply = Remote(Service.Ipc.GuardianProtocol.OpSaveSettings, new { settings });
        if (reply.Acted) Settings = settings;      // reflect immediately; the poll confirms later
        return reply;
    }

    // ------------------------------------------------------------------ learning

    /// <summary>
    /// What HERO has made of its own track record here.
    ///
    /// Assembled service-side because the ledger lives in the state root, which the dashboard
    /// cannot read once the lockdown has run — and a page that shows nothing on a properly
    /// installed machine and everything on an unprotected one would have it exactly backwards.
    /// </summary>
    internal Service.Ipc.LearningReply Learning()
        => IsRemote
            ? Service.Ipc.GuardianClient.LearningAsync().GetAwaiter().GetResult() ?? new()
            : BuildLearning();

    internal static Service.Ipc.LearningReply BuildLearning()
    {
        var softened = OutcomeStore.Softened().ToDictionary(s => s.RuleId, StringComparer.Ordinal);

        var descriptions = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            foreach (var rule in RuleCatalogue.All()) descriptions[rule.Id] = rule.Description;
        }
        catch { }

        var rules = OutcomeStore.Tallies()
            .Select(t => new Service.Ipc.LearnedRule
            {
                RuleId = t.RuleId,
                Description = descriptions.TryGetValue(t.RuleId, out var d) ? d : "",
                Influence = softened.TryGetValue(t.RuleId, out var s) ? s.Influence : 1.0,
                Programs = softened.TryGetValue(t.RuleId, out var p) ? p.Programs : 0,
                Allows = t.Allows,
                Acts = t.Acts,
                Dismisses = t.Dismisses,
            })
            // Softened rules first — they are the ones that changed HERO's behaviour — then by how
            // much HERO has seen of the rule at all.
            .OrderBy(r => r.Influence)
            .ThenByDescending(r => r.Allows + r.Acts + r.Dismisses)
            .ToList();

        return new Service.Ipc.LearningReply { Sealed = OutcomeStore.LedgerIsSealed, Rules = rules };
    }

    /// <summary>Asks HERO to forget what it has concluded. The record of what happened stays.</summary>
    internal Service.Ipc.CommandReply ResetLearning()
    {
        if (IsRemote) return Remote(Service.Ipc.GuardianProtocol.OpLearningReset, new { });

        bool wrote = OutcomeStore.ResetInfluence();
        return new Service.Ipc.CommandReply
        {
            Acted = wrote,
            Message = wrote ? "HERO has forgotten what it learned." : "There was nothing to forget.",
            Rung = "Observe",
            Outcome = wrote ? "Performed" : "NoChange",
        };
    }

    /// <summary>Writes one cosmetic preference, through the service when there is one.</summary>
    internal void SaveRawSetting(string key, bool value)
    {
        if (IsRemote) { Remote(Service.Ipc.GuardianProtocol.OpSaveRawSetting, new { key, value }); return; }

        Core.RawSettings.Write(key, value);
        if (key == "resolveHostnames") Peers.ResolveHostnames = value;
    }

    /// <summary>
    /// Takes settings handed over by the dashboard and persists them. Service side.
    ///
    /// MERGES USER PREFERENCES ONLY. It does not adopt the object wholesale, and that distinction
    /// is a security boundary rather than tidiness.
    ///
    /// The first version assigned the incoming object directly, and a test that round-tripped
    /// settings.json through the pipe proved what that costs: <c>ObservationEndsUtc</c> came back
    /// null and was saved, silently ending the shakedown period that gates autonomous action;
    /// <c>RunAtStartup</c> flipped true to false; <c>FirstRunUtc</c> reset to now. Any interactive
    /// process could have done the same deliberately — clear the observation window, clear
    /// <c>AutoActionDisabledUntilUtc</c>, and HERO is armed early on a machine of the caller's
    /// choosing.
    ///
    /// The allowlists are excluded for the same reason. They look like preferences, but
    /// <see cref="Scorer.Allow"/> enforces narrow scopes when an entry is added through the allow
    /// command, and accepting a wholesale list here would be a way around that: an attacker could
    /// simply post an allowlist naming their own binary.
    /// </summary>
    /// <param name="callerElevated">
    /// Whether the caller proved an elevated administrator token. Settings that govern WHETHER AND
    /// WHEN HERO ACTS are refused without it — see <see cref="DescribeGuardedChange"/>.
    /// </param>
    internal (bool Accepted, string Message) ReplaceSettings(Core.HeroSettings incoming, bool callerElevated)
    {
        var current = Settings;

        if (!callerElevated && DescribeGuardedChange(current, incoming) is { } guarded)
        {
            Service.ServiceLog.Write($"Refused a settings change from a non-elevated caller: {guarded}.");
            return (false, $"Changing {guarded} needs administrator rights. " +
                           "Run HERO as an administrator to change how the guardian responds.");
        }

        // User preferences: the things the Settings page legitimately owns.
        current.Autonomy = incoming.Autonomy;
        current.RunAtStartup = incoming.RunAtStartup;
        current.StartupMethod = incoming.StartupMethod;
        current.QuietHours = incoming.QuietHours;
        current.RequireHardIndicatorForAutoAction = incoming.RequireHardIndicatorForAutoAction;
        current.MaxAutoActionsPerHour = incoming.MaxAutoActionsPerHour;
        current.MaxAutoActionsPerSweep = incoming.MaxAutoActionsPerSweep;
        current.UiScale = incoming.UiScale;

        // Everything else — ObservationEndsUtc, AutoActionDisabledUntilUtc, FirstRunUtc,
        // LastStartUtc, LastCleanExitUtc, SchemaVersion and the allowlists — stays as the service
        // has it. They are HERO's record of its own life, not the user's preferences.

        current.SaveSafe();
        ApplyAutonomy();
        Peers.ResolveHostnames = ReadResolveHostnames();
        return (true, "Settings saved.");
    }

    /// <summary>
    /// Names the first setting in <paramref name="incoming"/> that changes how the guardian
    /// RESPONDS, or null when nothing of the sort changed.
    ///
    /// The field allowlist in <see cref="ReplaceSettings"/> stops a caller rewriting HERO's record
    /// of its own life. It does nothing about the fields that are legitimately the user's, and four
    /// of those decide whether HERO defends the machine at all. The pipe grants the Interactive
    /// SID, so before this check the only authentication for disarming the guardian was being
    /// logged in — an attacker who could not open settings.json could simply ask SYSTEM to rewrite
    /// the fields that mattered, which is the ACL bypass in its purest form.
    ///
    /// Guarded in BOTH directions, which is the part worth explaining. There are two ways to hurt
    /// someone through these settings and they pull opposite ways:
    ///
    ///   - DISARM: Autonomy to Observe, the caps to zero, quiet hours suppressing action. HERO
    ///     watches and never intervenes, so the attacker's malware runs unopposed.
    ///   - OVER-ARM: RequireHardIndicatorForAutoAction off, the caps raised. HERO acts on weaker
    ///     evidence and more often, and can be steered into quarantining the user's own work.
    ///
    /// A rule that only guarded one direction would be half a rule. "Any change to how HERO
    /// responds needs consent" is also something a person can recite back, which a threshold-based
    /// rule would not be.
    ///
    /// Deliberately NOT guarded: UiScale, RunAtStartup and StartupMethod. None of them affects the
    /// guardian — the service is Automatic and starts without the tray app — and gating the zoom
    /// level behind a UAC prompt would teach people to elevate HERO by reflex, which is worse for
    /// them than any of this is good.
    /// </summary>
    private static string? DescribeGuardedChange(Core.HeroSettings current, Core.HeroSettings incoming)
    {
        if (current.Autonomy != incoming.Autonomy)
            return $"the autonomy level (to \"{incoming.Autonomy}\")";

        if (current.RequireHardIndicatorForAutoAction != incoming.RequireHardIndicatorForAutoAction)
            return "whether a hard indicator is required before acting";

        if (current.MaxAutoActionsPerHour != incoming.MaxAutoActionsPerHour)
            return "the hourly limit on autonomous actions";

        if (current.MaxAutoActionsPerSweep != incoming.MaxAutoActionsPerSweep)
            return "the per-sweep limit on autonomous actions";

        var a = current.QuietHours;
        var b = incoming.QuietHours;
        if (a.Enabled != b.Enabled || a.Start != b.Start || a.End != b.End
            || a.SuppressAutoAction != b.SuppressAutoAction)
        {
            return "quiet hours";
        }

        return null;
    }

    /// <summary>
    /// Points the response engine at the user's chosen autonomy level.
    ///
    /// Observe keeps the engine in dry run, so it still computes and records exactly what it
    /// WOULD have done. That is what makes a shakedown period meaningful: at the end of it the
    /// user can see the actions HERO wanted to take and judge whether it was right, rather than
    /// having to choose between "silent" and "armed" with no evidence either way.
    /// </summary>
    /// <summary>
    /// True when this engine is hosted by the LocalSystem service rather than by the tray app.
    ///
    /// IsSystem is exact — it tests for the LocalSystem SID rather than inferring from elevation or
    /// from an interactive window station, both of which have exceptions. A failure to read the
    /// token is treated as "this is the service", because the only thing gated on it is a per-user
    /// registry write that is wrong to perform when uncertain.
    /// </summary>
    private static bool RunningAsSystem()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch { return true; }
    }

    internal void ApplyAutonomy()
    {
        if (Response is null) return;
        Response.DryRun = Settings.Autonomy == AutonomyLevel.Observe;

        // THE LINE ABOVE USED TO BE THE WHOLE METHOD, and that is why HERO never acted. DryRun was
        // the only thing settings reached; ResponseEngine.AutonomyEnabled was read by the gate and
        // assigned by nobody, so every verdict that cleared the evidence bar was explained away
        // with "automatic action is switched off" no matter what the user had chosen. Everything
        // underneath it — the observation window, the post-crash pause, quiet hours, the caps —
        // was unreachable, which is also why nothing ever noticed those were unread.
        //
        // A closure rather than a value, because AutoActionPermitted is a function of the clock:
        // the 72-hour window expires, quiet hours start and end, the post-crash pause lifts. None
        // of those fire a settings change, so a value read here would be stale — and stale in the
        // permissive direction. It reads Settings on each call rather than capturing it, so a
        // settings object replaced by the IPC merge is picked up on the next decision.
        Response.AutonomyPolicy = () =>
        {
            bool permitted = Settings.AutoActionPermitted(DateTime.UtcNow, out string why);
            return (permitted, why);
        };

        // The two caps the user can actually see. Settings owns the numbers, the breaker enforces
        // them, and neither had a reader before now.
        Response.MaxAutoActionsPerHour = Settings.MaxAutoActionsPerHour;
        Response.MaxAutoActionsPerSweep = Settings.MaxAutoActionsPerSweep;
    }

    /// <summary>
    /// The user's "this is fine". This is HERO's main learning input, and the scope matters:
    /// a path-only allowlist is a persistence primitive, because an attacker who can write to
    /// that path inherits the trust. <see cref="Scorer.Allow"/> enforces the narrow scopes.
    /// </summary>
    /// <param name="ruleId">
    /// Which finding is being silenced. Required by <see cref="AllowScope.RuleForEntity"/> and
    /// ignored by the others.
    ///
    /// It was never passed. Scorer.Allow has taken this parameter all along and refuses
    /// RuleForEntity without it, so that scope has never once succeeded — which matters more than
    /// it looks: it is the ONLY approval an unelevated caller may make (every other scope now
    /// requires an elevated one), and the only one that names a rule rather than blessing a file.
    /// The narrowest, most honest thing a user can say about a false positive — "this particular
    /// check is wrong about this particular program" — was the one thing the product could not
    /// record.
    /// </param>
    internal AllowResult Allow(Subject subject, AllowScope scope, string? ruleId = null)
    {
        if (IsRemote)
        {
            var reply = Remote(Service.Ipc.GuardianProtocol.OpAllow,
                new { subjectKey = subject.Key, scope = scope.ToString(), ruleId = ruleId ?? "" });
            return new AllowResult(reply.Acted, null, reply.Message);
        }

        // Read the verdict BEFORE the approval clears it, or there is nothing left to attribute
        // the outcome to. Only an accepted approval is recorded: a refused one approved nothing,
        // and counting attempts would make the refusal path — which leaves the finding live to be
        // attempted again — a free way to manufacture outcomes.
        Verdict? accused;
        lock (_verdictLock) _verdicts.TryGetValue(subject.Key, out accused);

        var result = _scorer.Allow(subject, scope, ruleId);
        if (result.Accepted)
        {
            if (accused is not null)
            {
                // Derived rather than passed, and derived in the direction that under-claims.
                // GuardianCommands refuses every scope except RuleForEntity without an elevated
                // caller, so reaching here with any other scope proves elevation. RuleForEntity may
                // be either, and recording the weaker claim is the right way round: a future reader
                // that trusts "elevated" must never be told so on evidence this method does not
                // actually have.
                bool provedElevated = scope != AllowScope.RuleForEntity;

                OutcomeStore.Record(OutcomeStore.KindAllow, accused, provedElevated,
                    detail: ruleId is { Length: > 0 } ? $"{scope}:{ruleId}" : scope.ToString());
            }

            lock (_verdictLock) _verdicts.Remove(subject.Key);
            lock (_planLock) _plans.Remove(subject.Key);
            try { Baseline.Save(); } catch { }
        }
        return result;
    }

    /// <summary>
    /// The opposite verdict: the user says this is hostile. The entity is marked Blocked in the
    /// baseline, which it never recovers from without an explicit reset — unlike ordinary trust,
    /// which decays back on its own.
    /// </summary>
    internal void Deny(Subject subject)
    {
        _scorer.Deny(subject);
        try { Baseline.Save(); } catch { }
    }

    /// <summary>
    /// Hides a finding for a while without teaching the baseline anything about it.
    /// The duration is explicit because a dismissal that never expires is an allowlist entry
    /// wearing a disguise, and one that expires in seconds is a button that does nothing.
    /// </summary>
    internal void Dismiss(string subjectKey, TimeSpan? duration = null)
    {
        if (IsRemote)
        {
            Remote(Service.Ipc.GuardianProtocol.OpDismiss,
                new { subjectKey, days = (duration ?? TimeSpan.FromDays(1)).TotalDays });

            // Drop it locally too so the finding disappears on this refresh rather than the next
            // poll. The service is the authority; this is only about the button feeling honest.
            lock (_verdictLock) _verdicts.Remove(subjectKey);
            return;
        }

        var granted = duration ?? TimeSpan.FromDays(1);

        // Recorded ONLY when it dismissed something HERO was actually reporting. Dismiss reaches
        // this over the pipe without elevation and resolves nothing, so a subject key HERO holds no
        // finding for must write nothing at all — otherwise a loop of fabricated keys is a
        // disk-filling primitive wearing the costume of a feature.
        //
        // The duration recorded is the one GRANTED, not the one asked for: GuardianCommands clamps
        // an unelevated request to a day and the dashboard discards the reply, so the user is never
        // told. Logging the request would put a number in the record that never happened.
        Verdict? dismissed;
        lock (_verdictLock) _verdicts.TryGetValue(subjectKey, out dismissed);
        if (dismissed is not null)
        {
            OutcomeStore.Record(OutcomeStore.KindDismiss, dismissed, elevated: false,
                detail: $"{granted.TotalDays:0.#}d");
        }

        Dismissals.Dismiss(subjectKey, granted, "dismissed by the user");
        lock (_verdictLock) _verdicts.Remove(subjectKey);
        lock (_planLock) _plans.Remove(subjectKey);
    }

    /// <summary>Undoes a dismissal so the finding can be raised again.</summary>
    internal void Undismiss(string subjectKey)
    {
        if (IsRemote) { Remote(Service.Ipc.GuardianProtocol.OpUndismiss, new { subjectKey }); return; }
        Dismissals.Restore(subjectKey);
    }

    /// <summary>
    /// Re-takes the persistence inventory immediately and re-judges it.
    ///
    /// Needed after the user acts on a persistence finding. The inventory otherwise refreshes on
    /// a ten-minute cadence, so a removed auto-start stayed visible in the list long after it was
    /// gone — leaving the user unable to tell whether the action had worked. A security tool that
    /// cannot show its own effect is worse than one that does nothing.
    /// </summary>
    internal Task RescanPersistenceAsync()
    {
        if (IsRemote)
        {
            return Task.Run(() => Remote(Service.Ipc.GuardianProtocol.OpRescanPersistence, new { }));
        }

        _lastPersistenceScan = DateTime.UtcNow;
        return Task.Run(ScanPersistence);
    }

    /// <summary>
    /// Confirms whether a persistence finding still holds, by re-reading that ONE entry rather
    /// than the whole inventory. Returns null when the entry has gone entirely.
    /// </summary>
    internal PersistenceEntry? Recheck(PersistenceEntry entry)
    {
        if (IsRemote)
        {
            // Keyed by subject, not by entry: the service will only re-read an entry it currently
            // holds a finding for.
            var reply = Remote(Service.Ipc.GuardianProtocol.OpRecheck,
                new { subjectKey = "persist:" + entry.Key });
            return reply.EntryGone ? null : reply.Entry;
        }

        try
        {
            var fresh = PersistenceScanner.Scan();

            // The inventory is replaced whether or not the sweep was complete — a partial list is
            // still a better view than a stale one, and this path prunes no verdicts. What it must
            // not do is answer "gone" on the strength of an incomplete read, which is what the
            // caller uses to close a finding.
            lock (_persistLock) { _persistence = fresh.Entries; PersistenceVersion++; }
            PersistenceScannedUtc = DateTime.UtcNow;

            var match = fresh.Entries.FirstOrDefault(e => e.Key == entry.Key);
            if (match is not null) return match;

            // Not found, and the sweep could not see everything. "I did not find it" is not "it is
            // not there", so the finding stands rather than being reported as resolved.
            return fresh.Complete ? null : entry;
        }
        catch { return entry; }
    }

    /// <summary>
    /// Reverse DNS is the only outbound request HERO makes, so the preference lives outside the
    /// security schema and defaults to on: the lookup goes to the machine''s own resolver, which
    /// performed the forward lookup moments earlier and learns nothing new from the reverse one.
    /// </summary>
    private static bool ReadResolveHostnames()
    {
        try
        {
            if (!File.Exists(HeroPaths.Settings)) return true;
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(HeroPaths.Settings));
            if (doc.RootElement.TryGetProperty("resolveHostnames", out var v) &&
                v.ValueKind is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False)
                return v.GetBoolean();
        }
        catch { }
        return true;
    }

    /// <summary>Re-reads settings from disk, e.g. after the Settings screen writes them.</summary>
    internal void ReloadSettings()
    {
        Settings = HeroSettings.Load();
        ApplyAutonomy();
        Peers.ResolveHostnames = ReadResolveHostnames();
    }

    private DateTime _lastFaultLogUtc = DateTime.MinValue;
    private string _lastFaultType = "";

    /// <summary>
    /// Records a failed poll where somebody will see it.
    ///
    /// The only subscriber to Faulted was MainWindow, which writes the exception type into a
    /// breadcrumb label. In the service there is no window, so every probe failure was raised into
    /// an event with nothing attached and discarded — and because a faulted poll skips Observed,
    /// the guardian went on reporting itself healthy while ingesting nothing.
    ///
    /// Throttled, because the loop polls once a second and a broken probe fails every time: the
    /// first of a kind is written immediately, then at most one line a minute. Without that the
    /// answer would be buried in its own repetitions, and ServiceLog caps at 2 MB.
    /// </summary>
    private void OnEngineFaulted(Exception ex)
    {
        try
        {
            string type = ex.GetType().Name;
            var now = DateTime.UtcNow;

            bool newKind = !string.Equals(type, _lastFaultType, StringComparison.Ordinal);
            if (!newKind && now - _lastFaultLogUtc < TimeSpan.FromMinutes(1)) return;

            _lastFaultType = type;
            _lastFaultLogUtc = now;

            int run = Engine.ConsecutiveFaults;
            Service.ServiceLog.Write(
                $"Monitor poll FAILED ({type}: {ex.Message}). " +
                (run > 1 ? $"{run} consecutive failures — nothing is being observed or scored while this persists."
                         : "Nothing was observed or scored for this tick."));
        }
        catch { /* a diagnostic must never be the thing that breaks the loop */ }
    }

    private void OnObserved(SnapshotDelta delta)
    {
        if (delta.StartedProcesses.Count > 0)
        {
            lock (_recentLock)
            {
                foreach (var p in delta.StartedProcesses)
                {
                    if (p.PathUnavailable) continue;
                    if (HeroPaths.IsOwnState(p.ImagePath)) continue;
                    _recentStarts.Insert(0, p);
                    RecentStartsVersion++;
                }
                if (_recentStarts.Count > RecentCap)
                    _recentStarts.RemoveRange(RecentCap, _recentStarts.Count - RecentCap);
            }

            QueueVerification(delta.StartedProcesses.Select(p => p.ImagePath));
        }

        // Watched time and connection learning, every poll. Both were stranded in a Baseline
        // method that nothing called, which is why PeerAssessor could never find a peer familiar
        // and why ObservedHours stayed at zero however long HERO ran. Cheap and lock-internal, so
        // it stays on the poll thread rather than being handed to a task that might run late.
        Baseline.IngestPoll(delta);

        Observed?.Invoke(delta);

        // Detection runs off the poll thread. Rules are cheap, but scoring touches the baseline
        // under a lock and the baseline is also being written by the verification worker.
        if (delta.StartedProcesses.Count > 0)
            _ = Task.Run(() => Evaluate(delta));

        if (DateTime.UtcNow - _lastPersistenceScan > PersistenceInterval)
        {
            _lastPersistenceScan = DateTime.UtcNow;
            _ = Task.Run(ScanPersistence);
        }
    }

    /// <summary>
    /// Judges the processes that started this tick.
    ///
    /// Only NEW processes are evaluated, not the whole table. Re-scoring 350 unchanged processes
    /// every second would cost far more than the 21ms poll itself and would tell us nothing new;
    /// a process that was benign a second ago has not become malicious by continuing to exist.
    /// Behavioural rules that need history (beaconing) read it from the baseline instead.
    /// </summary>
    private void Evaluate(SnapshotDelta delta)
    {
        try
        {
            var context = new DetectionContext
            {
                Snapshot = delta.Current,
                Delta = delta,
                Verifier = Verifier,
            };

            var now = DateTime.UtcNow;

            // One tick's worth of newly started processes is one sweep. That is the unit the
            // per-sweep cap is about: a rule misfiring across a cohort fires them all in the same
            // batch, so bounding the batch is what bounds the damage.
            Response?.BeginSweep();

            foreach (var process in delta.StartedProcesses)
            {
                if (process.PathUnavailable) continue;
                if (HeroPaths.IsOwnState(process.ImagePath)) continue;

                // HERO must not detect itself. Its own image is signed by whatever the user's
                // build produces, which on a development machine is nothing at all.
                if (process.Pid == Environment.ProcessId) continue;

                var signature = Verifier.TryGetCached(process.ImagePath);
                var parent = delta.Current.ByPid.TryGetValue(process.ParentPid, out var pp) ? pp.Name : null;
                Baseline.Observe(process, signature, parent, now);

                var subject = new ProcessSubject(process);
                var signals = new List<Signal>();
                foreach (var rule in _rules)
                {
                    if (Settings.IsRuleMuted(rule.Id, now)) continue;
                    try { signals.AddRange(rule.Evaluate(subject, context)); }
                    catch { /* one bad rule must not silence the rest */ }
                }

                if (signals.Count == 0) continue;

                var verdict = _scorer.Score(subject, signals, Baseline, context);
                if (verdict.Confidence == Confidence.Informational) continue;

                Raise(verdict, delta.Current);
            }

            PruneVerdicts(delta.Current);
        }
        catch { /* detection must never take down the monitor */ }
    }

    /// <summary>
    /// Records a verdict and asks the response ladder what it wants to do about it.
    ///
    /// Respond is called even in Observe mode, because in dry run it still produces the plan and
    /// the gate explanation without touching anything. The UI needs that plan to offer the user
    /// the right buttons, and the shakedown report needs it to show what HERO would have done.
    /// </summary>
    private void Raise(Verdict verdict, Snapshot? snapshot)
    {
        // A dismissed finding is not re-raised until its dismissal expires. Without this the
        // ten-minute persistence rescan resurrected everything the user had waved away, which
        // made the Dismiss button appear broken.
        if (Dismissals.IsDismissed(verdict.Subject.Key)) return;

        lock (_verdictLock) _verdicts[verdict.Subject.Key] = verdict;

        try
        {
            var plan = Response.Respond(verdict, snapshot);
            lock (_planLock) _plans[verdict.Subject.Key] = plan;
        }
        catch { /* a failure to plan must not suppress the finding itself */ }

        VerdictRaised?.Invoke(verdict);
    }
    /// <summary>
    /// Replaces the persistence half of the verdict set with exactly what the latest sweep raised.
    ///
    /// REBUILT, NOT ACCUMULATED, because accumulation was a bug the user found by pressing the
    /// button: "Remove this auto-start" disabled the Google Play Games service, the very next sweep
    /// correctly dropped it from the inventory (428 entries to 427) — and the finding stayed on the
    /// Threats page, still carrying the timestamp of the sweep before the removal. Nothing was
    /// wrong with the removal. Nothing ever deleted the verdict.
    ///
    /// <see cref="PruneVerdicts"/> only ever considered "proc:" keys, so a "persist:" verdict
    /// outlived the thing it was about: an entry that was disabled, deleted, uninstalled by its own
    /// vendor, or that simply stopped scoring above Informational, was reported for as long as the
    /// service ran. A security tool that keeps showing a finding after you have acted on it teaches
    /// you that its buttons do not work, which is worse than not offering them.
    ///
    /// The rule is deliberately absolute — the persistence verdicts ARE the last sweep's output —
    /// because any softer rule is another thing that can accumulate. Callers must therefore only
    /// use this after a COMPLETE sweep; a partial one would clear findings it merely failed to see.
    /// </summary>
    private void ReplacePersistenceVerdicts(HashSet<string> raised)
    {
        lock (_verdictLock)
        {
            var stale = _verdicts.Keys
                .Where(k => k.StartsWith("persist:", StringComparison.Ordinal) && !raised.Contains(k))
                .ToList();

            foreach (var key in stale) _verdicts.Remove(key);

            if (stale.Count > 0)
            {
                lock (_planLock)
                {
                    foreach (var key in stale) _plans.Remove(key);
                }
            }
        }
    }

    /// <summary>Drops verdicts about processes that have since exited, so the list reflects now.</summary>
    private void PruneVerdicts(Snapshot current)
    {
        lock (_verdictLock)
        {
            if (_verdicts.Count == 0) return;
            var live = new HashSet<string>(
                current.Processes.Select(p => new ProcessSubject(p).Key));

            foreach (var key in _verdicts.Keys
                         .Where(k => k.StartsWith("proc:", StringComparison.Ordinal) && !live.Contains(k))
                         .ToList())
            {
                _verdicts.Remove(key);
            }
        }
    }

    private void ScanPersistence()
    {
        try
        {
            var scan = PersistenceScanner.Scan();
            var entries = scan.Entries;

            if (!scan.Complete)
            {
                Service.ServiceLog.Write(
                    "Persistence sweep INCOMPLETE — could not read: " + string.Join("; ", scan.Failures) +
                    ". Existing findings will be kept rather than pruned.");
            }

            // Verify the images behind persistence entries in parallel: a serial pass over the
            // 240 executables on this machine took 193s, versus 6.9s parallel.
            Verifier.VerifyMany(entries.Select(e => e.ImagePath).Where(p => p.Length > 0));

            lock (_persistLock) { _persistence = entries; PersistenceVersion++; }
            PersistenceScannedUtc = DateTime.UtcNow;

            var snapshot = Engine.Latest;
            if (snapshot is null) return;

            var context = new DetectionContext { Snapshot = snapshot, Delta = null, Verifier = Verifier };
            var now = DateTime.UtcNow;

            // One persistence inventory is one sweep, which is what gives the per-sweep cap a
            // boundary to count against.
            Response?.BeginSweep();

            // What this sweep actually found. Everything else with a "persist:" key is stale by
            // definition once the sweep finishes — see ReplacePersistenceVerdicts.
            var raised = new HashSet<string>(StringComparer.Ordinal);

            foreach (var entry in entries)
            {
                // HERO's own run-at-logon entry is not a finding.
                if (StartupRegistration.IsOwnStartupArtifact(entry)) continue;

                // A DISABLED auto-start cannot run, so it is not a threat — it is history.
                //
                // This is not a cosmetic filter. HERO's own RemovePersistence disables a scheduled
                // task rather than deleting it, precisely so the change is reversible. Without this
                // check the disabled entry was re-scored on the next ten-minute inventory and raised
                // all over again, so acting on the finding appeared to do nothing no matter how many
                // times the user pressed the button. The entry still appears on the Persistence
                // screen, where showing disabled items is correct.
                if (!entry.Enabled) continue;

                var subject = new PersistenceSubject(entry);
                var signals = new List<Signal>();
                foreach (var rule in _rules)
                {
                    if (Settings.IsRuleMuted(rule.Id, now)) continue;
                    try { signals.AddRange(rule.Evaluate(subject, context)); }
                    catch { }
                }
                if (signals.Count == 0) continue;

                var verdict = _scorer.Score(subject, signals, Baseline, context);
                if (verdict.Confidence == Confidence.Informational) continue;

                Raise(verdict, snapshot);
                raised.Add(subject.Key);
            }

            // Only reached when the sweep completed, which is the precondition
            // ReplacePersistenceVerdicts documents: a partial sweep would clear findings it merely
            // failed to see. Anything thrown above lands in the catch below and prunes nothing.
            //
            // "Completed" now means more than "did not throw". Each scanner used to swallow its own
            // failure and return what it had, so a sweep in which the services key or the task
            // query failed outright still arrived here looking successful — and pruning on that
            // basis deleted findings HERO had already made, because the entries backing them were
            // simply not seen this time. Absence is only evidence when the sweep was complete.
            if (scan.Complete) ReplacePersistenceVerdicts(raised);

            Baseline.Save();
        }
        catch { }
    }

    /// <summary>
    /// Asks for these images to be signature-checked, if they have not been already.
    ///
    /// Verification is otherwise only triggered by a process START, so a program that was already
    /// running when HERO launched and never restarts would stay unverified — and the Network view
    /// would show "still checking" for it forever.
    /// </summary>
    /// <summary>
    /// Asks for these images to be verified.
    ///
    /// In remote mode the request must cross the pipe. Queueing it locally verified files for a
    /// cache no page reads — the dashboard's signature answers all come from the service — so the
    /// service was never told to look and every user application stayed "still checking" forever.
    /// </summary>
    internal void RequestVerification(IEnumerable<string> paths)
    {
        if (!IsRemote) { QueueVerification(paths); return; }

        var wanted = paths.Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (wanted.Count == 0) return;

        // Only ask about images the service has not already answered for, or every refresh would
        // re-send the same few hundred paths once a second.
        var unanswered = wanted.Where(p => Verifier.TryGetCached(p) is null).ToList();
        if (unanswered.Count > 0) Service.Ipc.GuardianClient.RequestVerify(unanswered);
    }
    private void QueueVerification(IEnumerable<string> paths)
    {
        var fresh = new List<string>();
        lock (_verifyQueued)
        {
            foreach (var p in paths)
            {
                if (string.IsNullOrEmpty(p)) continue;
                if (_verifyQueued.Add(p)) fresh.Add(p);
            }
        }
        if (fresh.Count == 0) return;

        _ = Task.Run(async () =>
        {
            // Serialised so a burst of process starts cannot spawn a thundering herd of
            // WinVerifyTrust calls.
            await _verifyGate.WaitAsync();
            try { foreach (var p in fresh) Verifier.Verify(p); }
            finally
            {
                _verifyGate.Release();

                // RELEASED WHEN THE WORK IS DONE. This set is a dedup for work IN FLIGHT, not a
                // record of what has ever been verified — the verifier's own cache is that, and it
                // keys on (path, length, write time) so it invalidates itself when a binary is
                // replaced. Add-only, the two disagreed: the verifier correctly forgot an updated
                // image, this set refused to ask about it again, and TryGetCached then returned
                // null for that path for the life of the service.
                //
                // Which was not a quiet failure. A null signature was read as "not validly signed",
                // so the baseline classified an ordinary application update as a signer break,
                // stripped the entity's earned standing and latched SignerChanged — three findings
                // from one unremoved string.
                lock (_verifyQueued)
                {
                    foreach (var p in fresh) _verifyQueued.Remove(p);
                }
            }
        });
    }

    private async Task WarmAsync()
    {
        await _verifyGate.WaitAsync();
        try
        {
            if (Engine.Latest is { } snap)
            {
                Verifier.VerifyMany(snap.Processes
                    .Where(p => !p.PathUnavailable)
                    .Select(p => p.ImagePath));
            }
        }
        catch { }
        finally { _verifyGate.Release(); }

        _lastPersistenceScan = DateTime.UtcNow;
        ScanPersistence();
    }

    public async ValueTask DisposeAsync()
    {
        // ConfigureAwait(false) throughout: this runs during application exit and must never try
        // to resume on the dispatcher, which by then may be blocked waiting for it.
        await Engine.DisposeAsync().ConfigureAwait(false);

        // Neither of these belongs to a REMOTE instance, and both were doing real harm ungated.
        //
        // Baseline: when remote, this is the placeholder built at StartRemote — "unused when
        // remote, but pages may still touch it" — and it is EMPTY. Its FilePath is empty too, so
        // Save() resolves to HeroPaths.Baseline and every clean exit of the dashboard wrote a blank
        // model over the service's learned baseline. Save() has no guard against being empty. The
        // service re-saved from its own in-memory copy soon afterwards, which is the only reason
        // this was survivable rather than catastrophic.
        //
        // NoteCleanExit: the dashboard is not the guardian's lifetime. Stamping "exited cleanly" on
        // the shared settings when a VIEW closed says something untrue about the thing that does
        // the watching. It also runs from the elevated child and the installer, both of which reach
        // OnExit through Shutdown() and neither of which is a guardian run at all.
        if (!IsRemote)
        {
            try { Baseline?.Save(); } catch { }
            try { Settings.NoteCleanExit(DateTime.UtcNow); } catch { }
        }

        _verifyGate.Dispose();
    }
}
