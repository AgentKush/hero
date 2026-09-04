using System.Text.Json;
using Hero.Guardian;

namespace Hero.Service.Ipc;

/// <summary>
/// The commands the dashboard may ask the guardian service to perform.
///
/// EVERY COMMAND RESOLVES ITS TARGET THROUGH THE VERDICT SET.
///
/// The client sends a subject key. This class looks that key up among the verdicts the service is
/// currently holding, and acts on the <see cref="Subject"/> it finds there — never on a path, pid
/// or registry location supplied by the caller. An unknown key is refused.
///
/// The reason is that HERO is now a LocalSystem service whose pipe any interactive user can open.
/// A command surface that accepted arbitrary targets would let any process running as the signed-
/// in user ask SYSTEM to terminate any process, quarantine any file, or delete any registry value
/// — HERO would become the privilege escalation it exists to detect. Routing through the verdict
/// set bounds the blast radius to things HERO independently decided were worth flagging.
///
/// The trade is real and worth stating: a finding that has aged out of the verdict set can no
/// longer be acted on, and the user has to let HERO see it again. That is the correct direction to
/// fail.
/// </summary>
internal static class GuardianCommands
{
    /// <summary>
    /// Returns <see cref="object"/> rather than a single reply type because
    /// <see cref="GuardianProtocol.OpAct"/> answers with the engine's own
    /// <see cref="ResponseResult"/>. That record carries the incident id, the undo record path and
    /// the forensic snapshot path, and the Threats page already knows how to render it — flattening
    /// it into a common shape would have thrown that away and forced a rewrite of code that the
    /// move to a service otherwise left alone.
    /// </summary>
    /// <param name="callerElevated">
    /// Whether the client holds an elevated administrator token, established by impersonation in
    /// GuardianPipeServer. Opening the pipe proves only that the caller is interactive, so this is
    /// the only thing separating "the user at the keyboard" from "the user at the keyboard who has
    /// deliberately consented to change how the guardian defends them".
    /// </param>
    internal static object Execute(string op, JsonElement? args, bool callerElevated = false)
    {
        var guardian = GuardianService.Current;

        return op switch
        {
            GuardianProtocol.OpDismiss => Dismiss(guardian, args, callerElevated),
            GuardianProtocol.OpUndismiss => Undismiss(guardian, args),
            GuardianProtocol.OpAllow => Allow(guardian, args, callerElevated),
            GuardianProtocol.OpRecheck => Recheck(guardian, args),
            GuardianProtocol.OpAct => Act(guardian, args, callerElevated),
            GuardianProtocol.OpSaveSettings => SaveSettings(guardian, args, callerElevated),
            GuardianProtocol.OpSaveRawSetting => SaveRawSetting(guardian, args),
            GuardianProtocol.OpVaultRestore => VaultRestore(guardian, args, callerElevated),
            GuardianProtocol.OpVaultDelete => VaultDelete(guardian, args, callerElevated),
            GuardianProtocol.OpRescanPersistence => RescanPersistence(guardian),

            // Neither is gated. The read exposes counts of the user's own responses to their own
            // machine's findings, and the reset only ever makes HERO stricter — the direction an
            // attacker has no use for. See OutcomeStore.ResetInfluence for the disk-fill guard,
            // which is the only thing the reset actually needed protecting against.
            GuardianProtocol.OpLearning => GuardianService.BuildLearning(),
            GuardianProtocol.OpLearningReset => ResetLearning(),

            // Maintenance names a cleanup target by ID and the host resolves it against the
            // service's own catalogue — see MaintenanceHost for why a path never crosses here.
            GuardianProtocol.OpMaintenanceMeasure => MaintenanceHost.Measure(Required(args, "targetId")),
            GuardianProtocol.OpMaintenanceClean => MaintenanceHost.Clean(Required(args, "targetId"), callerElevated),
            GuardianProtocol.OpMaintenanceStatus => MaintenanceHost.Status(Required(args, "jobId")),

            _ => throw new InvalidOperationException($"Unknown command '{op}'."),
        };
    }

    /// <summary>
    /// The standard refusal for a command that weakens the guardian's defence of the machine.
    ///
    /// GATING settings.save ALONE WAS HALF A FIX, and this is the other half. That command was
    /// chosen because it could set Autonomy to Observe — but every operation gated here reaches the
    /// same end state, "the attacker's malware runs unopposed", and most reach it faster and more
    /// durably:
    ///
    ///   allow          mints a 365-day, hash-pinned allowlist entry for the caller's own binary.
    ///                  ReplaceSettings excludes the allowlists from the settings merge for exactly
    ///                  this reason — "an attacker could simply post an allowlist naming their own
    ///                  binary" — and this command let them post one anyway.
    ///   dismiss        suppresses a subject for up to 90 days BEFORE it exists. Raise() returns on
    ///                  IsDismissed ahead of Respond(), so a dismissal kills detection and response,
    ///                  not just the notification. Subject keys are constructed from values the
    ///                  attacker chooses or already knows.
    ///   act/undo       replays a recorded UndoRecord as SYSTEM, restoring the persistence HERO just
    ///                  removed. Action ids are readable: the state root grants Users read.
    ///   act/resume     thaws a suspended process. Its "undoing containment is never gated" comment
    ///                  was written when the only caller was in-process.
    ///   vault.restore  moves a quarantined sample back where it came from.
    ///   vault.delete   destroys the evidence of what was found.
    ///
    /// Reversing containment is not the innocent direction. It was treated as one throughout,
    /// because for an in-process caller it was the user undoing their own action; the pipe made
    /// "the user" mean "anyone signed in".
    /// </summary>
    private static CommandReply RequiresElevation(string what) => new()
    {
        Acted = false,
        Refused = true,
        Message = $"{what} needs administrator rights. Run HERO as an administrator to do this.",
    };

    // ------------------------------------------------------------------ argument reading

    private static string Text(JsonElement? args, string name)
    {
        if (args is { } element
            && element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String)
        {
            return value.GetString() ?? "";
        }
        return "";
    }

    private static string Required(JsonElement? args, string name)
    {
        var value = Text(args, name);
        if (value.Length == 0) throw new InvalidOperationException($"'{name}' is required.");
        return value;
    }

    /// <summary>The live verdict for a subject key, or null when HERO no longer holds one.</summary>
    private static Verdict? Find(GuardianService guardian, string subjectKey)
        => guardian.Verdicts.FirstOrDefault(v => v.Subject.Key == subjectKey);

    private static Subject Resolve(GuardianService guardian, JsonElement? args)
    {
        var key = Required(args, "subjectKey");
        var verdict = Find(guardian, key)
            ?? throw new InvalidOperationException(
                "HERO no longer holds a finding for that subject, so it will not act on it. " +
                "Refresh and try again.");
        return verdict.Subject;
    }

    private static CommandReply Ok(string message, bool acted = true) => new()
    {
        Acted = acted,
        Message = message,
        Rung = "Observe",
        Outcome = acted ? "Performed" : "NoChange",
    };

    private static CommandReply From(ResponseResult result) => new()
    {
        Acted = result.Acted,
        Refused = result.Refused,
        Rung = result.Rung.ToString(),
        Message = result.Message,
        Outcome = result.Outcome.ToString(),
    };

    /// <summary>The vault answers with its own result type, which reports Success rather than an
    /// outcome ladder. Mapped here so the dashboard has one reply shape to render.</summary>
    private static CommandReply FromVault(QuarantineResult result) => new()
    {
        Acted = result.Success,
        Refused = !result.Success,
        Rung = "Quarantine",
        Message = result.Message,
        Outcome = result.Success ? "Performed" : "RefusedByOs",
    };

    // ------------------------------------------------------------------ commands

    private const double UnelevatedDismissalDays = 1;

    private static CommandReply Dismiss(GuardianService guardian, JsonElement? args, bool callerElevated)
    {
        var key = Required(args, "subjectKey");

        // Dismissal is the one command that does NOT require a live verdict: the user is saying
        // "stop telling me about this", and refusing because the finding has momentarily aged out
        // would make the button unreliable in exactly the situation it is pressed.
        //
        // That property is also what makes it a weapon, because a dismissal is NOT merely cosmetic:
        // Raise() returns on IsDismissed BEFORE it calls Respond(), so a dismissed subject is never
        // scored, never acted on and never ledgered. And subject keys are built from values a
        // caller supplies or already knows — "persist:" + Category|Location|Name for an autostart
        // it is about to create, or "proc:<pid>:<start ticks>" for a process it just started
        // suspended. So a finding can be silenced BEFORE the thing it would report exists.
        //
        // Rather than gate it outright — the "stop telling me about this" button has to keep
        // working for the person at the keyboard — an un-elevated dismissal is capped at a day.
        // Long enough to be useful, short enough that it cannot be a persistence primitive. The
        // 90-day option stays, behind consent.
        double? days = null;
        if (args is { } element && element.TryGetProperty("days", out var d) && d.ValueKind == JsonValueKind.Number)
            days = Math.Clamp(d.GetDouble(), 1, 90);

        if (!callerElevated && (days ?? UnelevatedDismissalDays) > UnelevatedDismissalDays)
            days = UnelevatedDismissalDays;

        guardian.Dismiss(key, days is { } value ? TimeSpan.FromDays(value) : null);
        return Ok(days is null ? "Hidden." : $"Hidden for {days:0} day(s).");
    }

    private static CommandReply Undismiss(GuardianService guardian, JsonElement? args)
    {
        guardian.Undismiss(Required(args, "subjectKey"));
        return Ok("Shown again.");
    }

    /// <summary>
    /// <see cref="RequiresElevation"/> in the shape the act command returns. Act's arms hand back a
    /// <see cref="ResponseResult"/> rather than a CommandReply, and the Threats page renders that
    /// record directly, so a refusal has to arrive as one too or it will not be shown.
    /// </summary>
    private static Guardian.ResponseResult Refuse(string what) => new()
    {
        Rung = Guardian.ResponseRung.Observe,
        Outcome = Guardian.ActionOutcome.RefusedNeedsElevation,
        Message = $"{what} needs administrator rights. Run HERO as an administrator to do this.",
    };

    private static CommandReply Allow(GuardianService guardian, JsonElement? args, bool callerElevated)
    {
        var subject = Resolve(guardian, args);
        var scopeText = Text(args, "scope");

        if (!Enum.TryParse<AllowScope>(scopeText, ignoreCase: true, out var scope))
            throw new InvalidOperationException($"'{scopeText}' is not an allow scope.");

        // An allowlist entry is the most durable way to disarm HERO for one binary: Hash scope
        // pins the file's SHA-256 for 365 days and marks the entity user-allowed in the baseline,
        // after which its signals are dropped. ReplaceSettings already refuses to accept a
        // wholesale allowlist over this pipe, for the stated reason that "an attacker could simply
        // post an allowlist naming their own binary" — and then this command accepted one entry at
        // a time with no check at all.
        //
        // RuleForEntity is left open deliberately: it silences ONE rule for one entity, which is
        // the "stop flagging this for that reason" button, and it does not pin a hash or grant a
        // path standing trust.
        if (!callerElevated && scope != AllowScope.RuleForEntity)
            return RequiresElevation($"Adding a lasting \"{scope}\" exception");

        // Which finding is being silenced. Only RuleForEntity uses it, and only RuleForEntity is
        // reachable unelevated — so this is the one string on the whole allow surface that an
        // ordinary user's click actually depends on.
        string ruleId = Text(args, "ruleId");

        var result = guardian.Allow(subject, scope, ruleId);
        return new CommandReply
        {
            Acted = result.Accepted,
            Refused = !result.Accepted,
            Rung = "Observe",
            Outcome = result.Accepted ? "Performed" : "Refused",
            Message = result.Reason,
        };
    }

    private static CommandReply Recheck(GuardianService guardian, JsonElement? args)
    {
        if (Resolve(guardian, args) is not PersistenceSubject persistence)
            throw new InvalidOperationException("Only a persistence finding can be rechecked.");

        var still = guardian.Recheck(persistence.Entry);
        return new CommandReply
        {
            Acted = true,
            Rung = "Observe",
            Outcome = "Performed",
            Entry = still,
            EntryGone = still is null,
            Message = still is null ? "The entry is gone."
                    : still.Enabled ? "The entry is still enabled."
                    : "The entry is present but disabled.",
        };
    }

    private static ResponseResult Act(GuardianService guardian, JsonElement? args, bool callerElevated)
    {
        var engine = guardian.Response
            ?? throw new InvalidOperationException("The response engine is not running.");

        var action = Required(args, "action").ToLowerInvariant();
        string incident = Text(args, "incident");
        if (incident.Length == 0) incident = $"user-{DateTime.UtcNow:yyyyMMddHHmmss}";
        string reason = Text(args, "reason");
        if (reason.Length == 0) reason = "Requested from the HERO dashboard.";

        // Undo names a recorded action rather than a subject, so it is the one command that does
        // not resolve a subject. (The claim that "the engine validates the id against its own
        // ledger" was never true; HeroPaths.IsSafeStateId now stops the id escaping the undo
        // directory, which is a different and narrower guarantee.)
        //
        // Elevated only. An undo record is replayed AS SYSTEM and restores whatever HERO removed —
        // the registry value, byte-for-byte with its original type, the scheduled task, the
        // quarantined sample, the firewall rule. The action ids are not secret either: the state
        // root grants Users read, so %ProgramData%\HERO\undo\ can simply be listed. Without this,
        // HERO is a persistence-restoration service for anyone signed in.
        if (action == "undo")
        {
            return callerElevated
                ? engine.Undo(Required(args, "actionId"))
                : Refuse("Reversing an action HERO has taken");
        }

        var subject = Resolve(guardian, args);

        // The user doing something about a finding is the strongest signal HERO ever gets that a
        // rule was right, and it was being thrown away. Recorded here rather than inside the
        // engine because this is the one place that knows the response came from a person: the
        // engine's own autonomous path runs through the same methods.
        //
        // Resolve() has already matched the subject against a verdict HERO currently holds, so
        // reaching this line is itself the proof that there is something real to attribute to.
        try
        {
            var acted = guardian.Verdicts.FirstOrDefault(v => v.Subject.Key == subject.Key);
            if (acted is not null)
                Guardian.OutcomeStore.Record(Guardian.OutcomeStore.KindAct, acted, callerElevated, action);
        }
        catch { /* recording an action must never prevent it */ }

        var outcome = Perform(guardian, engine, subject, action, incident, reason, callerElevated);

        // Re-check reality rather than assume the action worked. A persistence action changes the
        // very thing the inventory is built from, and the sweep that rebuilds it runs every ten
        // minutes — so without this the finding a user just removed stays on screen until then, which
        // is exactly how "Remove this auto-start" came to look broken. Asking for a fresh sweep also
        // means HERO never claims a removal succeeded on its own say-so: the finding disappears
        // because the entry is gone, not because a button was pressed.
        if (outcome.Acted && subject is PersistenceSubject)
        {
            try { _ = guardian.RescanPersistenceAsync(); }
            catch { /* the ten-minute sweep will catch up */ }
        }

        return outcome;
    }

    private static ResponseResult Perform(GuardianService guardian, Guardian.ResponseEngine engine,
                                          Subject subject, string action, string incident,
                                          string reason, bool callerElevated)
    {
        return subject switch
        {
            ProcessSubject p => action switch
            {
                "suspend" => engine.Suspend(p.Process, incident, reason, userInitiated: true),

                // Resume is containment REVERSAL. Its "always allowed - undoing containment is
                // never gated" rule was written when the only caller was in-process, i.e. the user
                // undoing their own click. Over the pipe it means any signed-in account can thaw a
                // process HERO froze.
                "resume" => callerElevated
                    ? engine.Resume(p.Process.Pid)
                    : Refuse("Resuming a process HERO suspended"),
                "blocknetwork" => engine.BlockNetwork(p.Process, incident, reason, userInitiated: true),
                "killtree" => engine.KillTree(p.Process, incident, reason, userInitiated: true),
                "quarantine" => engine.Quarantine(p.Process.ImagePath, incident, reason, userInitiated: true),
                _ => throw new InvalidOperationException($"'{action}' is not an action for a process."),
            },

            PersistenceSubject e => action switch
            {
                "removepersistence" => engine.RemovePersistence(e.Entry, incident, reason, userInitiated: true),
                "quarantine" => engine.Quarantine(e.Entry.ImagePath, incident, reason, userInitiated: true),
                _ => throw new InvalidOperationException($"'{action}' is not an action for an auto-start."),
            },

            _ => throw new InvalidOperationException("That finding cannot be acted on."),
        };
    }

    /// <summary>
    /// Persists settings on the service's behalf.
    ///
    /// The service is the sole writer of %ProgramData%\HERO, so the dashboard cannot save this
    /// file itself. What it can still do locally is the per-user half — the HKCU Run entry — which
    /// a LocalSystem service must NOT write, because SYSTEM's HKCU is not the user's.
    /// </summary>
    private static CommandReply SaveSettings(GuardianService guardian, JsonElement? args, bool callerElevated)
    {
        if (args is not { } element || !element.TryGetProperty("settings", out var payload))
            throw new InvalidOperationException("'settings' is required.");

        var incoming = payload.Deserialize<Core.HeroSettings>(GuardianProtocol.Json)
            ?? throw new InvalidOperationException("Settings could not be read.");

        var (accepted, message) = guardian.ReplaceSettings(incoming, callerElevated);
        return accepted
            ? Ok(message)
            : new CommandReply { Acted = false, Refused = true, Message = message };
    }

    /// <summary>
    /// Writes one cosmetic key into settings.json.
    ///
    /// Restricted to a named set. The client is asking the service to write into HERO's own
    /// settings file, and an unrestricted key/value write would let any interactive process set
    /// arbitrary keys there — including, once the schema grows, ones that mean something.
    /// </summary>
    private static CommandReply SaveRawSetting(GuardianService guardian, JsonElement? args)
    {
        string[] allowed = { "animationsEnabled", "resolveHostnames" };

        var key = Required(args, "key");
        if (!allowed.Contains(key, StringComparer.Ordinal))
            throw new InvalidOperationException($"'{key}' is not a settable preference.");

        if (args is not { } element
            || !element.TryGetProperty("value", out var raw)
            || raw.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidOperationException("'value' must be true or false.");
        }

        Core.RawSettings.Write(key, raw.GetBoolean());
        if (key == "resolveHostnames") guardian.Peers.ResolveHostnames = raw.GetBoolean();

        return Ok("Preference saved.");
    }

    // Both are containment reversal or evidence destruction, and both take an id the attacker can
    // enumerate: the payloads are closed to Users, but the manifests beside them are deliberately
    // readable so a person can see what was taken and why, and a manifest's filename IS the id.
    //
    // Restore moves a quarantined sample back to its original path. Delete destroys the sample and
    // the record of it — the one operation in HERO that intentionally loses data.

    private static CommandReply VaultRestore(GuardianService guardian, JsonElement? args, bool callerElevated)
        => callerElevated
            ? FromVault(guardian.Vault.Restore(Required(args, "id")))
            : RequiresElevation("Restoring a quarantined file");

    private static CommandReply VaultDelete(GuardianService guardian, JsonElement? args, bool callerElevated)
        => callerElevated
            ? FromVault(guardian.Vault.Delete(Required(args, "id")))
            : RequiresElevation("Permanently destroying a quarantined file");

    private static CommandReply ResetLearning()
    {
        bool wrote = OutcomeStore.ResetInfluence();
        return wrote
            ? Ok("HERO has forgotten what it learned.")
            : Ok("There was nothing to forget.", acted: false);
    }

    private static CommandReply RescanPersistence(GuardianService guardian)
    {
        _ = guardian.RescanPersistenceAsync();
        return Ok("Rescanning auto-starts.", acted: false);
    }
}
