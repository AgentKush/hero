using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Hero.Guardian;
using Microsoft.Win32;

namespace Hero.Core;

/// <summary>How HERO arranges to be running after the next logon.</summary>
internal enum StartupMethod
{
    None = 0,
    /// <summary>HKCU\...\CurrentVersion\Run. The only mechanism measured working unelevated.</summary>
    RegistryRun = 1,
    /// <summary>A logon-triggered task under \HERO. Implemented, but see the recommendation.</summary>
    ScheduledTask = 2,
    /// <summary>A shortcut in the per-user Startup folder. Detected, not created — see below.</summary>
    StartupShortcut = 3,
}

/// <summary>The health of whatever is (or is not) registered.</summary>
internal enum StartupHealth
{
    /// <summary>Nothing registered anywhere HERO knows to look.</summary>
    NotRegistered,
    /// <summary>Registered, pointing at this exact executable, and switched on.</summary>
    Healthy,
    /// <summary>Registered, but pointing somewhere else — the exe moved or was reinstalled.</summary>
    StalePath,
    /// <summary>Registered and correct, but the user switched it off in Task Manager.</summary>
    DisabledByUser,
    /// <summary>More than one mechanism is registered. Harmless but untidy and confusing.</summary>
    Conflicting,
    /// <summary>The registration could not be read. Never report this as "not registered".</summary>
    Unreadable,
}

/// <summary>What HERO found when it looked at its own logon registration.</summary>
internal sealed record StartupState
{
    internal required StartupHealth Health { get; init; }
    /// <summary>The mechanism actually in place, or None.</summary>
    internal required StartupMethod Method { get; init; }
    /// <summary>Every mechanism found registered, for the conflicting case.</summary>
    internal IReadOnlyList<StartupMethod> AllFound { get; init; } = Array.Empty<StartupMethod>();
    /// <summary>The command as stored, e.g. <c>"D:\...\HERO.exe" --tray</c>.</summary>
    internal string RegisteredCommand { get; init; } = "";
    /// <summary>Executable resolved out of <see cref="RegisteredCommand"/>.</summary>
    internal string RegisteredExePath { get; init; } = "";
    /// <summary>True when the registered exe is not the one currently running.</summary>
    internal bool PathIsStale { get; init; }
    /// <summary>True when the registered exe no longer exists on disk at all.</summary>
    internal bool RegisteredExeMissing { get; init; }
    /// <summary>A sentence for the UI. Always populated, including in the healthy case.</summary>
    internal string Detail { get; init; } = "";

    internal bool WillRunAtLogon => Health is StartupHealth.Healthy or StartupHealth.Conflicting;
}

/// <summary>Outcome of a register/unregister attempt.</summary>
internal sealed record StartupResult(bool Success, string Message)
{
    /// <summary>True when the operation failed specifically for want of administrator rights.</summary>
    internal bool NeedsElevation { get; init; }
    /// <summary>True when nothing needed doing. Success is also true.</summary>
    internal bool NoChange { get; init; }
}

/// <summary>One row of the mechanism comparison, for the settings UI.</summary>
internal sealed record StartupOption
{
    internal required StartupMethod Method { get; init; }
    internal required string Display { get; init; }
    internal required bool WorksUnelevated { get; init; }
    internal required bool Implemented { get; init; }
    internal IReadOnlyList<string> For { get; init; } = Array.Empty<string>();
    internal IReadOnlyList<string> Against { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Registers HERO to start at logon, without administrator rights, and knows how to take itself
/// back off again.
///
/// <para><b>The comparison, and the recommendation.</b> Three mechanisms are available to a
/// medium-integrity per-user app:</para>
///
/// <list type="number">
/// <item><b>HKCU Run key</b> — a single registry write. Measured working unelevated on this
/// machine. Launches after the shell is ready, at medium integrity, which is exactly the context
/// HERO wants. The user can see and disable it in Task Manager &gt; Startup, and Windows records
/// that decision in <c>Explorer\StartupApproved\Run</c>, which this class reads so the UI reflects
/// reality rather than assuming the entry is live.</item>
/// <item><b>Logon-triggered scheduled task</b> — richer (delay, restart-on-failure, battery
/// policy) and invisible to the Task Manager startup list, which is a drawback rather than a
/// feature for a tool asking to be trusted. <c>schtasks /Create /SC ONLOGON</c> was measured
/// returning "Access is denied" unelevated on this machine, even with an explicit <c>/RU</c>,
/// while <c>/SC ONCE</c> succeeded — so it is the logon trigger specifically that schtasks.exe
/// could not create. The adversarial critique is right that this tests schtasks.exe rather than
/// Windows: registering the same trigger through <c>ITaskFolder.RegisterTaskDefinition</c> with
/// <c>TASK_LOGON_INTERACTIVE_TOKEN</c> and <c>TASK_RUNLEVEL_LUA</c> is a different code path, and
/// that is the path implemented here. It has NOT been observed succeeding on this machine, so it
/// is offered but not defaulted to, and <see cref="Enable"/> verifies the task exists afterwards
/// rather than trusting a silent success.</item>
/// <item><b>Startup-folder shortcut</b> — equivalent in effect to the Run key and subject to the
/// same StartupApproved tombstone. Creating one needs IShellLink via raw COM for no benefit the
/// Run key does not already give, so it is DETECTED here (so HERO recognises one as itself if a
/// future installer writes it) but deliberately not created.</item>
/// </list>
///
/// <para><b>Recommendation: the HKCU Run key.</b> It is the only option with a measured success on
/// this machine, it is the one the user can find and switch off without HERO's cooperation, and a
/// startup mechanism that fails silently is worse than none at all.</para>
///
/// <para><b>Self-detection.</b> HERO's own Run entry is the single most predictable false positive
/// the product can generate, so <see cref="IsOwnStartupArtifact"/> exists and the persistence
/// scanner must consult it. The match is on the exact resolved executable path, never on the
/// value name: a Run value called "HERO" pointing at some other binary is not HERO, it is
/// something wearing HERO's name, and <see cref="IsImpersonation"/> says so.</para>
/// </summary>
internal static class StartupRegistration
{
    /// <summary>Value name in the Run key, task name stem, and shortcut stem.</summary>
    internal const string EntryName = "HERO";

    /// <summary>Argument HERO is launched with at logon: start hidden in the tray.</summary>
    internal const string TrayArgument = "--tray";

    internal const string RunKeySubPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    internal const string StartupApprovedRunSubPath =
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    internal const string StartupApprovedFolderSubPath =
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    /// <summary>
    /// The guardian service's key name. Lives here with the other names HERO answers to, because
    /// this class is the single place that decides what counts as HERO's own startup identity.
    /// </summary>
    internal const string ServiceName = "HeroGuardian";

    /// <summary>Fragment every service's registry location contains, used to qualify a name match.</summary>
    private const string ServiceKeyFragment = @"CurrentControlSet\Services";

    /// <summary>Own subfolder so an uninstall can remove HERO's tasks without guessing.</summary>
    internal const string TaskFolderName = "HERO";
    internal const string TaskName = "HERO Guardian";
    /// <summary>Full task path as the Task Scheduler and schtasks.exe report it.</summary>
    internal const string TaskFullPath = @"\HERO\HERO Guardian";

    /// <summary>Name of the shortcut HERO would recognise as its own, if one ever exists.</summary>
    internal const string ShortcutFileName = "HERO.lnk";

    // ------------------------------------------------------------ identity

    /// <summary>Full path of the running executable, or "" if the runtime will not say.</summary>
    internal static string ExePath
    {
        get
        {
            try { return Environment.ProcessPath ?? ""; }
            catch { return ""; }
        }
    }

    /// <summary>The exact string HERO writes into the Run key.</summary>
    internal static string ExpectedCommand => $"\"{ExePath}\" {TrayArgument}";

    internal static string ShortcutPath
    {
        get
        {
            try
            {
                var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                return string.IsNullOrEmpty(startup) ? "" : Path.Combine(startup, ShortcutFileName);
            }
            catch { return ""; }
        }
    }

    // ---------------------------------------------------- the comparison table

    /// <summary>The three mechanisms, with the reasons the recommendation went the way it did.</summary>
    internal static IReadOnlyList<StartupOption> Options { get; } = new StartupOption[]
    {
        new()
        {
            Method = StartupMethod.RegistryRun,
            Display = "Registry Run key (recommended)",
            WorksUnelevated = true,
            Implemented = true,
            For = new[]
            {
                "Measured working without administrator rights on this machine.",
                "Starts after the shell is ready, at medium integrity — what HERO wants.",
                "Visible in Task Manager > Startup, so the user can disable HERO without HERO's help.",
                "A single registry value: trivially and completely removable.",
            },
            Against = new[]
            {
                "Windows can mark it disabled in StartupApproved; HERO must read that, not assume.",
                "No launch delay, so HERO competes with everything else starting at logon.",
                "HERO's own persistence scan will see it — hence the self-detection below.",
            },
        },
        new()
        {
            Method = StartupMethod.ScheduledTask,
            Display = "Scheduled task with a logon trigger",
            WorksUnelevated = false,
            Implemented = true,
            For = new[]
            {
                "Supports a start delay, so HERO stays out of the logon storm.",
                "Survives being overlooked in Task Manager's startup list.",
                "Can restart HERO if it exits unexpectedly.",
            },
            Against = new[]
            {
                "schtasks.exe was measured refusing to create a logon trigger unelevated on this machine.",
                "The COM registration path may still work but has not been observed doing so here.",
                "Hidden from the Task Manager startup list — bad manners for a security tool.",
                "If it silently fails, HERO simply never starts, which is worse than not offering it.",
            },
        },
        new()
        {
            Method = StartupMethod.StartupShortcut,
            Display = "Shortcut in the Startup folder",
            WorksUnelevated = true,
            Implemented = false,
            For = new[]
            {
                "No registry write at all; the user can delete the file.",
                "Same StartupApproved tombstone semantics as the Run key.",
            },
            Against = new[]
            {
                "Creating a .lnk needs IShellLink through raw COM for no benefit over the Run key.",
                "A .lnk's target cannot be read back without the same COM, so self-detection is weaker.",
                "Detected here, deliberately not created.",
            },
        },
    };

    /// <summary>The recommended mechanism, with its reasoning attached.</summary>
    internal static StartupOption Recommended => Options[0];

    // ------------------------------------------------------------------ query

    /// <summary>
    /// Reports what is actually registered right now. Never throws. An unreadable location is
    /// reported as <see cref="StartupHealth.Unreadable"/>, never as "not registered" — the whole
    /// point of this class is that HERO should not tell the user it starts at logon when it does
    /// not, nor the reverse.
    /// </summary>
    internal static StartupState Query()
    {
        var found = new List<StartupMethod>();

        var run = QueryRunKey();
        if (run.Health != StartupHealth.NotRegistered) found.Add(StartupMethod.RegistryRun);

        var task = QueryScheduledTask();
        if (task.Health != StartupHealth.NotRegistered) found.Add(StartupMethod.ScheduledTask);

        var link = QueryShortcut();
        if (link.Health != StartupHealth.NotRegistered) found.Add(StartupMethod.StartupShortcut);

        if (found.Count == 0)
        {
            // Preserve an Unreadable verdict from any probe rather than flattening it to "no".
            var unreadable = new[] { run, task, link }.FirstOrDefault(s => s.Health == StartupHealth.Unreadable);
            return unreadable ?? new StartupState
            {
                Health = StartupHealth.NotRegistered,
                Method = StartupMethod.None,
                Detail = "HERO is not registered to start at logon.",
            };
        }

        // The Run key wins when several exist, because it is the one HERO writes by default and
        // the one the user can see.
        var primary = found.Contains(StartupMethod.RegistryRun) ? run
                    : found.Contains(StartupMethod.ScheduledTask) ? task
                    : link;

        if (found.Count > 1)
        {
            return primary with
            {
                Health = StartupHealth.Conflicting,
                AllFound = found,
                Detail = "HERO is registered to start at logon more than once ("
                       + string.Join(", ", found.Select(Describe))
                       + "). Only one is needed; the others can be removed.",
            };
        }

        return primary with { AllFound = found };
    }

    private static string Describe(StartupMethod m) => m switch
    {
        StartupMethod.RegistryRun => "registry Run key",
        StartupMethod.ScheduledTask => "scheduled task",
        StartupMethod.StartupShortcut => "Startup folder shortcut",
        _ => "none",
    };

    private static StartupState QueryRunKey()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeySubPath);
            if (key?.GetValue(EntryName)?.ToString() is not { Length: > 0 } command)
                return NotRegistered(StartupMethod.RegistryRun);

            var exe = ExtractExe(command);
            bool stale = !SamePath(exe, ExePath);
            bool missing = exe.Length > 0 && !FileExistsSafe(exe);
            bool disabled = IsTombstoneDisabled(StartupApprovedRunSubPath, EntryName);

            return new StartupState
            {
                Health = disabled ? StartupHealth.DisabledByUser
                       : stale ? StartupHealth.StalePath
                       : StartupHealth.Healthy,
                Method = StartupMethod.RegistryRun,
                RegisteredCommand = command,
                RegisteredExePath = exe,
                PathIsStale = stale,
                RegisteredExeMissing = missing,
                Detail = disabled
                    ? "HERO's startup entry exists but was switched off in Task Manager > Startup."
                    : stale
                        ? $"HERO's startup entry points at {exe}, but HERO is running from {ExePath}. "
                          + (missing ? "That file no longer exists." : "Re-register to fix it.")
                        : "HERO starts at logon via the registry Run key.",
            };
        }
        catch (System.Security.SecurityException) { return Unreadable(StartupMethod.RegistryRun); }
        catch (UnauthorizedAccessException) { return Unreadable(StartupMethod.RegistryRun); }
        catch { return Unreadable(StartupMethod.RegistryRun); }
    }

    private static StartupState QueryShortcut()
    {
        try
        {
            var path = ShortcutPath;
            if (path.Length == 0 || !File.Exists(path)) return NotRegistered(StartupMethod.StartupShortcut);

            bool disabled = IsTombstoneDisabled(StartupApprovedFolderSubPath, ShortcutFileName);
            return new StartupState
            {
                Health = disabled ? StartupHealth.DisabledByUser : StartupHealth.Healthy,
                Method = StartupMethod.StartupShortcut,
                RegisteredCommand = path,
                // The .lnk target is not resolved: that needs IShellLink, which HERO does not
                // declare. So this shortcut is recognised by its own path only, and a shortcut
                // named HERO.lnk pointing elsewhere would NOT be recognised as HERO's — which is
                // the safe direction to be wrong in.
                RegisteredExePath = "",
                Detail = disabled
                    ? "A HERO shortcut exists in the Startup folder but is switched off."
                    : "A HERO shortcut exists in the Startup folder.",
            };
        }
        catch { return Unreadable(StartupMethod.StartupShortcut); }
    }

    /// <summary>
    /// Windows records a user's Task Manager startup decision as a binary blob. Observed values:
    /// first byte 0x02 or 0x06 means enabled, 0x03 means the user disabled it. The widely-used
    /// test is the low bit — 0x03 has it set, 0x02 and 0x06 do not.
    /// </summary>
    private static bool IsTombstoneDisabled(string subPath, string valueName)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(subPath);
            if (key?.GetValue(valueName) is byte[] { Length: > 0 } b) return (b[0] & 0x01) != 0;
        }
        catch { }
        return false;
    }

    private static StartupState NotRegistered(StartupMethod m) => new()
    {
        Health = StartupHealth.NotRegistered,
        Method = m,
        Detail = "Not registered.",
    };

    private static StartupState Unreadable(StartupMethod m) => new()
    {
        Health = StartupHealth.Unreadable,
        Method = m,
        Detail = $"HERO could not read its own {Describe(m)} registration, so it cannot say whether it starts at logon.",
    };

    // ---------------------------------------------------------------- enable

    /// <summary>
    /// Brings the machine into line with <paramref name="settings"/>. Idempotent: safe to call on
    /// every start, which is also how a stale path heals itself after the executable moves.
    /// </summary>
    internal static StartupResult Reconcile(HeroSettings settings)
    {
        try
        {
            if (!settings.RunAtStartup) return DisableAll();

            var method = settings.StartupMethod == StartupMethod.None
                ? Recommended.Method
                : settings.StartupMethod;

            // userInitiated: false is the whole point of the distinction. Reconcile runs on every
            // start, so if it cleared the StartupApproved tombstone the way an explicit "turn this
            // on" does, a user who switched HERO off in Task Manager > Startup would find it
            // switched back on at the next logon, for ever. That would destroy the single property
            // this class's recommendation rests on: that the user can disable HERO without HERO's
            // cooperation. Reconcile heals a moved executable; it does not overrule a human.
            var result = Enable(method, userInitiated: false);

            // Whichever mechanism is in force, the other two must not linger. Two registrations
            // means two HEROs racing for the single-instance mutex at every logon.
            foreach (var other in new[] { StartupMethod.RegistryRun, StartupMethod.ScheduledTask, StartupMethod.StartupShortcut })
                if (other != method) Disable(other);

            return result;
        }
        catch (Exception ex)
        {
            return new StartupResult(false, "Startup registration failed: " + ex.Message);
        }
    }

    /// <summary>
    /// Registers HERO to start at logon by <paramref name="method"/>. Idempotent, and verifies
    /// the registration afterwards rather than trusting the write to have taken.
    /// </summary>
    /// <remarks>
    /// This overload is the user-initiated one: the settings toggle. It clears a Task Manager
    /// "disabled" tombstone, because the user has just asked for the opposite. Automatic callers
    /// must use the two-argument form with <c>userInitiated: false</c>.
    /// </remarks>
    internal static StartupResult Enable(StartupMethod method) => Enable(method, userInitiated: true);

    /// <summary>
    /// Registers HERO to start at logon.
    /// </summary>
    /// <param name="userInitiated">
    /// True only when a human just asked for this. It gates one thing: clearing the
    /// <c>Explorer\StartupApproved\Run</c> tombstone that records a Task Manager "disable HERO"
    /// decision. Clearing it on an automatic reconciliation would silently undo that decision at
    /// every logon.
    /// </param>
    internal static StartupResult Enable(StartupMethod method, bool userInitiated)
    {
        if (ExePath.Length == 0)
            return new StartupResult(false, "HERO cannot determine its own executable path, so it cannot register for startup.");

        return method switch
        {
            StartupMethod.RegistryRun => EnableRunKey(userInitiated),
            StartupMethod.ScheduledTask => EnableScheduledTask(),
            StartupMethod.StartupShortcut => new StartupResult(false,
                "HERO does not create Startup-folder shortcuts. Creating one needs IShellLink through raw COM "
                + "and offers nothing the registry Run key does not already do. Use the Run key instead."),
            _ => new StartupResult(false, "No startup mechanism selected."),
        };
    }

    private static StartupResult EnableRunKey(bool userInitiated)
    {
        try
        {
            var want = ExpectedCommand;

            using var key = Registry.CurrentUser.CreateSubKey(RunKeySubPath, writable: true);
            if (key is null)
                return new StartupResult(false, "The registry Run key could not be opened for writing.");

            var existing = key.GetValue(EntryName)?.ToString();
            bool alreadyCorrect = string.Equals(existing, want, StringComparison.OrdinalIgnoreCase);

            if (!alreadyCorrect) key.SetValue(EntryName, want, RegistryValueKind.String);

            // Turning startup on is an explicit request, so an old Task Manager "disabled"
            // tombstone is cleared. Deleting the value is how Windows represents "never
            // disabled", which is cleaner than writing an enabled blob of our own. An automatic
            // reconciliation must NOT do this — see Enable(method, userInitiated).
            bool wasTombstoned = userInitiated && ClearTombstone(StartupApprovedRunSubPath, EntryName);

            var after = Query();
            if (after.Method != StartupMethod.RegistryRun || after.Health is StartupHealth.NotRegistered or StartupHealth.Unreadable)
                return new StartupResult(false, "HERO wrote its startup entry but could not read it back. Startup is not confirmed.");

            // Reporting "HERO will start at logon" while Windows holds a disable tombstone would
            // be exactly the lie Query() exists to prevent, so say what is actually true.
            if (after.Health is StartupHealth.DisabledByUser)
                return new StartupResult(true,
                    "HERO's startup entry is in place, but it is switched off in Task Manager > Startup, "
                    + "so HERO will not actually start at logon until you switch it back on there.")
                { NoChange = alreadyCorrect };

            return new StartupResult(true,
                alreadyCorrect && !wasTombstoned
                    ? "HERO was already set to start at logon."
                    : "HERO will now start at logon (registry Run key).")
            { NoChange = alreadyCorrect && !wasTombstoned };
        }
        catch (UnauthorizedAccessException ex)
        {
            return new StartupResult(false, "Access denied writing HKCU Run: " + ex.Message);
        }
        catch (Exception ex)
        {
            return new StartupResult(false, "Could not write the startup entry: " + ex.Message);
        }
    }

    private static bool ClearTombstone(string subPath, string valueName)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(subPath, writable: true);
            if (key?.GetValue(valueName) is null) return false;
            key.DeleteValue(valueName, throwOnMissingValue: false);
            return true;
        }
        catch { return false; }
    }

    // --------------------------------------------------------------- disable

    /// <summary>Removes every HERO startup registration. Used by the uninstall path.</summary>
    internal static StartupResult DisableAll()
    {
        var messages = new List<string>();
        bool ok = true;
        foreach (var m in new[] { StartupMethod.RegistryRun, StartupMethod.ScheduledTask, StartupMethod.StartupShortcut })
        {
            var r = Disable(m);
            if (!r.Success) { ok = false; messages.Add(r.Message); }
        }
        return ok
            ? new StartupResult(true, "HERO will not start at logon.")
            : new StartupResult(false, string.Join(" ", messages));
    }

    /// <summary>Removes one registration. Succeeds (with NoChange) when there was nothing to remove.</summary>
    internal static StartupResult Disable(StartupMethod method)
    {
        switch (method)
        {
            case StartupMethod.RegistryRun:
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(RunKeySubPath, writable: true);
                    bool had = key?.GetValue(EntryName) is not null;
                    key?.DeleteValue(EntryName, throwOnMissingValue: false);
                    // Leaving the tombstone behind would make a later re-register look disabled.
                    ClearTombstone(StartupApprovedRunSubPath, EntryName);
                    return new StartupResult(true, had ? "Startup entry removed." : "No startup entry to remove.")
                    { NoChange = !had };
                }
                catch (Exception ex)
                {
                    return new StartupResult(false, "Could not remove the startup entry: " + ex.Message);
                }

            case StartupMethod.ScheduledTask:
                return DisableScheduledTask();

            case StartupMethod.StartupShortcut:
                try
                {
                    var path = ShortcutPath;
                    if (path.Length == 0 || !File.Exists(path))
                        return new StartupResult(true, "No Startup shortcut to remove.") { NoChange = true };
                    File.Delete(path);
                    ClearTombstone(StartupApprovedFolderSubPath, ShortcutFileName);
                    return new StartupResult(true, "Startup shortcut removed.");
                }
                catch (Exception ex)
                {
                    return new StartupResult(false, "Could not remove the Startup shortcut: " + ex.Message);
                }

            default:
                return new StartupResult(true, "Nothing to do.") { NoChange = true };
        }
    }

    // ----------------------------------------------------------- self-identity

    /// <summary>
    /// True when a persistence artifact is HERO's own startup registration.
    ///
    /// The persistence scanner MUST call this and exclude the match, otherwise HERO reports itself
    /// as persistence on every sweep — the one false positive guaranteed to happen on every
    /// machine. The test is the resolved executable path, never the value name: an entry called
    /// "HERO" pointing at something else is not HERO.
    /// </summary>
    /// <param name="location">Registry key path, folder, or "Task Scheduler".</param>
    /// <param name="name">Value name, file name, or task path.</param>
    /// <param name="target">The raw command line or target as stored.</param>
    internal static bool IsOwnStartupArtifact(string? location, string? name, string? target)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var self = ExePath;
        if (self.Length == 0) return false;

        // Run key: an HKCU Run-family key, our value name, our exe.
        if (name.Equals(EntryName, StringComparison.OrdinalIgnoreCase)
            && location is { Length: > 0 } loc
            && IsCurrentUserRunLocation(loc))
        {
            return SamePath(ExtractExe(target ?? ""), self);
        }

        // Scheduled task: our full task path, our exe.
        if ((name.Equals(TaskFullPath, StringComparison.OrdinalIgnoreCase)
             || name.Equals(TaskFullPath.TrimStart('\\'), StringComparison.OrdinalIgnoreCase))
            && SamePath(ExtractExe(target ?? ""), self))
        {
            return true;
        }

        // Service: HERO's own service key, pointing at a HERO binary we recognise.
        //
        // "Recognise" is deliberately wider here than the running executable. A service
        // registration is machine-wide and outlives any one build: a developer running the
        // bin\Debug copy while the installed service points at Program Files is the ordinary
        // case, not an impostor, and raising an impersonation signal for it would be a false
        // alarm on the author's own machine. The install directory recorded in the integrity
        // manifest is the second anchor, and that file cannot be written without elevation
        // (verified), so it is a stronger claim than the path of whatever happens to be running.
        if (name.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)
            && location is { Length: > 0 } serviceLocation
            && serviceLocation.Contains(ServiceKeyFragment, StringComparison.OrdinalIgnoreCase))
        {
            string exe = ExtractExe(target ?? "");
            if (SamePath(exe, self)) return true;

            // A FILE HERO RECORDED, not merely a file in HERO's folder. The second anchor used to be
            // "inside the recorded install directory", which handed HERO's identity to anything an
            // attacker could drop there: evil.exe beside HERO.exe, the service key repointed at it,
            // and this method would call the result ours — no persistence finding, and
            // IsImpersonation silent too. Verified before the change that it did exactly that.
            if (Service.SelfIntegrity.IsRecordedFile(exe)) return true;
        }

        // Startup shortcut: the .lnk at our exact path. The target cannot be resolved without
        // IShellLink, so this is a path match on the shortcut file itself and nothing more.
        var link = ShortcutPath;
        if (link.Length > 0
            && name.Equals(ShortcutFileName, StringComparison.OrdinalIgnoreCase)
            && (SamePath(target ?? "", link) || SamePath(Path.Combine(location ?? "", name), link)))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// True for any HKCU autorun key HERO's own entry could plausibly be read out of.
    ///
    /// This is deliberately loose about WHICH Run key, because the strong condition is applied
    /// separately and always: the stored command must resolve to this exact executable. Being
    /// loose here is therefore not a hole, whereas being strict was a false positive: the
    /// persistence scanner reads every Run key through both registry views and appends
    /// " (WOW64)" to the 32-bit row's Location, and it enumerates RunOnce, RunServices and
    /// Policies\Explorer\Run alongside Run. An exact <c>EndsWith("CurrentVersion\Run")</c> test
    /// failed on all of those, which made HERO report its own startup entry as persistence — and,
    /// worse, made <see cref="IsImpersonation"/> accuse it of wearing HERO's name.
    /// </summary>
    private static bool IsCurrentUserRunLocation(string location)
    {
        var loc = location.Replace('/', '\\').Replace(" (WOW64)", "", StringComparison.OrdinalIgnoreCase).TrimEnd('\\');

        if (!loc.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase)
            && !loc.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
            return false;

        // HERO only ever writes plain Run, but a stale entry from a hand edit or an older build
        // can sit in any of these, and recognising it as ours is always the safer error.
        foreach (var suffix in new[] { @"\Run", @"\RunOnce", @"\RunOnceEx", @"\RunServices", @"\RunServicesOnce" })
            if (loc.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return true;

        return false;
    }

    /// <summary>Convenience overload for the persistence scanner.</summary>
    internal static bool IsOwnStartupArtifact(PersistenceEntry entry) =>
        IsOwnStartupArtifact(entry.Location, entry.Name, entry.Target);

    /// <summary>
    /// True when something has taken HERO's startup identity — a Run value or task called "HERO"
    /// whose executable is NOT this one. That is not a false positive to suppress, it is a signal
    /// in its own right, so it is reported separately from <see cref="IsOwnStartupArtifact"/>.
    /// A stale entry left behind by a previous install of HERO looks identical, which is why this
    /// is evidence for the scorer rather than grounds for action.
    /// </summary>
    internal static bool IsImpersonation(string? location, string? name, string? target)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        bool wearsOurName = name.Equals(EntryName, StringComparison.OrdinalIgnoreCase)
                         || name.Equals(ShortcutFileName, StringComparison.OrdinalIgnoreCase)
                         || name.Equals(TaskFullPath, StringComparison.OrdinalIgnoreCase)
                         || name.Equals(ServiceName, StringComparison.OrdinalIgnoreCase);
        return wearsOurName && !IsOwnStartupArtifact(location, name, target);
    }

    // ---------------------------------------------------------------- helpers

    private static bool FileExistsSafe(string path)
    {
        try { return File.Exists(path); } catch { return false; }
    }

    /// <summary>
    /// True when <paramref name="path"/> sits inside <paramref name="directory"/>. Compared after
    /// full-path resolution so that "..\HERO\HERO.exe" cannot masquerade as being outside, and
    /// anchored on a trailing separator so that "C:\Program Files\HERO Extra" is not treated as
    /// being inside "C:\Program Files\HERO".
    /// </summary>
    /// <summary>Full-path comparison that never throws on a malformed stored path.</summary>
    internal static bool SamePath(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        try
        {
            return string.Equals(Path.GetFullPath(a.Trim()), Path.GetFullPath(b.Trim()),
                                 StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Pulls the executable out of a stored command. HERO always writes a quoted path, so the
    /// quoted case is the one that matters; the unquoted fallbacks exist because a previous
    /// version, a hand edit, or an impostor may not have been so tidy.
    /// </summary>
    internal static string ExtractExe(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return "";
        var s = command.Trim();

        if (s.StartsWith('"'))
        {
            int close = s.IndexOf('"', 1);
            return close > 1 ? s[1..close] : s.Trim('"');
        }

        int ext = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (ext > 0) return s[..(ext + 4)];

        int space = s.IndexOf(' ');
        return space > 0 ? s[..space] : s;
    }

    // ------------------------------------------------- scheduled task via COM
    //
    // Late-bound COM against Schedule.Service: no interop assembly, no NuGet, no TLB. Two traps
    // are handled below and both produce silent wrong answers if missed:
    //   * ITaskCollection/ITaskFolderCollection Item is a parameterised PROPERTY. Calling it with
    //     BindingFlags.InvokeMethod throws DISP_E_MEMBERNOTFOUND, which — if swallowed — reads as
    //     "no tasks", i.e. a clean machine.
    //   * Those collections are 1-BASED.
    // Neither is needed for the register/query path below (which addresses tasks by name), but the
    // helpers are here because getting them wrong is the documented way to lose an afternoon.

    private const int TaskTriggerLogon = 9;
    private const int TaskActionExec = 0;
    private const int TaskCreateOrUpdate = 6;
    private const int TaskLogonInteractiveToken = 3;
    /// <summary>TASK_RUNLEVEL_LUA. Never HIGHEST: that is permanent silent elevation at logon.</summary>
    private const int TaskRunLevelLua = 0;
    private const int TaskInstancesIgnoreNew = 2;

    private const int ErrorAccessDenied = unchecked((int)0x80070005);
    private const int ErrorFileNotFound = unchecked((int)0x80070002);
    private const int ErrorPathNotFound = unchecked((int)0x80070003);

    private static object? NewScheduler()
    {
        var t = Type.GetTypeFromProgID("Schedule.Service");
        if (t is null) return null;
        var svc = Activator.CreateInstance(t);
        if (svc is null) return null;
        // Connect(serverName, user, domain, password) — all null means "this machine, me".
        Call(svc, "Connect", null, null, null, null);
        return svc;
    }

    private static object? Get(object o, string name, params object?[] args) =>
        o.GetType().InvokeMember(name, BindingFlags.GetProperty, null, o, args);

    private static void Set(object o, string name, object? value) =>
        o.GetType().InvokeMember(name, BindingFlags.SetProperty, null, o, new[] { value });

    private static object? Call(object o, string name, params object?[] args) =>
        o.GetType().InvokeMember(name, BindingFlags.InvokeMethod, null, o, args);

    /// <summary>Indexer access for the Task Scheduler collections. 1-based, and a PROPERTY.</summary>
    private static object? Idx(object collection, int oneBasedIndex) =>
        collection.GetType().InvokeMember("Item", BindingFlags.GetProperty, null, collection,
                                          new object[] { oneBasedIndex });

    private static string CurrentUserName()
    {
        try { return WindowsIdentity.GetCurrent().Name; }
        catch { return Environment.UserDomainName + "\\" + Environment.UserName; }
    }

    private static StartupResult EnableScheduledTask()
    {
        object? svc = null;
        try
        {
            svc = NewScheduler();
            if (svc is null)
                return new StartupResult(false, "The Task Scheduler service could not be reached.");

            object root = Call(svc, "GetFolder", "\\")!;

            // Late-bound calls surface every failure wrapped in TargetInvocationException, so a
            // bare `catch (COMException)` here would never fire and the folder would never be
            // created. IsNotFound unwraps before classifying.
            object? folder = null;
            try { folder = Call(root, "GetFolder", TaskFolderName); }
            catch (Exception ex) when (IsNotFound(ex)) { }
            folder ??= Call(root, "CreateFolder", TaskFolderName, null)!;

            object def = Call(svc, "NewTask", 0)!;

            object reg = Get(def, "RegistrationInfo")!;
            Set(reg, "Author", EntryName);
            Set(reg, "Description", "Starts HERO in the notification area at logon.");

            object settings = Get(def, "Settings")!;
            // Defaults that would break a tray guardian, each corrected deliberately:
            Set(settings, "DisallowStartIfOnBatteries", false); // default true — would skip on a laptop
            Set(settings, "StopIfGoingOnBatteries", false);
            Set(settings, "ExecutionTimeLimit", "PT0S");        // default PT72H would kill HERO after 3 days
            Set(settings, "StartWhenAvailable", true);
            Set(settings, "MultipleInstances", TaskInstancesIgnoreNew);
            Set(settings, "AllowDemandStart", true);
            Set(settings, "Enabled", true);
            // Not hidden. A security tool that conceals its own scheduled task is indistinguishable
            // from the thing it is hunting, and the user must be able to find and delete it.
            Set(settings, "Hidden", false);

            object principal = Get(def, "Principal")!;
            Set(principal, "Id", "Author");
            Set(principal, "UserId", CurrentUserName());
            Set(principal, "LogonType", TaskLogonInteractiveToken);
            Set(principal, "RunLevel", TaskRunLevelLua);

            object triggers = Get(def, "Triggers")!;
            object trigger = Call(triggers, "Create", TaskTriggerLogon)!;
            Set(trigger, "Id", "HeroLogon");
            Set(trigger, "UserId", CurrentUserName());
            // 20 seconds: past the worst of the logon storm, but short enough that the first
            // persistence sweep still happens within half a minute of the desktop appearing.
            Set(trigger, "Delay", "PT20S");
            Set(trigger, "Enabled", true);

            object actions = Get(def, "Actions")!;
            object action = Call(actions, "Create", TaskActionExec)!;
            Set(action, "Path", ExePath);
            Set(action, "Arguments", TrayArgument);
            var dir = Path.GetDirectoryName(ExePath);
            if (!string.IsNullOrEmpty(dir)) Set(action, "WorkingDirectory", dir);

            // TASK_CREATE_OR_UPDATE gives idempotency for free.
            Call(folder, "RegisterTaskDefinition", TaskName, def, TaskCreateOrUpdate,
                 null, null, TaskLogonInteractiveToken, null);

            // Never trust a silent success. If the task cannot be read back, HERO would otherwise
            // believe it starts at logon and simply never start.
            var after = QueryScheduledTask();
            if (after.Health is StartupHealth.NotRegistered or StartupHealth.Unreadable)
                return new StartupResult(false,
                    "The scheduled task appeared to register but could not be read back. Use the registry Run key instead.");

            return new StartupResult(true, "HERO will now start at logon (scheduled task \\HERO\\HERO Guardian).");
        }
        catch (Exception ex)
        {
            var real = Unwrap(ex);
            bool denied = real is UnauthorizedAccessException
                       || real is COMException { HResult: ErrorAccessDenied }
                       || real.HResult == ErrorAccessDenied;

            return denied
                ? new StartupResult(false, ElevationMessage("access denied")) { NeedsElevation = true }
                : new StartupResult(false, "The logon task could not be created: " + real.Message
                                         + " Use the registry Run key instead.");
        }
        finally
        {
            ReleaseCom(svc);
        }
    }

    private static string ElevationMessage(string detail) =>
        $"Windows refused to create a logon-triggered task without administrator rights ({detail}). "
        + "This machine measured the same refusal from schtasks.exe. Use the registry Run key, which needs no elevation.";

    private static StartupResult DisableScheduledTask()
    {
        object? svc = null;
        try
        {
            svc = NewScheduler();
            if (svc is null) return new StartupResult(true, "Task Scheduler unavailable; nothing removed.") { NoChange = true };

            object root = Call(svc, "GetFolder", "\\")!;

            object? folder = null;
            try { folder = Call(root, "GetFolder", TaskFolderName); }
            catch (Exception ex) when (IsNotFound(ex)) { }

            if (folder is null)
                return new StartupResult(true, "No scheduled task to remove.") { NoChange = true };

            bool removed = false;
            try { Call(folder, "DeleteTask", TaskName, 0); removed = true; }
            catch (Exception ex) when (IsNotFound(ex)) { }

            // Remove HERO's folder too, so an uninstall leaves nothing behind. This fails
            // harmlessly if the user has put something else in there.
            try { Call(root, "DeleteFolder", TaskFolderName, 0); } catch { }

            return new StartupResult(true, removed ? "Scheduled task removed." : "No scheduled task to remove.")
            { NoChange = !removed };
        }
        catch (Exception ex)
        {
            return new StartupResult(false, "Could not remove the scheduled task: " + Unwrap(ex).Message);
        }
        finally
        {
            ReleaseCom(svc);
        }
    }

    private static StartupState QueryScheduledTask()
    {
        object? svc = null;
        try
        {
            svc = NewScheduler();
            if (svc is null) return NotRegistered(StartupMethod.ScheduledTask);

            object root = Call(svc, "GetFolder", "\\")!;

            object folder;
            try { folder = Call(root, "GetFolder", TaskFolderName)!; }
            catch (Exception ex) when (IsNotFound(ex)) { return NotRegistered(StartupMethod.ScheduledTask); }

            object task;
            try { task = Call(folder, "GetTask", TaskName)!; }
            catch (Exception ex) when (IsNotFound(ex)) { return NotRegistered(StartupMethod.ScheduledTask); }

            bool enabled = Get(task, "Enabled") is bool b && b;

            object def = Get(task, "Definition")!;
            object actions = Get(def, "Actions")!;
            int count = Get(actions, "Count") is int c ? c : 0;

            string exe = "", args = "";
            if (count > 0 && Idx(actions, 1) is { } first)
            {
                exe = Get(first, "Path")?.ToString() ?? "";
                args = Get(first, "Arguments")?.ToString() ?? "";
            }

            bool stale = !SamePath(exe, ExePath);
            return new StartupState
            {
                Health = !enabled ? StartupHealth.DisabledByUser
                       : stale ? StartupHealth.StalePath
                       : StartupHealth.Healthy,
                Method = StartupMethod.ScheduledTask,
                RegisteredCommand = (exe.Length > 0 ? $"\"{exe}\"" : "") + (args.Length > 0 ? " " + args : ""),
                RegisteredExePath = exe,
                PathIsStale = stale,
                RegisteredExeMissing = exe.Length > 0 && !FileExistsSafe(exe),
                Detail = !enabled
                    ? "HERO's logon task exists but is disabled."
                    : stale
                        ? $"HERO's logon task points at {exe}, but HERO is running from {ExePath}."
                        : "HERO starts at logon via a scheduled task.",
            };
        }
        catch
        {
            // The task tree could not be walked. Reporting "not registered" here would be a lie
            // of exactly the kind this class exists to avoid.
            return Unreadable(StartupMethod.ScheduledTask);
        }
        finally
        {
            ReleaseCom(svc);
        }
    }

    private static bool IsNotFound(Exception ex)
    {
        var e = Unwrap(ex);
        return e is COMException { HResult: ErrorFileNotFound or ErrorPathNotFound }
            || e is FileNotFoundException
            || e is DirectoryNotFoundException;
    }

    private static Exception Unwrap(Exception ex) =>
        ex is TargetInvocationException { InnerException: { } inner } ? inner : ex;

    private static void ReleaseCom(object? o)
    {
        try { if (o is not null && Marshal.IsComObject(o)) Marshal.FinalReleaseComObject(o); }
        catch { /* the RCW is collectable either way */ }
    }
}
