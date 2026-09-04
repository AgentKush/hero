namespace Hero.Maintenance;

/// <summary>
/// Windows shell and privacy traces: the file-backed half of CCleaner 7's twenty "Windows" rules.
///
/// Only ten of those twenty describe files at all, and after removing what
/// <see cref="DiskCleanup"/> already owns and what is unsafe to port, seven rows survive. The
/// reasoning for every exclusion is recorded here rather than in a survey document, because the
/// next person to read ccleaner.ini will otherwise re-derive the same traps.
///
/// EXCLUDED — REGISTRY ONLY. Seven rules contain RegKey entries and zero FileKey entries, so
/// there is nothing for a <see cref="CleanupTarget"/> to enumerate: Run (RunMRU), Search
/// Assistant Autocomplete (ACMru), Other Explorer MRUs (twenty keys, several of them per-VALUE
/// deletions such as <c>MostRecentApplication|Name</c> — a granularity this type could not
/// express even if registry support existed), Tray Notifications Cache (IconStreams),
/// Window Size/Location Cache (StreamMRU/Streams), Menu Order Cache, and User Assist History.
/// DNS Cache is excluded for a different reason: it is <c>Action1=CleanDNSCache</c>, an in-memory
/// flush of the Dnscache service with no path and no bytes, so it could never belong in a
/// size-driven catalogue at all.
///
/// EXCLUDED — ALREADY OWNED BY <see cref="DiskCleanup"/>, not re-added here: the thumbnail and
/// icon caches (shell.thumbnail-cache), the font cache, Prefetch — which HERO deliberately
/// measures and refuses to clean, so porting CCleaner's 14-day <c>FileDeleteIfOlderThan</c> gate
/// would reverse a decision that file argues for at length — user and kernel crash dumps,
/// both WER queues, CBS/DISM logs, and %windir%\Panther. That last one matters: CCleaner's own
/// rule names <c>setupact.log</c> exactly and therefore MISSES the 204.98 MB
/// <c>SetupAct_2025-11-09-23-38-02.log</c> sitting in Panther, whereas logs.panther takes the
/// whole directory and already claims all 928.48 MB measured there today. A "biggest find"
/// target for it would have been a pure duplicate.
///
/// ONE GAP FOUND AND LEFT ALONE: dumps.kernel names Minidump and LiveKernelReports but not
/// <c>%windir%\MEMORY.DMP</c>, which on a 64 GB machine can be 64 GB by itself. Adding it here
/// would put a second row called "kernel crash dumps" in front of the user, so it is recorded
/// as a one-path addition for the owner of DiskCleanup.cs instead.
///
/// EXCLUDED — DANGEROUS TO PORT. Three rules are omitted outright:
///
/// 1. Start Menu Shortcuts and Desktop Shortcuts. Their FileKeys are <c>%StartMenu%|*.lnk|RECURSE</c>
///    and <c>%Desktop%|*.lnk|RECURSE</c> — every shortcut on the machine. The entire safety of
///    those rules lives in <c>OnFile1=*.lnk|FileDeleteInvalidShortcuts</c>, a per-file predicate
///    that resolves each link and deletes only when its target is gone. <see cref="CleanupTarget.Filter"/>
///    is the right hook, but there is no in-box managed shortcut resolver — it needs IShellLink
///    COM interop or a hand-written MS-SHLLINK parser, and NuGet is banned here. Measured payoff
///    for getting that right: 243 .lnk files totalling 0.32 MB. Getting it wrong erases the
///    user's Start Menu and Desktop. %Desktop% is also already on the
///    <see cref="ProtectedPaths"/> floor, which is the clearest possible signal that a RECURSE
///    glob rooted there does not belong in this catalogue.
///
/// 2. IIS Log Files. CCleaner gates it on <c>HKLM\System\CurrentControlSet\Services\w3svc</c>,
///    which is absent here, and its first FileKey is <c>%SystemDirectory%\LogFiles|*.*|RECURSE</c>
///    — not an IIS path on a machine without IIS. HERO has no registry gate, and the caller only
///    drops targets whose paths are ALL missing, so that FileKey would keep the row alive against
///    C:\Windows\System32\LogFiles: 70.13 MB containing WMI\RtBackup (the live ETW real-time
///    session store), the actively traced NT Kernel Logger.etl and NtfsLog.etl.00N segments, and
///    the startup-repair logs. <see cref="ProtectedPaths"/> would refuse the deletions at
///    execution time because System32 is on the floor, but the row would still have been measured
///    and shown as reclaimable — the row would be a lie even though the delete would fail. Only
///    the inetpub FileKey is ported below.
///
/// 3. Chkdsk File Fragments (<c>%SystemDrive%|File*.chk</c>). <see cref="FileWalk"/> enumerates
///    with <c>RecurseSubdirectories = true</c> unconditionally and there is no way to ask a
///    target for a single non-recursive directory, so naming a volume root would walk the whole
///    of C: to find the zero matches actually present. The same recursion rule is why
///    <c>%windir%|*.log</c> (0.45 MB, non-recursive by design in the ini) is not ported either:
///    as a HERO target it would sweep every .log under the entire Windows tree.
/// </summary>
internal static class ShellTraceTargets
{
    private static string Local => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Roaming => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string WinDir => Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static string ProgramData => Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    /// <summary>
    /// The system drive WITH its trailing separator. Deliberately not
    /// <c>Environment.GetEnvironmentVariable("SystemDrive")</c>, which yields "C:" — and
    /// <c>Path.Combine("C:", "inetpub")</c> produces the drive-RELATIVE path "C:inetpub", which
    /// resolves against the process's per-drive current directory rather than the root.
    /// </summary>
    private static string SystemDrive => Path.GetPathRoot(WinDir) ?? @"C:\";

    /// <summary>
    /// Shell traces first, then the log directories, because the shell rows are the ones the user
    /// has an opinion about. The caller drops targets whose paths are all absent, so rows are
    /// emitted unconditionally — the IIS row below exists on this machine only as a refusal.
    /// </summary>
    internal static IEnumerable<CleanupTarget> Enumerate()
    {
        // ------------------------------------------------------------------ jump lists

        string recent = Path.Combine(Roaming, "Microsoft", "Windows", "Recent");
        string automatic = Path.Combine(recent, "AutomaticDestinations");
        string custom = Path.Combine(recent, "CustomDestinations");

        // 75 files, 0.71 MB measured: 55 .automaticDestinations-ms (0.58 MB) and 20
        // .customDestinations-ms (0.13 MB). CCleaner implements this as Action1=TaskbarJumpLists
        // with no FileKey at all — an internal shell API — but the backing store is these two
        // ordinary directories, so HERO can do it as a plain file target.
        //
        // The two subdirectories are named individually and their parent %Recent% never is. That
        // is not tidiness: %Recent% is the recent-documents store and these live INSIDE it, so a
        // target rooted one level up would take both traces at once under a row labelled for only
        // one of them.
        //
        // Lock-tested here: the three largest .automaticDestinations-ms files all opened for
        // exclusive ReadWrite, so unlike the thumbnail cache these are not pinned open by
        // explorer.exe and the reported reclaim should actually be achieved.
        yield return new CleanupTarget
        {
            Id = "shell.jumplists",
            Category = CleanupCategory.ShellCache,
            DisplayName = "Taskbar and Start jump lists",
            Description = "The recent-file lists that appear when you right-click an app on the " +
                          "taskbar or in Start, plus anything you pinned inside one. 0.71 MB here — " +
                          "this is a privacy and tidiness action, not a space one.",
            Paths = new[] { automatic, custom },
            Risk = CleanupRisk.Medium,
            Tier = AutomationTier.Prompt,
            WhatBreaksIfWrong = "Every pinned app forgets its recent files, and any document you " +
                                "pinned into a jump list is unpinned — pins have no undo.",
            RestoreHint = "The recent-file entries rebuild as you reopen files. Pinned entries do " +
                          "not come back; you have to pin them again.",
        };

        // ----------------------------------------------------------- recent documents

        // Measured: exactly one .lnk (ms-screenclip---source=PrintScreen.lnk, ~0 MB) directly in
        // %Recent%, plus the two jump-list subdirectories above. The payoff is nil; the reason
        // this row exists is that "clear my recent documents" is a thing users ask for.
        //
        // TWO SAFETY MECHANISMS, BOTH NECESSARY. FileWalk recurses unconditionally, so a target
        // rooted at %Recent% descends into AutomaticDestinations and CustomDestinations and would
        // silently destroy the jump lists as a side effect of clearing one shortcut.
        // PruneDirectoryNames stops the walk entering them, and the Filter independently requires
        // each file to sit directly in %Recent%. Either alone would do the job today; both are
        // here because the failure is invisible — the jump lists would simply be gone, under a row
        // that said "recent documents".
        //
        // CCleaner's rule also clears HKCU\...\Explorer\RecentDocs, which is out of scope for a
        // file-path catalogue. The Description says so rather than promising a clean wipe: with
        // the registry half intact, the Recent Items list partly repopulates.
        yield return new CleanupTarget
        {
            Id = "shell.recent-documents",
            Category = CleanupCategory.ShellCache,
            DisplayName = "Recent documents list",
            Description = "The shortcuts behind Explorer's Recent Items. Windows also keeps this " +
                          "list in the registry, which HERO does not touch, so the list will partly " +
                          "come back — clearing the files removes the shortcuts, not every trace.",
            Paths = new[] { recent },
            Risk = CleanupRisk.Medium,
            Tier = AutomationTier.Prompt,
            PruneDirectoryNames = new[] { "AutomaticDestinations", "CustomDestinations" },
            Filter = f => f.Path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
                       && string.Equals(Path.GetDirectoryName(f.Path), recent, StringComparison.OrdinalIgnoreCase),
            WhatBreaksIfWrong = "Recently-opened files stop appearing in Explorer, in the Start " +
                                "menu and in apps that read the shell's recent list. No document " +
                                "itself is touched.",
            RestoreHint = "The list refills as you open files.",
        };

        // ---------------------------------------------------------------- widgets

        // Ordinary WebView2 caches belonging to the Widgets board, taken as the five leaf
        // directories CCleaner names and never the EBWebView root — that root also holds
        // Default\Local Storage and the cookie database, which is the same sign-the-user-out trap
        // DiskCleanup's browser allowlist exists to avoid.
        //
        // Measured here: the package and EBWebView\Default exist, Code Cache exists and is empty,
        // and coupon_db, the two Service Worker directories and SmartScreen\local are all absent.
        // So this renders an honest 0 B row on this machine — the Widgets board has effectively
        // never been used. It is kept because the row costs nothing and is a real reclaim on a
        // machine where the board is open all day.
        string widgets = Path.Combine(Local, "Packages",
            "MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy", "LocalState", "EBWebView", "Default");

        yield return new CleanupTarget
        {
            Id = "shell.widgets-web-cache",
            Category = CleanupCategory.ShellCache,
            DisplayName = "Widgets board cache",
            Description = "Compiled script and cached web content behind the Windows widgets panel. " +
                          "Its cookies and local storage are not touched and are not reachable from " +
                          "this action.",
            Paths = new[]
            {
                Path.Combine(widgets, "Code Cache"),
                Path.Combine(widgets, "coupon_db"),
                Path.Combine(widgets, "Service Worker", "CacheStorage"),
                Path.Combine(widgets, "Service Worker", "ScriptCache"),
                Path.Combine(widgets, "SmartScreen", "local"),
            },
            Risk = CleanupRisk.Regenerable,
            // NOT Automatic, despite this measuring almost nothing.
            //
            // The five leaves are correct, but their parent is a live Chromium profile. That
            // Default directory holds Login Data, Login Data For Account, Web Data (payment
            // cards), History, Preferences and Secure Preferences right now. A row that deletes
            // WITHOUT ASKING from one path-join away from a credential store is the wrong shape
            // whatever today's leaf list says: any later edit that adds a sixth leaf, or moves
            // "widgets" up one level to EBWebView, would then run unattended.
            //
            // An earlier comment here concluded the board "has effectively never been used".
            // Measured false: Cache is 244 files / 22.46 MB and History was last written in
            // November. The per-leaf claims were accurate and the row honestly renders 0 B — the
            // inference was the dangerous part, because it is what an editor would rely on when
            // deciding it was safe to widen the paths.
            Tier = AutomationTier.Prompt,
            WhatBreaksIfWrong = "The widgets panel takes a moment longer to draw once. Nothing is " +
                                "lost and you stay signed in.",
            RestoreHint = "Nothing to restore — the panel refetches what it needs.",
            BlockerProbe = () =>
                // Advisory, never blocking. Widgets.exe and WidgetService.exe were both running
                // during the survey and are restarted by the shell whenever they are closed,
                // so treating them as a hard blocker the way a browser is treated would make this
                // row permanently unactionable — the same mistake DiskCleanup warns about for
                // msedgewebview2.exe.
                MaintenanceGuards.AnyRunning("Widgets", "WidgetService", "WebExperienceHost")
                    ? new[]
                    {
                        new CleanupBlocker("widgets-running",
                            "The widgets host is running, so some cache files will be skipped as in " +
                            "use. It restarts itself, so there is nothing useful to close.",
                            Blocking: false),
                    }
                    : Array.Empty<CleanupBlocker>(),
        };

        // ------------------------------------------------------- windows service logs

        // 18.63 MB across 4 files, essentially one item: wiatrace.bak.log at 16.00 MB with a live
        // wiatrace.log at 2.63 MB beside it. That is Windows Image Acquisition tracing — scanner
        // and camera diagnostics — which nothing on this machine reads and which the stisvc
        // service rotates on its own. ESE.TXT and PASSWD.LOG are also here and are both zero
        // bytes; the filter is *.log so ESE.TXT is left where it is.
        //
        // The live wiatrace.log is expected to fail with a sharing violation while stisvc holds
        // it, which the executor already reports as SkipReason.InUse rather than as an error.
        //
        // NOT INCLUDED: %windir%\System32\wbem\Logs (0 files here anyway). Everything under
        // System32 is on the ProtectedPaths floor, so it would be measured as reclaimable and then
        // refused at execution — a row that promises bytes it can never deliver.
        yield return new CleanupTarget
        {
            Id = "logs.windows-debug",
            Category = CleanupCategory.Logs,
            DisplayName = "Windows service trace logs",
            Description = "C:\\Windows\\Debug — device and service traces, 18.63 MB here and almost " +
                          "all of it scanner/camera tracing nobody reads. Windows rotates these " +
                          "itself; clearing them just does it sooner.",
            Paths = new[] { Path.Combine(WinDir, "Debug") },
            Risk = CleanupRisk.Low,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            // Without this the empty-directory pruner deletes C:\Windows\Debug\WIA itself. Both
            // matching .log files live in that subdirectory, not at the root, so clearing them
            // empties it; WIA is not a declared root and is not on the ProtectedPaths floor (only
            // System32, SysWOW64, WinSxS, Installer and assembly are), so pruning walks up and
            // removes it. It is created at install time with an ACL granting the imaging service
            // write access, and that ACL is not reconstructed — scanner tracing would silently
            // stop. The same argument is already written out on logs.event-trace below; it simply
            // was not applied here.
            PruneEmptyDirectories = false,
            Filter = f => f.Path.EndsWith(".log", StringComparison.OrdinalIgnoreCase),
            WhatBreaksIfWrong = "If someone is currently diagnosing a scanner, printer or device " +
                                "installation problem, this is the trace they would read.",
            RestoreHint = "None. The services write fresh traces as they run.",
        };

        // ---------------------------------------------------------- modern setup logs

        // %windir%\Logs\MoSetup: 5.95 MB across 4 files — UpdateAgent.log 4.50 MB,
        // DeviceInventory.xml 1.26 MB, ActionList.xml 0.14 MB, BlueBox.log 0.04 MB. This is the
        // one feature-update log directory DiskCleanup's logs.panther does NOT name (it takes
        // %windir%\Panther and %windir%\Logs\WindowsUpdate), which is why it gets a row of its own
        // rather than being folded into a duplicate of that one.
        //
        // No filter: the two XML files are upgrade-run artefacts exactly like the two logs, and a
        // *.log filter would leave 1.40 MB of them behind for no reason.
        yield return new CleanupTarget
        {
            Id = "logs.modern-setup",
            Category = CleanupCategory.WindowsUpdate,
            DisplayName = "Feature update staging logs",
            Description = "C:\\Windows\\Logs\\MoSetup — what the upgrade engine recorded the last " +
                          "time it staged a feature update, including a full device inventory. " +
                          "5.95 MB here.",
            Paths = new[] { Path.Combine(WinDir, "Logs", "MoSetup") },
            Risk = CleanupRisk.Low,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            WhatBreaksIfWrong = "A feature update that failed or rolled back recently loses part of " +
                                "its evidence. Keep these if an upgrade misbehaved in the last month.",
            RestoreHint = "None. The next upgrade attempt writes a fresh set.",
        };

        // ------------------------------------------------------------ event trace logs

        // 233 .etl files / 17.12 MB under %windir%\Logs, but only about 5.4 MB of that is honestly
        // this row's to claim: 28 of those files live in Logs\WindowsUpdate, which logs.panther
        // already takes WITHOUT a filter, so the subtree is excluded here rather than counted
        // twice under two different rows. What remains is waasmedic (203 files, 3.83 MB), NetSetup
        // (1 file, 1.50 MB), SIH, and SceSetupLog.etl in %windir%\security\logs.
        //
        // CCleaner ships this rule OFF by default with a warning attached, and that instinct is
        // right for a reason worth stating: these files are the backing store of LIVE ETW sessions.
        // An exclusive open of the largest waasmedic traces fails outright, so a good fraction of
        // any run will be skipped as in-use and the achieved reclaim will undershoot the scan. The
        // advisory below says so before the user presses anything.
        //
        // The filter is an exact ".etl" match, which deliberately excludes rotated ".etl.001"-style
        // segments: those are the ring members an active session is writing into right now.
        yield return new CleanupTarget
        {
            Id = "logs.event-trace",
            Category = CleanupCategory.Logs,
            DisplayName = "Event trace logs (.etl)",
            Description = "Binary ETW traces from Windows' own servicing and networking components. " +
                          "Small here (about 5.4 MB after excluding the ones the setup-log row " +
                          "already covers), but tracing can grow without bound on a machine that " +
                          "has been diagnosing something.",
            Paths = new[]
            {
                Path.Combine(WinDir, "Logs"),
                Path.Combine(WinDir, "security", "logs"),
                Path.Combine(ProgramData, "USOShared", "Logs", "User"),
            },
            Risk = CleanupRisk.Low,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            // Substring match on the full path, so the separator is what stops this also excluding
            // a sibling directory whose name merely starts with "WindowsUpdate".
            ExcludeSubPaths = new[]
            {
                Path.Combine(WinDir, "Logs", "WindowsUpdate") + Path.DirectorySeparatorChar,
                // logs.modern-setup takes Logs\MoSetup with no filter, and MoSetup sits inside this
                // row's root. It holds no .etl today so the double-claim is latent, but a row that
                // measures bytes another row also measures reads 0 B after the first is run, which
                // reads as a broken tool. Excluded for the same reason WindowsUpdate above is.
                Path.Combine(WinDir, "Logs", "MoSetup") + Path.DirectorySeparatorChar,
            },
            Filter = f => f.Path.EndsWith(".etl", StringComparison.OrdinalIgnoreCase),
            // These directories are created at install time and inherit specific ACLs. Removing
            // one because this run happened to empty it saves nothing and risks a service finding
            // its log directory gone, so the empty shells are left in place.
            PruneEmptyDirectories = false,
            WhatBreaksIfWrong = "A support engineer loses the traces behind an update or network " +
                                "problem that is still unresolved.",
            RestoreHint = "None. Windows writes new traces continuously.",
            BlockerProbe = () => new[]
            {
                new CleanupBlocker("etw-sessions-active",
                    "Live ETW sessions hold several of these files open, so some will be skipped as " +
                    "in use and the space actually freed will be less than the figure shown.",
                    Blocking: false),
            },
        };

        // ------------------------------------------------------------------- IIS logs

        // Deliberately ONE path, and deliberately a path that does not exist here — see the class
        // header. CCleaner's first FileKey for this rule points at %SystemDirectory%\LogFiles,
        // which on a machine without IIS is not a web server's log directory at all but the live
        // ETW real-time session store. That FileKey is not ported; this row is the inetpub half
        // only, which is absent on this machine and therefore renders nothing.
        //
        // Web server logs are request-by-request records of who visited what and when, so they are
        // evidence rather than junk, and there is no age gate that makes that untrue — Prompt only.
        yield return new CleanupTarget
        {
            Id = "logs.iis",
            Category = CleanupCategory.Logs,
            DisplayName = "IIS request logs",
            Description = "Request logs written by Internet Information Services, if it is " +
                          "installed. Only C:\\inetpub\\logs\\LogFiles is ever touched.",
            Paths = new[] { Path.Combine(SystemDrive, "inetpub", "logs", "LogFiles") },
            Risk = CleanupRisk.Medium,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            MinimumAge = TimeSpan.FromDays(30),
            WhatBreaksIfWrong = "Traffic history and the audit trail for anything served by this " +
                                "machine are gone, including the evidence for an incident nobody " +
                                "has noticed yet.",
            RestoreHint = "None. IIS starts a new log file and the old records do not come back.",
        };

        // --------------------------------------------------- surveyed and not shipped

        // Windows Search crawl logs (%ProgramData%\Microsoft\Search\Data\Applications\Windows\
        // GatherLogs\SystemIndex, *.Crwl) are implementable and safe — 2 files, 0.01 MB, rewritten
        // by the indexer within the hour. They are omitted because a row that reclaims ten
        // kilobytes costs the user more attention than it returns, which is the same padding
        // problem DiskCleanup's header objects to for uninstalled software.
        //
        // %windir%\SoftwareDistribution\DataStore\Logs (7.51 MB) is omitted for a harder reason.
        // CCleaner matches it as *.log, but the directory contains edb.log, edb0002D.log,
        // edb0002E.log, edbres00001.jrs, edbres00002.jrs, edb.chk and edbtmp.log — the ESE
        // transaction log set, reserve logs and checkpoint for DataStore.edb, the Windows Update
        // database. Deleting a live database's transaction logs is not a cleanup, it is a repair
        // step, and the supported form of it is the stop-wuauserv/bits/UsoSvc/DoSvc sequence that
        // DiskCleanup's wu.download-cache target already models. 7.51 MB is not worth a second,
        // less careful path to the same files.
    }
}
