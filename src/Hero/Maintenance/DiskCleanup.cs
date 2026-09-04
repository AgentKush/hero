namespace Hero.Maintenance;

/// <summary>
/// The Windows-side reclaim catalogue.
///
/// Every target here is declared, not discovered at random: each one names its exact paths, says
/// whether it needs administrator rights, states what breaks if HERO is wrong, and refuses to
/// render at all when the software it belongs to is not installed. A maintenance page listing
/// caches for tools the user does not have reads as generic and untrustworthy, and on this
/// machine that is most of the usual list — Firefox, Brave, Slack, Teams, Spotify, Windows.old
/// and the Delivery Optimization cache are all absent.
///
/// The admin boundary was measured rather than assumed. Unelevated, C:\Windows\Temp reports
/// "0 files" and the font cache is denied even a stat, so both must surface as
/// <see cref="AccessState.AccessDenied"/> and never as a clean zero.
/// </summary>
internal static class DiskCleanup
{
    private static string Local => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Roaming => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string WinDir => Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static string ProgramData => Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    /// <summary>
    /// True when a named service is in the Running state. Read-only, unelevated, never throws.
    ///
    /// SERVICE_QUERY_STATUS is granted to everyone for the in-box services this asks about, so no
    /// elevation is needed just to look. Anything that fails is reported as "not running", because
    /// this is used to decide whether to BLOCK an action: failing closed here would mean a check
    /// that cannot be performed silently forbids the operation forever.
    /// </summary>
    private static bool ServiceIsRunning(string name)
    {
        try
        {
            using var scm = Service.Native.OpenSCManagerW(null, null, Service.Native.SC_MANAGER_CONNECT);
            if (scm.IsInvalid) return false;

            using var service = Service.Native.OpenServiceW(scm, name, Service.Native.SERVICE_QUERY_STATUS);
            if (service.IsInvalid) return false;

            var status = default(Service.Native.SERVICE_STATUS);
            if (!Service.Native.QueryServiceStatus(service, ref status)) return false;

            return status.dwCurrentState == Service.Native.SERVICE_RUNNING;
        }
        catch { return false; }
    }
    private static string Profile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    /// <summary>
    /// Every Windows-side target that applies to this machine. Targets whose paths are all
    /// absent are dropped; targets whose paths exist but are unreadable are KEPT, because
    /// "requires administrator" is information and a missing row is not.
    /// </summary>
    internal static IReadOnlyList<CleanupTarget> Enumerate()
    {
        var all = new List<CleanupTarget>();

        all.Add(UserTemp());
        all.Add(WindowsTemp());
        all.Add(WindowsUpdateDownloads());
        all.AddRange(DeliveryOptimization());
        all.AddRange(ErrorReporting());
        all.AddRange(CrashDumps());
        all.Add(ThumbnailAndIconCache());
        all.Add(FontCache());
        all.Add(Prefetch());
        all.AddRange(RecycleBins());
        all.AddRange(BrowserCaches());
        all.AddRange(ApplicationCaches());
        all.Add(InternetCache());
        all.AddRange(ServicingLogs());
        all.AddRange(ReadOnlyObservations());

        // Developer caches. These were WRITTEN AND NEVER CALLED: DevCaches.cs is 823 lines
        // describing uv, npm, pip, cargo, Gradle, Maven, NuGet, pnpm, Yarn, the JVM and VS Code,
        // its own header records 14 GB measured on this machine — uv 6.70 GB, npm 3.40 GB,
        // Gradle 1.53 GB, NuGet 1.26 GB, pip 1.03 GB — and nothing in the entire product ever
        // invoked it. Enumerate() is the one path the Maintenance page reads, so a target
        // catalogue that is not added here does not exist as far as the user is concerned.
        all.AddRange(DevCaches.Enumerate());

        // Per-browser, per-profile targets. DiskCleanup's own BrowserCaches() stays: it covers the
        // generic Chromium cache and Firefox, and BrowserTargets deliberately does not re-add them.
        all.AddRange(BrowserTargets.Enumerate());

        // Windows shell and privacy traces. Only ten of CCleaner's twenty equivalents are
        // implementable here — seven are registry-only, with no FileKey entries at all, and the
        // Start Menu and Desktop shortcut rules match EVERY .lnk and are safe only because of a
        // per-file predicate that resolves each shortcut's target first.
        all.AddRange(ShellTraceTargets.Enumerate());

        // Third-party application caches, chosen by probing this machine rather than by copying a
        // rule list: WhatsApp, iCloud, iTunes, Zoom, Slack, Telegram, Skype, OneDrive, Adobe and
        // both Teams layouts are all absent here, while AMD's shader cache alone is 5.20 GB.
        all.AddRange(AppCacheTargets.Enumerate());

        // A target with no surviving path is not a row. Note that "exists" here includes paths
        // that probe as access-denied, so C:\Windows\Temp and the font cache still render (as
        // "requires administrator") while a genuinely absent Windows.old renders not at all.
        return all.Where(t => t.Exists).ToList();
    }

    // -------------------------------------------------------------------- temp

    /// <summary>
    /// %TEMP%, measured at 2.80 GB across 4,809 files.
    ///
    /// Two gates keep this safe enough to automate. The seven-day age gate skips installers
    /// staging payloads and IDEs holding recovery data, and an explicit exclusion list covers the
    /// directories where a generic sweeper would otherwise destroy live work — including the
    /// agent scratchpad under %TEMP%\claude and Blender's crash-recovery directories, whose only
    /// copy of an unsaved scene lives there. The per-app items know about those; the generic
    /// sweeper is the one that actually runs on a schedule, so it has to know too.
    /// </summary>
    private static CleanupTarget UserTemp()
    {
        string temp = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar);

        var excluded = new List<string>
        {
            // Named live-state directories. Matched as substrings of the full path.
            Path.DirectorySeparatorChar + "claude" + Path.DirectorySeparatorChar,
            Path.DirectorySeparatorChar + "blender",
            Path.DirectorySeparatorChar + "UnrealEditor",
            Path.DirectorySeparatorChar + "MSBuildTemp",
            Path.DirectorySeparatorChar + "vscode-",
        };
        excluded.AddRange(RecentlyTouchedSubdirectories(temp, TimeSpan.FromHours(24)));

        return new CleanupTarget
        {
            Id = "temp.user",
            Category = CleanupCategory.WindowsTemp,
            DisplayName = "Temporary files (your account)",
            Description = "Files programs left in %TEMP%. Only entries untouched for more than a " +
                          "week are eligible, and any directory written to in the last day is skipped whole.",
            Paths = new[] { temp },
            Risk = CleanupRisk.Low,
            Tier = AutomationTier.Automatic,
            MinimumAge = TimeSpan.FromDays(7),
            ExcludeSubPaths = excluded,
            WhatBreaksIfWrong = "An installer or editor loses a file it was still using; almost " +
                                "always it simply recreates it.",
            RestoreHint = "Nothing to restore — programs recreate what they need.",
        };
    }

    /// <summary>
    /// C:\Windows\Temp. Reported 0.0 MB / 0 files unelevated, which is an ACL artefact and not
    /// an empty folder — the canonical example of why a measured zero and an unreadable path
    /// must render differently.
    /// </summary>
    private static CleanupTarget WindowsTemp() => new()
    {
        Id = "temp.windows",
        Category = CleanupCategory.WindowsTemp,
        DisplayName = "Temporary files (machine-wide)",
        Description = "C:\\Windows\\Temp. HERO cannot read this without administrator rights, so " +
                      "any figure shown here is 'unknown', never zero.",
        Paths = new[] { Path.Combine(WinDir, "Temp") },
        Risk = CleanupRisk.Low,
        NeedsAdmin = true,
        Tier = AutomationTier.Prompt,
        MinimumAge = TimeSpan.FromDays(7),
        WhatBreaksIfWrong = "A SYSTEM service loses a file it was mid-way through writing.",
    };

    // ---------------------------------------------------------- windows update

    /// <summary>
    /// The Windows Update download cache: 6.56 GB across 307,372 files.
    ///
    /// Deliberately NOT inferred to be stale from its file-size distribution — many small
    /// expanded payloads are equally the signature of an update being retried, and this machine
    /// logged ten WindowsUpdateClient install failures in seven days. Staleness is therefore
    /// decided by observable state: no pending-reboot flags, and nothing written into the cache
    /// recently.
    ///
    /// Ordering the integrator must honour before executing this plan: stop wuauserv, bits,
    /// UsoSvc and DoSvc (wuauserv alone does not release everything on Windows 11), delete, then
    /// restart them. Aborting is correct if any service refuses to stop.
    /// </summary>
    private static CleanupTarget WindowsUpdateDownloads()
    {
        string download = Path.Combine(WinDir, "SoftwareDistribution", "Download");

        return new CleanupTarget
        {
            Id = "wu.download-cache",
            Category = CleanupCategory.WindowsUpdate,
            DisplayName = "Windows Update download cache",
            Description = "Update payloads Windows has already applied or given up on. Clearing " +
                          "this is the standard remedy for repeated update install failures, which " +
                          "this machine is currently experiencing.",
            Paths = new[] { download },
            Risk = CleanupRisk.Low,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            WhatBreaksIfWrong = "A staged update has to download again — potentially several GB on " +
                                "a metered connection — and a half-staged update can look confusing " +
                                "until it retries.",
            RestoreHint = "Windows Update re-downloads whatever it still needs.",
            BlockerProbe = () =>
            {
                var blockers = new List<CleanupBlocker>();

                // A pending restart is TWO different situations and only one of them is dangerous.
                //
                // Component servicing mid-transaction (CBS RebootPending / RebootInProgress /
                // PackagesPending) means files are staged and the restart will consume them, so
                // removing the payload store can strand it. That stays a hard block.
                //
                // Windows Update's own RebootRequired means the opposite: the install FINISHED and
                // is only waiting for a restart to take effect, which makes the payloads here spent.
                // Clearing them is the documented remedy for repeated update failures, and this
                // target's own description says so. Blocking on it was treating "an update is half
                // applied" and "an update is fully applied" as the same state. Measured on this
                // machine: CBS absent, WU present, TrustedInstaller and wuauserv both stopped —
                // nothing in flight, and HERO refused anyway.
                var reboot = SystemHealth.PendingReboot();
                if (reboot.ServicingInFlight)
                {
                    blockers.Add(new CleanupBlocker("servicing-in-flight",
                        "Component servicing is mid-transaction and the restart will consume staged " +
                        $"files. Clearing the cache now can strand it ({reboot.Summary}). Restart first."));
                }
                else if (reboot.Pending)
                {
                    // Advisory: worth saying, not worth refusing over.
                    blockers.Add(new CleanupBlocker("pending-reboot",
                        $"A restart is pending ({reboot.Summary}), but component servicing is not " +
                        "mid-transaction, so the payloads here are already applied. Clearing them is " +
                        "the usual remedy for repeated update failures.",
                        Blocking: false));
                }

                // "Is a download actually in flight" asked of the SERVICES that would be doing it,
                // rather than of file timestamps.
                //
                // Two previous versions of this check used timestamps and both were wrong, in
                // opposite directions, for the same underlying reason — the thing being measured is
                // also the thing HERO is modifying:
                //
                //   1. The Download folder's own mtime. Changes whenever any entry is added or
                //      removed, so it read "94 minutes" on a cache whose newest real content was
                //      6.5 hours old, and blocked for hours on an unrelated bump.
                //   2. The newest child entry's mtime. Accurate before the run and self-defeating
                //      during it: deleting files inside a per-update folder updates that folder,
                //      so the run aborted itself after 511 of 734,915 files with "the newest item
                //      here was written moments ago". The moments-ago writer was HERO. Worse, the
                //      partial run then left fresh timestamps that refused the NEXT attempt too.
                //
                // wuauserv and BITS are what move update payloads. If neither is running, nothing
                // can be downloading, whatever the timestamps say — and HERO deleting files cannot
                // start a service. Measured while the cache held 10.46 GB: both Stopped.
                try
                {
                    var busy = new List<string>();
                    if (ServiceIsRunning("wuauserv")) busy.Add("Windows Update");
                    if (ServiceIsRunning("bits")) busy.Add("Background Intelligent Transfer");

                    if (busy.Count > 0 && Directory.Exists(download))
                    {
                        blockers.Add(new CleanupBlocker("download-active",
                            $"{string.Join(" and ", busy)} {(busy.Count == 1 ? "is" : "are")} running, so an " +
                            "update may be in flight. Try again once it settles."));
                    }
                }
                catch { }

                return blockers;
            },
        };
    }

    /// <summary>
    /// Delivery Optimization holds peer-shared update content. Two locations exist across
    /// builds; neither is present on this machine, so no row renders. The DO PowerShell cmdlets
    /// are deliberately not used to size it — they query the DO service and are documented as
    /// needing an elevated session, so they belong to the admin tier rather than alongside the
    /// verified-unelevated probes.
    /// </summary>
    private static IEnumerable<CleanupTarget> DeliveryOptimization()
    {
        var paths = new[]
        {
            Path.Combine(WinDir, "SoftwareDistribution", "DeliveryOptimization"),
            Path.Combine(WinDir, "ServiceProfiles", "NetworkService", "AppData", "Local",
                         "Microsoft", "Windows", "DeliveryOptimization", "Cache"),
        };

        yield return new CleanupTarget
        {
            Id = "wu.delivery-optimization",
            Category = CleanupCategory.WindowsUpdate,
            DisplayName = "Delivery Optimization cache",
            Description = "Update content cached for sharing with other PCs on the network.",
            Paths = paths,
            Risk = CleanupRisk.Regenerable,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            WhatBreaksIfWrong = "Nothing — the content re-downloads. Only bandwidth is lost.",
        };
    }

    // ----------------------------------------------------------- crash records

    /// <summary>
    /// Windows Error Reporting queues.
    ///
    /// These are diagnostic gold while a crash is still unexplained, so anything from the last
    /// week is out of scope and the UI is expected to show the top faulting executables from
    /// <see cref="ErrorReportSummary"/> before offering the action at all.
    /// </summary>
    private static IEnumerable<CleanupTarget> ErrorReporting()
    {
        string userWer = Path.Combine(Local, "Microsoft", "Windows", "WER");
        string machineWer = Path.Combine(ProgramData, "Microsoft", "Windows", "WER");

        yield return new CleanupTarget
        {
            Id = "wer.user",
            Category = CleanupCategory.Diagnostics,
            DisplayName = "Crash report queue (your account)",
            Description = "Queued and archived Windows Error Reporting data. Reports from the last " +
                          "seven days are kept — they are the only local record of what crashed.",
            Paths = new[]
            {
                Path.Combine(userWer, "ReportQueue"),
                Path.Combine(userWer, "ReportArchive"),
                Path.Combine(userWer, "Temp"),
            },
            Risk = CleanupRisk.Low,
            Tier = AutomationTier.Automatic,
            MinimumAge = TimeSpan.FromDays(7),
            WhatBreaksIfWrong = "A crash you have not investigated yet loses its evidence.",
        };

        yield return new CleanupTarget
        {
            Id = "wer.machine",
            Category = CleanupCategory.Diagnostics,
            DisplayName = "Crash report queue (machine-wide)",
            Description = "The system-wide error reporting queue.",
            Paths = new[]
            {
                Path.Combine(machineWer, "ReportQueue"),
                Path.Combine(machineWer, "ReportArchive"),
                Path.Combine(machineWer, "Temp"),
            },
            Risk = CleanupRisk.Low,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            MinimumAge = TimeSpan.FromDays(7),
            WhatBreaksIfWrong = "As above, for crashes in system components.",
        };
    }

    /// <summary>
    /// Crash dumps. Measured: 255.1 MB across 10 files in the user CrashDumps folder, an empty
    /// C:\Windows\Minidump (no recent bugchecks — genuinely good news) and no MEMORY.DMP.
    ///
    /// A full MEMORY.DMP on a 64 GB machine can itself be 64 GB, which makes this the highest
    /// variance item in the catalogue. Ten dumps totalling 255 MB is a stability signal worth
    /// reporting, not merely space, so the UI is expected to cluster them by faulting process
    /// via <see cref="CrashDumpSummary"/>.
    /// </summary>
    private static IEnumerable<CleanupTarget> CrashDumps()
    {
        yield return new CleanupTarget
        {
            Id = "dumps.user",
            Category = CleanupCategory.Diagnostics,
            DisplayName = "Application crash dumps",
            Description = "Memory dumps written when a program of yours crashed. Anything from the " +
                          "last week is kept.",
            Paths = new[] { Path.Combine(Local, "CrashDumps") },
            Risk = CleanupRisk.Low,
            Tier = AutomationTier.Prompt,
            MinimumAge = TimeSpan.FromDays(7),
            Filter = f => f.Path.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase),
            WhatBreaksIfWrong = "A dump is the only artefact that can explain a crash you have not " +
                                "debugged yet.",
        };

        yield return new CleanupTarget
        {
            Id = "dumps.kernel",
            Category = CleanupCategory.Diagnostics,
            DisplayName = "Kernel crash dumps",
            Description = "Minidumps and live kernel reports from system crashes.",
            Paths = new[]
            {
                Path.Combine(WinDir, "Minidump"),
                Path.Combine(WinDir, "LiveKernelReports"),
            },
            Risk = CleanupRisk.Low,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            MinimumAge = TimeSpan.FromDays(7),
            WhatBreaksIfWrong = "The evidence for a blue screen you have not diagnosed is lost.",
        };
    }

    // ------------------------------------------------------------ shell caches

    /// <summary>
    /// Thumbnail and icon caches: 8.7 MB across 33 files here, but 0.5–2 GB on a machine with a
    /// large media library, and a corrupt thumbcache is a common cause of blank or wrong icons.
    ///
    /// Explorer holds these open, so most will be skipped as in-use. The tempting fix —
    /// MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT — is documented as callable only by an
    /// administrator or LocalSystem (it writes PendingFileRenameOperations under HKLM), so on an
    /// unelevated scheduled run it would fail silently. HERO deletes what is unlocked and asks
    /// the shell to rebuild via ie4uinit; it does not pretend to have done more.
    /// </summary>
    private static CleanupTarget ThumbnailAndIconCache() => new()
    {
        Id = "shell.thumbnail-cache",
        Category = CleanupCategory.ShellCache,
        DisplayName = "Thumbnail and icon cache",
        Description = "Explorer's picture thumbnails and icon database. Purely regenerable; the " +
                      "reason to clear it is broken or blank icons, not space.",
        Paths = new[] { Path.Combine(Local, "Microsoft", "Windows", "Explorer") },
        Risk = CleanupRisk.Regenerable,
        Tier = AutomationTier.Prompt,
        Filter = f =>
        {
            var name = Path.GetFileName(f.Path);
            return name.StartsWith("thumbcache_", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("iconcache_", StringComparison.OrdinalIgnoreCase);
        },
        WhatBreaksIfWrong = "Nothing. Folders full of images redraw their thumbnails slowly for a while.",
        RestoreHint = "Explorer rebuilds both caches on demand; run 'ie4uinit.exe -show' to hurry it.",
        BlockerProbe = () => new List<CleanupBlocker>
        {
            // Advisory rather than blocking: Explorer is always running, and the files it does
            // not currently hold open can still be removed.
            new("explorer-running",
                "Explorer holds most of these files open, so some will be skipped as in use. " +
                "Sign out and back in for a complete rebuild.",
                Blocking: false),
        },
    };

    /// <summary>
    /// The font cache. Access was denied even to a Test-Path when unelevated, which is why this
    /// is admin-gated to READ, not just to clean. It is a repair action, not a space win, and is
    /// presented as such: the payoff is fixing corrupted text rendering.
    /// </summary>
    private static CleanupTarget FontCache() => new()
    {
        Id = "shell.font-cache",
        Category = CleanupCategory.ShellCache,
        DisplayName = "Font cache",
        Description = "The system font cache. Clearing it fixes garbled or missing text; it " +
                      "reclaims very little space and is offered as a repair, not a reclaim.",
        Paths = new[]
        {
            Path.Combine(WinDir, "ServiceProfiles", "LocalService", "AppData", "Local", "FontCache"),
        },
        Risk = CleanupRisk.Regenerable,
        NeedsAdmin = true,
        Tier = AutomationTier.Prompt,
        Filter = f => f.Path.EndsWith(".dat", StringComparison.OrdinalIgnoreCase),
        WhatBreaksIfWrong = "Text briefly renders with fallback fonts while the cache rebuilds.",
        RestoreHint = "The FontCache service rebuilds it automatically after a restart.",
    };

    /// <summary>
    /// Prefetch: measured, explained, and deliberately never cleaned.
    ///
    /// Every junk cleaner clears this and it is cargo cult — Prefetch is size-capped by Windows,
    /// self-maintaining, and clearing it measurably slows the next launch of every application.
    /// It is exposed read-only because the .pf filenames encode which executables actually run on
    /// this machine, which is useful evidence for the Guardian half and for spotting scheduled
    /// tasks belonging to software that is long gone.
    /// </summary>
    private static CleanupTarget Prefetch() => new()
    {
        Id = "shell.prefetch",
        Category = CleanupCategory.Informational,
        DisplayName = "Prefetch (read-only)",
        Description = "Windows' launch-acceleration data. HERO shows the size and refuses to clear it.",
        Paths = new[] { Path.Combine(WinDir, "Prefetch") },
        Risk = CleanupRisk.NeverClean,
        NeedsAdmin = true,
        Tier = AutomationTier.ReadOnly,
        WhatBreaksIfWrong = "Clearing Prefetch slows the next launch of every program and reclaims " +
                            "almost nothing, because Windows caps its size already.",
    };

    // ------------------------------------------------------------ recycle bins

    /// <summary>
    /// One row per fixed volume that has a bin with anything in it.
    ///
    /// The measured totals are E: 107.4 GB / 226,184 items, F: 2.83 GB, D: 222 MB, C: ~0 —
    /// making this by a wide margin the largest reclaim on the machine and simultaneously the
    /// most irreversible action in the catalogue. There is no vault behind a recycle bin: the
    /// bin IS the vault. It is prompt-only, permanently.
    /// </summary>
    private static IEnumerable<CleanupTarget> RecycleBins()
    {
        foreach (var drive in FixedDrives())
        {
            yield return new RecycleBinTarget
            {
                Id = "recyclebin." + drive.Name.TrimEnd('\\', ':').ToLowerInvariant(),
                Category = CleanupCategory.RecycleBin,
                DisplayName = $"Recycle Bin on {drive.Name}",
                Description = "Files you have already deleted. Emptying is permanent — there is no " +
                              "second undo behind the Recycle Bin.",
                Paths = new[] { Path.Combine(drive.Name, "$RECYCLE.BIN") },
                VolumeRoot = drive.Name,
                Risk = CleanupRisk.High,
                Tier = AutomationTier.Prompt,
                PruneEmptyDirectories = false,
                WhatBreaksIfWrong = "Anything the user meant to restore is gone for good. Users " +
                                    "routinely restore from the bin days later.",
                RestoreHint = "None. Filter by deletion date and empty only what is genuinely old.",
            };
        }
    }

    /// <summary>Ready fixed volumes. Kept out of the iterator above because a try/catch cannot
    /// live in the same method as a yield.</summary>
    internal static List<DriveInfo> FixedDrives()
    {
        var result = new List<DriveInfo>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed) result.Add(drive);
                }
                catch { /* a volume that vanished mid-enumeration */ }
            }
        }
        catch { }
        return result;
    }

    // ----------------------------------------------------------- browser caches

    private sealed record ChromiumBrowser(string Name, string[] Roots, string[] Processes, string CloseAdvice);

    /// <summary>
    /// The ONLY directories a browser cache clean may touch, relative to a profile directory.
    ///
    /// This is an allowlist and it is the entire mechanism. A blocklist would eventually reach
    /// Cookies, Login Data, Web Data, History, Bookmarks, Local Storage or Local State and log
    /// the user out of everything or lose saved passwords — an unrecoverable, trust-ending
    /// failure. Nothing is deleted because it "looks like" a cache; only these names qualify,
    /// and they become the executor's roots so no sibling path is even addressable.
    /// </summary>
    private static readonly string[] ProfileCacheLeaves =
    {
        Path.Combine("Cache", "Cache_Data"),
        Path.Combine("Code Cache", "js"),
        Path.Combine("Code Cache", "wasm"),
        "GPUCache",
        Path.Combine("Service Worker", "CacheStorage"),
        Path.Combine("Service Worker", "ScriptCache"),
        "DawnGraphiteCache",
        "DawnWebGPUCache",
        // Opera GX puts part of its HTTP cache here, in the LOCAL root while its Code Cache and
        // GPUCache live in the ROAMING root — which is why browsers are modelled as a list of
        // roots rather than one directory per vendor.
        "System Cache",
    };

    /// <summary>Cache directories that sit beside the profiles rather than inside one.</summary>
    private static readonly string[] RootCacheLeaves =
    {
        "ShaderCache", "GrShaderCache", "GraphiteDawnCache", "GPUPersistentCache",
    };

    private static IEnumerable<CleanupTarget> BrowserCaches()
    {
        var browsers = new[]
        {
            new ChromiumBrowser("Google Chrome",
                new[] { Path.Combine(Local, "Google", "Chrome", "User Data") },
                new[] { "chrome" },
                "Close Chrome"),

            new ChromiumBrowser("Microsoft Edge",
                new[] { Path.Combine(Local, "Microsoft", "Edge", "User Data") },
                new[] { "msedge" },
                // Deliberately specific: msedgewebview2.exe is NOT msedge.exe, and treating any
                // Edge-family process as "Edge is open" would make this row permanently
                // unactionable on Windows 11, where WebView2 hosts run constantly.
                "Close Edge — including any window kept alive by Startup Boost, which you can turn " +
                "off in Settings > System"),

            new ChromiumBrowser("Brave",
                new[] { Path.Combine(Local, "BraveSoftware", "Brave-Browser", "User Data") },
                new[] { "brave" },
                "Close Brave"),

            new ChromiumBrowser("Opera GX",
                // BOTH roots. The roaming root holds Code Cache and GPUCache and ALSO holds
                // Cookies, Login Data and Local State, so the leaf allowlist is doing real work
                // here rather than being a formality.
                new[]
                {
                    Path.Combine(Local, "Opera Software", "Opera GX Stable"),
                    Path.Combine(Roaming, "Opera Software", "Opera GX Stable"),
                },
                new[] { "opera" },
                "Close Opera GX"),

            new ChromiumBrowser("Opera",
                new[]
                {
                    Path.Combine(Local, "Opera Software", "Opera Stable"),
                    Path.Combine(Roaming, "Opera Software", "Opera Stable"),
                },
                new[] { "opera" },
                "Close Opera"),
        };

        foreach (var browser in browsers)
        {
            var paths = DiscoverChromiumCachePaths(browser.Roots);
            if (paths.Count == 0) continue;

            yield return new CleanupTarget
            {
                Id = "browser." + browser.Name.Replace(' ', '-').ToLowerInvariant(),
                Category = CleanupCategory.BrowserCache,
                DisplayName = $"{browser.Name} cache",
                Description = "Cached web content, compiled script and GPU shaders. Cookies, saved " +
                              "passwords, history and bookmarks are not touched and are not even " +
                              "reachable from this action.",
                Paths = paths,
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                WhatBreaksIfWrong = "Pages load a little slower once, until the cache refills. You " +
                                    "stay signed in to everything.",
                RestoreHint = "The browser refills its cache as you browse.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker(browser.Name,
                        "clear its cache", browser.Processes);
                    if (b is null) return Array.Empty<CleanupBlocker>();
                    return new[] { b with { Detail = b.Detail + " " + browser.CloseAdvice + "." } };
                },
            };
        }

        foreach (var target in FirefoxCaches()) yield return target;
    }

    /// <summary>
    /// Expands each browser root into the concrete allowlisted cache directories that actually
    /// exist. These become the target's paths, and therefore the executor's roots, so the
    /// allowlist is enforced by construction rather than by a check that could be skipped.
    /// </summary>
    private static List<string> DiscoverChromiumCachePaths(IReadOnlyList<string> roots)
    {
        var found = new List<string>();

        foreach (var root in roots)
        {
            if (FileWalk.Probe(root) != AccessState.Measured) continue;

            foreach (var leaf in RootCacheLeaves)
                AddIfPresent(found, Path.Combine(root, leaf));

            IEnumerable<string> profiles;
            try
            {
                profiles = Directory.EnumerateDirectories(root)
                    .Where(d =>
                    {
                        var name = Path.GetFileName(d);
                        return name.Equals("Default", StringComparison.OrdinalIgnoreCase)
                            || name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase);
                    });
            }
            catch { continue; }

            foreach (var profile in profiles)
                foreach (var leaf in ProfileCacheLeaves)
                    AddIfPresent(found, Path.Combine(profile, leaf));
        }

        return found;
    }

    /// <summary>
    /// Adds a path only if it exists AND survives the profile-artefact tripwire. The allowlist
    /// above is the mechanism; this is the assertion that catches a future edit which adds a
    /// leaf name too close to the credential store.
    /// </summary>
    private static void AddIfPresent(List<string> into, string path)
    {
        if (FileWalk.Probe(path) != AccessState.Measured) return;
        if (ProtectedPaths.TouchesBrowserProfile(path)) return;
        into.Add(path);
    }

    private static IEnumerable<CleanupTarget> FirefoxCaches()
    {
        var paths = FirefoxCachePaths();
        if (paths.Count == 0) yield break;

        yield return new CleanupTarget
        {
            Id = "browser.firefox",
            Category = CleanupCategory.BrowserCache,
            DisplayName = "Firefox cache",
            Description = "Firefox's network and startup caches. Profile data is untouched.",
            Paths = paths,
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "Pages load slightly slower once.",
            BlockerProbe = () =>
            {
                var b = MaintenanceGuards.RunningBlocker("Firefox", "clear its cache", "firefox");
                return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
            },
        };
    }

    private static List<string> FirefoxCachePaths()
    {
        var paths = new List<string>();
        string profilesRoot = Path.Combine(Local, "Mozilla", "Firefox", "Profiles");
        if (FileWalk.Probe(profilesRoot) != AccessState.Measured) return paths;

        try
        {
            foreach (var profile in Directory.EnumerateDirectories(profilesRoot))
            {
                // Firefox keeps its network cache under cache2 in the LOCAL profile tree; the
                // roaming profile of the same name holds cookies, logins and the key database
                // and is never referenced here.
                AddIfPresent(paths, Path.Combine(profile, "cache2"));
                AddIfPresent(paths, Path.Combine(profile, "startupCache"));
            }
        }
        catch { }
        return paths;
    }

    // ------------------------------------------------------------- app caches

    /// <summary>
    /// Electron applications, which are Chromium underneath and get the same allowlist
    /// discipline: %APPDATA%\discord also contains 'Local Storage' and 'sessionData' holding the
    /// login token, so only the three named cache directories are ever addressed.
    ///
    /// Measured: Discord 363.2 MB. Slack, Teams and Spotify are not installed here and render
    /// no rows.
    /// </summary>
    private static IEnumerable<CleanupTarget> ApplicationCaches()
    {
        var apps = new (string Id, string Name, string[] Dirs, string[] Processes)[]
        {
            ("discord", "Discord", new[]
            {
                Path.Combine(Roaming, "discord", "Cache"),
                Path.Combine(Roaming, "discord", "Code Cache"),
                Path.Combine(Roaming, "discord", "GPUCache"),
            }, new[] { "Discord" }),

            ("slack", "Slack", new[]
            {
                Path.Combine(Roaming, "Slack", "Cache"),
                Path.Combine(Roaming, "Slack", "Code Cache"),
                Path.Combine(Roaming, "Slack", "GPUCache"),
                Path.Combine(Roaming, "Slack", "Service Worker", "CacheStorage"),
            }, new[] { "slack" }),

            ("teams.classic", "Microsoft Teams (classic)", new[]
            {
                Path.Combine(Roaming, "Microsoft", "Teams", "Cache"),
                Path.Combine(Roaming, "Microsoft", "Teams", "Code Cache"),
                Path.Combine(Roaming, "Microsoft", "Teams", "GPUCache"),
                Path.Combine(Roaming, "Microsoft", "Teams", "Service Worker", "CacheStorage"),
            }, new[] { "Teams" }),

            ("teams.new", "Microsoft Teams", new[]
            {
                Path.Combine(Local, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft",
                             "MSTeams", "EBWebView", "Default", "Cache"),
                Path.Combine(Local, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft",
                             "MSTeams", "EBWebView", "Default", "Code Cache"),
                Path.Combine(Local, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft",
                             "MSTeams", "EBWebView", "Default", "GPUCache"),
            }, new[] { "ms-teams" }),

            // Only the embedded-browser cache. BOTH of Spotify's other local directories hold
            // playable audio, not cache: \Storage is the streamed-track cache and \Data is where
            // downloaded-for-offline tracks live on current desktop builds. Losing offline
            // downloads on an automatic run — possibly with no connection to re-fetch them — is
            // exactly the class of unrecoverable annoyance the allowlist discipline exists to
            // prevent, and neither directory is worth the risk of getting the split wrong.
            ("spotify", "Spotify", new[]
            {
                Path.Combine(Local, "Spotify", "Browser", "Cache"),
            }, new[] { "Spotify" }),
        };

        foreach (var app in apps)
        {
            var present = app.Dirs.Where(d => FileWalk.Probe(d) == AccessState.Measured).ToList();
            if (present.Count == 0) continue;

            yield return new CleanupTarget
            {
                Id = "app." + app.Id,
                Category = CleanupCategory.AppCache,
                DisplayName = $"{app.Name} cache",
                Description = $"{app.Name}'s Chromium caches. Its login token and local storage are " +
                              "not touched.",
                Paths = present,
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                WhatBreaksIfWrong = "Images and emoji reload once. You stay signed in.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker(app.Name, "clear its cache", app.Processes);
                    return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
                },
            };
        }
    }

    /// <summary>
    /// INetCache: 5.2 MB, trivial in itself, but a useful regression test for the walker. Two
    /// junctions point here — %LOCALAPPDATA%\Temporary Internet Files and
    /// %LOCALAPPDATA%\Microsoft\Windows\Temporary Internet Files — so this small folder is
    /// reachable by three paths and a scanner that follows reparse points triple-counts it.
    /// </summary>
    private static CleanupTarget InternetCache()
    {
        string root = Path.Combine(Local, "Microsoft", "Windows", "INetCache");
        return new CleanupTarget
        {
            Id = "cache.inetcache",
            Category = CleanupCategory.ShellCache,
            DisplayName = "Internet cache (WinINet / WebView)",
            Description = "Cached downloads from the legacy Internet stack, still used by WebView " +
                          "hosts and some desktop apps.",
            Paths = new[]
            {
                Path.Combine(root, "IE"),
                Path.Combine(root, "Low"),
                Path.Combine(root, "Content.IE5"),
            },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "Nothing; content re-downloads.",
        };
    }

    // -------------------------------------------------------------- servicing logs

    /// <summary>
    /// CBS (26.7 MB measured) and Panther (472.2 MB measured) logs.
    ///
    /// The live CBS.log is held open by TrustedInstaller and is excluded by filter, not by luck.
    /// A large CBS log set is itself a health signal — above roughly 200 MB it means servicing is
    /// struggling — so <see cref="SystemHealth"/> reports the size even when this target is not
    /// actioned. These must never be cleared in the same run as a DISM operation, because
    /// CBS.log is the primary diagnostic when DISM fails.
    /// </summary>
    private static IEnumerable<CleanupTarget> ServicingLogs()
    {
        yield return new CleanupTarget
        {
            Id = "logs.cbs",
            Category = CleanupCategory.Logs,
            DisplayName = "Component servicing logs",
            Description = "Rotated CBS and DISM logs. The live CBS.log is left alone — it is the " +
                          "first thing anyone needs when an update fails.",
            Paths = new[]
            {
                Path.Combine(WinDir, "Logs", "CBS"),
                Path.Combine(WinDir, "Logs", "DISM"),
            },
            Risk = CleanupRisk.Low,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            Filter = f =>
            {
                var name = Path.GetFileName(f.Path);
                if (name.Equals("CBS.log", StringComparison.OrdinalIgnoreCase)) return false;
                if (name.Equals("dism.log", StringComparison.OrdinalIgnoreCase)) return false;
                return name.StartsWith("CbsPersist_", StringComparison.OrdinalIgnoreCase)
                    || name.EndsWith(".cab", StringComparison.OrdinalIgnoreCase)
                    || name.EndsWith(".log", StringComparison.OrdinalIgnoreCase);
            },
            WhatBreaksIfWrong = "A servicing failure you are still diagnosing loses its history.",
        };

        yield return new CleanupTarget
        {
            Id = "logs.panther",
            Category = CleanupCategory.Logs,
            DisplayName = "Windows setup and upgrade logs",
            Description = "Setup logs retained from past feature updates (setupact.log, setuperr.log " +
                          "and their diagnostic payloads).",
            Paths = new[]
            {
                Path.Combine(WinDir, "Panther"),
                Path.Combine(WinDir, "Logs", "WindowsUpdate"),
            },
            Risk = CleanupRisk.Low,
            NeedsAdmin = true,
            Tier = AutomationTier.Prompt,
            WhatBreaksIfWrong = "If a feature update failed recently and someone is still " +
                                "diagnosing it, this is the evidence. Keep them if an upgrade " +
                                "failed in the last month.",
        };
    }

    // ------------------------------------------------- measured but never cleaned

    /// <summary>
    /// Rows that exist purely so HERO can show a number and explain its restraint.
    ///
    /// This is the credibility anchor. A maintenance tool that says "WinSxS is 21.9 GB and here
    /// is why almost none of that is yours to reclaim" is trusted more than one that adds the
    /// apparent size to a headline total — which would overstate that single item roughly
    /// fourfold, because WinSxS is overwhelmingly hardlinks into System32.
    /// </summary>
    private static IEnumerable<CleanupTarget> ReadOnlyObservations()
    {
        yield return new CleanupTarget
        {
            Id = "observe.winsxs",
            Category = CleanupCategory.Informational,
            DisplayName = "Component store (WinSxS) — read-only",
            Description = "Apparent size is misleading: WinSxS is mostly NTFS hardlinks into " +
                          "System32, so the real incremental cost is a fraction of what a directory " +
                          "sum reports. Only DISM's own analysis can say what is reclaimable, and " +
                          "only when it says cleanup is recommended.",
            Paths = new[] { Path.Combine(WinDir, "WinSxS") },
            Risk = CleanupRisk.NeverClean,
            NeedsAdmin = true,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Reporting the apparent size as reclaimable is the classic " +
                                "cleanup-tool lie. Component cleanup is offered separately, gated " +
                                "on DISM's own verdict, and /ResetBase is never offered by default " +
                                "because it makes every installed update permanently un-removable.",
        };

        yield return new CleanupTarget
        {
            Id = "observe.installer",
            Category = CleanupCategory.Informational,
            DisplayName = "Windows Installer cache — read-only",
            Description = "The MSI and MSP cache (3.3 GB here). HERO measures it and will not " +
                          "clean it, at any risk level.",
            Paths = new[] { Path.Combine(WinDir, "Installer") },
            Risk = CleanupRisk.NeverClean,
            NeedsAdmin = true,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Deleting a cached package makes that product impossible to repair, " +
                                "patch or uninstall — the uninstaller asks for a source file that no " +
                                "longer exists and the app is stuck installed forever. Visual Studio " +
                                "and the VC++ redistributables are the usual casualties, and this " +
                                "machine has four Visual Studio products installed.",
        };

        yield return new CleanupTarget
        {
            Id = "observe.windows-old",
            Category = CleanupCategory.Informational,
            DisplayName = "Previous Windows installation — read-only",
            Description = "C:\\Windows.old, when a feature update has left one. HERO reports it and " +
                          "does not delete it directly.",
            Paths = new[] { @"C:\Windows.old" },
            Risk = CleanupRisk.NeverClean,
            NeedsAdmin = true,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Removing it destroys the only route back to the previous Windows " +
                                "build, and a raw recursive delete cannot finish anyway — it hits " +
                                "TrustedInstaller-owned files and leaves a half-deleted tree. Use " +
                                "the Previous Installations cleanup handler.",
        };

        yield return new CleanupTarget
        {
            Id = "observe.downloads",
            Category = CleanupCategory.Informational,
            DisplayName = "Downloads folder — read-only",
            Description = "Shown with its size and age spread so you can decide. HERO never deletes " +
                          "here and never will on a schedule.",
            Paths = new[] { Path.Combine(Profile, "Downloads") },
            Risk = CleanupRisk.NeverClean,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Downloads is a de-facto document folder — installers still needed, " +
                                "licence files, one-off exports. Automatic deletion here is the " +
                                "single most disliked thing Storage Sense does.",
        };
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// Top-level subdirectories of <paramref name="root"/> written to recently, returned as
    /// path fragments to exclude. One stat per subdirectory rather than per file, so the cost is
    /// negligible even on a busy %TEMP%.
    /// </summary>
    private static IEnumerable<string> RecentlyTouchedSubdirectories(string root, TimeSpan window)
    {
        var cutoff = DateTime.UtcNow - window;
        List<string> result = new();
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(root))
            {
                try
                {
                    if (Directory.GetLastWriteTimeUtc(dir) >= cutoff)
                        result.Add(dir + Path.DirectorySeparatorChar);
                }
                catch { /* an unreadable subdirectory is excluded by being unwalkable anyway */ }
            }
        }
        catch { }
        return result;
    }

    /// <summary>
    /// Crash dumps grouped by the process that produced them. User-mode dump filenames are
    /// &lt;process&gt;.&lt;pid&gt;.dmp, so the faulting program is recoverable without opening
    /// the dump. Ten dumps from one executable is a stability finding, not just 255 MB.
    /// </summary>
    internal static IReadOnlyList<(string Process, int Count, long Bytes, DateTime NewestUtc)> CrashDumpSummary()
    {
        var groups = new Dictionary<string, (int Count, long Bytes, DateTime Newest)>(StringComparer.OrdinalIgnoreCase);
        string dir = Path.Combine(Local, "CrashDumps");
        try
        {
            if (Directory.Exists(dir))
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.dmp"))
                {
                    var name = Path.GetFileName(file);
                    int dot = name.IndexOf('.');
                    string proc = dot > 0 ? name[..dot] : name;
                    var info = new FileInfo(file);
                    groups.TryGetValue(proc, out var acc);
                    groups[proc] = (acc.Count + 1, acc.Bytes + info.Length,
                                    info.LastWriteTimeUtc > acc.Newest ? info.LastWriteTimeUtc : acc.Newest);
                }
            }
        }
        catch { }

        return groups.Select(kv => (kv.Key, kv.Value.Count, kv.Value.Bytes, kv.Value.Newest))
                     .OrderByDescending(g => g.Count)
                     .ToList();
    }

    /// <summary>
    /// Faulting executables named by the queued WER reports, newest first. Shown before the
    /// error-reporting queues are offered for deletion: clearing them loses the only local
    /// record of what crashed, and a crash in the last 48 hours means keeping them by default.
    /// </summary>
    internal static IReadOnlyList<(string Application, int Count, DateTime NewestUtc)> ErrorReportSummary()
    {
        var groups = new Dictionary<string, (int Count, DateTime Newest)>(StringComparer.OrdinalIgnoreCase);
        string root = Path.Combine(Local, "Microsoft", "Windows", "WER");

        foreach (var sub in new[] { "ReportQueue", "ReportArchive" })
        {
            string dir = Path.Combine(root, sub);
            try
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var reportDir in Directory.EnumerateDirectories(dir))
                {
                    // Report directories are named e.g. AppCrash_devenv.exe_<hash>_<...>.
                    var parts = Path.GetFileName(reportDir).Split('_');
                    string app = parts.Length > 1 ? parts[1] : Path.GetFileName(reportDir);
                    var when = Directory.GetLastWriteTimeUtc(reportDir);
                    groups.TryGetValue(app, out var acc);
                    groups[app] = (acc.Count + 1, when > acc.Newest ? when : acc.Newest);
                }
            }
            catch { }
        }

        return groups.Select(kv => (kv.Key, kv.Value.Count, kv.Value.Newest))
                     .OrderByDescending(g => g.Newest)
                     .ToList();
    }

    /// <summary>
    /// Asks the shell to rebuild its icon cache. The supported unelevated follow-up to clearing
    /// thumbcache/iconcache files, in place of the delayed-rename trick that silently requires
    /// administrator rights.
    /// </summary>
    internal static void RefreshShellIconCache()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("ie4uinit.exe", "-show")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            p?.WaitForExit(10000);
        }
        catch { /* cosmetic; the files are already gone */ }
    }
}
