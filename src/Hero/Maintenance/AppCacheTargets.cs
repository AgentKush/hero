namespace Hero.Maintenance;

/// <summary>
/// Third-party application caches, sized on this machine rather than transcribed from a rule list.
///
/// The starting point was CCleaner 7's rule file (707 sections under
/// <c>C:\Program Files\Piriform\CCleaner 7\ccleaner.ini</c>) and almost none of its headline
/// application rules survive contact with this box. WhatsApp, iCloud, iTunes, Zoom, Telegram,
/// Skype, OneDrive, WPS Office, Adobe Creative Cloud, both Teams layouts, NVIDIA's and Intel's
/// shader caches and the EA, Origin, GOG and Riot launchers were all probed directly and are
/// absent. What this machine actually is — an AMD gaming and game-development box — decides where
/// the bytes are: 5.20 GB of driver shader cache, 1.88 GB of Roblox assets, 2.0 GB of Steam web
/// and artwork cache, and a long tail of Electron apps.
///
/// THREE THINGS LEARNED WHILE MEASURING, each of which changed a target below.
///
/// 1. A DIRECTORY CALLED "CACHE" CAN HOLD CREDENTIALS. <c>%LocalAppData%\Steam\htmlcache</c> is a
///    complete Chromium profile: beside 1.00 GB of real cache its <c>Default</c> holds Login Data,
///    Login Data For Account, Web Data, History, Top Sites and Network\Cookies. Its name invites a
///    wholesale delete that would sign the user out of the in-client store. Nothing here ever names
///    an application's data root — only Chromium's own cache directory names, via
///    <see cref="ChromiumCachesUnder"/>, so a sibling credential file is not addressable.
///
/// 2. Risk, NOT Tier, IS WHAT STOPS A DELETION. <see cref="CleanupExecutor.Execute"/> refuses on
///    <see cref="CleanupRisk.NeverClean"/>; <see cref="AutomationTier.ReadOnly"/> only steers the
///    UI. A row meant to be shown and never deleted therefore has to be NeverClean, or a future
///    caller that builds a plan and runs it will delete it anyway. Every shown-only target at the
///    bottom of this file is NeverClean for that reason and not as a mood.
///
/// 3. THE DELETION FLOOR ALREADY FORBIDS PROGRAM FILES. <see cref="ProtectedPaths"/> lists both
///    Program Files roots, so Steam's 1.03 GB of install-directory caches can be measured but never
///    removed — a target offering them would preview 9,835 files and then skip every one as
///    <see cref="SkipReason.Protected"/>. <see cref="AddIfSafe"/> now asks the floor at declaration
///    time so that failure mode cannot be shipped by accident, and the Steam install caches are
///    declared shown-only with the reason stated.
///
/// Not covered here on purpose: developer package managers and VS Code (<see cref="DevCaches"/>),
/// browsers and Discord's Chromium caches (<see cref="DiskCleanup"/>), and
/// <c>%AppData%\Claude</c>'s 31.5 GB of non-cache state, of which only the Chromium caches are
/// touched — the rest is conversation and MCP state that needs its own survey.
/// </summary>
internal static class AppCacheTargets
{
    private static string Local => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Roaming => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string ProgramFilesX86 => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

    /// <summary>
    /// Every third-party application cache that applies to this machine, biggest reclaim first so
    /// the catalogue opens on the 5.20 GB win rather than on a 26 MB log directory. Targets whose
    /// paths have all vanished are dropped by the caller, so rows for absent software are free to
    /// declare.
    ///
    /// WIRING: registered once, at <see cref="DiskCleanup.Enumerate"/>. Nothing else calls it, and
    /// the catalogue does not de-duplicate by id, so a second call site would render every row
    /// twice. (An earlier draft of this note pointed at a <c>ThirdPartyCaches.cs</c> that covered
    /// the same ground; that file was an unassigned duplicate of this one and has been removed.
    /// The note is corrected rather than deleted because, left as it was, it invited an integrator
    /// to go looking for the other file and un-register this one — silently removing every row
    /// below from the product.)
    /// </summary>
    internal static IEnumerable<CleanupTarget> Enumerate()
    {
        foreach (var t in GpuShaderCaches()) yield return t;
        foreach (var t in GameLaunchers()) yield return t;
        foreach (var t in EmbeddedBrowsers()) yield return t;
        foreach (var t in ElectronApplications()) yield return t;
        foreach (var t in InstallerLeftovers()) yield return t;
        foreach (var t in ShownNeverDeleted()) yield return t;
    }

    // ------------------------------------------------------- the Chromium allowlist

    /// <summary>
    /// The ONLY directory names a cache clean may address inside an Electron or CEF application,
    /// and the reason this file is short.
    ///
    /// Every name here is defined by Chromium itself, not by the application wrapping it, which is
    /// what makes one list serve seventeen unrelated programs. It is an allowlist for the same
    /// reason <see cref="DiskCleanup"/>'s is: a blocklist would eventually have to enumerate
    /// Cookies, Login Data, Local Storage, IndexedDB, Session Storage, Preferences and Network, and
    /// missing one of them signs the user out of an application permanently.
    ///
    /// The Dawn entries look like clutter at 0.5 MB each and are kept anyway — they are WebGPU
    /// shader caches that grow with use, and the cost of listing a name that is already proven safe
    /// is nothing next to the cost of adding it later under pressure.
    /// </summary>
    private static readonly string[] ChromiumCacheLeaves =
    {
        "Cache", "Code Cache", "GPUCache",
        "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GraphiteDawnCache",
        "GrShaderCache", "ShaderCache",
        Path.Combine("Service Worker", "CacheStorage"),
        Path.Combine("Service Worker", "ScriptCache"),
    };

    /// <summary>
    /// Every <c>app-&lt;version&gt;</c> directory under a Squirrel application root EXCEPT the
    /// highest-versioned one.
    ///
    /// Returns nothing at all — not a partial list — when there are fewer than two versions, or
    /// when any directory name fails to parse as a version. The failure being guarded against is
    /// deleting the application the user is running, and a resolver that is unsure must decline
    /// rather than approximate.
    /// </summary>
    private static IReadOnlyList<string> SupersededAppVersions(string root)
    {
        if (FileWalk.Probe(root) != AccessState.Measured) return Array.Empty<string>();

        var versions = new List<(Version Version, string Path)>();

        foreach (var dir in Directory.EnumerateDirectories(root, "app-*"))
        {
            // "app-".Length == 4. A suffixed name such as app-3.6.4-beta does not parse, which
            // withdraws the whole row — the conservative direction.
            var name = Path.GetFileName(dir);
            if (name.Length <= 4 || !Version.TryParse(name[4..], out var version))
                return Array.Empty<string>();

            versions.Add((version, dir));
        }

        if (versions.Count < 2) return Array.Empty<string>();

        var live = versions.Max(v => v.Version);

        var older = new List<string>();
        foreach (var (version, path) in versions)
        {
            if (version == live) continue;
            if (ProtectedPaths.IsForbidden(path, out _)) continue;
            older.Add(path);
        }

        return older;
    }

    /// <summary>
    /// Expands application data roots into the concrete cache directories that exist right now.
    ///
    /// Both layouts are checked because both are in use here: WeMod, Vortex and Discord put their
    /// caches directly in the app root, while Steam's htmlcache and Spotify's MSIX package use
    /// Chromium's <c>Default</c> profile layout. The returned list becomes the target's Paths and
    /// therefore the executor's roots, so the allowlist is enforced by construction rather than by
    /// a check somewhere downstream that a later edit could route around.
    /// </summary>
    private static List<string> ChromiumCachesUnder(params string[] roots)
    {
        var found = new List<string>();
        foreach (var root in roots)
        {
            if (FileWalk.Probe(root) != AccessState.Measured) continue;
            foreach (var leaf in ChromiumCacheLeaves)
            {
                AddIfSafe(found, Path.Combine(root, leaf));
                AddIfSafe(found, Path.Combine(root, "Default", leaf));
            }
        }
        return found;
    }

    /// <summary>
    /// Adds a path only if it exists and clears both tripwires.
    ///
    /// The browser-profile check catches a future edit that adds a leaf name too close to the
    /// credential store. The forbidden check is the one that earns its place today: without it a
    /// target under Program Files previews a size, gets approved, and then skips every single file
    /// as <see cref="SkipReason.Protected"/> — a silent, confusing nothing. Better to discover that
    /// here, where the path can simply not be offered.
    /// </summary>
    private static void AddIfSafe(List<string> into, string path)
    {
        if (FileWalk.Probe(path) != AccessState.Measured) return;
        if (ProtectedPaths.TouchesBrowserProfile(path)) return;
        if (ProtectedPaths.IsForbidden(path, out _)) return;
        into.Add(path);
    }

    // ----------------------------------------------------------- GPU shader caches

    private static IEnumerable<CleanupTarget> GpuShaderCaches()
    {
        // 5.20 GB measured, and the largest single reclaim anywhere on this machine — bigger than
        // every CCleaner application rule that matches here added together. DxcCache is 4.59 GB
        // across 269 files, DxCache 412.9 MB / 615, OglCache 208.8 MB / 38, VkCache 8.1 MB / 30,
        // DX9Cache 0.8 MB / 66.
        //
        // The safety argument is the cache key, not the file names: each .parc pipeline archive is
        // keyed by driver version and shader hash, so a driver update invalidates the lot anyway.
        // This directory is designed to be thrown away.
        //
        // %LocalAppData%\AMD\CN (38.9 MB) is deliberately absent from the list — it holds Radeon
        // Software's per-game profiles and overlay settings, which are configuration the user chose.
        yield return new CleanupTarget
        {
            Id = "gpu.amd.shader-cache",
            Category = CleanupCategory.EngineCache,
            DisplayName = "AMD shader cache",
            Description = "Compiled shaders the AMD driver keeps so games do not rebuild them every " +
                          "launch. 5.20 GB here. Your Radeon Software settings and per-game profiles " +
                          "are stored elsewhere and are not touched.",
            Paths = new[]
            {
                Path.Combine(Local, "AMD", "DxcCache"),
                Path.Combine(Local, "AMD", "DxCache"),
                Path.Combine(Local, "AMD", "OglCache"),
                Path.Combine(Local, "AMD", "VkCache"),
                Path.Combine(Local, "AMD", "DX9Cache"),
            },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "The first few minutes of each game stutter while shaders recompile. " +
                                "Nothing is lost and no game needs reinstalling.",
            RestoreHint = "Nothing to restore — the driver rebuilds each shader the first time a game asks.",
            BlockerProbe = () => new List<CleanupBlocker>
            {
                // Advisory, not blocking. There is no list of "every game" to check, and a running
                // game holds only the archives it is currently reading — those fail File.Delete
                // with a sharing violation and are recorded as skipped, which is the correct
                // outcome rather than something to prevent.
                new("game-may-be-running",
                    "A game that is open right now keeps the shader archives it is using open, so " +
                    "those are skipped. Close your games for a complete clean.",
                    Blocking: false),
            },
        };

        // Absent on this machine — probed directly, all four paths missing — and shipped anyway
        // because NVIDIA is the commonest GPU there is and a row costs nothing when its paths do
        // not resolve. The same reasoning as the driver cache above applies: these are keyed by
        // driver version and discarded on every driver update.
        yield return new CleanupTarget
        {
            Id = "gpu.nvidia.shader-cache",
            Category = CleanupCategory.EngineCache,
            DisplayName = "NVIDIA shader cache",
            Description = "Compiled shaders the NVIDIA driver keeps so games do not rebuild them " +
                          "every launch. Your driver settings and game profiles are not touched.",
            Paths = new[]
            {
                Path.Combine(Local, "NVIDIA", "DXCache"),
                Path.Combine(Local, "NVIDIA", "GLCache"),
                Path.Combine(Local, "NVIDIA", "ComputeCache"),
                Path.Combine(Local, "NVIDIA Corporation", "NV_Cache"),
            },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "The first few minutes of each game stutter while shaders recompile.",
            RestoreHint = "Nothing to restore — the driver rebuilds shaders on demand.",
        };

        yield return new CleanupTarget
        {
            Id = "gpu.intel.shader-cache",
            Category = CleanupCategory.EngineCache,
            DisplayName = "Intel graphics shader cache",
            Description = "Compiled shaders the Intel graphics driver keeps between launches.",
            Paths = new[]
            {
                Path.Combine(Local, "Intel", "ShaderCache"),
                Path.Combine(Local, "Intel", "ShaderCacheDX9"),
            },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "The first few minutes of each game stutter while shaders recompile.",
            RestoreHint = "Nothing to restore — the driver rebuilds shaders on demand.",
        };
    }

    // -------------------------------------------------------------- game launchers

    private static IEnumerable<CleanupTarget> GameLaunchers()
    {
        // 1.03 GB across 9,566 files under %LocalAppData%\Steam\htmlcache, of which the allowlist
        // reaches 1.01 GB — Cache 343.2 MB, Default\Cache 339.8 MB, Default\Code Cache 298.9 MB,
        // Code Cache 14.9 MB, GrShaderCache 13.7 MB, and four smaller GPU caches.
        //
        // The 12 MB it does not reach is the whole point. Enumerating htmlcache\Default turns up
        // Login Data, Login Data For Account, Web Data, History, Top Sites, Affiliation Database and
        // Network\Cookies sitting in the same directory as the cache. Naming Chromium's cache leaves
        // costs 1% of the reclaim and removes the sign-out failure entirely.
        var steamHtml = ChromiumCachesUnder(Path.Combine(Local, "Steam", "htmlcache"));
        if (steamHtml.Count > 0)
        {
            yield return new CleanupTarget
            {
                Id = "app.steam.html-cache",
                Category = CleanupCategory.AppCache,
                DisplayName = "Steam store and library cache",
                Description = "Pages, images and scripts Steam's built-in browser cached for the " +
                              "store, library and community tabs. 1.01 GB here. Your sign-in, " +
                              "cookies and browsing history live in sibling files that this cannot reach.",
                Paths = steamHtml,
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                WhatBreaksIfWrong = "Store and library pages reload from the network once. You stay " +
                                    "signed in to Steam.",
                RestoreHint = "Nothing to restore — Steam refetches pages as you browse.",
                BlockerProbe = () =>
                {
                    // Blocking, unlike the advisory probes elsewhere: steamwebhelper.exe is the
                    // Chromium host and it holds the cache index open, so deleting underneath it
                    // does not merely skip files, it can leave the index describing blocks that are
                    // gone and force Steam to rebuild the whole cache on next launch.
                    var b = MaintenanceGuards.RunningBlocker("Steam", "clear its web cache",
                        "steam", "steamwebhelper");
                    if (b is null) return Array.Empty<CleanupBlocker>();
                    return new[] { b with { Detail = b.Detail + " Steam must be fully exited, not just closed to the tray." } };
                },
            };
        }

        // 1.88 GB across 13,931 files, sharded into 256 hex directories — a content-addressed store
        // of downloaded meshes, textures and audio. Content-addressed is the safety argument: every
        // entry is named for the hash of bytes the Roblox servers still hold, so nothing in here is
        // authored locally or unique to this machine.
        //
        // Prompt rather than Automatic purely on bandwidth. No data is at risk, but the next few
        // sessions re-download nearly 2 GB and that is not a cost to spend on someone's behalf.
        //
        // \Versions (978.3 MB, the installed client) and \LocalStorage (local game state) are
        // deliberately not named.
        yield return new CleanupTarget
        {
            Id = "app.roblox.asset-cache",
            Category = CleanupCategory.AppCache,
            DisplayName = "Roblox asset cache",
            Description = "Models, textures and sounds Roblox downloaded so repeat visits to a game " +
                          "load faster. 1.88 GB here. The installed client and your local game data " +
                          "are not touched.",
            Paths = new[] { Path.Combine(Local, "Roblox", "rbx-storage") },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Prompt,
            WhatBreaksIfWrong = "The next few games load slowly while about 2 GB re-downloads. " +
                                "Nothing is lost.",
            RestoreHint = "Nothing to restore — Roblox re-downloads each asset on demand.",
            BlockerProbe = () =>
            {
                var b = MaintenanceGuards.RunningBlocker("Roblox", "clear its asset cache",
                    "RobloxPlayerBeta", "RobloxStudioBeta", "RobloxPlayerLauncher");
                return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
            },
        };

        // 165.6 MB / 658 files. The directory name carries the launcher build number — webcache_4430
        // today — so the generic name and the measured name are both listed rather than a wildcard
        // this code cannot verify. The caller drops whichever is absent, and a launcher update that
        // bumps the number simply retires the stale row instead of silently matching nothing.
        yield return new CleanupTarget
        {
            Id = "app.epic.web-cache",
            Category = CleanupCategory.AppCache,
            DisplayName = "Epic Games Launcher cache",
            Description = "Store pages and images the Epic launcher cached. 165.6 MB here. Your " +
                          "library, sign-in and installed games are not touched.",
            Paths = new[]
            {
                Path.Combine(Local, "EpicGamesLauncher", "Saved", "webcache"),
                Path.Combine(Local, "EpicGamesLauncher", "Saved", "webcache_4430"),
            },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "The Epic store tab reloads from the network once. You stay signed in.",
            RestoreHint = "Nothing to restore — the launcher refetches pages when opened.",
            BlockerProbe = () =>
            {
                var b = MaintenanceGuards.RunningBlocker("The Epic Games Launcher", "clear its cache",
                    "EpicGamesLauncher", "EpicWebHelper");
                return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
            },
        };

        // BrowserCaches 99.7 MB / 770 files plus Cache 44.9 MB / 517. \Account is left out: at
        // 0.1 MB it reclaims nothing and it is what keeps the client signed in.
        yield return new CleanupTarget
        {
            Id = "app.battlenet.cache",
            Category = CleanupCategory.AppCache,
            DisplayName = "Battle.net launcher cache",
            Description = "News panels, shop pages and images the Battle.net client cached. " +
                          "144.6 MB here. Your saved sign-in is not touched.",
            Paths = new[]
            {
                Path.Combine(Local, "Battle.net", "BrowserCaches"),
                Path.Combine(Local, "Battle.net", "Cache"),
            },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "News and shop panels reload from the network once. You stay signed in.",
            RestoreHint = "Nothing to restore — Battle.net refetches on next launch.",
            BlockerProbe = () =>
            {
                var b = MaintenanceGuards.RunningBlocker("Battle.net", "clear its cache", "Battle.net");
                return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
            },
        };

        // 132.2 MB / 1,136 files, which is essentially the whole of Ubisoft Connect's local
        // footprint — the only siblings are an empty \spool, settings.yaml and user.dat. Named as
        // \cache explicitly rather than the launcher root so those three stay out of reach.
        yield return new CleanupTarget
        {
            Id = "app.ubisoft.cache",
            Category = CleanupCategory.AppCache,
            DisplayName = "Ubisoft Connect cache",
            Description = "Store and news content the Ubisoft Connect launcher cached. 132.2 MB here. " +
                          "Your settings and saved sign-in are not touched.",
            Paths = new[] { Path.Combine(Local, "Ubisoft Game Launcher", "cache") },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "Launcher pages reload from the network once. You stay signed in.",
            RestoreHint = "Nothing to restore — the launcher refetches when opened.",
            BlockerProbe = () =>
            {
                var b = MaintenanceGuards.RunningBlocker("Ubisoft Connect", "clear its cache",
                    "UbisoftConnect", "upc", "UplayWebCore");
                return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
            },
        };

        // Absent here (probed: no GOG.com directory at all) and included because GOG Galaxy is a
        // common fourth launcher. \webcache is its CEF cache; the storage\ database that holds the
        // library and sign-in is a sibling and is not named.
        yield return new CleanupTarget
        {
            Id = "app.gog.web-cache",
            Category = CleanupCategory.AppCache,
            DisplayName = "GOG Galaxy cache",
            Description = "Store pages and artwork GOG Galaxy cached. Your library database and " +
                          "sign-in are not touched.",
            Paths = new[] { Path.Combine(Local, "GOG.com", "Galaxy", "webcache") },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "Store pages reload from the network once. You stay signed in.",
            RestoreHint = "Nothing to restore — Galaxy refetches as you browse.",
        };
    }

    // ------------------------------------------------------------ embedded browsers

    private static IEnumerable<CleanupTarget> EmbeddedBrowsers()
    {
        // 807.4 MB across 5,623 files — by a wide margin the biggest thing Overwolf owns, and pure
        // CEF disk cache for the overlay apps it hosts.
        //
        // Its siblings are why this names one directory and not the Overwolf root: \Extensions
        // (149.2 MB) is the installed overlay applications themselves and \PackagesCache (61.5 MB)
        // is their update payloads. Neither is browser cache, and clearing them makes Overwolf
        // re-download working software.
        yield return new CleanupTarget
        {
            Id = "app.overwolf.browser-cache",
            Category = CleanupCategory.AppCache,
            DisplayName = "Overwolf overlay cache",
            Description = "Web content cached by the Overwolf overlay apps. 807.4 MB here. The " +
                          "installed overlays themselves are not touched.",
            Paths = new[] { Path.Combine(Local, "Overwolf", "CefBrowserCache") },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "Overlay panels redraw from the network the first time each is opened.",
            RestoreHint = "Nothing to restore — Overwolf refetches as overlays are used.",
            BlockerProbe = () =>
            {
                var b = MaintenanceGuards.RunningBlocker("Overwolf", "clear its overlay cache",
                    "Overwolf", "OverwolfLauncher", "OverwolfBrowser");
                return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
            },
        };

        // Spotify on this machine is the MSIX/Store build (SpotifyAB.SpotifyMusic_zpdnekdrzrea0).
        // %LocalAppData%\Spotify does not exist at all, which means DiskCleanup's existing
        // `app.spotify` rule — pointed at %LocalAppData%\Spotify\Browser\Cache — matches nothing
        // here and renders no row. This covers what is actually installed.
        //
        // 413.5 MB of unambiguous Chromium cache: Default\Cache 356.3 MB, Default\Code Cache
        // 45.1 MB, GrShaderCache 10.5 MB, Default\GPUCache 1.6 MB. The 1.16 GB \Data directory
        // beside them is a separate, deliberately undeletable row further down.
        var spotify = ChromiumCachesUnder(Path.Combine(
            Local, "Packages", "SpotifyAB.SpotifyMusic_zpdnekdrzrea0", "LocalCache", "Spotify"));
        if (spotify.Count > 0)
        {
            yield return new CleanupTarget
            {
                Id = "app.spotify.store.browser-cache",
                Category = CleanupCategory.AppCache,
                DisplayName = "Spotify interface cache",
                Description = "Artwork and page resources Spotify cached for its own interface. " +
                              "413.5 MB here. Your account, playlists and any downloaded music are " +
                              "stored elsewhere and are not touched.",
                Paths = spotify,
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                WhatBreaksIfWrong = "Album art reloads once. You stay signed in to Spotify.",
                RestoreHint = "Nothing to restore — Spotify refetches artwork as you browse.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker("Spotify", "clear its interface cache", "Spotify");
                    return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
                },
            };
        }
    }

    // ---------------------------------------------------------- Electron applications

    /// <summary>
    /// Application data roots already owned by another catalogue, excluded from discovery so the
    /// same bytes never appear as two rows. Discord, Slack and Teams belong to
    /// <see cref="DiskCleanup"/>'s own application caches; <c>Code</c> is VS Code and belongs to
    /// <see cref="DevCaches"/>; WeMod and Vortex get named rows below because their exclusions are
    /// worth saying out loud.
    /// </summary>
    private static readonly HashSet<string> AlreadyOwned = new(StringComparer.OrdinalIgnoreCase)
    {
        "discord", "discordcanary", "discordptb", "Slack", "Microsoft", "Code", "Spotify",
        "WeMod", "Vortex",
        // Browser vendors. Their profiles sit two levels down so the marker test below would not
        // reach them anyway, but a browser cache misfiled as an app cache is exactly the mistake
        // worth being explicit about.
        "Google", "BraveSoftware", "Mozilla", "Opera Software",
    };

    private static IEnumerable<CleanupTarget> ElectronApplications()
    {
        // WeMod: Cache 304.9 MB, GPUCache 5.6 MB, two Dawn caches, 310.5 MB reachable of a 626.2 MB
        // footprint. The allowlist leaves out \Partitions (209.5 MB) even though most of it is
        // cache — Electron session partitions carry their own cookie jars, so that is where a
        // sign-out would come from — and \games (1.0 MB), which is per-game cheat configuration the
        // user set up by hand.
        var wemod = ChromiumCachesUnder(Path.Combine(Roaming, "WeMod"));
        if (wemod.Count > 0)
        {
            yield return new CleanupTarget
            {
                Id = "app.wemod.cache",
                Category = CleanupCategory.AppCache,
                DisplayName = "WeMod cache",
                Description = "Game artwork and page resources WeMod cached. 310.5 MB here. Your " +
                              "account and your per-game settings are not touched.",
                Paths = wemod,
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                WhatBreaksIfWrong = "Game art reloads once. You stay signed in.",
                RestoreHint = "Nothing to restore — WeMod refetches on next launch.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker("WeMod", "clear its cache", "WeMod");
                    return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
                },
            };
        }

        // Vortex: Cache 188.6 MB, Code Cache 9.3 MB, GPUCache 5.6 MB, three Dawn caches — 205 MB of
        // a 448.0 MB footprint.
        //
        // Here the exclusions matter more than the target does. \downloads (102.9 MB) holds mod
        // archives fetched from Nexus, some of which get delisted and become genuinely
        // unrecoverable; \sonsoftheforest (96.0 MB), \skyrimse, \witcher3, \baldursgate3 and
        // \stellarblade hold the deployment state that maps mods onto game installs; \state.v2 is
        // Vortex's own database. Losing any of them means rebuilding a mod setup by hand. The
        // allowlist reaches none of them.
        var vortex = ChromiumCachesUnder(Path.Combine(Roaming, "Vortex"));
        if (vortex.Count > 0)
        {
            yield return new CleanupTarget
            {
                Id = "app.vortex.cache",
                Category = CleanupCategory.AppCache,
                DisplayName = "Vortex mod manager cache",
                Description = "Thumbnails and page resources Vortex cached from Nexus Mods. 205 MB " +
                              "here. Your downloaded mod archives and your per-game mod setups are " +
                              "not touched.",
                Paths = vortex,
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                WhatBreaksIfWrong = "Mod thumbnails reload from Nexus once. No mod file or deployment " +
                                    "is affected.",
                RestoreHint = "Nothing to restore — Vortex refetches thumbnails as you browse.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker("Vortex", "clear its cache", "Vortex");
                    return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
                },
            };
        }

        // Everything else Electron, found rather than listed.
        //
        // Enumerating %APPDATA% and %LOCALAPPDATA% for a GPUCache or Code Cache child turns up
        // fifteen more applications here beyond the ones named above: Claude, WwiseLauncher,
        // UnityHub, CurseForge, Antigravity, Wand, steam-connector, Pax Autocratica Launcher,
        // The Jackbox Megapicker, Mr.Mine, ai-combinator-launcher, GitHub Desktop,
        // bluestacks-services and others. No hand-written rule list would ever name a game jam
        // launcher or an incremental game, and between them they hold about 1.1 GB.
        //
        // One row rather than fifteen, because most are 5-30 MB and a maintenance page with fifteen
        // near-empty rows is worse than one honest one. The trade-off is that the user cannot opt
        // out of a single app — acceptable, because every path is a Chromium cache directory whose
        // loss costs a redraw.
        var discovered = DiscoverElectronRoots();
        var discoveredCaches = ChromiumCachesUnder(discovered.ToArray());
        if (discoveredCaches.Count > 0)
        {
            string names = NameList(discovered);
            yield return new CleanupTarget
            {
                Id = "app.electron.discovered",
                Category = CleanupCategory.AppCache,
                DisplayName = "Other app caches",
                Description = $"Cached images, pages and compiled scripts belonging to {names}. Each " +
                              "of these is built on the same web engine as a browser, so only the " +
                              "engine's own cache folders are cleared — sign-ins, settings and saved " +
                              "data are untouched.",
                Paths = discoveredCaches,
                Risk = CleanupRisk.Regenerable,
                // The only row here whose paths NOBODY can enumerate at review time: they are
                // chosen at runtime from every immediate child of %APPDATA% and %LOCALAPPDATA%
                // that has a GPUCache or Code Cache child, then intersected with a leaf allowlist
                // containing the very generic name "Cache". The structural test is weaker than it
                // looks — CEF, NW.js and Qt WebEngine also write GPUCache, and "Cache" is a name
                // any application may create for any purpose.
                //
                // The named rows above stay Automatic because their paths are fixed and were
                // measured. This one asks first: an unauditable path set is the wrong thing to
                // delete from with nobody at the keyboard.
                Tier = AutomationTier.Prompt,
                WhatBreaksIfWrong = "Each app redraws its interface from the network once. You stay " +
                                    "signed in everywhere.",
                RestoreHint = "Nothing to restore — each app refetches what it needs.",
                BlockerProbe = () => new List<CleanupBlocker>
                {
                    // Advisory on purpose, and this one is a judgement call worth recording.
                    //
                    // A blocking probe needs a reliable process name per application, and the
                    // directory name does not give one: UnityHub's process is "Unity Hub", GitHub
                    // Desktop's is "GitHubDesktop", ai-combinator-launcher's is anyone's guess.
                    // Guessing wrong either blocks the row forever or never, and both are worse
                    // than the truth — which is that Chromium holds its cache blocks open, so a
                    // file belonging to a running app fails File.Delete with a sharing violation
                    // and is recorded as skipped. The file system is the interlock here.
                    new("apps-may-be-running",
                        "Any of these apps that is open right now keeps its cache files open, so " +
                        "those files are skipped rather than deleted. Close the ones you care about " +
                        "for a complete clean.",
                        Blocking: false),
                },
            };
        }
    }

    /// <summary>
    /// Application data roots that are Electron or CEF underneath.
    ///
    /// The marker is a GPUCache or Code Cache child directory: Chromium creates both and nothing
    /// else does, which makes this a structural test rather than a name-matching heuristic. Only
    /// the immediate children of the two AppData roots are examined — one attribute query each,
    /// roughly 400 in total, and browsers stay out of scope because their profiles sit two levels
    /// deeper.
    /// </summary>
    private static List<string> DiscoverElectronRoots()
    {
        var roots = new List<string>();

        foreach (var appData in new[] { Roaming, Local })
        {
            List<string> children;
            try { children = Directory.EnumerateDirectories(appData).ToList(); }
            catch { continue; }

            foreach (var dir in children)
            {
                string name = Path.GetFileName(dir) ?? "";
                if (name.Length == 0 || AlreadyOwned.Contains(name)) continue;
                if (FileWalk.Probe(Path.Combine(dir, "GPUCache")) != AccessState.Measured &&
                    FileWalk.Probe(Path.Combine(dir, "Code Cache")) != AccessState.Measured) continue;
                roots.Add(dir);
            }
        }

        return roots;
    }

    /// <summary>
    /// The discovered applications as a readable phrase. Capped at six named plus a count, because
    /// this lands in a Description the user reads and seventeen comma-separated directory names is
    /// not a sentence.
    /// </summary>
    private static string NameList(IReadOnlyList<string> roots)
    {
        // Written as a loop rather than a Select(Path.GetFileName) method group: under the span
        // conversions .NET 10 enables, that method group has two applicable overloads and the
        // conversion is not worth the argument.
        var names = new List<string>(roots.Count);
        foreach (var root in roots)
        {
            string name = Path.GetFileName(root) ?? "";
            if (name.Length > 0) names.Add(name);
        }
        names.Sort(StringComparer.OrdinalIgnoreCase);

        if (names.Count <= 6) return string.Join(", ", names);
        return string.Join(", ", names.Take(6)) + $" and {names.Count - 6} other apps";
    }

    // -------------------------------------------------------- installer leftovers

    private static IEnumerable<CleanupTarget> InstallerLeftovers()
    {
        // 1.07 GB. Squirrel is the auto-updater behind most Electron apps — Discord, GitHub Desktop
        // and friends. It extracts each update into %LocalAppData%\SquirrelTemp\temp<letter> and is
        // supposed to remove it afterwards. Six such directories and two loose files have piled up
        // here (tempg 330.2 MB, tempb 320.6 MB, tempe 239.1 MB, plus tempc 124.0 MB and temph
        // 80.0 MB as files), which means the cleanup step has failed repeatedly. Every one is an
        // abandoned copy of an update that is already installed.
        //
        // Prompt rather than Automatic on a timing risk, not a data risk: if an update happens to be
        // extracting at that moment, removing its staging directory fails that one update and the
        // app retries on next launch. The age gate makes even that unlikely.
        yield return new CleanupTarget
        {
            Id = "app.squirrel.stale-installers",
            Category = CleanupCategory.AppCache,
            DisplayName = "Leftover app update files",
            Description = "Copies of already-installed updates that apps unpacked and failed to clean " +
                          "up afterwards. 1.07 GB here. No installed application is affected.",
            Paths = new[] { Path.Combine(Local, "SquirrelTemp") },
            Risk = CleanupRisk.Low,
            Tier = AutomationTier.Prompt,
            MinimumAge = TimeSpan.FromDays(1),
            WhatBreaksIfWrong = "An update that was unpacking at that moment starts over on the app's " +
                                "next launch.",
            RestoreHint = "Nothing to restore — apps re-download an update if they still need it.",
        };

        // 974.9 MB across 17 files: the unpacked SketchUp 2026 installer, kept only so Windows can
        // repair or modify the installation without asking for the download again.
        //
        // Low rather than Regenerable, and named as the version leaf rather than the
        // "Downloaded Installations" parent. The parent is a Trimble convention that other
        // installers of theirs also write into, and a rule that swallowed a future sibling
        // wholesale would be reclaiming something never measured.
        yield return new CleanupTarget
        {
            Id = "app.sketchup.cached-installer",
            Category = CleanupCategory.AppCache,
            DisplayName = "SketchUp 2026 installer cache",
            Description = "The unpacked SketchUp installer, kept so Windows can repair or change the " +
                          "installation without downloading it again. 974.9 MB here. SketchUp itself " +
                          "keeps working normally.",
            Paths = new[] { Path.Combine(Local, "Downloaded Installations", "SketchUp 2026") },
            Risk = CleanupRisk.Low,
            Tier = AutomationTier.Prompt,
            WhatBreaksIfWrong = "Repairing or modifying SketchUp later asks you to download the " +
                                "installer again — a large download at an inconvenient moment.",
            RestoreHint = "Download the installer from SketchUp if a repair ever asks for it.",
        };

        // 220.1 MB: installer.exe 111.3 MB plus \pending 108.6 MB — a downloaded CurseForge update
        // and a staged one. Same shape as the Squirrel leftovers and the same reasoning; the
        // modpacks and mod files CurseForge manages live elsewhere entirely.
        yield return new CleanupTarget
        {
            Id = "app.curseforge.stale-updater",
            Category = CleanupCategory.AppCache,
            DisplayName = "CurseForge update downloads",
            Description = "A downloaded CurseForge installer and a staged update. 220.1 MB here. Your " +
                          "modpacks and mod files are stored elsewhere and are not touched.",
            Paths = new[] { Path.Combine(Local, "curseforge-updater") },
            Risk = CleanupRisk.Low,
            Tier = AutomationTier.Prompt,
            MinimumAge = TimeSpan.FromDays(1),
            WhatBreaksIfWrong = "CurseForge downloads its next update again instead of using the copy " +
                                "it had staged.",
            RestoreHint = "Nothing to restore — CurseForge re-downloads its updater when needed.",
        };

        // 305.0 MB across 4 files: the .nupkg archives and RELEASES index Squirrel keeps so the next
        // GitHub Desktop update can be a small patch rather than a full download.
        //
        // What this target pointedly does NOT name: app-3.6.2 (2.6 MB), app-3.6.3 (719.1 MB) and
        // app-3.6.4 (716.6 MB). Only one of those is live, the stub resolves which at runtime, and
        // this contract takes a fixed list of paths. There is no hard-coded version number that
        // stays correct across an update, and picking the wrong one deletes the running application.
        // That 1.00 GB is left on the table on purpose; claiming it needs a resolver that reads the
        // Squirrel stub, not a literal in a path list.
        //
        // The age gate covers the only real hazard: a download in progress writes now, so an update
        // that is mid-flight is skipped rather than half-removed.
        yield return new CleanupTarget
        {
            Id = "app.githubdesktop.update-packages",
            Category = CleanupCategory.AppCache,
            DisplayName = "GitHub Desktop update downloads",
            Description = "Update archives GitHub Desktop keeps so its next update can be a small " +
                          "patch. 305.0 MB here. The application itself and your repositories are " +
                          "not touched.",
            Paths = new[] { Path.Combine(Local, "GitHubDesktop", "packages") },
            Risk = CleanupRisk.Low,
            Tier = AutomationTier.Prompt,
            MinimumAge = TimeSpan.FromDays(1),
            WhatBreaksIfWrong = "The next GitHub Desktop update downloads the whole application " +
                                "instead of a small patch.",
            RestoreHint = "Nothing to restore — GitHub Desktop refetches what it needs when it updates.",
        };

        // The 1.00 GB the row above deliberately left alone: superseded app-<version> directories.
        //
        // That comment was right that a hard-coded version number is never safe and that this needs
        // a resolver. It is wrong only about where the resolver can live — Paths is built here, at
        // Enumerate() time, not baked into a literal, so the version set can be read from disk on
        // every run and stays correct across updates.
        //
        // The rule is deliberately the crudest one that cannot be wrong: keep the HIGHEST version,
        // offer every lower one. Squirrel's GitHubDesktop.exe stub launches the newest app-* it
        // finds, so the highest is the live application by construction.
        //
        // Measured here: app-3.6.2 2.6 MB (already gutted, carries Squirrel's .dead marker),
        // app-3.6.3 719.1 MB (superseded but NOT marked .dead — which is exactly why .dead cannot
        // be the test), app-3.6.4 716.6 MB (live). Offering the two lower ones reclaims 721.7 MB.
        //
        // If ANY directory name fails to parse as a version the whole row is withdrawn rather than
        // guessed at. Deleting the running application is not a mistake worth risking to reclaim
        // disk, and a partial ordering over a set this small is worthless.
        var ghRoot = Path.Combine(Local, "GitHubDesktop");
        var superseded = SupersededAppVersions(ghRoot);

        if (superseded.Count > 0)
            yield return new CleanupTarget
            {
                Id = "app.githubdesktop.old-versions",
                Category = CleanupCategory.AppCache,
                DisplayName = "GitHub Desktop superseded versions",
                Description = "Complete copies of older GitHub Desktop versions left behind by its " +
                              "updater. The version you actually run is never included — only " +
                              "releases a newer one has replaced.",
                Paths = superseded,
                Risk = CleanupRisk.Low,
                Tier = AutomationTier.Prompt,
                // A version installed in the last day may still be mid-rollback.
                MinimumAge = TimeSpan.FromDays(1),
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker(
                        "GitHub Desktop", "remove its superseded versions", "GitHubDesktop");
                    return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
                },
                WhatBreaksIfWrong = "If GitHub Desktop ever rolls back to the previous version it " +
                                    "downloads it again instead of switching to a local copy. Your " +
                                    "repositories and settings live elsewhere and are not touched.",
                RestoreHint = "Nothing to restore — the running version is untouched and a rollback " +
                              "re-downloads.",
            };

        // 26.2 MB / 15 files. DiskCleanup.ApplicationCaches() already owns Discord's Cache, Code
        // Cache and GPUCache as `app.discord`; this adds only the log directory, which that rule
        // does not cover and which is the second-largest disposable thing Discord owns.
        yield return new CleanupTarget
        {
            Id = "app.discord.logs",
            Category = CleanupCategory.Logs,
            DisplayName = "Discord logs",
            Description = "Discord's own diagnostic logs. 26.2 MB here. Useful only when reporting a " +
                          "bug to Discord.",
            Paths = new[] { Path.Combine(Roaming, "discord", "logs") },
            Risk = CleanupRisk.Regenerable,
            Tier = AutomationTier.Automatic,
            WhatBreaksIfWrong = "A Discord bug report loses the log that would have explained a past " +
                                "crash or call failure.",
            RestoreHint = "Nothing to restore — Discord writes new logs as it runs.",
            BlockerProbe = () => new List<CleanupBlocker>
            {
                // Advisory rather than blocking: Discord is running essentially always on this
                // machine, and a blocking probe would make a 26 MB row permanently unactionable.
                // The live log file is held open and simply gets skipped.
                new("discord-running",
                    "Discord holds its current log file open, so that one is skipped. The rotated " +
                    "logs, which are the bulk of it, are removed either way.",
                    Blocking: false),
            },
        };
    }

    // ------------------------------------------------- measured, shown, never deleted

    /// <summary>
    /// Rows that exist so the Maintenance page can account for 2.4 GB without offering to reclaim
    /// it. An unexplained gap of that size is an invitation to go hunting with a less careful tool,
    /// and "here is what it is and why HERO will not touch it" is the more trustworthy answer.
    ///
    /// Every one is <see cref="CleanupRisk.NeverClean"/> rather than merely
    /// <see cref="AutomationTier.ReadOnly"/>, because the tier is advice to the UI and the risk is
    /// what <see cref="CleanupExecutor.Execute"/> actually refuses on.
    /// </summary>
    private static IEnumerable<CleanupTarget> ShownNeverDeleted()
    {
        // 1.16 GB (1,187.7 MB / 416 files) in the Store build's LocalCache\Spotify\Data, and
        // shown-only because the evidence genuinely conflicts and 1.16 GB is not worth being wrong
        // about when the failure mode is destroying music that needs a connection to restore.
        //
        // For cleaning it: CCleaner 7 ships this exact path as [Spotify - Data Cache] with
        // Default=True, while shipping \Storage separately as [Spotify - Offline songs] with
        // Default=False and a warning dialog — Piriform reads Data as the streaming cache and
        // Storage as the downloads. The MSIX layout agrees, in that Data sits under LocalCache,
        // which is the Store convention for "deletable, the app refetches", where LocalState is the
        // half that gets backed up. And neither LocalCache\Spotify\Storage nor
        // LocalState\Spotify\Storage exists on this machine, so there are no offline downloads here.
        //
        // Against cleaning it: DiskCleanup.ApplicationCaches() states the opposite in its own
        // comment — that on current builds \Data is where offline tracks live — and declines to
        // touch either directory.
        //
        // An unresolved contradiction about a directory that might hold offline music resolves to
        // NeverClean. The row still shows the size so the user can see where the space went.
        yield return new CleanupTarget
        {
            Id = "app.spotify.store.data",
            Category = CleanupCategory.Informational,
            DisplayName = "Spotify audio store — read-only",
            Description = "1.16 GB Spotify keeps under 'Data'. This is almost certainly cached " +
                          "streamed audio, but on some builds it is where downloaded-for-offline " +
                          "music lives, so HERO shows the size and refuses to delete it.",
            Paths = new[]
            {
                Path.Combine(Local, "Packages", "SpotifyAB.SpotifyMusic_zpdnekdrzrea0",
                             "LocalCache", "Spotify", "Data"),
            },
            Risk = CleanupRisk.NeverClean,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "If this build keeps offline downloads here, that music is gone and " +
                                "has to be re-downloaded — which needs a connection you may not have " +
                                "when you notice.",
            RestoreHint = "Re-download the affected playlists in Spotify while online.",
        };

        // 465.0 MB / 14 files. Despite sitting beside the caches, module_data is not cache:
        // discord_voice and discord_utils are downloaded native modules Discord loads at startup.
        // Discord does re-fetch them, but a failure mid-fetch leaves voice chat and screen share
        // broken until the next successful update, and CCleaner's own [Discord] rule pointedly
        // avoids it too.
        yield return new CleanupTarget
        {
            Id = "app.discord.native-modules",
            Category = CleanupCategory.Informational,
            DisplayName = "Discord voice components — read-only",
            Description = "465.0 MB of components Discord downloaded for voice and screen share. It " +
                          "sits beside the cache but is not cache, so HERO leaves it alone.",
            Paths = new[] { Path.Combine(Roaming, "discord", "module_data") },
            Risk = CleanupRisk.NeverClean,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Voice chat and screen share stop working until Discord successfully " +
                                "re-downloads the components.",
            RestoreHint = "Reinstall Discord if the voice components go missing.",
        };

        // 1.77 GB inside the Steam install directory: appcache\librarycache 924.7 MB / 9,797 files
        // (per-appid capsule and hero artwork), depotcache 742.7 MB / 885, appcache\httpcache
        // 75.7 MB / 10,000 and logs 35.7 MB / 38.
        //
        // Shown rather than offered for a mechanical reason before a judgement one: Steam is
        // installed to C:\Program Files (x86)\Steam here — confirmed via
        // HKCU\Software\Valve\Steam\SteamPath, and worth noting because CCleaner's own [Steam] rule
        // detects on %ProgramFiles%\Steam and therefore never fires on this machine at all — and
        // ProtectedPaths lists both Program Files roots as forbidden. A target offering these would
        // preview 20,720 files and delete none of them.
        //
        // The judgement reason applies to the depot manifests independently: they are what
        // "Verify integrity of game files" reads, and one deleted mid-update is a plausible way to
        // wedge a download. Steam's own Settings > Downloads > Clear Download Cache is the supported
        // route for anyone who wants this space back.
        yield return new CleanupTarget
        {
            Id = "app.steam.install-caches",
            Category = CleanupCategory.Informational,
            DisplayName = "Steam install-folder caches — read-only",
            Description = "1.77 GB of library artwork, download manifests and logs inside Steam's " +
                          "program folder. HERO never deletes anything under Program Files, so this " +
                          "is shown for the record only. Use Steam's own Settings > Downloads > " +
                          "Clear Download Cache if you want it back.",
            Paths = new[]
            {
                Path.Combine(ProgramFilesX86, "Steam", "appcache", "librarycache"),
                Path.Combine(ProgramFilesX86, "Steam", "appcache", "httpcache"),
                Path.Combine(ProgramFilesX86, "Steam", "depotcache"),
                Path.Combine(ProgramFilesX86, "Steam", "logs"),
            },
            Risk = CleanupRisk.NeverClean,
            NeedsAdmin = true,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Removing a depot manifest can leave a game update or integrity check " +
                                "failing partway through and starting over.",
            RestoreHint = "Steam refetches artwork and manifests by itself; 'Verify integrity of game " +
                          "files' rebuilds what it needs.",
        };
    }
}
