using System.Text.Json;

namespace Hero.Maintenance;

/// <summary>
/// The browser catalogue: the privacy-affecting half that <see cref="DiskCleanup"/> deliberately
/// does not offer, plus cache coverage for every Chromium and Gecko build it does not name.
///
/// OWNERSHIP, AND WHY THIS FILE DOES NOT SHIP A SECOND "Chrome cache" ROW.
/// DiskCleanup.BrowserCaches() already emits one Regenerable cache row each for Chrome, Edge,
/// Brave, Opera GX and Opera, built from its own leaf allowlist (Cache\Cache_Data, Code Cache\js,
/// Code Cache\wasm, GPUCache, Service Worker\CacheStorage, Service Worker\ScriptCache,
/// DawnGraphiteCache, DawnWebGPUCache, System Cache, plus ShaderCache / GrShaderCache /
/// GraphiteDawnCache / GPUPersistentCache beside the profiles), and FirefoxCaches() covers
/// cache2 and startupCache. Emitting the same bytes again under a different id would show the
/// user two rows claiming the same reclaim, and after they ran the first one the second would
/// read 0 B — which reads as a broken tool, not a thorough one. So the cache builder below skips
/// the five Chromium browsers and the one Gecko app DiskCleanup already claims, and this file's
/// contribution to those installs is the cookie, site-data and session rows instead.
///
/// What DiskCleanup's two arrays genuinely miss, measured on this machine on 2026-09-03, for
/// whoever extends them (a two-line edit there beats a duplicate row here): extensions_crx_cache
/// 15.6 MB in Chrome and 5.0 MB in Opera GX, component_crx_cache 1.6 MB in Opera GX,
/// Cache\No_Vary_Search, image_cache, Media Cache, BrowserMetrics and the profile-level
/// GrShaderCache / GraphiteDawnCache. About 25 MB in total — real, but not worth a second row.
///
/// PROFILE ENUMERATION IS THE WHOLE JOB, AND GLOBBING IS THE WRONG ANSWER.
/// CCleaner's rule file resolves Chromium browsers with a macro that expands to "User Data\*",
/// then appends a leaf and hopes the leaf fails to exist under everything that is not a profile.
/// Measured here: Chrome's User Data holds 38 immediate child directories, Edge's 56, Opera GX's
/// 22, and in every one of the three exactly ONE of them is a profile. The other 37 / 55 / 21 are
/// component stores (Safe Browsing, WidevineCdm, Crashpad, hyphen-data, SafetyTips...). That
/// over-match is survivable for a "\Cache" style rule and dangerous for a flat one such as
/// "&lt;profile&gt;|History", which under a wildcard arm would match a file of that name anywhere
/// in the tree. HERO reads the browser's own answer instead: the KEYS of profile.info_cache in
/// "User Data\Local State", falling back to "child directories that contain a Preferences file",
/// which selected exactly Default and rejected all 113 component directories here.
///
/// Delete by KEY, label by name: Edge's directory "Default" carries the info_cache display name
/// "Profile 1", Chrome's carries "Finlay", and Opera GX's is the empty string. A UI that labels a
/// profile from that field has to fall back to the directory name, and a cleaner that resolves a
/// path from it would look for a directory that does not exist.
///
/// THE EXECUTOR CANNOT DELETE A BARE FILE, AND THAT SHAPES THIS CATALOGUE.
/// CleanupExecutor.Validate accepts a file only when its path starts with a declared root plus a
/// separator, so a target whose root IS a file measures correctly and then skips every item as
/// OutsideTarget. Chromium keeps History, Web Data, Login Data, Bookmarks, Favicons and Top Sites
/// as bare files directly in the profile directory, so reaching them would mean declaring the
/// profile directory itself as a deletion root — the one thing the leaf allowlist exists to
/// prevent. Those rows are therefore read-only here, and say so in plain words rather than
/// quietly measuring something they cannot act on. The cookie database escapes that fate only
/// because modern Chromium moved it into a "Network" subdirectory, which is a legitimate root.
/// </summary>
internal static class BrowserTargets
{
    private static string Local => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Roaming => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private const StringComparison OIC = StringComparison.OrdinalIgnoreCase;

    /// <summary>
    /// Every browser row. Targets whose paths are all absent are dropped by the caller, so
    /// browsers that are not installed are still described here — the cost is one GetFileAttributesW
    /// per candidate path and the benefit is that HERO works on a machine that is not this one.
    /// </summary>
    internal static IEnumerable<CleanupTarget> Enumerate()
    {
        var chromium = new List<DiscoveredChromium>();
        foreach (var browser in ChromiumFamily())
        {
            var profiles = DiscoverProfiles(browser);
            if (profiles.Count == 0) continue;
            chromium.Add(new DiscoveredChromium(browser, profiles));
        }

        foreach (var found in chromium)
            foreach (var target in ChromiumTargets(found))
                yield return target;

        // The two read-only rows span the whole family rather than repeating per browser: the
        // explanation is identical for all of them and five copies of it is noise, not honesty.
        if (ChromiumHistoryObservation(chromium) is { } history) yield return history;
        if (ChromiumCredentialObservation(chromium) is { } credentials) yield return credentials;

        foreach (var target in GeckoTargets()) yield return target;
    }

    // ---------------------------------------------------------------- chromium family

    /// <param name="Slug">Stable id fragment. Written out rather than derived from the display
    /// name so that renaming a row in the UI cannot silently orphan a user's saved preferences.</param>
    /// <param name="Roots">User Data roots. A list because Opera splits one install across two.</param>
    /// <param name="Processes">Process names that mean "this browser is open".</param>
    private sealed record ChromiumBrowser(
        string Slug, string Name, IReadOnlyList<string> Roots,
        IReadOnlyList<string> Processes, string CloseAdvice);

    private sealed record DiscoveredChromium(ChromiumBrowser Browser, IReadOnlyList<string> Profiles);

    /// <summary>
    /// Slugs whose cache rows belong to <see cref="DiskCleanup"/>. See the class header: the
    /// duplicate-row problem is a user-visible trust failure, not a tidiness preference.
    /// </summary>
    private static readonly string[] CacheClaimedByDiskCleanup =
    {
        "chrome", "edge", "brave", "opera", "opera-gx",
    };

    private static IEnumerable<ChromiumBrowser> ChromiumFamily()
    {
        // Installed on this machine: Chrome, Edge and Opera GX. Everything else below was probed
        // and is absent, which is why none of their sizes appear in any comment here.
        yield return new ChromiumBrowser("chrome", "Google Chrome",
            new[] { Path.Combine(Local, "Google", "Chrome", "User Data") },
            new[] { "chrome" }, "Close Chrome");

        yield return new ChromiumBrowser("chrome-beta", "Google Chrome Beta",
            new[] { Path.Combine(Local, "Google", "Chrome Beta", "User Data") },
            new[] { "chrome" }, "Close Chrome Beta");

        // Canary ships as "Chrome SxS" on disk and runs side-by-side with stable, so its process
        // is also chrome.exe. A false "Chrome is open" blocker costs a skipped run; the reverse
        // costs a deletion underneath a live browser, so the loose match is the right way round.
        yield return new ChromiumBrowser("chrome-canary", "Google Chrome Canary",
            new[] { Path.Combine(Local, "Google", "Chrome SxS", "User Data") },
            new[] { "chrome" }, "Close Chrome Canary");

        yield return new ChromiumBrowser("edge", "Microsoft Edge",
            new[] { Path.Combine(Local, "Microsoft", "Edge", "User Data") },
            // msedgewebview2.exe is deliberately NOT listed. WebView2 hosts run constantly on
            // Windows 11 (widgets, Office, Teams), and treating them as "Edge is open" would make
            // every Edge row permanently unactionable.
            new[] { "msedge" },
            "Close Edge, including any window Startup Boost keeps alive after the last one closes");

        yield return new ChromiumBrowser("edge-beta", "Microsoft Edge Beta",
            new[] { Path.Combine(Local, "Microsoft", "Edge Beta", "User Data") },
            new[] { "msedge" }, "Close Edge Beta");

        yield return new ChromiumBrowser("edge-dev", "Microsoft Edge Dev",
            new[] { Path.Combine(Local, "Microsoft", "Edge Dev", "User Data") },
            new[] { "msedge" }, "Close Edge Dev");

        yield return new ChromiumBrowser("edge-canary", "Microsoft Edge Canary",
            new[] { Path.Combine(Local, "Microsoft", "Edge SxS", "User Data") },
            new[] { "msedge" }, "Close Edge Canary");

        yield return new ChromiumBrowser("brave", "Brave",
            new[] { Path.Combine(Local, "BraveSoftware", "Brave-Browser", "User Data") },
            new[] { "brave" }, "Close Brave");

        yield return new ChromiumBrowser("brave-beta", "Brave Beta",
            new[] { Path.Combine(Local, "BraveSoftware", "Brave-Browser-Beta", "User Data") },
            new[] { "brave" }, "Close Brave Beta");

        yield return new ChromiumBrowser("brave-nightly", "Brave Nightly",
            new[] { Path.Combine(Local, "BraveSoftware", "Brave-Browser-Nightly", "User Data") },
            new[] { "brave" }, "Close Brave Nightly");

        yield return new ChromiumBrowser("vivaldi", "Vivaldi",
            new[] { Path.Combine(Local, "Vivaldi", "User Data") },
            new[] { "vivaldi" }, "Close Vivaldi");

        // Opera is the one Chromium layout that is genuinely two-rooted, and it is not optional
        // to handle: measured here, the ROAMING root holds the profile (Local Storage 21.6 MB,
        // IndexedDB 64.1 MB, Sessions 3.1 MB, Service Worker 1,120 MB) while the LOCAL root holds
        // only Cache (70.9 MB) and System Cache (6.9 MB). Local State exists in the roaming root
        // alone, which is why profile names are collected across roots and then applied to every
        // root rather than resolved per root. There is also no "User Data" path segment: the
        // product directory is the User Data directory.
        yield return new ChromiumBrowser("opera-gx", "Opera GX",
            new[]
            {
                Path.Combine(Roaming, "Opera Software", "Opera GX Stable"),
                Path.Combine(Local, "Opera Software", "Opera GX Stable"),
            },
            new[] { "opera" }, "Close Opera GX");

        yield return new ChromiumBrowser("opera", "Opera",
            new[]
            {
                Path.Combine(Roaming, "Opera Software", "Opera Stable"),
                Path.Combine(Local, "Opera Software", "Opera Stable"),
            },
            new[] { "opera" }, "Close Opera");

        // Presto-era Opera 12 (\profile, cache4, opcache, wand.dat) is deliberately not modelled.
        // Anything still running it is a 2013 install, and the wildcards its layout needs are
        // exactly the kind this file refuses to write blind.

        yield return new ChromiumBrowser("opera-developer", "Opera Developer",
            new[]
            {
                Path.Combine(Roaming, "Opera Software", "Opera Developer"),
                Path.Combine(Local, "Opera Software", "Opera Developer"),
            },
            new[] { "opera" }, "Close Opera Developer");

        // Chromium's own builds ship as chrome.exe, so the running check is shared with Chrome.
        yield return new ChromiumBrowser("chromium", "Chromium",
            new[] { Path.Combine(Local, "Chromium", "User Data") },
            new[] { "chrome" }, "Close Chromium");

        // Yandex Browser's executable is literally browser.exe. Matching that name can be
        // triggered by an unrelated program, but a false positive only ever produces a "close it
        // first" blocker, never a deletion, so the loose name is acceptable here.
        yield return new ChromiumBrowser("yandex", "Yandex Browser",
            new[] { Path.Combine(Local, "Yandex", "YandexBrowser", "User Data") },
            new[] { "browser" }, "Close Yandex Browser");

        // Arc is MSIX-packaged, so its root lives under a package family whose suffix is a
        // publisher hash. Globbing the publisher prefix beats hard-coding the hash, which changes
        // if the app is ever re-signed. Note that writes inside a package container can be
        // virtualised, so a delete here is worth verifying before the reclaim is believed.
        var arcRoots = PackageFamilyRoots("TheBrowserCompany.Arc_", "LocalCache", "Local", "Arc", "User Data");
        if (arcRoots.Count > 0)
            yield return new ChromiumBrowser("arc", "Arc", arcRoots, new[] { "Arc" }, "Close Arc");
    }

    /// <summary>
    /// The profile directories of one browser, across all of its roots.
    ///
    /// Three tiers, in order of authority. Local State is the browser's own list and is believed
    /// first; "contains a Preferences file" is the cheap discriminator that rejected all 113
    /// non-profile directories measured across Chrome, Edge and Opera GX here; a bare "Default"
    /// is the last resort for a root whose Local State could not be read (Opera GX's LOCAL root
    /// has neither Local State nor Preferences, and would otherwise be invisible if its roaming
    /// sibling ever went missing). A wildcard over User Data is never a tier.
    /// </summary>
    private static List<string> DiscoverProfiles(ChromiumBrowser browser)
    {
        var names = new List<string>();

        foreach (var root in browser.Roots)
            foreach (var name in ProfileNamesFromLocalState(Path.Combine(root, "Local State")))
                if (!names.Contains(name, StringComparer.OrdinalIgnoreCase))
                    names.Add(name);

        if (names.Count == 0)
            foreach (var root in browser.Roots)
                foreach (var name in ProfileNamesFromPreferences(root))
                    if (!names.Contains(name, StringComparer.OrdinalIgnoreCase))
                        names.Add(name);

        if (names.Count == 0) names.Add("Default");

        var profiles = new List<string>();
        foreach (var root in browser.Roots)
            foreach (var name in names)
            {
                string candidate = Path.Combine(root, name);
                if (FileWalk.Probe(candidate, out bool isDirectory) == AccessState.Measured && isDirectory)
                    profiles.Add(candidate);
            }
        return profiles;
    }

    /// <summary>
    /// Profile directory names as the browser itself records them: the keys of
    /// profile.info_cache. Verified against Chrome, Edge and Opera GX on this machine.
    /// </summary>
    private static List<string> ProfileNamesFromLocalState(string localStatePath)
    {
        var names = new List<string>();
        try
        {
            if (!File.Exists(localStatePath)) return names;

            // Read the bytes and parse from memory rather than streaming: Local State is tens of
            // kilobytes, the browser may be writing it, and a short read that throws is caught
            // here and demoted to the Preferences probe rather than losing every profile.
            using var doc = JsonDocument.Parse(File.ReadAllBytes(localStatePath));
            if (!doc.RootElement.TryGetProperty("profile", out var profile)) return names;
            if (!profile.TryGetProperty("info_cache", out var cache)) return names;
            if (cache.ValueKind != JsonValueKind.Object) return names;

            foreach (var entry in cache.EnumerateObject())
                if (IsUsableProfileName(entry.Name))
                    names.Add(entry.Name);
        }
        catch (JsonException) { /* a truncated write mid-parse; the fallback covers it */ }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return names;
    }

    /// <summary>
    /// The fallback discriminator: a real profile has a Preferences file, a component store does
    /// not. Measured across the three installed browsers this selected exactly Default out of 116
    /// candidate directories.
    /// </summary>
    private static List<string> ProfileNamesFromPreferences(string root)
    {
        var names = new List<string>();
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(root))
            {
                string name = Path.GetFileName(dir);
                if (!IsUsableProfileName(name)) continue;
                if (File.Exists(Path.Combine(dir, "Preferences"))) names.Add(name);
            }
        }
        catch (DirectoryNotFoundException) { }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return names;
    }

    /// <summary>
    /// A profile name is about to be concatenated onto a root and handed to a deleter, and it
    /// came out of a JSON file on disk. That is enough reason to validate it even though nothing
    /// hostile is expected: a key containing a separator or ".." would walk the resulting path
    /// straight out of the browser's own directory.
    ///
    /// "System Profile" and "Guest Profile" are excluded on their own merits — the first is
    /// browser-internal state and the second is by definition throwaway, so neither is worth a
    /// row and neither should inherit a real profile's leaf list.
    /// </summary>
    private static bool IsUsableProfileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return false;
        if (name == "." || name == "..") return false;
        if (name.Equals("System Profile", OIC) || name.Equals("Guest Profile", OIC)) return false;
        return true;
    }

    // ------------------------------------------------------------------ chromium leaves

    /// <summary>
    /// Cache directories inside a profile. An allowlist, for the same reason DiskCleanup keeps
    /// one: a blocklist eventually reaches Login Data or Bookmarks, and the failure is
    /// unrecoverable rather than merely annoying. These names become the executor's roots, so no
    /// sibling of theirs is even addressable.
    ///
    /// Cache is taken whole rather than as Cache\Cache_Data: current Chromium puts everything
    /// under Cache_Data, but it also writes a No_Vary_Search sidecar directory next to it (present
    /// in Opera GX here), and older builds wrote entries straight into Cache.
    /// </summary>
    private static readonly string[] ProfileCacheLeaves =
    {
        "Cache",
        "Code Cache",
        "GPUCache",
        "GrShaderCache",
        "GraphiteDawnCache",
        "DawnWebGPUCache",
        "DawnGraphiteCache",
        // Compiled shaders and downloaded page images. image_cache measured 0.1 MB in Chrome and
        // in Edge; the value of listing it is that it is one of the leaves a leaf-table-driven
        // cleaner forgets, not its size.
        "image_cache",
        "Media Cache",
        "Application Cache",
        // Opera GX only: its HTTP cache is split into Cache (70.9 MB) and System Cache (6.9 MB),
        // both in the LOCAL root while the rest of the profile is in the roaming one.
        "System Cache",
        // The single largest genuinely regenerable browser item on this machine and the one a
        // mature commercial cleaner leaves behind entirely: Opera GX 1,097.1 MB across 11,544
        // files, Edge 162.2 MB across 1,004, Chrome 3.1 MB. Both leaves are re-fetched on the
        // next visit to the site that registered the worker.
        Path.Combine("Service Worker", "CacheStorage"),
        Path.Combine("Service Worker", "ScriptCache"),
        // Service Worker\Database is deliberately absent: it holds the registrations themselves,
        // so clearing it un-installs progressive web apps and can sign the user out of them.
    };

    /// <summary>Caches that sit beside the profiles rather than inside one, so they must be
    /// added once per root and never once per profile.</summary>
    private static readonly string[] RootCacheLeaves =
    {
        "ShaderCache", "GrShaderCache", "GraphiteDawnCache", "GPUPersistentCache",
        // Downloaded component and extension packages, re-fetched on demand. Measured:
        // extensions_crx_cache 15.6 MB in Chrome and 5.0 MB in Opera GX, component_crx_cache
        // 1.6 MB in Opera GX.
        "component_crx_cache", "extensions_crx_cache",
        // Telemetry scratch. CCleaner instead sweeps "User Data\*.pma", which requires naming the
        // User Data root itself as a deletion root — that root also holds Local State, the file
        // profile discovery depends on. HERO takes the directory and leaves the one loose .pma
        // file measured in Opera GX's root alone.
        "BrowserMetrics", "DeferredBrowserMetrics",
    };

    /// <summary>Site storage. Everything here is written by websites and is re-created on the
    /// next visit — but not necessarily with the same contents, which is what makes it High.</summary>
    private static readonly string[] SiteDataLeaves =
    {
        "Local Storage", "IndexedDB", "databases", "WebStorage",
        // Deliberately NOT here: "Storage" (its ext subtree is per-extension state), "Extension
        // State" and "Local Extension Settings" (an extension's own data — a content blocker's
        // custom filter list has no server copy at all), and "Sync Data" (deleting it triggers a
        // full re-sync rather than reclaiming anything).
    };

    /// <summary>Open tabs and per-tab state.</summary>
    private static readonly string[] SessionLeaves =
    {
        "Sessions", "Session Storage",
        // Edge writes a second, parallel session store that appears in no CCleaner rule and is
        // present on this machine at 0.1 MB.
        "EdgeSessions",
    };

    /// <summary>Bare profile files kept for the read-only history row. Not deletable: see the
    /// class header on the executor's containment rule.</summary>
    private static readonly string[] HistoryFiles =
    {
        "History", "Archived History", "Favicons", "Top Sites", "Visited Links",
        "Network Action Predictor", "Shortcuts",
    };

    /// <summary>The never-touch set, kept for the read-only row that proves HERO knows where they
    /// are. <see cref="CleanupExecutor"/> refuses any target whose risk is NeverClean, which is a
    /// stronger guarantee than the name guard on the delete path.</summary>
    private static readonly string[] CredentialFiles =
    {
        "Login Data", "Login Data For Account", "Web Data", "Bookmarks", "Bookmarks.bak",
        "Bookmarks.msbak", "Preferences", "Secure Preferences",
    };

    // ------------------------------------------------------------------ chromium targets

    private static IEnumerable<CleanupTarget> ChromiumTargets(DiscoveredChromium found)
    {
        var browser = found.Browser;

        if (!CacheClaimedByDiskCleanup.Contains(browser.Slug, StringComparer.OrdinalIgnoreCase))
        {
            var cache = new List<string>();
            foreach (var root in browser.Roots)
                foreach (var leaf in RootCacheLeaves)
                    AddCachePath(cache, Path.Combine(root, leaf));
            foreach (var profile in found.Profiles)
                foreach (var leaf in ProfileCacheLeaves)
                    AddCachePath(cache, Path.Combine(profile, leaf));

            if (cache.Count > 0)
                yield return new CleanupTarget
                {
                    Id = $"browser.{browser.Slug}.cache",
                    Category = CleanupCategory.BrowserCache,
                    DisplayName = $"{browser.Name} cache",
                    Description = "Cached web content, compiled script, GPU shaders and service " +
                                  "worker storage. Cookies, saved passwords, history and bookmarks " +
                                  "are not touched and are not reachable from this action.",
                    Paths = cache,
                    Risk = CleanupRisk.Regenerable,
                    Tier = AutomationTier.Automatic,
                    WhatBreaksIfWrong = "Pages load a little slower once, until the cache refills. " +
                                        "You stay signed in to everything.",
                    RestoreHint = "Nothing to restore — the browser refills its cache as you browse.",
                    BlockerProbe = () => RunningBlocker(browser),
                };
        }

        // ------------------------------------------------------------ cookies

        // The cookie database is the one privacy item that is addressable at all, because modern
        // Chromium moved it from a bare file in the profile root into a Network subdirectory —
        // and a directory can be a deletion root. Everything else in that directory stays:
        // "Device Bound Sessions" holds the device-bound session keys, and Trust Tokens,
        // TransportSecurity and Reporting and NEL are security state, not convenience data. The
        // filter names the two files by hand and refuses anything that is not directly in the
        // root, so a future Chromium adding a subdirectory under Network cannot widen this.
        var networkDirs = new List<string>();
        foreach (var profile in found.Profiles)
            AddDeletablePath(networkDirs, Path.Combine(profile, "Network"));

        if (networkDirs.Count > 0)
        {
            var roots = new HashSet<string>(networkDirs, StringComparer.OrdinalIgnoreCase);
            yield return new CleanupTarget
            {
                Id = $"browser.{browser.Slug}.cookies",
                Category = CleanupCategory.BrowserCache,
                DisplayName = $"{browser.Name} cookies",
                Description = "The cookie database. Clearing it is the same thing as choosing " +
                              "'Cookies and other site data' in the browser's own Clear browsing " +
                              "data dialog: every site forgets who you are. Nothing else in the " +
                              "Network directory is touched.",
                Paths = networkDirs,
                Risk = CleanupRisk.High,
                // Never Automatic, regardless of how little it measures. Signing someone out of
                // everything on a schedule, with no one at the keyboard, is the single fastest way
                // for a maintenance tool to be uninstalled.
                Tier = AutomationTier.Prompt,
                PruneEmptyDirectories = false,
                Filter = f =>
                {
                    var parent = Path.GetDirectoryName(f.Path);
                    if (parent is null || !roots.Contains(parent)) return false;
                    var name = Path.GetFileName(f.Path);
                    return name.Equals("Cookies", OIC) || name.Equals("Cookies-journal", OIC);
                },
                WhatBreaksIfWrong = "You are signed out of every website in " + browser.Name +
                                    ", including any work or school single sign-on, and every site " +
                                    "with two-factor authentication asks for it again.",
                RestoreHint = "None. You sign in again. Worth checking you can still reach any " +
                              "account whose second factor is an app on a phone you no longer have.",
                BlockerProbe = () => RunningBlocker(browser),
            };
        }

        // ------------------------------------------------------------ site data

        var siteData = new List<string>();
        foreach (var profile in found.Profiles)
            foreach (var leaf in SiteDataLeaves)
                AddDeletablePath(siteData, Path.Combine(profile, leaf));

        if (siteData.Count > 0)
            yield return new CleanupTarget
            {
                Id = $"browser.{browser.Slug}.site-data",
                Category = CleanupCategory.BrowserCache,
                DisplayName = $"{browser.Name} site data",
                Description = "What websites store on your machine beyond cookies: local storage, " +
                              "IndexedDB databases and the legacy WebSQL store. Kept separate from " +
                              "the cookie row because this is where offline data lives, and losing " +
                              "it is not the same as being signed out.",
                Paths = siteData,
                Risk = CleanupRisk.High,
                Tier = AutomationTier.Prompt,
                // Measured here: Opera GX 21.6 MB of Local Storage and 64.1 MB of IndexedDB,
                // Chrome 0.7 MB, Edge 0.1 MB. The Opera figure is the argument for the row and
                // simultaneously the argument for prompting — 64 MB of IndexedDB is not a cache,
                // it is what sites decided was worth keeping.
                // The leaf list excludes "Extension State" and "Local Extension Settings" to protect
                // extension-authored data, but IndexedDB — which IS in the list — carries the same
                // class of data under chrome-extension_<id>_0.indexeddb.leveldb. An extension that
                // keeps its state in IDB rather than in storage.local loses it here, so the sentence
                // below has to say so rather than describing only site-authored losses.
                WhatBreaksIfWrong = "Anything a site stored locally is gone: a half-written post, " +
                                    "an offline mailbox, a browser game's save, a site's own " +
                                    "settings. For anything that was never synced to a server this " +
                                    "is the only copy. Extensions that keep their data in IndexedDB " +
                                    "rather than in extension storage lose it too.",
                RestoreHint = "Sites rebuild what they can re-download. Whatever was authored " +
                              "locally and never uploaded does not come back.",
                BlockerProbe = () => RunningBlocker(browser),
            };

        // ------------------------------------------------------------ session and tabs

        var session = new List<string>();
        foreach (var profile in found.Profiles)
            foreach (var leaf in SessionLeaves)
                AddDeletablePath(session, Path.Combine(profile, leaf));

        if (session.Count > 0)
            yield return new CleanupTarget
            {
                Id = $"browser.{browser.Slug}.session",
                Category = CleanupCategory.BrowserCache,
                DisplayName = $"{browser.Name} saved session",
                Description = "The record of which tabs are open and what each one had in it. " +
                              "Clearing it is how you recover from a browser that reopens a broken " +
                              "or enormous set of tabs on every launch.",
                Paths = session,
                Risk = CleanupRisk.High,
                Tier = AutomationTier.Prompt,
                WhatBreaksIfWrong = "The tabs currently open in " + browser.Name + " are lost, " +
                                    "'Continue where you left off' has nothing to restore, and " +
                                    "Ctrl+Shift+T stops bringing tabs back. Text typed into a page " +
                                    "and never submitted goes with them.",
                RestoreHint = "History still holds the addresses, so tabs can be reopened by hand — " +
                              "but not their scroll position or anything typed into them.",
                BlockerProbe = () => RunningBlocker(browser),
            };
    }

    /// <summary>
    /// Browsing and download history, measured and refused.
    ///
    /// Two independent reasons, and either alone would be enough. First, Chromium keeps browsing
    /// history, the download list, typed-URL rankings and keyword search terms as tables in ONE
    /// SQLite file, and HERO ships zero NuGet packages — there is no in-box SQLite engine, so
    /// row-level deletion is not available and the only possible action is deleting the whole
    /// file, which takes the download list with it. Second, History is a bare file in the profile
    /// root, and CleanupExecutor only accepts paths beneath a declared root, so making it
    /// deletable would mean declaring the profile directory itself — which puts Login Data and
    /// Bookmarks inside the blast radius to reach a 588 KB file. The browser's own Clear browsing
    /// data does this properly, in one click, and leaves the profile consistent.
    /// </summary>
    private static CleanupTarget? ChromiumHistoryObservation(IReadOnlyList<DiscoveredChromium> found)
    {
        var paths = new List<string>();
        var names = new List<string>();
        foreach (var browser in found)
        {
            bool any = false;
            foreach (var profile in browser.Profiles)
                foreach (var file in HistoryFiles)
                    if (AddObservedPath(paths, Path.Combine(profile, file))) any = true;
            if (any) names.Add(browser.Browser.Name);
        }
        if (paths.Count == 0) return null;

        return new CleanupTarget
        {
            Id = "browser.chromium.history",
            Category = CleanupCategory.Informational,
            DisplayName = "Browser history and downloads list — read-only",
            Description = $"Browsing history, the download list and the site icons that go with " +
                          $"them, for {NameList(names)}. HERO measures these and will not delete " +
                          "them: they are single SQLite files holding several kinds of data at " +
                          "once, and it has no way to remove one kind without removing all of them.",
            Paths = paths,
            Risk = CleanupRisk.NeverClean,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Deleting the History file takes the download list and address-bar " +
                                "autocomplete with it, and there is no undo. Use the browser's own " +
                                "Clear browsing data, which deletes rows rather than the file and " +
                                "lets you keep the parts you want.",
            RestoreHint = "Only a signed-in browser that syncs history to an account can bring it " +
                          "back, and only for the devices that were syncing.",
        };
    }

    /// <summary>
    /// Passwords, payment cards and bookmarks: named, sized, and permanently off limits.
    ///
    /// This row exists to be seen. CCleaner ships working rules for every one of these files
    /// (guarded behind an off-by-default switch and a warning dialog), so a user with reason to
    /// distrust cleaners is right to ask what HERO does with them. The answer is a row that shows
    /// the exact paths and refuses at any risk level — and the refusal is structural, because
    /// CleanupExecutor aborts on a NeverClean target before it looks at a single file.
    /// </summary>
    private static CleanupTarget? ChromiumCredentialObservation(IReadOnlyList<DiscoveredChromium> found)
    {
        var paths = new List<string>();
        var names = new List<string>();
        foreach (var browser in found)
        {
            bool any = false;
            foreach (var profile in browser.Profiles)
                foreach (var file in CredentialFiles)
                    if (AddObservedPath(paths, Path.Combine(profile, file))) any = true;
            if (any) names.Add(browser.Browser.Name);
        }
        if (paths.Count == 0) return null;

        return new CleanupTarget
        {
            Id = "browser.chromium.credentials",
            Category = CleanupCategory.Informational,
            DisplayName = "Browser passwords, cards and bookmarks — read-only",
            Description = $"Saved passwords, autofill entries, payment cards, bookmarks and " +
                          $"settings for {NameList(names)}. Listed so you can see that HERO knows " +
                          "exactly where they are and still refuses to touch them.",
            Paths = paths,
            Risk = CleanupRisk.NeverClean,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Login Data is every saved password; Web Data is autofill — " +
                                "addresses, card numbers, bank details. Bookmarks are irreplaceable " +
                                "by definition, and Preferences and Local State are what profile " +
                                "detection reads, so deleting them breaks the enumeration that " +
                                "finds every other row on this page.",
            RestoreHint = "Nothing here is HERO's to restore. Sync, or a password manager outside " +
                          "the browser, is the only real backup.",
        };
    }

    // ------------------------------------------------------------------ gecko

    /// <param name="AppRoots">The application root, one level ABOVE Profiles. Crash Reports lives
    /// here, which is the detail that is easiest to get wrong.</param>
    /// <param name="OfferStorageRows">False for Thunderbird: see the comment on the table.</param>
    private sealed record GeckoApp(
        string Slug, string Name, IReadOnlyList<string> AppRoots,
        IReadOnlyList<string> Processes, bool OfferStorageRows);

    private static IEnumerable<GeckoApp> GeckoFamily()
    {
        var firefoxRoots = new List<string>
        {
            Path.Combine(Roaming, "Mozilla", "Firefox"),
            Path.Combine(Local, "Mozilla", "Firefox"),
        };
        firefoxRoots.AddRange(PackageFamilyRoots("Mozilla.Firefox_", "LocalCache", "Roaming", "Mozilla", "Firefox"));
        firefoxRoots.AddRange(PackageFamilyRoots("Mozilla.Firefox_", "LocalCache", "Local", "Mozilla", "Firefox"));

        // OfferStorageRows is FALSE for Firefox too, and the reason is worth the paragraph.
        //
        // The storage row rooted at profile\storage\default with no filter. On Gecko that directory
        // holds WebExtension storage under moz-extension+++<uuid> — for a password manager or a
        // wallet extension, an encrypted vault whose only copy is that directory. The Chromium
        // sibling row excludes extension state explicitly, with a comment that a content blocker's
        // filter list "has no server copy at all"; the identical data on Gecko was being deleted
        // with no mention in the Description or in WhatBreaksIfWrong.
        //
        // Its safety claim was also false. The Description said data a site "explicitly asked to
        // have kept permanently is left alone", justified by excluding storage\permanent — but on
        // modern Firefox an origin granted navigator.storage.persist() lives in storage\default
        // with a flag in .metadata-v2. storage\permanent is legacy, so the exclusion bought
        // nothing and the sentence told the user the opposite of what happened.
        //
        // The session row was wrong in the same direction: it claimed sessionstore.jsonlz4 is the
        // live copy, when after a crash the sole record of the open tabs is
        // sessionstore-backups\recovery.jsonlz4 — and the firefox.exe blocker cannot fire, because
        // after a crash the process is gone. It reassured the user at the one moment it was wrong.
        //
        // Doing this correctly means reading .metadata-v2 per origin and distinguishing
        // moz-extension origins from site origins. That is real work and it is not being rushed
        // into a row that deletes. Firefox keeps its cache and crash-report rows.
        yield return new GeckoApp("firefox", "Firefox", firefoxRoots, new[] { "firefox" }, false);

        // Thunderbird gets cache leaves and nothing else, ever. A Thunderbird profile contains
        // Mail\ and ImapMail\, and for a POP account those mbox files are the ONLY copy of the
        // user's email in existence. Named leaves are the whole defence: no recursion from the
        // profile root, no storage rows, no session row.
        yield return new GeckoApp("thunderbird", "Thunderbird",
            new[]
            {
                Path.Combine(Roaming, "Thunderbird"),
                Path.Combine(Local, "Thunderbird"),
            },
            new[] { "thunderbird" }, false);
    }

    /// <summary>
    /// Gecko cache leaves that DiskCleanup.FirefoxCaches() does not already claim.
    ///
    /// Deliberately excluded: cache2 and startupCache, which are exactly what that target
    /// deletes. Duplicating them here would produce two Firefox cache rows for the same bytes.
    /// </summary>
    private static readonly string[] GeckoCacheLeaves =
    {
        "jumpListCache", "OfflineCache", "safebrowsing", "thumbnails",
    };

    private static IEnumerable<CleanupTarget> GeckoTargets()
    {
        foreach (var app in GeckoFamily())
        {
            // Gecko profile directories are named "<8 random characters>.<name>", so they cannot
            // be predicted and must be enumerated. profiles.ini is deliberately NOT parsed: with
            // IsRelative=0 it can name an absolute path anywhere on the machine, and HERO will not
            // accept a deletion root on the say-so of an INI file it did not write. Enumerating
            // the children of the Profiles container is complete for every default install and
            // cannot escape that container.
            //
            // The roaming and local roots hold profile directories with the SAME names but
            // different contents — cookies and prefs in roaming, cache2 in local — which is why
            // every leaf below is offered under both roots and the existence probe decides. That
            // also settles a path this machine cannot verify (Firefox is not installed here):
            // whichever root actually holds safebrowsing, the probe finds it.
            var profiles = new List<string>();
            foreach (var root in app.AppRoots)
                profiles.AddRange(ChildDirectories(Path.Combine(root, "Profiles")));

            if (profiles.Count == 0) continue;

            var cache = new List<string>();
            foreach (var profile in profiles)
                foreach (var leaf in GeckoCacheLeaves)
                    AddCachePath(cache, Path.Combine(profile, leaf));

            if (cache.Count > 0)
                yield return new CleanupTarget
                {
                    Id = $"browser.{app.Slug}.secondary-cache",
                    Category = CleanupCategory.BrowserCache,
                    DisplayName = $"{app.Name} thumbnail and offline caches",
                    Description = "The page thumbnails on the new-tab page, the jump-list icons, " +
                                  "the offline application cache and the Safe Browsing block " +
                                  "lists. The main network cache is a separate row.",
                    Paths = cache,
                    Risk = CleanupRisk.Regenerable,
                    Tier = AutomationTier.Automatic,
                    WhatBreaksIfWrong = "New-tab tiles lose their pictures until you visit the " +
                                        "sites again, and Safe Browsing re-downloads its lists.",
                    RestoreHint = "Nothing to restore — all four rebuild themselves.",
                    BlockerProbe = () => RunningBlocker(app.Name, app.Processes, "Close " + app.Name),
                };

            var crashes = new List<string>();
            foreach (var root in app.AppRoots)
            {
                AddDeletablePath(crashes, Path.Combine(root, "Crash Reports", "pending"));
                AddDeletablePath(crashes, Path.Combine(root, "Crash Reports", "submitted"));
            }

            if (crashes.Count > 0)
                yield return new CleanupTarget
                {
                    Id = $"browser.{app.Slug}.crash-reports",
                    Category = CleanupCategory.Diagnostics,
                    DisplayName = $"{app.Name} crash reports",
                    Description = "Crash dumps waiting to be sent, and the receipts for ones " +
                                  "already sent. Reports from the last seven days are kept.",
                    // Crash Reports sits at the application root, one level above Profiles — the
                    // single most common place to get a Mozilla path wrong, because every other
                    // rule in this file is profile-relative.
                    Paths = crashes,
                    Risk = CleanupRisk.Low,
                    Tier = AutomationTier.Automatic,
                    MinimumAge = TimeSpan.FromDays(7),
                    WhatBreaksIfWrong = "A crash you are still investigating loses its evidence; " +
                                        "anything in 'pending' was never sent to Mozilla, so this " +
                                        "machine is the only place it exists.",
                    RestoreHint = "Nothing to restore.",
                };

            if (app.OfferStorageRows)
            {
                var storage = new List<string>();
                foreach (var profile in profiles)
                {
                    AddDeletablePath(storage, Path.Combine(profile, "storage", "default"));
                    AddDeletablePath(storage, Path.Combine(profile, "storage", "temporary"));
                    // storage\permanent is deliberately excluded. It holds IndexedDB that sites
                    // explicitly asked to have kept, which is a different promise from the
                    // quota-managed data above; CCleaner sweeps all three, which is more
                    // aggressive than its own description suggests.
                }

                if (storage.Count > 0)
                    yield return new CleanupTarget
                    {
                        Id = $"browser.{app.Slug}.site-data",
                        Category = CleanupCategory.BrowserCache,
                        DisplayName = $"{app.Name} site data",
                        Description = "Quota-managed storage: what sites saved locally and the " +
                                      "browser is allowed to evict. Data a site explicitly asked to " +
                                      "have kept permanently is left alone.",
                        Paths = storage,
                        Risk = CleanupRisk.High,
                        Tier = AutomationTier.Prompt,
                        WhatBreaksIfWrong = "Sites that keep you signed in through local storage " +
                                            "rather than a cookie sign you out, and offline data " +
                                            "that was never uploaded is gone.",
                        RestoreHint = "Sites re-download what they can. Local drafts do not return.",
                        BlockerProbe = () => RunningBlocker(app.Name, app.Processes, "Close " + app.Name),
                    };

                var session = new List<string>();
                foreach (var profile in profiles)
                    AddDeletablePath(session, Path.Combine(profile, "sessionstore-backups"));

                if (session.Count > 0)
                    yield return new CleanupTarget
                    {
                        Id = $"browser.{app.Slug}.session-backups",
                        Category = CleanupCategory.BrowserCache,
                        DisplayName = $"{app.Name} session backups",
                        Description = "Previous copies of the open-tab list, kept so a crashed " +
                                      "session can be recovered. The live session file itself is a " +
                                      "loose file in the profile and is not touched.",
                        Paths = session,
                        Risk = CleanupRisk.Medium,
                        Tier = AutomationTier.Prompt,
                        // sessionstore.jsonlz4 is the live copy and is a bare file, so the
                        // executor cannot address it anyway — which happens to be the right
                        // outcome: deleting the backups still leaves the current session intact.
                        WhatBreaksIfWrong = "If the browser crashes before it writes a new backup, " +
                                            "the 'restore previous session' offer has nothing " +
                                            "behind it and those tabs are lost.",
                        RestoreHint = "None, but the current session is unaffected.",
                        BlockerProbe = () => RunningBlocker(app.Name, app.Processes, "Close " + app.Name),
                    };
            }

            // ---------------------------------------------------------- gecko read-only

            var observed = new List<string>();
            foreach (var profile in profiles)
                foreach (var file in new[]
                         {
                             "places.sqlite", "favicons.sqlite", "cookies.sqlite", "logins.json",
                             "logins-backup.json", "key4.db", "prefs.js", "bookmarkbackups",
                         })
                    AddObservedPath(observed, Path.Combine(profile, file));

            if (observed.Count > 0)
                yield return new CleanupTarget
                {
                    Id = $"browser.{app.Slug}.profile-data",
                    Category = CleanupCategory.Informational,
                    DisplayName = $"{app.Name} profile data — read-only",
                    Description = "History, bookmarks, cookies, saved passwords and settings. " +
                                  "Measured so the size is visible; never deleted.",
                    Paths = observed,
                    Risk = CleanupRisk.NeverClean,
                    Tier = AutomationTier.ReadOnly,
                    // The Gecko trap, and the reason this row exists at all: places.sqlite is
                    // history AND bookmarks in the same file. CCleaner can clear history from it
                    // because it opens the database and deletes rows; HERO has no SQLite engine
                    // (zero NuGet, and none ships in the BCL), so its only option would be
                    // deleting the file — every bookmark with it. bookmarkbackups is the only
                    // recovery path if that file is ever corrupted, and key4.db is the master key
                    // without which logins.json is unreadable even if it survives.
                    WhatBreaksIfWrong = "places.sqlite holds history and bookmarks together, so " +
                                        "there is no way to clear one without destroying the " +
                                        "other. Use the browser's own Clear Recent History. " +
                                        "logins.json plus key4.db are every saved password, and " +
                                        "bookmarkbackups is the only way back from a corrupted " +
                                        "bookmark database.",
                    RestoreHint = "A Mozilla account that syncs, or a manual bookmark export. " +
                                  "Nothing here is HERO's to restore.",
                };
        }
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// Names that must never reach a deletion target, whatever a future edit to a leaf table
    /// says. The allowlists above are the mechanism; this is the assertion behind them, in the
    /// same spirit as DiskCleanup's use of ProtectedPaths.TouchesBrowserProfile.
    ///
    /// That helper cannot be used for the privacy rows: its list names Cookies, Local Storage,
    /// Session Storage, IndexedDB and Network, which are precisely the directories those rows
    /// exist to clear. So the cache rows go through it and the privacy rows go through this
    /// shorter list, which contains only things no row here may ever address.
    /// </summary>
    private static readonly string[] NeverAddressable =
    {
        "Login Data", "Login Data For Account", "Web Data", "Bookmarks", "Bookmarks.bak",
        "Bookmarks.msbak", "Preferences", "Secure Preferences", "Local State", "History",
        "Extension State", "Local Extension Settings", "themes_backup", "wand.dat",
        "places.sqlite", "logins.json", "key4.db", "prefs.js", "bookmarkbackups",
        "profiles.ini", "Mail", "ImapMail",
    };

    /// <summary>Adds a path to a target that will actually delete, after the existence probe and
    /// the never-addressable guard.</summary>
    private static void AddDeletablePath(List<string> into, string path)
    {
        if (FileWalk.Probe(path) != AccessState.Measured) return;
        foreach (var name in NeverAddressable)
            if (path.EndsWith(Path.DirectorySeparatorChar + name, OIC)) return;
        into.Add(path);
    }

    /// <summary>As above, plus the shared browser-profile tripwire. Cache leaves have no business
    /// anywhere near a profile artefact, so they get the stricter of the two checks.</summary>
    private static void AddCachePath(List<string> into, string path)
    {
        if (ProtectedPaths.TouchesBrowserProfile(path)) return;
        AddDeletablePath(into, path);
    }

    /// <summary>Adds a path to a read-only row. No name guard: these rows exist precisely to name
    /// the files nothing may delete, and the executor refuses a NeverClean target outright.</summary>
    private static bool AddObservedPath(List<string> into, string path)
    {
        if (FileWalk.Probe(path) != AccessState.Measured) return false;
        into.Add(path);
        return true;
    }

    private static IReadOnlyList<CleanupBlocker> RunningBlocker(ChromiumBrowser browser) =>
        RunningBlocker(browser.Name, browser.Processes, browser.CloseAdvice);

    /// <summary>
    /// Blocking, not advisory, and for a stronger reason than the cache rows have: Chromium keeps
    /// its cookie and session databases open and rewrites them from memory when it exits, so a
    /// "successful" delete under a live browser silently comes back. A row that reports a reclaim
    /// the user can watch reappear is worse than one that refuses to run.
    /// </summary>
    private static IReadOnlyList<CleanupBlocker> RunningBlocker(
        string name, IReadOnlyList<string> processes, string closeAdvice)
    {
        var blocker = MaintenanceGuards.RunningBlocker(name, "clear this", processes.ToArray());
        if (blocker is null) return Array.Empty<CleanupBlocker>();
        return new[] { blocker with { Detail = blocker.Detail + " " + closeAdvice + "." } };
    }

    /// <summary>
    /// "Chrome", "Chrome and Edge", "Chrome, Edge and Opera GX". The read-only rows are shared
    /// across the whole family, so their descriptions have to say which browsers they actually
    /// found rather than claiming to cover browsers that are not installed — the same objection
    /// DiskCleanup raises against listing caches for software the user does not have.
    /// </summary>
    private static string NameList(IReadOnlyList<string> names) => names.Count switch
    {
        0 => "no browser",
        1 => names[0],
        _ => string.Join(", ", names.Take(names.Count - 1)) + " and " + names[^1],
    };

    /// <summary>Immediate child directories, or nothing. Separate from its callers because a
    /// try/catch cannot share a method with a yield.</summary>
    private static List<string> ChildDirectories(string parent)
    {
        var result = new List<string>();
        try
        {
            if (FileWalk.Probe(parent, out bool isDirectory) != AccessState.Measured || !isDirectory)
                return result;
            result.AddRange(Directory.EnumerateDirectories(parent));
        }
        catch (DirectoryNotFoundException) { }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return result;
    }

    /// <summary>
    /// Roots inside an MSIX package container, found by publisher prefix rather than by the
    /// package family hash. The hash is stable per publisher signature but changes if the app is
    /// re-signed, and a hard-coded one that stops matching fails silently — the row simply never
    /// appears again, which is the worst kind of bug to notice.
    /// </summary>
    private static List<string> PackageFamilyRoots(string publisherPrefix, params string[] relative)
    {
        var result = new List<string>();
        string packages = Path.Combine(Local, "Packages");
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(packages, publisherPrefix + "*"))
            {
                var parts = new List<string> { dir };
                parts.AddRange(relative);
                result.Add(Path.Combine(parts.ToArray()));
            }
        }
        catch (DirectoryNotFoundException) { }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return result;
    }
}
