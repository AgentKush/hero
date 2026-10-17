using Microsoft.Win32;

namespace Hero.Maintenance;

/// <summary>
/// Where a developer machine actually keeps its reclaimable bytes.
///
/// Measured on this machine: uv 6.70 GB (224,647 files), npm 3.40 GB (174,367 files), Gradle
/// 1.53 GB, NuGet global-packages 1.05 GB plus a 214 MB HTTP cache, pip 1.03 GB, cargo registry
/// 117 MB. Absent and therefore rendering no rows at all: pnpm, Yarn, Maven, Docker Desktop, any
/// WSL distro, Blender's per-user config, and — importantly — any node_modules anywhere under
/// "D:\My projects", whose entire tree is 904 files.
///
/// Two rules run through everything here.
///
/// First, prefer the owning tool's own command. `uv cache prune`, `npm cache verify` and
/// `dotnet nuget locals http-cache --clear` all leave the tool's index consistent, which a
/// hand-deleted directory does not.
///
/// Second, the running-tool check is a point-in-time observation with no lock behind it. On a
/// developer box a build starts seconds after the check passes, so the check is re-run between
/// deletion batches by <see cref="CleanupExecutor"/> and the batch aborts rather than continuing
/// to delete inside a cache a compiler has just started reading.
/// </summary>
internal static class DevCaches
{
    private static string Local => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Roaming => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string Profile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    /// <summary>Processes whose presence means a build could be reading a package cache.</summary>
    private static readonly string[] BuildProcesses =
        { "MSBuild", "dotnet", "VBCSCompiler", "devenv", "cargo", "rustc", "node", "uv", "python", "java" };

    /// <summary>How the caller scopes the expensive, project-tree-walking detectors.</summary>
    internal sealed record DevScanOptions
    {
        /// <summary>Where the users' own code lives. See <see cref="DefaultProjectRoots"/>.</summary>
        internal IReadOnlyList<string> ProjectRoots { get; init; } = DefaultProjectRoots();

        /// <summary>
        /// The node_modules orphan detector ships OFF.
        ///
        /// There are zero node_modules directories under the project root on this machine, so
        /// every threshold in the scoring below would be tuned against no data. The detector is
        /// written, documented and testable; enabling it is a deliberate act once there is
        /// something to validate it against.
        /// </summary>
        internal bool EnableNodeModulesOrphanDetector { get; init; }

        /// <summary>Days of quiescence before a node_modules tree is even a candidate.</summary>
        internal int OrphanAgeDays { get; init; } = 90;
    }

    /// <summary>
    /// Where each signed-in user's code conventionally lives.
    ///
    /// THIS USED TO NAME THE DEVELOPER'S OWN FOLDERS — D:\My projects and D:\Projects, as string
    /// literals compiled into every copy of HERO. That is a personal path shipping to strangers,
    /// and on any machine that happened to have a D:\Projects it walked that tree twelve levels
    /// deep for a reason its owner was never told. The walk is read-only and its purpose is
    /// protective (see <see cref="ReferencedGradleDistributions"/>, which keeps Gradle versions a
    /// project still pins from being proposed for deletion), so the harm was small — but the
    /// literals were in the binary regardless.
    ///
    /// Resolved PER SIGNED-IN USER through <see cref="Core.UserHives"/>, not through
    /// Environment.SpecialFolder. That is not a style choice: the catalogue is built inside the
    /// guardian service, which runs as LocalSystem, and there SpecialFolder.MyDocuments resolves to
    /// the system profile's Documents rather than any person's. The Unreal line below used to be
    /// written only that way, so inside the service it could find an Unreal project only if one
    /// had been saved into the system profile. UserHives reads the profiles from the loaded hives
    /// and works the same under either identity.
    ///
    /// The literals were not free to lose, and an earlier version of this comment said they were.
    /// It had checked only D:\My projects, which holds no gradle-wrapper.properties. D:\Projects
    /// holds three, pinning gradle-9.0.0-bin (270.5 MB) and gradle-9.2.1-bin (143.3 MB), so on the
    /// developer's machine dropping it would have offered 413.8 MB of in-use build tooling for
    /// deletion as "unreferenced". The user's own folders therefore come from
    /// <see cref="Core.HeroSettings.DeveloperRoots"/> first — the same list that caps autonomous
    /// action in <see cref="Guardian.ProtectedSet"/>, since both mean "where my code lives".
    /// </summary>
    internal static IReadOnlyList<string> DefaultProjectRoots()
    {
        var roots = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string p)
        {
            if (seen.Add(p) && FileWalk.Probe(p) == AccessState.Measured) roots.Add(p);
        }

        foreach (var named in Core.HeroSettings.Current.DeveloperRoots) Add(named);

        foreach (var user in Core.UserHives.Folders())
        {
            Add(Path.Combine(user.Profile, "source", "repos"));        // Visual Studio's default
            Add(Path.Combine(user.Profile, "Projects"));
            Add(Path.Combine(user.Profile, "Documents", "Unreal Projects"));
        }

        // The calling identity's own Documents as well. The per-user line above assembles the
        // path, so it misses a Documents folder redirected into OneDrive; this one resolves the
        // redirection correctly whenever the caller IS that user, which the dashboard is. Inside
        // the service it names systemprofile and simply finds nothing.
        Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Unreal Projects"));
        return roots;
    }

    /// <summary>
    /// Every developer-side cache that applies to this machine.
    ///
    /// The project-tree findings — build output, Unreal subtrees, orphaned node_modules — are
    /// deliberately NOT returned here. They need per-item selection and none of them may ever be
    /// deleted as a category, so they are exposed as candidate lists that the UI ranks and the
    /// user picks from one at a time.
    /// </summary>
    internal static IReadOnlyList<CleanupTarget> Enumerate()
    {
        var all = new List<CleanupTarget>();
        all.AddRange(NodePackageManagers());
        all.AddRange(PythonCaches());
        all.AddRange(RustCaches());
        all.AddRange(DotNetCaches());
        all.AddRange(JvmCaches());
        all.AddRange(EditorCaches());
        all.AddRange(VirtualDiskObservations());

        return all.Where(t => t.Exists).ToList();
    }

    // -------------------------------------------------------------------- node

    private static IEnumerable<CleanupTarget> NodePackageManagers()
    {
        string npmCache = ResolveNpmCache();
        if (FileWalk.Probe(npmCache) == AccessState.Measured)
        {
            yield return new CleanupTarget
            {
                Id = "dev.npm-cache",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "npm cache",
                Description = "Downloaded npm packages. The cache is content-addressed and " +
                              "self-healing, so clearing it never breaks an installed node_modules — " +
                              "it only costs a re-download.",
                Paths = new[] { npmCache },
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                PreferredCommand = new ToolCommand("npm", "cache verify",
                    "Drops corrupted and expired entries and reports what it reclaimed, without " +
                    "throwing away entries that are still good. 'npm cache clean --force' is the " +
                    "aggressive alternative.", ViaShell: true),
                WhatBreaksIfWrong = "Nothing installs differently; the next install downloads again.",
                RestoreHint = "npm refills the cache on the next install.",
            };
        }

        // pnpm's store is content-addressed and HARD-LINKED into every node_modules on the
        // machine. Deleting it therefore breaks existing installs rather than merely costing a
        // download, which is why it gets a much heavier risk rating than npm's cache.
        foreach (var store in new[] { Path.Combine(Local, "pnpm-store"), Path.Combine(Profile, ".pnpm-store") })
        {
            if (FileWalk.Probe(store) != AccessState.Measured) continue;
            yield return new CleanupTarget
            {
                Id = "dev.pnpm-store",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "pnpm store",
                Description = "pnpm's content-addressable store. Unlike npm's cache this is hard-linked " +
                              "into installed node_modules trees, so it is not free to delete.",
                Paths = new[] { store },
                Risk = CleanupRisk.Medium,
                Tier = AutomationTier.Prompt,
                PreferredCommand = new ToolCommand("pnpm", "store prune",
                    "Removes only packages no project references. Deleting the store directly " +
                    "breaks every existing install that hard-links into it.", ViaShell: true),
                WhatBreaksIfWrong = "Existing node_modules trees lose the files they link to and " +
                                    "every project needs reinstalling.",
            };
            break;
        }

        string yarnCache = Path.Combine(Local, "Yarn", "Cache");
        if (FileWalk.Probe(yarnCache) == AccessState.Measured)
        {
            yield return new CleanupTarget
            {
                Id = "dev.yarn-cache",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "Yarn cache",
                Description = "Downloaded Yarn packages.",
                Paths = new[] { yarnCache },
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                PreferredCommand = new ToolCommand("yarn", "cache clean", "Yarn's own cache clear.", ViaShell: true),
                WhatBreaksIfWrong = "Re-download only.",
            };
        }
    }

    /// <summary>
    /// npm's cache location, without paying for a process launch in the common case.
    ///
    /// The default is checked first because asking npm means launching cmd.exe to run a .cmd
    /// shim, which costs hundreds of milliseconds. npm is only consulted when the defaults are
    /// absent, which is exactly the case where the user has relocated it.
    /// </summary>
    private static string ResolveNpmCache()
    {
        foreach (var candidate in new[] { Path.Combine(Local, "npm-cache"), Path.Combine(Roaming, "npm-cache") })
            if (FileWalk.Probe(candidate) == AccessState.Measured) return candidate;

        var result = Shell.RunShim("npm config get cache", 10000);
        if (result.Succeeded)
        {
            var line = result.StandardOutput.Split('\n').FirstOrDefault(l => l.Trim().Length > 0)?.Trim();
            if (!string.IsNullOrEmpty(line) && FileWalk.Probe(line) == AccessState.Measured) return line;
        }

        return Path.Combine(Local, "npm-cache");
    }

    // ------------------------------------------------------------------ python

    private static IEnumerable<CleanupTarget> PythonCaches()
    {
        // uv: 6.70 GB across 224,647 files — the largest developer cache on this machine, and one
        // whose format changes across uv releases, so a cache left behind by an older uv is dead
        // weight rather than a warm start.
        string uvCache = Path.Combine(Local, "uv", "cache");
        if (FileWalk.Probe(uvCache) == AccessState.Measured)
        {
            yield return new CleanupTarget
            {
                Id = "dev.uv-cache",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "uv package cache",
                Description = "uv's download and build cache — the biggest single developer cache " +
                              "here. Pruning removes only entries nothing references.",
                Paths = new[] { uvCache },
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                PreferredCommand = new ToolCommand("uv", "cache prune",
                    "Removes unused entries and keeps uv's own index consistent. 'uv cache clean' " +
                    "removes everything and is the manual, aggressive option."),
                WhatBreaksIfWrong = "The next uv sync re-downloads wheels. Time and bandwidth, not breakage.",
                RestoreHint = "uv rebuilds the cache on the next sync.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker("uv", "prune its cache", "uv", "uvx");
                    return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
                },
            };
        }

        string pipCache = Path.Combine(Local, "pip", "cache");
        if (FileWalk.Probe(pipCache) != AccessState.Measured) yield break;

        // pip's cache splits into downloaded HTTP responses and wheels pip BUILT locally. The
        // first is free to discard; the second can represent a very expensive native compile
        // (anything MSVC-bound), so the two get separate rows rather than one 'pip cache purge'.
        foreach (var httpDir in new[] { "http", "http-v2" })
        {
            string path = Path.Combine(pipCache, httpDir);
            if (FileWalk.Probe(path) != AccessState.Measured) continue;

            yield return new CleanupTarget
            {
                Id = "dev.pip-http-cache",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "pip download cache",
                Description = "Wheels and source archives pip downloaded. Pure download cache.",
                Paths = new[] { path },
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                WhatBreaksIfWrong = "Re-download only.",
                RestoreHint = "pip refills it on the next install.",
            };
            break;
        }

        string wheels = Path.Combine(pipCache, "wheels");
        if (FileWalk.Probe(wheels) == AccessState.Measured)
        {
            yield return new CleanupTarget
            {
                Id = "dev.pip-wheel-cache",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "pip locally-built wheels",
                Description = "Wheels pip compiled on this machine rather than downloading.",
                Paths = new[] { wheels },
                Risk = CleanupRisk.Low,
                Tier = AutomationTier.Prompt,
                PreferredCommand = new ToolCommand("pip", "cache info",
                    "Shows how much of the cache is locally-built rather than downloaded, so the " +
                    "rebuild cost is visible before anything is removed."),
                WhatBreaksIfWrong = "Anything with a native extension has to compile again, which " +
                                    "for the scipy/numpy family can take many minutes each.",
            };
        }
    }

    // -------------------------------------------------------------------- rust

    private static IEnumerable<CleanupTarget> RustCaches()
    {
        string cargo = Path.Combine(Profile, ".cargo");
        if (FileWalk.Probe(cargo) != AccessState.Measured) yield break;

        // Three sub-caches with genuinely different restore sources, which the usual advice
        // conflates. src is extracted from the .crate files in cache, so it is restorable
        // offline; cache comes from the network; index is the registry index and, under the
        // sparse protocol that has been cargo's default since 1.70, is a cache of HTTP-fetched
        // JSON — also network-only. Deleting index on a machine that is offline breaks
        // dependency resolution even though cache is intact.
        var parts = new (string Leaf, string Name, string Restore, CleanupRisk Risk)[]
        {
            (Path.Combine("registry", "src"), "cargo extracted sources",
             "Re-extracted from the .crate files already in registry\\cache — works offline.", CleanupRisk.Regenerable),
            (Path.Combine("registry", "cache"), "cargo crate archives",
             "Re-downloaded from crates.io — needs a network connection.", CleanupRisk.Low),
            (Path.Combine("registry", "index"), "cargo registry index",
             "Re-fetched from the network. Not derivable from registry\\cache.", CleanupRisk.Low),
            (Path.Combine("git", "checkouts"), "cargo git checkouts",
             "Re-cloned from each dependency's repository.", CleanupRisk.Low),
        };

        foreach (var part in parts)
        {
            string path = Path.Combine(cargo, part.Leaf);
            if (FileWalk.Probe(path) != AccessState.Measured) continue;

            yield return new CleanupTarget
            {
                Id = "dev.cargo." + part.Leaf.Replace(Path.DirectorySeparatorChar, '-').ToLowerInvariant(),
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = part.Name,
                // ~/.cargo/bin holds the installed toolchain binaries and is never a target here;
                // it is not a cache and deleting it uninstalls rustup's shims.
                Description = "Part of cargo's registry cache. The installed toolchain in " +
                              ".cargo\\bin is never touched.",
                Paths = new[] { path },
                Risk = part.Risk,
                Tier = part.Risk == CleanupRisk.Regenerable ? AutomationTier.Automatic : AutomationTier.Prompt,
                RestoreHint = part.Restore,
                WhatBreaksIfWrong = "An offline build loses the packages it was going to resolve against.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker("A Rust build", "touch the cargo cache",
                        "cargo", "rustc");
                    return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
                },
            };
        }
    }

    // ------------------------------------------------------------------- .NET

    private static IEnumerable<CleanupTarget> DotNetCaches()
    {
        string httpCache = Path.Combine(Local, "NuGet", "v3-cache");
        if (FileWalk.Probe(httpCache) == AccessState.Measured)
        {
            yield return new CleanupTarget
            {
                Id = "dev.nuget-http-cache",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "NuGet HTTP cache",
                Description = "Cached responses from package feeds. Genuinely free to clear.",
                Paths = new[]
                {
                    httpCache,
                    Path.Combine(Local, "NuGet", "plugins-cache"),
                    Path.Combine(Path.GetTempPath(), "NuGetScratch"),
                },
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                PreferredCommand = new ToolCommand("dotnet", "nuget locals http-cache --clear",
                    "Clears exactly the caches NuGet considers disposable, and reports the paths " +
                    "it used, so nothing is guessed."),
                WhatBreaksIfWrong = "The next restore talks to the feed instead of the cache.",
                BlockerProbe = BuildBlocker,
            };
        }

        // The global packages folder is a different proposition: clearing it forces EVERY
        // solution on the machine to restore again, and this machine carries VS 2022, VS 2026 and
        // two Build Tools installs. It also breaks offline builds outright.
        string globalPackages = Path.Combine(Profile, ".nuget", "packages");
        if (FileWalk.Probe(globalPackages) == AccessState.Measured)
        {
            yield return new CleanupTarget
            {
                Id = "dev.nuget-global-packages",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "NuGet global packages folder",
                Description = "Every NuGet package extracted for every solution on this machine.",
                Paths = new[] { globalPackages },
                Risk = CleanupRisk.Medium,
                Tier = AutomationTier.Prompt,
                PreferredCommand = new ToolCommand("dotnet", "nuget locals global-packages --clear",
                    "NuGet's own clear. Every project on the machine restores again afterwards."),
                WhatBreaksIfWrong = "Offline builds stop working until a restore succeeds, and every " +
                                    "solution pays a full restore — with four Visual Studio products " +
                                    "installed that is a lot of re-downloading.",
                BlockerProbe = BuildBlocker,
            };
        }
    }

    private static IReadOnlyList<CleanupBlocker> BuildBlocker()
    {
        var b = MaintenanceGuards.RunningBlocker("A build", "clear package caches", BuildProcesses);
        return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
    }

    // -------------------------------------------------------------------- JVM

    private static IEnumerable<CleanupTarget> JvmCaches()
    {
        string gradle = Path.Combine(Profile, ".gradle");
        if (FileWalk.Probe(gradle) == AccessState.Measured)
        {
            // DEFERRED until the filter first runs, rather than computed while the catalogue is
            // built. The catalogue is enumerated on the UI thread when the Maintenance page opens,
            // and this walks every project root twelve levels deep. It used to be one developer's
            // folder; it is now every signed-in user's source\repos and Projects as well, which on
            // a stranger's machine can be a very large tree to walk before a page can paint.
            var referenced = new Lazy<List<string>>(ReferencedGradleDistributions);

            yield return new CleanupTarget
            {
                Id = "dev.gradle-caches",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "Gradle caches",
                Description = "Downloaded artefacts, compiled build scripts and the task output cache.",
                Paths = new[]
                {
                    Path.Combine(gradle, "caches", "modules-2"),
                    Path.Combine(gradle, "caches", "build-cache-1"),
                    Path.Combine(gradle, "daemon"),
                },
                Risk = CleanupRisk.Low,
                Tier = AutomationTier.Prompt,
                PreferredCommand = new ToolCommand("gradle", "--stop",
                    "Stops the Gradle daemon first. Deleting files the daemon has memory-mapped " +
                    "produces build failures that look like anything but a cleanup.", ViaShell: true),
                WhatBreaksIfWrong = "The next build re-downloads its dependencies and recompiles its " +
                                    "build scripts.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker("The Gradle daemon",
                        "clear its caches", "java", "gradle");
                    if (b is null) return Array.Empty<CleanupBlocker>();
                    return new[] { b with { Detail = b.Detail + " Run 'gradle --stop' first." } };
                },
            };

            // Each wrapper distribution is a full Gradle release, often several hundred MB, and
            // one accumulates per version any project has ever pinned. Only versions that NO
            // gradle-wrapper.properties on the machine still references are offered.
            string dists = Path.Combine(gradle, "wrapper", "dists");
            if (FileWalk.Probe(dists) == AccessState.Measured)
            {
                yield return new CleanupTarget
                {
                    Id = "dev.gradle-distributions",
                    Category = CleanupCategory.PackageManagerCache,
                    DisplayName = "Unreferenced Gradle distributions",
                    Description = "Downloaded Gradle releases that no project on this machine pins. " +
                                  "Versions still referenced by a gradle-wrapper.properties are excluded.",
                    Paths = new[] { dists },
                    Risk = CleanupRisk.Low,
                    Tier = AutomationTier.Prompt,
                    Filter = f => !referenced.Value.Any(r => f.Path.Contains(r, StringComparison.OrdinalIgnoreCase)),
                    WhatBreaksIfWrong = "A project pinned to a removed version re-downloads it — " +
                                        "slow, but self-healing.",
                };
            }
        }

        string maven = Path.Combine(Profile, ".m2", "repository");
        if (FileWalk.Probe(maven) == AccessState.Measured)
        {
            yield return new CleanupTarget
            {
                Id = "dev.maven-repository",
                Category = CleanupCategory.PackageManagerCache,
                DisplayName = "Maven local repository",
                Description = "Downloaded Maven artefacts, plus anything installed locally with " +
                              "'mvn install' — which is NOT re-downloadable.",
                Paths = new[] { maven },
                Risk = CleanupRisk.Medium,
                Tier = AutomationTier.Prompt,
                WhatBreaksIfWrong = "Locally-installed snapshot artefacts have no upstream to " +
                                    "re-download from and must be rebuilt from their source projects.",
            };
        }
    }

    /// <summary>
    /// Gradle distribution names pinned by any gradle-wrapper.properties under the project roots.
    /// Deleting a distribution a project still references only costs a re-download, but silently
    /// doing so on every build is the sort of churn that makes a tool unwelcome.
    /// </summary>
    private static List<string> ReferencedGradleDistributions()
    {
        var names = new List<string>();
        foreach (var root in DefaultProjectRoots())
        {
            var options = new WalkOptions
            {
                PruneDirectoryNames = new[] { "node_modules", ".git", "build", "obj", "bin" },
                MaxDepth = 12,
            };
            foreach (var file in FileWalk.FindFiles(root, new[] { "gradle-wrapper.properties" }, options, 200))
            {
                try
                {
                    foreach (var line in File.ReadLines(file.Path))
                    {
                        if (!line.StartsWith("distributionUrl", StringComparison.OrdinalIgnoreCase)) continue;
                        int slash = line.LastIndexOf('/');
                        if (slash >= 0 && slash + 1 < line.Length)
                            names.Add(line[(slash + 1)..].Replace(".zip", "").Trim());
                    }
                }
                catch { }
            }
        }
        return names;
    }

    // ----------------------------------------------------------------- editors

    private static IEnumerable<CleanupTarget> EditorCaches()
    {
        string code = Path.Combine(Roaming, "Code");
        if (FileWalk.Probe(code) == AccessState.Measured)
        {
            yield return new CleanupTarget
            {
                Id = "dev.vscode-cache",
                Category = CleanupCategory.AppCache,
                DisplayName = "Visual Studio Code caches",
                Description = "VS Code's web, GPU and extension-download caches, plus its logs. " +
                              "Settings, keybindings and installed extensions are untouched.",
                Paths = new[]
                {
                    Path.Combine(code, "Cache"),
                    Path.Combine(code, "CachedData"),
                    Path.Combine(code, "CachedExtensionVSIXs"),
                    Path.Combine(code, "GPUCache"),
                    Path.Combine(code, "Code Cache"),
                    Path.Combine(code, "logs"),
                },
                Risk = CleanupRisk.Regenerable,
                Tier = AutomationTier.Automatic,
                WhatBreaksIfWrong = "The first launch afterwards is slightly slower.",
                BlockerProbe = () =>
                {
                    var b = MaintenanceGuards.RunningBlocker("VS Code", "clear its caches", "Code");
                    return b is null ? Array.Empty<CleanupBlocker>() : new[] { b };
                },
            };
        }

        // The Visual Studio installer's offline package cache. Reported, never cleaned
        // automatically, and explicitly framed as a tradeoff rather than a free win: repair and
        // modify operations must re-download many gigabytes afterwards.
        string vsPackages = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "VisualStudio", "Packages");
        if (FileWalk.Probe(vsPackages) is AccessState.Measured or AccessState.AccessDenied)
        {
            yield return new CleanupTarget
            {
                Id = "dev.vs-installer-cache",
                Category = CleanupCategory.Informational,
                DisplayName = "Visual Studio installer cache — read-only",
                Description = "The offline installer cache shared by every Visual Studio product. " +
                              "Safe to remove while VS runs, but repair and modify then need to " +
                              "re-download everything. Use the Visual Studio Installer's own " +
                              "'Clean up' rather than deleting the folder.",
                Paths = new[] { vsPackages },
                Risk = CleanupRisk.NeverClean,
                NeedsAdmin = true,
                Tier = AutomationTier.ReadOnly,
                WhatBreaksIfWrong = "HERO will never offer to uninstall a Visual Studio edition " +
                                    "either: with 2022 and 2026 side by side the older toolset is " +
                                    "usually kept deliberately.",
            };
        }
    }

    // ---------------------------------------------------- virtual disk sprawl

    /// <summary>
    /// A virtual disk that has grown and will not shrink on its own.
    /// </summary>
    /// <param name="Path">The .vhd/.vhdx on the host.</param>
    /// <param name="HostBytes">What the file occupies on the host volume.</param>
    /// <param name="Owner">BlueStacks engine name, WSL distro, Docker, or "unknown".</param>
    internal sealed record VirtualDiskCandidate(string Path, long HostBytes, string Owner)
    {
        /// <summary>
        /// Compaction only recovers blocks the GUEST has zeroed or discarded, and Android guests
        /// under BlueStacks generally do not pass discard through to the host disk. A dynamic
        /// 111 GB image that grew to 111 GB therefore usually compacts to roughly 111 GB unless
        /// free space inside the guest is zeroed first. Any headline reclaim figure quoted before
        /// a dry run is guesswork.
        /// </summary>
        internal string ExpectedReclaim => "unknown until a dry-run compaction is performed; " +
                                           "run fstrim (or zero free space) inside the guest first, " +
                                           "or the reclaim is close to nothing";
    }

    /// <summary>
    /// Finds virtual disks worth talking about, without touching them.
    ///
    /// Compaction is not offered as a cleanup target because it is not a deletion: it needs the
    /// owning VM fully stopped, it needs the guest to have discarded its free blocks, and on this
    /// machine one of the two BlueStacks engines is a rooted Tiramisu64 instance whose root setup
    /// is expensive to rebuild. The route, when it is built, is the in-box VirtDisk API
    /// (OpenVirtualDisk / AttachVirtualDisk with ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER /
    /// CompactVirtualDisk / DetachVirtualDisk) — never diskpart, which automounts the guest's
    /// ext4 partitions and makes Windows offer to format them.
    /// </summary>
    internal static IReadOnlyList<VirtualDiskCandidate> FindVirtualDisks(CancellationToken ct = default)
    {
        var results = new List<VirtualDiskCandidate>();
        var options = new WalkOptions { MaxDepth = 8, PruneDirectoryNames = new[] { "Windows", "WinSxS" } };

        void Scan(string root, string owner)
        {
            foreach (var file in FileWalk.FindFiles(root, new[] { ".vhdx", ".vhd" }, options, 200, ct))
                results.Add(new VirtualDiskCandidate(file.Path, file.Length, owner));
        }

        Scan(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "BlueStacks_nxt", "Engine"), "BlueStacks");
        Scan(Path.Combine(Local, "Docker", "wsl"), "Docker Desktop");

        // WSL distros register their install location under Lxss; the packaged default under
        // %LOCALAPPDATA%\Packages is only one of several possibilities.
        try
        {
            using var lxss = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Lxss");
            if (lxss is not null)
            {
                foreach (var name in lxss.GetSubKeyNames())
                {
                    using var distro = lxss.OpenSubKey(name);
                    if (distro?.GetValue("BasePath") is string basePath)
                        Scan(basePath, distro.GetValue("DistributionName") as string ?? "WSL");
                }
            }
        }
        catch { /* no WSL distros registered */ }

        return results.OrderByDescending(v => v.HostBytes).ToList();
    }

    private static IEnumerable<CleanupTarget> VirtualDiskObservations()
    {
        var disks = FindVirtualDisks();
        if (disks.Count == 0) yield break;

        yield return new CleanupTarget
        {
            Id = "dev.virtual-disks",
            Category = CleanupCategory.VirtualDisk,
            DisplayName = "Virtual machine disks — read-only",
            Description = "Android, WSL and Docker disk images. These grow and never shrink by " +
                          "themselves, but the host file size is not the same as space wasted: " +
                          "most of it is usually in use inside the guest.",
            Paths = disks.Select(d => d.Path).ToList(),
            Risk = CleanupRisk.NeverClean,
            Tier = AutomationTier.ReadOnly,
            WhatBreaksIfWrong = "Deleting one destroys the whole virtual machine, and compacting " +
                                "the wrong one — or compacting while it is running — can corrupt " +
                                "the guest filesystem. HERO reports sizes here and nothing more.",
        };
    }

    // ------------------------------------------------ project-tree detectors

    /// <summary>A build-output directory that is safe to delete, with the evidence for that claim.</summary>
    internal sealed record BuildOutputCandidate(
        string Path, string ProjectFile, long Bytes, long Files, DateTime LastWriteUtc, bool HasSiblingObj);

    /// <summary>
    /// Finds MSBuild obj/ and bin/ trees — the safest developer reclaim that exists, provided
    /// the pairing test is honest.
    ///
    /// 'bin' is a dangerously generic directory name: plenty of non-.NET projects keep
    /// hand-written tools, vendored binaries or downloaded SDKs in one. So a bin/ qualifies only
    /// when it has a co-located project file AND a sibling obj/, because MSBuild always creates
    /// the two together. Anything modified in the last day is skipped, and .git subtrees are
    /// pruned outright so a bin/ whose contents are tracked in git — which by definition is not
    /// build output — is never proposed.
    /// </summary>
    internal static IReadOnlyList<BuildOutputCandidate> FindBuildOutputs(
        IReadOnlyList<string>? roots = null, CancellationToken ct = default)
    {
        roots ??= DefaultProjectRoots();
        var results = new List<BuildOutputCandidate>();
        var options = new WalkOptions
        {
            MaxDepth = 16,
            PruneDirectoryNames = new[] { "node_modules", ".git", "packages", "DerivedDataCache" },
        };

        foreach (var root in roots)
        {
            foreach (var dir in FileWalk.FindDirectories(root, new[] { "obj", "bin" }, options, 4000, ct))
            {
                if (ct.IsCancellationRequested) break;

                var parent = Path.GetDirectoryName(dir);
                if (string.IsNullOrEmpty(parent)) continue;

                string? project = ProjectFileIn(parent);
                if (project is null) continue;

                bool isBin = Path.GetFileName(dir).Equals("bin", StringComparison.OrdinalIgnoreCase);
                bool siblingObj = Directory.Exists(Path.Combine(parent, "obj"));
                if (isBin && !siblingObj) continue;

                DateTime touched;
                try { touched = Directory.GetLastWriteTimeUtc(dir); }
                catch { continue; }
                if (DateTime.UtcNow - touched < TimeSpan.FromHours(24)) continue;

                var measured = FileWalk.ScanRoots(new[] { dir }, options, null, 0, null, ct);
                results.Add(new BuildOutputCandidate(dir, project, measured.Bytes, measured.Files,
                                                     touched, siblingObj));
            }
        }

        return results.OrderByDescending(r => r.Bytes).ToList();
    }

    private static string? ProjectFileIn(string directory)
    {
        try
        {
            foreach (var pattern in new[] { "*.csproj", "*.fsproj", "*.vbproj", "*.sln", "*.slnx" })
            {
                var hit = Directory.EnumerateFiles(directory, pattern).FirstOrDefault();
                if (hit is not null) return hit;
            }
        }
        catch { }
        return null;
    }

    /// <summary>An Unreal project and the sizes of each disposable subtree, kept separate so the
    /// user chooses per category rather than accepting one aggregate number.</summary>
    internal sealed record UnrealProjectCandidate(
        string ProjectFile, long DerivedDataCacheBytes, long IntermediateBytes,
        long SavedLogsBytes, long BinariesBytes, bool HasSourceDirectory);

    /// <summary>
    /// Locates Unreal projects and sizes their regenerable subtrees.
    ///
    /// Two exclusions matter and both come from this user's actual projects. Projects living
    /// INSIDE an engine install are skipped — globbing *.uproject across a drive matches the
    /// sample and template projects shipped with UE_5.8, Twinmotion and RealityScan, and deleting
    /// their Intermediate or Binaries corrupts the installed engine's template set. And Binaries\
    /// is only ever a candidate when the project has a Source\ directory: SatisfactoryModding and
    /// ModWorkspace ship PREBUILT binaries from a modding SDK, so deleting theirs does not trigger
    /// a rebuild, it produces a project that will not open until the SDK is fetched again.
    ///
    /// Saved\ is likewise not uniformly disposable — SaveGames, Config and Collections hold real
    /// user data — so only Logs, Crashes and Autosaves are ever measured.
    /// </summary>
    internal static IReadOnlyList<UnrealProjectCandidate> FindUnrealProjects(
        IReadOnlyList<string>? roots = null, CancellationToken ct = default)
    {
        roots ??= DefaultProjectRoots();
        var results = new List<UnrealProjectCandidate>();
        var findOptions = new WalkOptions
        {
            MaxDepth = 10,
            PruneDirectoryNames = new[]
            {
                "node_modules", ".git", "DerivedDataCache", "Intermediate", "Saved", "Binaries", "Content",
            },
        };
        var sizeOptions = new WalkOptions { MaxDepth = 24 };

        foreach (var root in roots)
        {
            foreach (var uproject in FileWalk.FindFiles(root, new[] { ".uproject" }, findOptions, 200, ct))
            {
                if (ct.IsCancellationRequested) break;

                var found = Path.GetDirectoryName(uproject.Path);
                if (string.IsNullOrEmpty(found)) continue;
                string dir = found;
                if (IsInsideEngineInstall(dir)) continue;

                results.Add(new UnrealProjectCandidate(
                    uproject.Path,
                    SubtreeBytes(dir, sizeOptions, ct, "DerivedDataCache"),
                    SubtreeBytes(dir, sizeOptions, ct, "Intermediate"),
                    SubtreeBytes(dir, sizeOptions, ct, "Saved", "Logs")
                        + SubtreeBytes(dir, sizeOptions, ct, "Saved", "Crashes")
                        + SubtreeBytes(dir, sizeOptions, ct, "Saved", "Autosaves"),
                    SubtreeBytes(dir, sizeOptions, ct, "Binaries"),
                    Directory.Exists(Path.Combine(dir, "Source"))));
            }
        }

        return results.OrderByDescending(r => r.DerivedDataCacheBytes + r.IntermediateBytes).ToList();
    }

    private static long SubtreeBytes(string baseDir, WalkOptions options, CancellationToken ct,
                                     params string[] parts) =>
        FileWalk.ScanRoots(new[] { Path.Combine(baseDir, Path.Combine(parts)) },
                           options, null, 0, null, ct).Bytes;

    /// <summary>
    /// True when a .uproject lives inside an installed engine rather than being a user project.
    /// The marker is Engine\Binaries\Win64\UnrealEditor.exe somewhere above it.
    /// </summary>
    private static bool IsInsideEngineInstall(string directory)
    {
        var current = new DirectoryInfo(directory);
        for (int i = 0; i < 10 && current is not null; i++)
        {
            try
            {
                if (File.Exists(Path.Combine(current.FullName, "Engine", "Binaries", "Win64", "UnrealEditor.exe")))
                    return true;
            }
            catch { }
            current = current.Parent;
        }
        return false;
    }

    /// <summary>A node_modules tree and every piece of evidence for calling it abandoned.</summary>
    internal sealed record NodeModulesCandidate(
        string Path, long Bytes, long Files, DateTime NewestProjectWriteUtc,
        DateTime NewestGitWriteUtc, bool HasLockfile, bool HasGit, string RestoreCommand)
    {
        /// <summary>
        /// Every condition must hold. Age alone is a bad signal — a finished, shipped project
        /// still needs its dependencies to rebuild, and mtimes get bulk-rewritten by antivirus,
        /// backup restores and copies between drives. A project without a lockfile can never
        /// qualify, because reinstalling it is not reproducible and may pull different versions.
        /// </summary>
        internal bool IsOrphanCandidate(int ageDays) =>
            HasLockfile
            && DateTime.UtcNow - NewestProjectWriteUtc > TimeSpan.FromDays(ageDays)
            && (!HasGit || DateTime.UtcNow - NewestGitWriteUtc > TimeSpan.FromDays(ageDays));
    }

    /// <summary>
    /// The node_modules orphan detector, written and shipped DISABLED.
    ///
    /// There are zero node_modules directories under the project root on this machine, so there
    /// is nothing to tune the thresholds against and no honest way to advertise a reclaim. The
    /// scoring is documented on <see cref="NodeModulesCandidate.IsOrphanCandidate"/>; the known
    /// weaknesses are documented here rather than hidden: a fresh clone or a branch switch
    /// rewrites working-tree mtimes to now while .git object mtimes stay old, and a repository
    /// whose active development happens in a linked worktree elsewhere looks dead at the main
    /// checkout. Nothing found here is ever deleted automatically, at any confidence.
    /// </summary>
    internal static IReadOnlyList<NodeModulesCandidate> FindOrphanedNodeModules(
        DevScanOptions options, CancellationToken ct = default)
    {
        var results = new List<NodeModulesCandidate>();
        if (!options.EnableNodeModulesOrphanDetector) return results;

        var findOptions = new WalkOptions
        {
            MaxDepth = 12,
            PruneDirectoryNames = new[] { ".git", "obj", "bin", "DerivedDataCache", "target" },
        };
        var sizeOptions = new WalkOptions { MaxDepth = 32 };

        foreach (var root in options.ProjectRoots)
        {
            // node_modules is in the match list, so the walk stops AT each hit and never
            // enumerates the nested node_modules inside it — which would otherwise be both the
            // dominant cost and a source of double-counted candidates.
            foreach (var dir in FileWalk.FindDirectories(root, new[] { "node_modules" }, findOptions, 2000, ct))
            {
                if (ct.IsCancellationRequested) break;

                var owner = Path.GetDirectoryName(dir);
                if (string.IsNullOrEmpty(owner)) continue;
                string project = owner;
                if (!File.Exists(Path.Combine(project, "package.json"))) continue;

                string? lockfile = new[] { "package-lock.json", "pnpm-lock.yaml", "yarn.lock" }
                    .Select(f => Path.Combine(project, f))
                    .FirstOrDefault(File.Exists);

                string gitDir = Path.Combine(project, ".git");
                bool hasGit = Directory.Exists(gitDir);

                var measured = FileWalk.ScanRoots(new[] { dir }, sizeOptions, null, 0, null, ct);

                results.Add(new NodeModulesCandidate(
                    Path: dir,
                    Bytes: measured.Bytes,
                    Files: measured.Files,
                    NewestProjectWriteUtc: NewestWrite(project, excludeDirName: "node_modules", ct),
                    NewestGitWriteUtc: hasGit ? NewestWrite(gitDir, null, ct) : DateTime.MinValue,
                    HasLockfile: lockfile is not null,
                    HasGit: hasGit,
                    RestoreCommand: lockfile is null
                        ? "no lockfile — reinstalling is not reproducible, so this must never be cleaned"
                        : Path.GetFileName(lockfile) switch
                        {
                            "pnpm-lock.yaml" => "pnpm install --frozen-lockfile",
                            "yarn.lock" => "yarn install --immutable",
                            _ => "npm ci",
                        }));
            }
        }

        return results.OrderByDescending(r => r.Bytes).ToList();
    }

    /// <summary>Newest write time anywhere under a directory, optionally ignoring one subtree.</summary>
    private static DateTime NewestWrite(string root, string? excludeDirName, CancellationToken ct)
    {
        var options = new WalkOptions
        {
            MaxDepth = 24,
            PruneDirectoryNames = excludeDirName is null ? Array.Empty<string>() : new[] { excludeDirName },
        };

        // A single root means ScanRoots runs on one thread, so the predicate can safely carry the
        // running maximum rather than materialising a list of every file just to take a max of it.
        DateTime newest = DateTime.MinValue;
        FileWalk.ScanRoots(new[] { root }, options, null, 0, f =>
        {
            if (f.LastWriteUtc > newest) newest = f.LastWriteUtc;
            return false;
        }, ct);
        return newest;
    }
}
