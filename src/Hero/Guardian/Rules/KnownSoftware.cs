using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using Hero.Interop;

namespace Hero.Guardian.Rules;

/// <summary>
/// Where a file lives, expressed as a trust-relevant class rather than a substring test.
///
/// The classes exist because substring matching produces exactly the wrong answers on this
/// machine: Windows Defender itself runs from %ProgramData%, AMD ships a third-party binary
/// under System32\AMD, Realtek's autorun points into the DriverStore, and every Electron app
/// the user owns installs into %LOCALAPPDATA%\Programs.
/// </summary>
internal enum PathClass
{
    Unknown,
    /// <summary>System32 / SysWOW64 / WinSxS / servicing / SystemApps — only servicing writes here.</summary>
    SystemProtected,
    /// <summary>Elsewhere under %SystemRoot%. explorer.exe lives here, so this is normal.</summary>
    WindowsRoot,
    /// <summary>System32\DriverStore\FileRepository\*.inf_amd64_* — the modern driver package location.</summary>
    DriverStore,
    ProgramFiles,
    /// <summary>%ProgramData%. NOT inherently suspicious: WinDefend runs from here.</summary>
    ProgramData,
    /// <summary>MSIX/AppX package payload (Program Files\WindowsApps, %LOCALAPPDATA%\Packages).</summary>
    WindowsApps,
    /// <summary>%LOCALAPPDATA%\Programs, WinGet packages, scoop, chocolatey — per-user installs.</summary>
    UserPrograms,
    /// <summary>Ordinary %APPDATA% / %LOCALAPPDATA% content.</summary>
    UserData,
    Temp,
    Downloads,
    Public,
    RecycleBin,
    /// <summary>A source tree or build output directory — the user's own work.</summary>
    DevWorkspace,
    Removable,
    Network,
}

/// <summary>
/// The class of software an image belongs to. Used to damp provenance signals: on this machine
/// nine unsigned binaries are running and every one is a Python shim, a uv cache entry, a WinGet
/// package or Microsoft's own WidgetService. Recognising those as a normal software class is the
/// single most important false-positive control HERO has.
/// </summary>
internal enum SoftwareClass
{
    Unknown,
    WindowsComponent,
    DriverPackage,
    StoreApp,
    Browser,
    ElectronApp,
    GameLauncher,
    GameEngine,
    ContentCreation,
    PythonToolchain,
    NodeToolchain,
    RustToolchain,
    DotNetToolchain,
    JavaToolchain,
    Containers,
    AndroidEmulator,
    Editor,
    VersionControl,
    ScriptHost,
    WindowsLolBin,
    RemoteAccess,
    TunnelClient,
    MiningTool,
    SecurityTool,
}

/// <summary>How much the recognition is worth to a rule that is about to accuse this file.</summary>
internal enum TrustHint
{
    /// <summary>Nothing recognised. Provenance signals apply at full strength.</summary>
    None,
    /// <summary>A normal software class for this machine. Unsigned-ness carries little information.</summary>
    Recognised,
    /// <summary>A location only the OS or a package installer writes to.</summary>
    SystemManaged,
}

/// <summary>What HERO thinks an image is, without having verified anything.</summary>
internal readonly record struct SoftwareIdentity(
    SoftwareClass Class,
    PathClass Location,
    TrustHint Trust,
    string Label)
{
    internal bool IsRecognised => Trust != TrustHint.None;

    internal bool IsDeveloperTooling => Class is SoftwareClass.PythonToolchain
        or SoftwareClass.NodeToolchain or SoftwareClass.RustToolchain
        or SoftwareClass.DotNetToolchain or SoftwareClass.JavaToolchain
        or SoftwareClass.Containers or SoftwareClass.Editor or SoftwareClass.VersionControl
        or SoftwareClass.GameEngine or SoftwareClass.ContentCreation;

    internal bool InUserWritableLocation => KnownSoftware.IsUserWritable(Location);
}

/// <summary>Cheap, cached facts about a file on disk. Never re-stats on the hot path.</summary>
internal readonly record struct ImageFact(bool Exists, DateTime LastWriteUtc, DateTime CreationUtc, long Length);

/// <summary>
/// The machine's software vocabulary.
///
/// Every rule in HERO consults this before accusing anything. It is deliberately a plain static
/// classifier with no learned state, so its behaviour is reviewable: a reader can see exactly why
/// uv.exe is not treated as an anomaly, and can add a class without touching a rule.
///
/// Nothing here decides guilt. It answers two questions: "what kind of thing is this?" and
/// "is this location one the user can write to?".
/// </summary>
internal static class KnownSoftware
{
    // ------------------------------------------------------------------ well-known locations

    private static readonly string System32 = Folder(Environment.SpecialFolder.System);
    private static readonly string SysWow64 = Folder(Environment.SpecialFolder.SystemX86);
    private static readonly string WindowsDir = Folder(Environment.SpecialFolder.Windows);
    private static readonly string ProgramFilesDir = Folder(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86Dir = Folder(Environment.SpecialFolder.ProgramFilesX86);
    private static readonly string ProgramDataDir = Folder(Environment.SpecialFolder.CommonApplicationData);
    private static readonly string LocalAppData = Folder(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string RoamingAppData = Folder(Environment.SpecialFolder.ApplicationData);
    private static readonly string UserProfile = Folder(Environment.SpecialFolder.UserProfile);
    private static readonly string TempDir = Ensure(SafeTempPath());
    private static readonly string DownloadsDir = Ensure(ResolveDownloads());
    private static readonly string PublicDir = Ensure(Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public");

    private static string Folder(Environment.SpecialFolder f)
    {
        try { return Ensure(Environment.GetFolderPath(f)); } catch { return "\u0000"; }
    }

    private static string SafeTempPath()
    {
        try { return Path.GetTempPath(); } catch { return ""; }
    }

    /// <summary>
    /// Downloads is resolved through the known-folder API rather than string-built from
    /// %USERPROFILE%, because on Windows 11 it is commonly redirected into OneDrive. Building
    /// the path by hand would leave HERO watching a folder nothing is ever downloaded into.
    /// </summary>
    private static string ResolveDownloads()
    {
        var folderId = new Guid("374DE290-123F-4565-9164-39C4925E467B");
        IntPtr p = IntPtr.Zero;
        try
        {
            if (Native.SHGetKnownFolderPath(ref folderId, 0, IntPtr.Zero, out p) == 0 && p != IntPtr.Zero)
                return Marshal.PtrToStringUni(p) ?? "";
        }
        catch { /* fall through to the string-built guess */ }
        finally { if (p != IntPtr.Zero) Marshal.FreeCoTaskMem(p); }

        return UserProfile.Length > 1 ? Path.Combine(UserProfile.TrimEnd('\\'), "Downloads") : "";
    }

    /// <summary>Terminates a directory with a backslash so prefix tests cannot match a sibling
    /// ("C:\Program Files" must not match "C:\Program Files Extra"). Empty stays empty, and an
    /// unresolvable folder becomes a sentinel that can never prefix-match a real path.</summary>
    private static string Ensure(string? dir)
    {
        if (string.IsNullOrWhiteSpace(dir)) return "\u0000";
        return dir.EndsWith('\\') ? dir : dir + "\\";
    }

    private static bool Under(string path, string prefix) =>
        prefix.Length > 1 && path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    // ------------------------------------------------------------------ name sets

    /// <summary>Lowercase file name with the extension removed — the key every set below uses.</summary>
    internal static string NameKey(string pathOrName)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return "";
        var name = Path.GetFileNameWithoutExtension(pathOrName) ?? "";
        return name.ToLowerInvariant();
    }

    private static HashSet<string> Set(params string[] names) => new(names, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The living-off-the-land inventory: signed Microsoft binaries that execute attacker-supplied
    /// content. Membership is NOT a signal — every one of these runs legitimately on this machine
    /// dozens of times a day. It only matters in conjunction with a parent, an argument shape or a
    /// persistence entry.
    /// </summary>
    internal static readonly IReadOnlySet<string> LolBins = Set(
        "rundll32", "regsvr32", "mshta", "wscript", "cscript", "certutil", "certreq", "bitsadmin",
        "msiexec", "installutil", "regasm", "regsvcs", "msbuild", "cmstp", "control", "pcalua",
        "hh", "ieexec", "msdt", "esentutl", "expand", "extrac32", "makecab", "replace", "xwizard",
        "odbcconf", "mavinject", "syncappvpublishingserver", "presentationhost", "dfsvc", "wsreset",
        "computerdefaults", "fodhelper", "sdclt", "eventvwr", "dnscmd", "scriptrunner", "appinstaller",
        "workfolders", "datasvcutil", "forfiles", "wmic", "curl", "findstr", "atbroker", "diskshadow",
        "ftp", "gpscript", "ie4uinit", "infdefaultinstall", "mmc", "msconfig", "netsh", "pnputil",
        "print", "rasautou", "runonce", "schtasks", "reg", "sc", "taskkill", "net", "net1",
        "vssadmin", "wbadmin", "bcdedit", "wevtutil", "powershell", "pwsh", "cmd", "explorer");

    /// <summary>
    /// The subset with no plausible explanation as the child of a document, browser or archiver.
    /// msiexec is deliberately absent: opening a downloaded installer from the browser's download
    /// shelf launches it as a child of the browser, which is the most ordinary software-install
    /// action on Windows. conhost is absent because "conhost --headless" is the ConPTY mechanism
    /// behind every Windows Terminal and VS Code shell session on this machine.
    /// </summary>
    internal static readonly IReadOnlySet<string> HighRiskLolBins = Set(
        "mshta", "regsvr32", "rundll32", "wscript", "cscript", "certutil", "bitsadmin", "installutil",
        "regasm", "regsvcs", "cmstp", "odbcconf", "mavinject", "xwizard", "syncappvpublishingserver",
        "presentationhost", "ieexec", "msdt", "fodhelper", "computerdefaults", "sdclt", "eventvwr",
        "wsreset", "dfsvc", "pcalua", "esentutl", "extrac32", "atbroker");

    /// <summary>Shells and script hosts — things whose whole job is to run supplied text.</summary>
    internal static readonly IReadOnlySet<string> ScriptHosts = Set(
        "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta");

    /// <summary>
    /// Interpreters. Every one of these is a better living-off-the-land binary than half the
    /// Windows list ("node -e", "python -c", "wsl bash -c" bypass the whole command-line family),
    /// and every one of them is core developer tooling on this machine. They are scanned for
    /// argument content but never treated as anomalous by lineage rules.
    /// </summary>
    internal static readonly IReadOnlySet<string> Interpreters = Set(
        "node", "python", "python3", "pythonw", "deno", "bun", "ruby", "perl", "php", "lua",
        "wsl", "bash", "sh", "zsh", "java", "dotnet", "nu", "tclsh");

    internal static readonly IReadOnlySet<string> Browsers = Set(
        "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera", "opera_gx", "vivaldi",
        "iexplore", "chromium", "librewolf", "waterfox", "tor");

    internal static readonly IReadOnlySet<string> Archivers = Set(
        "7zfm", "7zg", "7z", "winrar", "rar", "unrar", "bandizip", "peazip", "nanazip");

    internal static readonly IReadOnlySet<string> DocumentApps = Set(
        "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "visio", "wordpad",
        "acrobat", "acrord32", "foxitpdfreader", "sumatrapdf");

    internal static readonly IReadOnlySet<string> Terminals = Set(
        "windowsterminal", "wt", "conhost", "openconsole", "alacritty", "wezterm", "hyper", "cmder");

    /// <summary>
    /// Build tools and developer parents. A child of one of these is presumed to be part of a
    /// build, which is what makes write-then-execute, short-lived process churn and unsigned
    /// output normal rather than notable.
    /// </summary>
    internal static readonly IReadOnlySet<string> DeveloperTools = Set(
        "node", "npm", "npx", "pnpm", "yarn", "corepack", "python", "python3", "pythonw", "pip",
        "uv", "uvx", "poetry", "conda", "cargo", "rustc", "rustup", "rust-analyzer", "dotnet",
        "msbuild", "vbcsccompiler", "csc", "cl", "link", "lib", "cmake", "ninja", "make", "nmake",
        "gcc", "g++", "clang", "clang++", "lld", "git", "gh", "code", "code-insiders", "devenv",
        "rider64", "idea64", "pycharm64", "clion64", "webstorm64", "javac", "gradle", "mvn",
        "go", "gofmt", "deno", "bun", "docker", "kubectl", "podman", "ffmpeg", "blender",
        "unrealeditor", "unrealbuildtool", "unrealpak", "shadercompileworker", "unrealeditor-cmd",
        "vstest.console", "testhost", "vshost", "nuget", "wsl", "vcpkg",
        // AI coding assistants are developer tooling on this machine and spawn shells constantly.
        "claude", "claude-code", "cursor", "windsurf", "copilot");

    /// <summary>
    /// Supervisors and watchers that legitimately restart their children forever. Without this
    /// list the "mutual watchdog" pattern names dotnet watch, nodemon and vite on this machine.
    /// </summary>
    internal static readonly IReadOnlySet<string> Supervisors = Set(
        "nodemon", "vite", "webpack", "next", "concurrently", "pm2", "supervisor", "watchexec",
        "cargo-watch", "dotnet", "tsc", "esbuild", "rollup", "turbo");

    /// <summary>
    /// Managed remote-access agents. These are RATs by function, which is why they are listed —
    /// and why the rule keys on FIRST APPEARANCE plus a user-writable location, never on presence.
    /// TeamViewer is verified installed and legitimate on this machine.
    /// </summary>
    private static readonly IReadOnlySet<string> RemoteAccessAgents = Set(
        "anydesk", "teamviewer", "teamviewer_service", "tv_w32", "tv_x64", "screenconnect",
        "connectwisecontrol", "ateraagent", "splashtop", "srservice", "srmanager", "rustdesk",
        "supremo", "supremoservice", "aa_v3", "dwagent", "dwagsvc", "action1_agent", "action1_remote",
        "pdqconnectagent", "meshagent", "client32", "logmein", "lmiguardiansvc", "gotoassist",
        "g2mcomm", "za_access", "zaservice", "remote_access", "level", "syncro", "basupsrvc",
        "agentmon", "rmmservice", "rutserv", "rfusclient", "atera", "ninjarmmagent", "kaseya");

    /// <summary>
    /// Remote tools this user plausibly installed on purpose for their own machine. Kept apart so
    /// they get a "confirm once" rather than an accusation.
    /// </summary>
    private static readonly IReadOnlySet<string> UserChosenRemoteTools = Set(
        "parsec", "parsecd", "moonlight", "sunshine", "steam", "steamwebhelper", "tailscale",
        "tailscale-ipn", "tailscaled", "warp-svc", "cloudflarewarp", "chrome_remote_desktop_host",
        "remoting_host", "mstsc", "rdclient");

    private static readonly IReadOnlySet<string> TunnelClients = Set(
        "ngrok", "cloudflared", "frpc", "frps", "chisel", "gost", "rathole", "bore", "lt",
        "localtunnel", "plink", "socat", "iox", "pagekite", "ssh");

    private static readonly IReadOnlySet<string> MinerImages = Set(
        "xmrig", "nbminer", "phoenixminer", "t-rex", "trex", "lolminer", "gminer", "teamredminer",
        "srbminer-multi", "srbminer", "ethminer", "cpuminer", "xmr-stak", "nicehashminer",
        "excavator", "miniz", "bzminer", "rigel");

    /// <summary>
    /// Publishers whose valid signature is worth a strong damping. Deliberately short: this is a
    /// trust shortcut, not an inventory, and a valid signature from anyone at all already carries
    /// most of the weight.
    /// </summary>
    private static readonly string[] TrustedPublisherFragments =
    {
        "Microsoft", "NVIDIA", "Advanced Micro Devices", "Intel", "Realtek", "Epic Games",
        "Blender Foundation", "Valve", "Python Software Foundation", "OpenJS", "Docker",
        "JetBrains", "Google", "Mozilla", "Opera", "GitHub", "Canonical", "Oracle", "Unity",
        "Autodesk", "Adobe", "Logitech", "Razer", "Corsair", "Discord", "Slack", "Postman",
        "Cloudflare", "TeamViewer", "Riot Games", "Ubisoft", "Electronic Arts", "now.gg",
    };

    /// <summary>
    /// Domains whose documented installation path is a download cradle. The user runs these:
    /// `irm https://astral.sh/uv/install.ps1 | iex` is how uv is installed. Matching one damps
    /// the cradle rule rather than clearing it, because a lookalike domain is a real technique.
    /// </summary>
    private static readonly string[] KnownInstallerHosts =
    {
        "rustup.rs", "sh.rustup.rs", "win.rustup.rs", "get.scoop.sh", "chocolatey.org",
        "community.chocolatey.org", "pnpm.io", "get.pnpm.io", "bun.sh", "astral.sh", "aka.ms",
        "microsoft.com", "windows.net", "github.com", "githubusercontent.com", "nodejs.org",
        "python.org", "deno.land", "dot.net", "dotnet.microsoft.com", "nuget.org", "crates.io",
        "npmjs.org", "npmjs.com", "pypi.org", "docker.com", "winget.azureedge.net",
    };

    /// <summary>
    /// Public DNS-over-HTTPS / DNS-over-TLS resolvers. HERO cannot see hostnames, so "a
    /// non-standard resolver" is not observable; what IS observable is a non-browser process
    /// talking directly to a public resolver, which is how a payload resolves C2 without
    /// touching the Windows resolver (and therefore without appearing in any local DNS cache).
    /// </summary>
    private static readonly IReadOnlySet<string> PublicDnsResolvers = Set(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15", "76.76.2.0",
        "76.76.10.0", "45.90.28.0", "45.90.30.0", "185.228.168.9", "76.76.19.19",
        "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2620:fe::fe");

    /// <summary>
    /// Mining-pool ports, external destinations only.
    ///
    /// 7777 is deliberately absent: it is the Unreal Engine default game/server port and this is
    /// an Unreal developer's machine. 8888, 9999 and 6666 are absent for the same reason —
    /// Jupyter, dev APIs and local services own them. What is left is a weak hint that may never
    /// score meaningfully without a miner-shaped image name or command line alongside it.
    /// </summary>
    private static readonly int[] MiningPorts = { 3333, 3334, 3335, 4444, 5555, 5556, 14433, 14444, 45560, 45700 };

    /// <summary>Ports whose whole purpose is letting someone else drive this machine.</summary>
    private static readonly int[] RemoteControlPorts = { 22, 3389, 4899, 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5938, 5985, 5986, 6129, 7070 };

    /// <summary>Hostname fragments used by mining pools. Matched against command lines only,
    /// since HERO has no DNS plane.</summary>
    private static readonly string[] PoolHostFragments =
    {
        "stratum+tcp://", "stratum+ssl://", "nanopool.org", "minexmr", "moneroocean.stream",
        "f2pool.com", "ethermine.org", "herominers.com", "hashvault.pro", "supportxmr.com",
        "zergpool.com", "unmineable.com", "nicehash.com", "2miners.com", "flexpool", "kryptex",
    };

    // ------------------------------------------------------------------ predicates

    internal static bool IsLolBin(string pathOrName) => LolBins.Contains(NameKey(pathOrName));
    internal static bool IsHighRiskLolBin(string pathOrName) => HighRiskLolBins.Contains(NameKey(pathOrName));
    internal static bool IsScriptHost(string pathOrName) => ScriptHosts.Contains(NameKey(pathOrName));
    internal static bool IsInterpreter(string pathOrName) => Interpreters.Contains(NameKey(pathOrName));
    internal static bool IsBrowser(string pathOrName) => Browsers.Contains(NameKey(pathOrName));
    internal static bool IsArchiver(string pathOrName) => Archivers.Contains(NameKey(pathOrName));
    internal static bool IsDocumentApp(string pathOrName) => DocumentApps.Contains(NameKey(pathOrName));
    internal static bool IsTerminal(string pathOrName) => Terminals.Contains(NameKey(pathOrName));
    internal static bool IsDeveloperTool(string pathOrName) => DeveloperTools.Contains(NameKey(pathOrName));
    internal static bool IsSupervisor(string pathOrName) => Supervisors.Contains(NameKey(pathOrName));
    internal static bool IsTunnelClient(string pathOrName) => TunnelClients.Contains(NameKey(pathOrName));
    internal static bool IsMinerImage(string pathOrName) => MinerImages.Contains(NameKey(pathOrName));
    internal static bool IsUserChosenRemoteTool(string pathOrName) => UserChosenRemoteTools.Contains(NameKey(pathOrName));
    internal static bool IsPublicDnsResolver(string ip) => PublicDnsResolvers.Contains(ip);
    internal static bool IsMiningPoolPort(int port) => Array.IndexOf(MiningPorts, port) >= 0;
    internal static bool IsRemoteControlPort(int port) => Array.IndexOf(RemoteControlPorts, port) >= 0;

    internal static bool IsRemoteAccessAgent(string pathOrName, out string product)
    {
        var key = NameKey(pathOrName);
        if (RemoteAccessAgents.Contains(key)) { product = key; return true; }
        product = "";
        return false;
    }

    internal static bool MentionsMiningPool(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return false;
        foreach (var fragment in PoolHostFragments)
            if (commandLine.Contains(fragment, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    internal static bool IsTrustedPublisher(string signer)
    {
        if (string.IsNullOrWhiteSpace(signer)) return false;
        foreach (var fragment in TrustedPublisherFragments)
            if (signer.Contains(fragment, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    internal static bool IsMicrosoftPublisher(string signer) =>
        !string.IsNullOrWhiteSpace(signer) && signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

    internal static bool MentionsKnownInstallerHost(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return false;
        foreach (var host in KnownInstallerHosts)
            if (commandLine.Contains(host, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// Chromium and Electron helper processes.
    ///
    /// Their argument blocks are enormous, punctuation-dense and full of base64 — the exact shape
    /// a naive obfuscation heuristic scores. Measured on this machine: --gpu-preferences carries a
    /// 110-character base64 blob and --field-trial-handle a comma-separated integer soup, on every
    /// renderer and utility process of every Electron app installed.
    /// </summary>
    internal static bool IsChromiumChild(string commandLine) =>
        !string.IsNullOrEmpty(commandLine)
        && commandLine.Contains("--type=", StringComparison.OrdinalIgnoreCase)
        && (commandLine.Contains("--user-data-dir", StringComparison.OrdinalIgnoreCase)
            || commandLine.Contains("--field-trial-handle", StringComparison.OrdinalIgnoreCase)
            || commandLine.Contains("--utility-sub-type", StringComparison.OrdinalIgnoreCase));

    private static readonly ConcurrentDictionary<string, string> ModuleResolutionCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Where a bare program or module name is looked for, in the order the loader would find it.
    ///
    /// WindowsPowerShell\v1.0 has to be here even though it is not System32: powershell.exe lives
    /// there, not in System32, so without it a perfectly ordinary autorun of the form
    /// <c>powershell.exe -File "C:\Program Files\Vendor\update.ps1"</c> had an unresolvable host and
    /// was reported as a script host pointed somewhere unknown. %SystemRoot% is included for the
    /// same reason explorer.exe is a special case elsewhere in this file.
    /// </summary>
    private static readonly string[] BareNameProbeDirs =
    {
        System32,
        SysWow64,
        System32.Length > 1 ? Path.Combine(System32, @"WindowsPowerShell\v1.0") : "",
        SysWow64.Length > 1 ? Path.Combine(SysWow64, @"WindowsPowerShell\v1.0") : "",
        WindowsDir,
    };

    /// <summary>
    /// Resolves a module or program reference the way Windows itself would: expands environment
    /// variables, strips quotes, and — for a bare file name with no directory — probes System32
    /// and SysWOW64, which is where rundll32 and the loader find in-box modules.
    ///
    /// This matters more than it looks. Nine in-box Windows scheduled tasks on this machine are of
    /// the form <c>%windir%\system32\rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask</c>. Without
    /// expansion and bare-name resolution they classify as "a DLL from an unknown location loaded
    /// through a Windows utility" — nine high-severity false positives against Windows itself,
    /// on every scan.
    ///
    /// Returns "" when the reference cannot be resolved, which is itself informative: a bare module
    /// name that exists nowhere is a phantom-DLL opportunity.
    /// </summary>
    internal static string ResolveModuleReference(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";
        if (ModuleResolutionCache.Count > 4096) ModuleResolutionCache.Clear();

        return ModuleResolutionCache.GetOrAdd(raw, static input =>
        {
            var s = input.Trim().Trim('"', '\'');
            if (s.Length == 0) return "";
            // A switch is not a module. rundll32 takes "/d" before the DLL name, and a resolver
            // that treated "/d acproxy.dll" as a path classified an in-box Windows task as a DLL
            // from an unknown location.
            if (s[0] is '/' or '-') return "";

            try { s = Environment.ExpandEnvironmentVariables(s); } catch { /* keep the raw form */ }
            if (s.Contains('\\') || (s.Length > 2 && s[1] == ':')) return s;

            foreach (var dir in BareNameProbeDirs)
            {
                if (dir.Length < 2) continue;
                try
                {
                    var probe = Path.Combine(dir, s);
                    if (File.Exists(probe)) return probe;
                }
                catch { /* invalid characters in the name */ }
            }
            return "";
        });
    }

    /// <summary>
    /// Splits a command line into arguments the way the loader does, honouring double quotes.
    ///
    /// Splitting on whitespace alone is wrong in precisely the case that matters most here: every
    /// path under "C:\Program Files\" contains a space, so a naive split turns one argument into
    /// two fragments and neither resolves. Measured against this machine's own autoruns, that made
    /// <c>powershell.exe -File "C:\Program Files\Vendor\update.ps1"</c> read as a script host
    /// pointed at an unknown location, and it handed rundll32's module resolver the tail of a path
    /// ("Files\Vendor\thing.dll") instead of the path.
    ///
    /// Commas are deliberately kept inside a token, because rundll32 and regsvr32 encode the
    /// entry point as <c>module.dll,EntryPoint</c> and the caller decides where to cut.
    /// </summary>
    internal static List<string> SplitArguments(string commandLine)
    {
        var tokens = new List<string>(8);
        if (string.IsNullOrEmpty(commandLine)) return tokens;

        var sb = new StringBuilder(64);
        bool quoted = false;
        foreach (char c in commandLine)
        {
            if (c == '"') { quoted = !quoted; continue; }
            if (!quoted && (c is ' ' or '\t' or '\r' or '\n'))
            {
                if (sb.Length > 0) { tokens.Add(sb.ToString()); sb.Clear(); }
                continue;
            }
            sb.Append(c);
        }
        if (sb.Length > 0) tokens.Add(sb.ToString());
        return tokens;
    }

    /// <summary>The file part of an argument, with any <c>,EntryPoint</c> or <c>;next</c> tail cut off.</summary>
    internal static string FilePartOf(string token)
    {
        int cut = token.AsSpan().IndexOfAny(',', ';');
        return (cut > 0 ? token[..cut] : token).Trim().Trim('\'');
    }

    /// <summary>
    /// True when every file the command line names resolves to a location only Windows or an
    /// installer writes to.
    ///
    /// This is what separates "Windows running its own maintenance through a utility" — which is
    /// most of the scheduled-task table — from "something running supplied content through a
    /// utility", which is the actual technique. An unresolvable reference returns false, because
    /// HERO cannot claim a file is safe when it cannot find it.
    /// </summary>
    internal static bool AllReferencesProtected(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return false;

        bool sawAnyFile = false;
        foreach (var token in SplitArguments(commandLine))
        {
            var candidate = FilePartOf(token);
            if (candidate.Length < 5) continue;
            if (candidate[0] is '/' or '-') continue;          // a switch, not a path
            if (!candidate.Contains('.')) continue;            // an entry-point name, not a file

            var resolved = ResolveModuleReference(candidate);
            if (resolved.Length == 0) return false;

            var cls = ClassifyPath(resolved);
            if (cls is not (PathClass.SystemProtected or PathClass.WindowsRoot or PathClass.ProgramFiles
                or PathClass.DriverStore or PathClass.WindowsApps))
                return false;

            sawAnyFile = true;
        }

        return sawAnyFile;
    }

    /// <summary>User-writable in the sense that matters: a place a non-admin process can drop a
    /// payload. %ProgramData% is included because its root is writable by authenticated users,
    /// even though Defender legitimately lives in a subdirectory of it.</summary>
    internal static bool IsUserWritable(PathClass c) => c is PathClass.UserData or PathClass.UserPrograms
        or PathClass.Temp or PathClass.Downloads or PathClass.Public or PathClass.RecycleBin
        or PathClass.DevWorkspace or PathClass.ProgramData or PathClass.Removable or PathClass.Network
        or PathClass.Unknown;

    /// <summary>Locations that exist for transient content. Something executing from here has,
    /// at minimum, chosen an odd place to live.</summary>
    internal static bool IsVolatile(PathClass c) =>
        c is PathClass.Temp or PathClass.Downloads or PathClass.Public or PathClass.RecycleBin;

    // ------------------------------------------------------------------ path classification

    private static readonly ConcurrentDictionary<string, PathClass> PathClassCache = new(StringComparer.OrdinalIgnoreCase);

    internal static PathClass ClassifyPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return PathClass.Unknown;
        if (PathClassCache.Count > 8192) PathClassCache.Clear();
        return PathClassCache.GetOrAdd(path, static p => ClassifyPathUncached(p));
    }

    private static PathClass ClassifyPathUncached(string path)
    {
        // Quotes arrive from service ImagePath values and from event-log properties: Windows writes
        // 7045's Service File Name as "C:\Program Files\WSL\wslservice.exe", quotes included.
        // Leaving them on made every quoted path fail the Program Files prefix test and fall
        // through to Unknown, which IsUserWritable treats as writable — verified against the WSL
        // and Google Play Games service installs recorded on this machine.
        var p = path.Trim().Trim('"');
        // \??\ and \SystemRoot\ forms arrive from service ImagePath values.
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = WindowsDir + p[12..];

        if (p.StartsWith(@"\\", StringComparison.Ordinal)) return PathClass.Network;
        if (p.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase)) return PathClass.RecycleBin;

        if (Under(p, TempDir) || p.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)
                              || p.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase))
            return PathClass.Temp;

        if (Under(p, DownloadsDir)) return PathClass.Downloads;
        if (Under(p, PublicDir)) return PathClass.Public;

        if (p.Contains(@"\DriverStore\FileRepository\", StringComparison.OrdinalIgnoreCase))
            return PathClass.DriverStore;

        if (p.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\AppData\Local\Packages\", StringComparison.OrdinalIgnoreCase))
            return PathClass.WindowsApps;

        if (Under(p, System32) || Under(p, SysWow64)
            || p.Contains(@"\WinSxS\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Windows\servicing\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Windows\SystemApps\", StringComparison.OrdinalIgnoreCase))
            return PathClass.SystemProtected;

        if (Under(p, WindowsDir)) return PathClass.WindowsRoot;
        if (Under(p, ProgramFilesDir) || Under(p, ProgramFilesX86Dir)) return PathClass.ProgramFiles;

        // Per-user installs come before the generic %LOCALAPPDATA% test, because every Electron
        // app the user owns lives under %LOCALAPPDATA%\Programs and must not read as "user data".
        if (p.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\AppData\Local\Microsoft\WinGet\Packages\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\scoop\apps\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\ProgramData\chocolatey\", StringComparison.OrdinalIgnoreCase))
            return PathClass.UserPrograms;

        if (LooksLikeDevelopmentOutput(p)) return PathClass.DevWorkspace;

        if (Under(p, ProgramDataDir)) return PathClass.ProgramData;
        if (Under(p, LocalAppData) || Under(p, RoamingAppData) || Under(p, UserProfile)) return PathClass.UserData;

        return DriveTypeOf(p) switch
        {
            DriveType.Removable or DriveType.CDRom => PathClass.Removable,
            DriveType.Network => PathClass.Network,
            _ => PathClass.Unknown,
        };
    }

    private static readonly ConcurrentDictionary<char, DriveType> DriveTypes = new();

    private static DriveType DriveTypeOf(string path)
    {
        if (path.Length < 3 || path[1] != ':') return DriveType.Unknown;
        char letter = char.ToUpperInvariant(path[0]);
        if (letter is < 'A' or > 'Z') return DriveType.Unknown;
        return DriveTypes.GetOrAdd(letter, static l =>
        {
            try { return new DriveInfo(l + ":\\").DriveType; }
            catch { return DriveType.Unknown; }
        });
    }

    // ------------------------------------------------------- developer workspace detection

    private static readonly string[] WorkspaceMarkerFiles =
        { ".git", "Cargo.toml", "package.json", "go.mod", "CMakeLists.txt", "pyvenv.cfg", "pnpm-workspace.yaml" };

    private static readonly string[] WorkspaceMarkerPatterns = { "*.sln", "*.slnx", "*.uproject", "*.csproj", "*.blend1" };

    private static readonly string[] BuildOutputSegments =
    {
        @"\bin\debug\", @"\bin\release\", @"\obj\debug\", @"\obj\release\",
        @"\target\debug\", @"\target\release\", @"\publish\", @"\out\build\",
        @"\node_modules\", @"\.venv\", @"\venv\scripts\", @"\saved\", @"\intermediate\",
        @"\derivedatacache\", @"\binaries\win64\",
    };

    private static readonly ConcurrentDictionary<string, bool> WorkspaceCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// True when the file is, on the balance of evidence, something the user built or installed
    /// as part of their own work.
    ///
    /// The ancestor search is what makes this correct rather than merely plausible. A
    /// self-contained publish lands in ...\bin\Release\net10.0\win-x64\publish\, which contains
    /// no project marker of its own — a rule that only inspected the containing directory would
    /// treat every binary the user ships as an unsigned stranger, which is precisely the sticky
    /// provenance score that makes an autonomous action reachable.
    /// </summary>
    internal static bool LooksLikeDevelopmentOutput(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        foreach (var seg in BuildOutputSegments)
            if (path.Contains(seg, StringComparison.OrdinalIgnoreCase)) return true;

        var dir = Path.GetDirectoryName(path) ?? "";
        if (dir.Length == 0) return false;
        if (WorkspaceCache.Count > 4096) WorkspaceCache.Clear();

        return WorkspaceCache.GetOrAdd(dir, static d =>
        {
            var current = d;
            // Six levels covers publish\<rid>\<tfm>\<config>\bin\<project> comfortably without
            // walking to the drive root on every miss.
            for (int depth = 0; depth < 6 && current.Length > 3; depth++)
            {
                try
                {
                    foreach (var marker in WorkspaceMarkerFiles)
                    {
                        var candidate = Path.Combine(current, marker);
                        if (File.Exists(candidate) || Directory.Exists(candidate)) return true;
                    }
                    foreach (var pattern in WorkspaceMarkerPatterns)
                    {
                        if (Directory.Exists(current) &&
                            Directory.EnumerateFiles(current, pattern, SearchOption.TopDirectoryOnly).Any())
                            return true;
                    }
                }
                catch { return false; }

                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent) || parent == current) break;
                current = parent;
            }
            return false;
        });
    }

    // ------------------------------------------------------------------ software classification

    /// <summary>
    /// Identifies an image without touching its contents.
    ///
    /// The order of the tests is load-bearing: path-shape evidence beats name evidence, because
    /// a file called python.exe under %LOCALAPPDATA%\uv\cache is a uv-managed interpreter while a
    /// file called python.exe in %TEMP% is nothing of the kind.
    /// </summary>
    internal static SoftwareIdentity Classify(string imagePath)
    {
        var location = ClassifyPath(imagePath);
        if (string.IsNullOrWhiteSpace(imagePath))
            return new SoftwareIdentity(SoftwareClass.Unknown, location, TrustHint.None, "");

        var p = imagePath;
        var key = NameKey(imagePath);

        // --- locations only the OS or a package manager writes to
        if (location == PathClass.DriverStore)
            return new SoftwareIdentity(SoftwareClass.DriverPackage, location, TrustHint.SystemManaged, "driver package");
        if (location == PathClass.WindowsApps)
            return new SoftwareIdentity(SoftwareClass.StoreApp, location, TrustHint.SystemManaged, "packaged (MSIX) app");
        if (location == PathClass.SystemProtected)
            return new SoftwareIdentity(SoftwareClass.WindowsComponent, location, TrustHint.SystemManaged, "Windows component");

        // --- Python and the uv cache layout, which accounts for most of this machine's
        //     unsigned running images.
        if (p.Contains(@"\uv\cache\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\uv\python\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\uv\tools\", StringComparison.OrdinalIgnoreCase))
            return new SoftwareIdentity(SoftwareClass.PythonToolchain, location, TrustHint.Recognised, "uv-managed Python");

        if (p.Contains(@"\.venv\Scripts\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\venv\Scripts\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\site-packages\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\pipx\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\miniconda3\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\anaconda3\", StringComparison.OrdinalIgnoreCase)
            || (p.Contains(@"\Scripts\", StringComparison.OrdinalIgnoreCase) && HasVenvMarker(p)))
            return new SoftwareIdentity(SoftwareClass.PythonToolchain, location, TrustHint.Recognised, "Python virtual environment");

        if (key is "python" or "python3" or "pythonw" or "pip" or "uv" or "uvx" or "poetry" or "conda")
            return new SoftwareIdentity(SoftwareClass.PythonToolchain, location, TrustHint.Recognised, "Python tooling");

        // --- Node
        if (p.Contains(@"\node_modules\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\nvm\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\fnm_multishells\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\AppData\Roaming\npm\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\pnpm\", StringComparison.OrdinalIgnoreCase)
            || key is "node" or "npm" or "npx" or "pnpm" or "yarn" or "corepack" or "bun" or "deno")
            return new SoftwareIdentity(SoftwareClass.NodeToolchain, location, TrustHint.Recognised, "Node/JS toolchain");

        // --- Rust
        if (p.Contains(@"\.cargo\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\.rustup\", StringComparison.OrdinalIgnoreCase)
            || key is "cargo" or "rustc" or "rustup" or "rust-analyzer")
            return new SoftwareIdentity(SoftwareClass.RustToolchain, location, TrustHint.Recognised, "Rust toolchain");

        // --- .NET / MSBuild / Visual Studio
        if (p.Contains(@"\Program Files\dotnet\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\MSBuild\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Microsoft Visual Studio\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\.dotnet\tools\", StringComparison.OrdinalIgnoreCase)
            || key is "dotnet" or "msbuild" or "csc" or "vbcsccompiler" or "devenv" or "testhost")
            return new SoftwareIdentity(SoftwareClass.DotNetToolchain, location, TrustHint.Recognised, ".NET toolchain");

        // --- Unreal
        if (p.Contains(@"\Epic Games\UE_", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Engine\Binaries\", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("unrealeditor", StringComparison.Ordinal)
            || key is "unrealbuildtool" or "unrealpak" or "shadercompileworker" or "crashreportclient"
                   or "epicgameslauncher" or "epicwebhelper")
            return new SoftwareIdentity(SoftwareClass.GameEngine, location, TrustHint.Recognised, "Unreal Engine");

        // --- Blender
        if (p.Contains(@"\Blender Foundation\", StringComparison.OrdinalIgnoreCase)
            || key is "blender" or "blender-launcher")
            return new SoftwareIdentity(SoftwareClass.ContentCreation, location, TrustHint.Recognised, "Blender");

        // --- Docker / WSL
        if (p.Contains(@"\Docker\Docker\", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("com.docker", StringComparison.Ordinal)
            || key is "docker" or "dockerd" or "wsl" or "wslhost" or "wslservice" or "wslrelay" or "vmmem")
            return new SoftwareIdentity(SoftwareClass.Containers, location, TrustHint.Recognised, "Docker/WSL");

        // --- BlueStacks. Called out explicitly because the user's own copy is patched for root,
        //     which breaks its Authenticode digest permanently and by design.
        if (p.Contains(@"\BlueStacks", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("bsthd", StringComparison.Ordinal)
            || key is "hd-player" or "bluestacks" or "hd-adbconnection" or "hd-frontend")
            return new SoftwareIdentity(SoftwareClass.AndroidEmulator, location, TrustHint.Recognised, "BlueStacks");

        // --- game launchers and stores
        if (p.Contains(@"\Steam\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\GOG Galaxy\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Ubisoft\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\EA Desktop\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Riot Games\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\Battle.net\", StringComparison.OrdinalIgnoreCase)
            || key is "steam" or "steamwebhelper" or "steamservice" or "gog galaxy" or "battle.net"
                   or "upc" or "uplay" or "eadesktop")
            return new SoftwareIdentity(SoftwareClass.GameLauncher, location, TrustHint.Recognised, "game launcher");

        if (Browsers.Contains(key))
            return new SoftwareIdentity(SoftwareClass.Browser, location, TrustHint.Recognised, "web browser");

        if (RemoteAccessAgents.Contains(key))
            return new SoftwareIdentity(SoftwareClass.RemoteAccess, location, TrustHint.None, "remote-access agent");

        if (TunnelClients.Contains(key))
            return new SoftwareIdentity(SoftwareClass.TunnelClient, location, TrustHint.None, "tunnel client");

        if (MinerImages.Contains(key))
            return new SoftwareIdentity(SoftwareClass.MiningTool, location, TrustHint.None, "cryptocurrency miner");

        // --- Electron / Squirrel per-user installs. Discord, VS Code, Slack, Postman, GitHub
        //     Desktop and Opera GX all land here and all look like "unsigned binary in a user
        //     directory" to a naive rule.
        if (location == PathClass.UserPrograms
            || p.Contains(@"\app-", StringComparison.OrdinalIgnoreCase) && p.Contains(@"\AppData\Local\", StringComparison.OrdinalIgnoreCase))
            return new SoftwareIdentity(SoftwareClass.ElectronApp, location, TrustHint.Recognised, "per-user installed app");

        if (key is "code" or "code-insiders" or "rider64" or "idea64" or "pycharm64" or "clion64"
                or "webstorm64" or "sublime_text" or "notepad++")
            return new SoftwareIdentity(SoftwareClass.Editor, location, TrustHint.Recognised, "editor/IDE");

        if (key is "git" or "gh" or "git-bash" or "bash" or "sh" or "tortoisegitproc")
            return new SoftwareIdentity(SoftwareClass.VersionControl, location, TrustHint.Recognised, "Git tooling");

        if (LolBins.Contains(key) && location is PathClass.SystemProtected or PathClass.WindowsRoot)
            return new SoftwareIdentity(SoftwareClass.WindowsLolBin, location, TrustHint.SystemManaged, "Windows utility");

        if (DeveloperTools.Contains(key))
            return new SoftwareIdentity(SoftwareClass.Unknown, location, TrustHint.Recognised, "developer tooling");

        if (location == PathClass.DevWorkspace)
            return new SoftwareIdentity(SoftwareClass.Unknown, location, TrustHint.Recognised, "your own project output");

        return new SoftwareIdentity(SoftwareClass.Unknown, location, TrustHint.None, "");
    }

    /// <summary>A Scripts\ directory is a Python venv only if its parent carries pyvenv.cfg.
    /// Checking the marker keeps "Scripts" from matching unrelated vendor layouts.</summary>
    private static bool HasVenvMarker(string imagePath)
    {
        try
        {
            var scripts = Path.GetDirectoryName(imagePath);
            var root = scripts is null ? null : Path.GetDirectoryName(scripts);
            return root is not null && File.Exists(Path.Combine(root, "pyvenv.cfg"));
        }
        catch { return false; }
    }

    // ------------------------------------------------------- canonical system-image locations

    private static readonly string[] ServicingDirs =
    {
        @"\WinSxS\", @"\Windows\servicing\", @"\Windows\SystemApps\",
    };

    /// <summary>
    /// Where each Windows image is genuinely allowed to live.
    ///
    /// This is a per-image map rather than a shared directory set for one measured reason:
    /// explorer.exe does not live in System32. It is C:\WINDOWS\Explorer.EXE, so a shared
    /// "System32 or SysWOW64 or WinSxS" rule would assign the strongest masquerade signal in the
    /// product to the user's own desktop shell on every boot, permanently.
    /// </summary>
    private static readonly Dictionary<string, string[]> CanonicalLocations = new(StringComparer.OrdinalIgnoreCase)
    {
        ["explorer"] = new[] { WindowsDir },
        ["smss"] = new[] { System32 },
        ["csrss"] = new[] { System32 },
        ["wininit"] = new[] { System32 },
        ["winlogon"] = new[] { System32 },
        ["services"] = new[] { System32 },
        ["lsass"] = new[] { System32 },
        ["lsaiso"] = new[] { System32 },
        ["svchost"] = new[] { System32 },
        ["spoolsv"] = new[] { System32 },
        ["searchindexer"] = new[] { System32 },
        ["taskhostw"] = new[] { System32 },
        ["sihost"] = new[] { System32 },
        ["ctfmon"] = new[] { System32 },
        ["fontdrvhost"] = new[] { System32 },
        ["dwm"] = new[] { System32 },
        ["runtimebroker"] = new[] { System32 },
        ["userinit"] = new[] { System32 },
        ["taskmgr"] = new[] { System32 },
        ["dllhost"] = new[] { System32, SysWow64 },
        ["rundll32"] = new[] { System32, SysWow64 },
        ["conhost"] = new[] { System32, SysWow64 },
        ["regsvr32"] = new[] { System32, SysWow64 },
        ["cmd"] = new[] { System32, SysWow64 },
        ["wscript"] = new[] { System32, SysWow64 },
        ["cscript"] = new[] { System32, SysWow64 },
        ["mshta"] = new[] { System32, SysWow64 },
    };

    /// <summary>True when <paramref name="imagePath"/> uses a Windows image name from somewhere it
    /// has no business being. Returns false for anything not in the canonical map.</summary>
    internal static bool IsSystemImageOutOfPlace(string imagePath, out string expected)
    {
        expected = "";
        if (string.IsNullOrWhiteSpace(imagePath)) return false;

        var key = NameKey(imagePath);
        if (!CanonicalLocations.TryGetValue(key, out var allowed)) return false;

        expected = string.Join(" or ", allowed.Select(a => a.TrimEnd('\\')));

        foreach (var dir in allowed)
            if (Under(imagePath, dir)) return false;

        // The component store and servicing stack legitimately host copies of these images.
        foreach (var dir in ServicingDirs)
            if (imagePath.Contains(dir, StringComparison.OrdinalIgnoreCase)) return false;

        return true;
    }

    /// <summary>
    /// The parent a Windows process should have. Only the entries that survive contact with
    /// reality are here: smss and userinit exit immediately, so "csrss has no live parent" is the
    /// normal state and must be read as unknown rather than wrong.
    /// </summary>
    private static readonly Dictionary<string, string[]> ExpectedParentMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost"] = new[] { "services" },
        ["taskhostw"] = new[] { "svchost" },
        ["lsass"] = new[] { "wininit" },
        ["services"] = new[] { "wininit" },
        ["spoolsv"] = new[] { "services" },
        ["searchindexer"] = new[] { "services" },
    };

    internal static bool HasExpectedParent(string childName, string parentName, out string expected)
    {
        expected = "";
        var key = NameKey(childName);
        if (!ExpectedParentMap.TryGetValue(key, out var parents)) return true;

        expected = string.Join(" or ", parents.Select(x => x + ".exe"));
        return parents.Contains(NameKey(parentName), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True when the name is one character away from a Windows image name — the "svch0st.exe"
    /// family. Only meaningful together with a non-canonical location, since the genuine article
    /// obviously matches its own name exactly.
    /// </summary>
    internal static bool IsNearMissOfSystemImage(string fileName, out string ofWhat)
    {
        ofWhat = "";
        var key = NameKey(fileName);
        if (key.Length < 4) return false;
        if (CanonicalLocations.ContainsKey(key)) return false;

        foreach (var candidate in CanonicalLocations.Keys)
        {
            if (Math.Abs(candidate.Length - key.Length) > 1) continue;
            if (IsOneEditApart(key, candidate)) { ofWhat = candidate + ".exe"; return true; }
        }
        return false;
    }

    /// <summary>
    /// Damerau-Levenshtein distance of exactly one: a substitution, an insertion, a deletion, or a
    /// transposition of two adjacent characters.
    ///
    /// Transposition has to be included rather than assumed away. "scvhost.exe" is the commonest
    /// real-world svchost lookalike and it is a transposition, not a substitution — plain
    /// Levenshtein scores it as distance 2 and misses it entirely.
    /// </summary>
    private static bool IsOneEditApart(string a, string b)
    {
        if (a.Length == b.Length)
        {
            int first = -1, second = -1, diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == b[i]) continue;
                diff++;
                if (diff == 1) first = i;
                else if (diff == 2) second = i;
                else return false;
            }
            if (diff == 1) return true;
            return diff == 2 && second == first + 1 && a[first] == b[second] && a[second] == b[first];
        }

        var (shorter, longer) = a.Length < b.Length ? (a, b) : (b, a);
        int si = 0, li = 0;
        bool skipped = false;
        while (si < shorter.Length && li < longer.Length)
        {
            if (shorter[si] == longer[li]) { si++; li++; continue; }
            if (skipped) return false;
            skipped = true;
            li++;
        }
        return true;
    }

    // ------------------------------------------------------------------ file facts

    private readonly record struct FactEntry(ImageFact Fact, long StampTicks);

    private static readonly ConcurrentDictionary<string, FactEntry> FactCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan FactTtl = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Cheap file metadata with a five-minute cache.
    ///
    /// Rules must never block on disk I/O, and a FileInfo stat is the one exception that is
    /// affordable: it is a metadata read the OS has almost always cached. The TTL exists so a
    /// per-second poll over ~360 processes cannot turn into 360 stats per second.
    /// </summary>
    internal static ImageFact Stat(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return default;
        long now = Environment.TickCount64;

        if (FactCache.TryGetValue(path, out var cached) && now - cached.StampTicks < FactTtl.TotalMilliseconds)
            return cached.Fact;

        ImageFact fact;
        try
        {
            var fi = new FileInfo(path);
            fact = fi.Exists
                ? new ImageFact(true, fi.LastWriteTimeUtc, fi.CreationTimeUtc, fi.Length)
                : new ImageFact(false, default, default, 0);
        }
        catch
        {
            // Access denied or a malformed path. "Unknown" is not "missing"; callers must not
            // read a failed stat as evidence of a deleted image.
            fact = new ImageFact(true, default, default, 0);
        }

        if (FactCache.Count > 8192) FactCache.Clear();
        FactCache[path] = new FactEntry(fact, now);
        return fact;
    }

    // ------------------------------------------------------------------ untrusted text

    /// <summary>
    /// Makes attacker-controlled text safe to log and to render.
    ///
    /// Command lines, registry values, service names and event-log payloads are all strings an
    /// attacker chooses. Right-to-left override in particular lets a file called "exe.txt" render
    /// as "txt.exe" in the alert the user is deciding on, so the bidi controls are removed rather
    /// than escaped.
    /// </summary>
    internal static string Sanitise(string? text, int max = 400)
    {
        if (string.IsNullOrEmpty(text)) return "";

        var sb = new StringBuilder(Math.Min(text.Length, max));
        foreach (char c in text)
        {
            if (sb.Length >= max) break;
            if (char.IsControl(c)) { sb.Append(' '); continue; }
            if (c is >= '\u200b' and <= '\u200f') continue;   // zero-width and directional marks
            if (c is >= '\u202a' and <= '\u202e') continue;   // bidi embedding/override
            if (c is >= '\u2066' and <= '\u2069') continue;   // bidi isolates
            sb.Append(c);
        }

        var result = sb.ToString().Trim();
        return text.Length > max ? result + "\u2026" : result;
    }
}
