using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using Hero.Core;
using Hero.Interop;

namespace Hero.Guardian;

/// <summary>
/// How strongly a subject is shielded from HERO.
///
/// The ordering is deliberate: everything from <see cref="Essential"/> upwards refuses the action
/// even when the user asks for it explicitly, because those actions bugcheck the machine, destroy
/// the logon session, or disable the antivirus. Everything below that band refuses only
/// *autonomous* action — HERO will still report the finding, and the user may still act.
/// </summary>
internal enum ProtectionTier
{
    /// <summary>Nothing shields this. Normal rules apply.</summary>
    None = 0,

    /// <summary>
    /// Carries a protected name but does NOT live where that name belongs — %TEMP%\svchost.exe.
    /// This is evidence of masquerading and should score UP, but it must never inherit protection,
    /// and it must never be actioned autonomously either: the cost of a genuine name collision
    /// (some vendor's own "SearchHost.exe") is asymmetric with the benefit of acting a minute sooner.
    /// </summary>
    NameMasquerade,

    /// <summary>The window the user is looking at, their shell, their terminal, their editor.</summary>
    UserSurface,

    /// <summary>Inside a developer root or a language toolchain cache. See <see cref="ProtectedSet.DeveloperRoots"/>.</summary>
    DeveloperRoot,

    /// <summary>Software on this machine that legitimately behaves like malware (see the list).</summary>
    KnownOddSoftware,

    /// <summary>Suspending this corrupts state that a resume cannot repair — VM workers, installers.</summary>
    NeverSuspend,

    /// <summary>Security stack, shell and UX. Killing it does not bugcheck; it wrecks the session.</summary>
    Essential,

    /// <summary>Kernel, session and boot critical. An elevated kill here bugchecks the machine.</summary>
    Critical,

    /// <summary>HERO itself, its ancestor chain, or its own children.</summary>
    Self,

    /// <summary>
    /// HERO could not identify the subject well enough to reason about it. Fail closed: an
    /// unidentifiable process is, on this machine, overwhelmingly likely to be a SYSTEM or PPL
    /// process whose handle we were denied — exactly the set that most needs protecting.
    /// </summary>
    Unresolvable,
}

/// <summary>The outcome of a protection check, with the sentence to show the user.</summary>
internal sealed record ProtectionResult(ProtectionTier Tier, string Reason)
{
    internal static readonly ProtectionResult Clear = new(ProtectionTier.None, "");

    /// <summary>True when HERO must not act on its own initiative.</summary>
    internal bool BlocksAutonomy => Tier != ProtectionTier.None;

    /// <summary>True when the action is refused even if the user explicitly asks for it.</summary>
    internal bool BlocksEverything => Tier is ProtectionTier.Critical
                                          or ProtectionTier.Essential
                                          or ProtectionTier.Self
                                          or ProtectionTier.Unresolvable;
}

/// <summary>
/// The explicit, exhaustive set of things HERO must never kill, suspend, quarantine or firewall.
///
/// This list — not any Windows API — is the primary safety mechanism, for two measured reasons.
///
/// First, the OS does not protect critical processes from an administrator. An elevated
/// TerminateProcess on csrss.exe succeeds and immediately bugchecks with CRITICAL_PROCESS_DIED
/// (0xEF). Nothing but this list stands between a scoring bug and a blue screen.
///
/// Second, the obvious API is not sufficient. IsProcessCritical returns FALSE for explorer,
/// audiodg, sihost, ctfmon and RuntimeBroker, so an implementation that trusted it would happily
/// authorise killing the user's entire shell and audio stack. It is used here as a veto, never as
/// an authorisation.
///
/// Two structural decisions follow from PLATFORM-FACTS §6 (226 of 358 image paths readable
/// unelevated; the other 132 denied with ERROR_ACCESS_DENIED):
///
///   * An unreadable image path terminates evaluation at <see cref="ProtectionTier.Unresolvable"/>
///     BEFORE any name-or-path rule runs. The spec's masquerade branch ("name in list but path
///     elsewhere — score it up") can only be reached once a full path was actually resolved.
///     Without that precedence, every Tier 0 process — none of whose paths are readable
///     unelevated — would fall into the masquerade branch and be promoted rather than protected.
///
///   * Protection under %WINDIR% is granted by PATH, not by signature. The catalog trap
///     (PLATFORM-FACTS §4) means a naive signature check reports svchost, lsass, explorer and
///     conhost as unsigned; if protection depended on a valid Microsoft signature, a defect in
///     the signature engine would silently unprotect the entire operating system. A signature
///     result, when available, only enriches the explanation. Anything a medium-integrity process
///     cannot write to is not somewhere a dropper can plant a masquerade.
/// </summary>
internal sealed class ProtectedSet
{
    /// <summary>Shared instance. Cheap to construct; ancestry is refreshed on demand.</summary>
    internal static ProtectedSet Shared { get; } = new();

    // ------------------------------------------------------------------ name lists

    /// <summary>
    /// Processes with no Win32 image path at ANY privilege level. They can never satisfy a
    /// path rule, so they are matched by name alone and bypass path resolution entirely.
    /// </summary>
    private static readonly HashSet<string> MinimalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Secure System", "Memory Compression", "MemCompression",
    };

    /// <summary>
    /// Tier 0 — kernel, session and boot critical. Terminating any of these produces an immediate
    /// bugcheck or an unrecoverable session.
    ///
    /// svchost.exe is here as a whole image and must stay that way: it hosts hundreds of unrelated
    /// services, so acting on it by image is never correct. The only legitimate response to a
    /// malicious svchost-hosted service is to act on that specific service, which requires
    /// elevation — see <see cref="ClassifyService"/>.
    ///
    /// msiexec.exe and TiWorker.exe are not bugcheck risks but are here anyway: killing or
    /// freezing an installer or Windows servicing mid-transaction leaves the machine in a state
    /// no undo record can repair.
    /// </summary>
    private static readonly HashSet<string> Tier0 = new(StringComparer.OrdinalIgnoreCase)
    {
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
        "LsaIso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "userinit.exe", "logonui.exe",
        "consent.exe", "TrustedInstaller.exe", "TiWorker.exe", "msiexec.exe", "wlanext.exe",
        "dasHost.exe", "WUDFHost.exe", "vmcompute.exe", "vmwp.exe", "vmms.exe", "NgcIso.exe",
        "SgrmBroker.exe", "WerFault.exe", "wermgr.exe", "CompatTelRunner.exe", "sppsvc.exe",
    };

    /// <summary>
    /// Tier 1 — security, shell and UX critical. Killing these does not bugcheck; it destroys the
    /// user's session, breaks text input, silences audio, or disables the machine's real antivirus.
    ///
    /// MsMpEng.exe deserves its own note. Defender opens handles to every process, reads their
    /// memory and hammers the disk — the exact composite signature naive behavioural heuristics
    /// call a RAT. It is excluded from action here and should be excluded from behavioural scoring
    /// upstream too, because "HERO killed your antivirus" is an attacker's dream outcome.
    ///
    /// conhost.exe and OpenConsole.exe are console hosts. This machine runs roughly thirty of
    /// them; killing one detaches a live terminal and loses whatever the user had not saved.
    ///
    /// dllhost/rundll32/regsvr32/mshta are LOLBin *hosts*. When one is genuinely malicious the
    /// payload is the command line and the loaded module, never the host binary — which is why
    /// they are protected from quarantine here rather than treated as suspects.
    /// </summary>
    private static readonly HashSet<string> Tier1 = new(StringComparer.OrdinalIgnoreCase)
    {
        "MsMpEng.exe", "MpDefenderCoreService.exe", "NisSrv.exe", "MpCmdRun.exe",
        "SecurityHealthService.exe", "SecurityHealthSystray.exe", "smartscreen.exe",
        "WmiPrvSE.exe", "WMIRegistrationService.exe", "spoolsv.exe", "audiodg.exe",
        "explorer.exe", "sihost.exe", "ctfmon.exe", "TextInputHost.exe", "RuntimeBroker.exe",
        "dllhost.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
        "SearchHost.exe", "SearchIndexer.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe",
        "StartMenuExperienceHost.exe", "ShellExperienceHost.exe", "ApplicationFrameHost.exe",
        "taskhostw.exe", "backgroundTaskHost.exe", "conhost.exe", "OpenConsole.exe",
        "LockApp.exe", "SystemSettings.exe", "dwm.exe",
    };

    /// <summary>
    /// Suspending any of these corrupts state that <see cref="ProtectedSet"/>'s resume cannot
    /// repair, so they are excluded from the suspend rung specifically.
    ///
    /// The virtualisation entries matter on this machine in particular: freezing a Hyper-V worker
    /// or the WSL VM desynchronises the guest's clock and can corrupt its disk image, and the
    /// user runs a rooted BlueStacks (HD-Player/BstkSVC) which is an Android VM with the same
    /// property. A fifteen-minute auto-resume does not undo a corrupted guest volume.
    /// </summary>
    private static readonly HashSet<string> NeverSuspendNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "msiexec.exe", "TiWorker.exe", "TrustedInstaller.exe", "vmwp.exe", "vmcompute.exe",
        "vmms.exe", "vmmem", "vmmemWSL", "wslservice.exe", "wsl.exe", "wslhost.exe",
        "com.docker.backend.exe", "com.docker.service", "dockerd.exe", "Docker Desktop.exe",
        "HD-Player.exe", "BstkSVC.exe", "VBoxSVC.exe", "vmware-vmx.exe",
        "VSSVC.exe", "swprv.exe", "wbengine.exe",
    };

    /// <summary>
    /// Software observed running on THIS machine that legitimately exhibits the behaviour every
    /// RAT heuristic looks for. Detection still fires and the user still sees it; autonomy does not.
    ///
    /// BlueStacks is rooted with ReZygisk/LSPosed, so its syscall and injection patterns are
    /// abnormal by design. TeamViewer and Cloudflare WARP are remote-access and tunnelling
    /// software — that is their entire purpose, not a compromise.
    /// </summary>
    private static readonly HashSet<string> KnownOddNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "HD-Player.exe", "BstkSVC.exe", "BlueStacksServices.exe", "HD-Agent.exe",
        "TeamViewer_Service.exe", "TeamViewer.exe", "warp-svc.exe", "warp-taskbar.exe",
        "steamservice.exe", "steam.exe", "steamwebhelper.exe",
        "GigabyteUpdateService.exe", "OverwolfUpdater.exe", "Overwolf.exe",
        "jhi_service.exe", "GooglePlayGamesServices.exe", "wslservice.exe",
        "Docker Desktop.exe", "com.docker.backend.exe", "dockerd.exe",
    };

    /// <summary>
    /// The surfaces the user is actually working in. Killing any of these loses unsaved work with
    /// no possible undo, which is a worse outcome than almost any malware HERO can catch.
    ///
    /// Shells and terminals are on this list even though they are also the classic LOLBins. That
    /// is the correct trade: a malicious PowerShell is contained by suspending it and blocking its
    /// network, not by yanking the window the user was typing into.
    /// </summary>
    private static readonly HashSet<string> UserSurfaceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "WindowsTerminal.exe", "wt.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
        "bash.exe", "sh.exe", "mintty.exe", "git-bash.exe", "wsl.exe",
        "devenv.exe", "Code.exe", "Code - Insiders.exe", "cursor.exe", "windsurf.exe",
        "rider64.exe", "idea64.exe", "pycharm64.exe", "clion64.exe", "webstorm64.exe",
        "sublime_text.exe", "notepad++.exe", "notepad.exe",
        "UnrealEditor.exe", "UE4Editor.exe", "blender.exe", "Unity.exe", "UnityHub.exe",
        "claude.exe", "node.exe",
    };

    /// <summary>
    /// Services that must never be stopped, disabled, deleted or reconfigured by HERO.
    ///
    /// BFE and MpsSvc are called out because stopping them is a known attacker move that disables
    /// the firewall wholesale. Any HERO action that would reduce the machine's security posture is
    /// refused by design, no matter how confident the verdict.
    /// </summary>
    private static readonly HashSet<string> ProtectedServiceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "WinDefend", "MpsSvc", "wscsvc", "SecurityHealthService", "Sense", "WdNisSvc", "WdFilter",
        "wuauserv", "TrustedInstaller", "BFE", "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM",
        "Power", "Schedule", "EventLog", "CryptSvc", "ProfSvc", "Themes", "AudioSrv", "Audiosrv",
        "AudioEndpointBuilder", "WSearch", "VSS", "swprv", "gpsvc", "SamSs", "Netlogon",
        "Dhcp", "Dnscache", "nsi", "WinHttpAutoProxySvc", "PlugPlay", "UserManager", "SENS",
        "SystemEventsBroker", "StateRepository", "TokenBroker", "AppInfo", "BrokerInfrastructure",
        "CoreMessagingRegistrar", "DPS", "EventSystem", "KeyIso", "NlaSvc", "SgrmBroker",
    };

    // ------------------------------------------------------------------ path roots

    private static readonly string WindowsDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32Dir =
        Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static readonly string SysWow64Dir =
        Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

    /// <summary>
    /// Where Store-delivered components live. Some Windows components ship from here rather than
    /// from %WINDIR% — Windows Terminal, and with it the OpenConsole.exe on the Tier 1 list, is
    /// installed to Program Files\WindowsApps on this machine (verified: package
    /// Microsoft.WindowsTerminal_..._x64__8wekyb3d8bbwe). A medium-integrity process cannot write
    /// there, so a protected name found under this root is the genuine component.
    /// </summary>
    private static readonly string WindowsAppsDir = BuildWindowsAppsDir();

    private static string BuildWindowsAppsDir()
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return string.IsNullOrEmpty(programFiles) ? "" : Path.Combine(programFiles, "WindowsApps");
    }

    /// <summary>
    /// Trees that must never be quarantined (a quarantine is a move, and a move out of these is
    /// silently catastrophic) and never bound to a firewall ApplicationName rule (which is
    /// path-based and therefore blocks that image for the whole system).
    /// </summary>
    private static readonly string[] DeniedTrees = BuildDeniedTrees();

    /// <summary>
    /// Carved back out of the %WINDIR% denial: malware genuinely does drop into these two, and
    /// neither is required for boot or servicing. They remain prompt-only, never autonomous.
    /// </summary>
    private static readonly string[] WindowsCarveOuts =
    {
        Path.Combine(WindowsDir, "Temp"),
        Path.Combine(WindowsDir, "Tasks"),
    };

    private static readonly string[] DeniedFileNames =
    {
        "pagefile.sys", "hiberfil.sys", "swapfile.sys", "$MFT", "bootmgr", "BOOTNXT", "ntldr",
    };

    private static string[] BuildDeniedTrees()
    {
        var list = new List<string> { WindowsDir };

        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        if (!string.IsNullOrEmpty(WindowsAppsDir)) list.Add(WindowsAppsDir);
        if (!string.IsNullOrEmpty(programData))
        {
            list.Add(Path.Combine(programData, "Microsoft", "Windows Defender"));
            list.Add(Path.Combine(programData, "Microsoft", "Windows Defender Advanced Threat Protection"));
        }

        // System volume roots. Enumerated per drive so the check survives a machine with more
        // than one fixed disk — this one has four.
        foreach (var root in EnumerateFixedRoots())
        {
            list.Add(Path.Combine(root, "$Recycle.Bin"));
            list.Add(Path.Combine(root, "System Volume Information"));
            list.Add(Path.Combine(root, "EFI"));
            list.Add(Path.Combine(root, "Recovery"));
        }

        // HERO's own state. A guardian that eats its own ledger cannot explain what it did.
        list.Add(HeroPaths.Root);
        try
        {
            var ownDir = Path.GetDirectoryName(Environment.ProcessPath);
            if (!string.IsNullOrEmpty(ownDir)) list.Add(ownDir);
        }
        catch { /* ProcessPath is null only for hosted scenarios HERO does not ship in */ }

        return list.Where(s => !string.IsNullOrEmpty(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static IEnumerable<string> EnumerateFixedRoots()
    {
        // Assigned in a catch rather than short-circuited with `yield break`, which C# forbids
        // inside a catch clause.
        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); }
        catch { drives = Array.Empty<DriveInfo>(); }

        foreach (var d in drives)
        {
            // GetDriveType matters here: this machine has a G: optical drive, and probing it
            // spins it up and can block for seconds.
            bool ok;
            try { ok = d.DriveType == DriveType.Fixed && d.IsReady; }
            catch { ok = false; }
            if (ok) yield return d.RootDirectory.FullName;
        }
    }

    // ------------------------------------------------------------- developer roots

    private readonly List<string> _developerRoots = new();
    private readonly object _sync = new();

    /// <summary>
    /// Directories whose contents are permanently ineligible for autonomous action.
    ///
    /// This is the single largest false-positive source on this machine. A freshly built, unsigned,
    /// high-entropy .exe that spawns children and opens sockets is textbook malware behaviour and
    /// textbook game-development behaviour at the same time, and no amount of scoring separates
    /// them. Precision beats recall here: detection still fires and the user is still told, the
    /// response ladder simply caps at observe-and-notify.
    ///
    /// Deliberately NOT auto-detected by marker files. Walking for .git / package.json /
    /// node_modules would promote %LOCALAPPDATA%\Programs and %APPDATA% — every Electron app ships
    /// those — which is the single most common infostealer drop location on a Windows machine.
    /// The seeds below are explicit, and the user edits the list in the dashboard.
    /// </summary>
    internal IReadOnlyList<string> DeveloperRoots
    {
        get { lock (_sync) return _developerRoots.ToArray(); }
    }

    internal ProtectedSet()
    {
        string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var seeds = new List<string>
        {
            @"D:\My projects",
            Path.Combine(user, ".nuget"),
            Path.Combine(user, ".cargo"),
            Path.Combine(user, ".rustup"),
            Path.Combine(user, "go"),
            Path.Combine(roaming, "npm"),
            Path.Combine(local, "Programs", "Microsoft VS Code"),

            // The nine unsigned-but-benign binaries measured running on this machine
            // (PLATFORM-FACTS §5) live under these three. They are simultaneously a normal
            // developer software class and a plausible drop location, so they suppress autonomy
            // only — HERO still reports anything it finds here.
            Path.Combine(local, "uv"),
            Path.Combine(local, "Microsoft", "WinGet", "Packages"),
            Path.Combine(roaming, "Claude", "Claude Extensions"),
        };

        lock (_sync)
        {
            foreach (var s in seeds)
                if (!string.IsNullOrWhiteSpace(s)) _developerRoots.Add(s.TrimEnd('\\', '/'));
        }

        OwnPid = Environment.ProcessId;
        OwnStartUtc = ReadOwnStart();
        RefreshLineage(null);
    }

    internal void AddDeveloperRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return;
        string trimmed = root.TrimEnd('\\', '/');
        lock (_sync)
        {
            if (!_developerRoots.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
                _developerRoots.Add(trimmed);
        }
    }

    internal bool RemoveDeveloperRoot(string root)
    {
        lock (_sync)
            return _developerRoots.RemoveAll(r => string.Equals(r, root?.TrimEnd('\\', '/'),
                                                                StringComparison.OrdinalIgnoreCase)) > 0;
    }

    // ------------------------------------------------------------------- lineage

    internal int OwnPid { get; }
    internal DateTime OwnStartUtc { get; }

    /// <summary>
    /// HERO's ancestors and descendants, each paired with a creation time so a recycled PID cannot
    /// impersonate one. Measured ancestry on this machine reaches session-critical processes within
    /// a few hops (pwsh -> claude -> claude -> sihost -> svchost -> services -> wininit), so
    /// protecting only the immediate parent would be useless.
    /// </summary>
    private volatile HashSet<(int Pid, long StartTicks)> _lineage = new();

    /// <summary>
    /// Recomputes HERO's ancestor chain and its own descendants. Called at construction and again
    /// per incident, because intermediate parents die and a stale chain protects the wrong PIDs.
    /// </summary>
    internal void RefreshLineage(Snapshot? snapshot)
    {
        try
        {
            Snapshot snap = snapshot ?? new Snapshot
            {
                TakenUtc = DateTime.UtcNow,
                Processes = ProcessProbe.Snapshot(false),
                Connections = Array.Empty<Connection>(),
                IdleSeconds = 0,
                ForegroundPid = 0,
            };

            var set = new HashSet<(int, long)> { (OwnPid, OwnStartUtc.Ticks) };

            if (snap.ByPid.TryGetValue(OwnPid, out var me))
            {
                foreach (var ancestor in snap.Ancestry(me, maxDepth: 16))
                    set.Add((ancestor.Pid, ancestor.StartTimeUtc.Ticks));
            }

            // Descendants: HERO's own helpers (a broker, a dump writer). Bounded walk — a
            // fixed-point pass over the table is cheap at ~358 rows and avoids recursion.
            var frontier = new HashSet<int> { OwnPid };
            for (int depth = 0; depth < 4; depth++)
            {
                var next = new HashSet<int>();
                foreach (var p in snap.Processes)
                {
                    if (!frontier.Contains(p.ParentPid) || frontier.Contains(p.Pid)) continue;
                    // A "child" that started before its parent is a recycled PID, not a child.
                    if (snap.ByPid.TryGetValue(p.ParentPid, out var parent) &&
                        parent.StartTimeUtc != default && p.StartTimeUtc != default &&
                        p.StartTimeUtc < parent.StartTimeUtc) continue;
                    next.Add(p.Pid);
                    set.Add((p.Pid, p.StartTimeUtc.Ticks));
                }
                if (next.Count == 0) break;
                frontier = next;
            }

            _lineage = set;
        }
        catch
        {
            // Never leave the lineage empty: at minimum HERO protects itself.
            _lineage = new HashSet<(int, long)> { (OwnPid, OwnStartUtc.Ticks) };
        }
    }

    private static DateTime ReadOwnStart()
    {
        try { return Process.GetCurrentProcess().StartTime.ToUniversalTime(); }
        catch { return default; }
    }

    // -------------------------------------------------------------- foreground

    private int _foregroundPid;
    private long _foregroundStamp;

    /// <summary>
    /// The foreground PID, cached for half a second. Classification runs once per row when the
    /// dashboard renders a process list, and a user32 round-trip per row is waste.
    /// </summary>
    private int ForegroundPid()
    {
        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _foregroundStamp) < 500) return Volatile.Read(ref _foregroundPid);
        int pid = 0;
        try { pid = ProcessProbe.ForegroundPid(); } catch { }
        Volatile.Write(ref _foregroundPid, pid);
        Interlocked.Exchange(ref _foregroundStamp, now);
        return pid;
    }

    // ------------------------------------------------------------ process checks

    /// <summary>
    /// True when HERO must not act on this process of its own accord.
    ///
    /// Use <see cref="Classify"/> when the distinction matters between "never, even if the user
    /// asks" (<see cref="ProtectionResult.BlocksEverything"/>) and "not without the user".
    /// </summary>
    internal bool IsProtected(ProcessRecord process, out string reason)
    {
        var result = Classify(process);
        reason = result.Reason;
        return result.BlocksAutonomy;
    }

    /// <summary>
    /// Cheap, allocation-light classification from an already-captured record. Safe to call per
    /// row in a UI list. It does NOT open a handle — see <see cref="ProbeLive"/> for the check
    /// that must run immediately before any destructive action.
    /// </summary>
    internal ProtectionResult Classify(ProcessRecord p)
    {
        // 1. The minimal process set. No image path exists for these at any privilege level, so
        //    they are matched by name and PID before any path logic can reject them.
        if (p.Pid <= 4)
            return new(ProtectionTier.Critical, $"PID {p.Pid} is the kernel's own process (Idle/System).");
        if (MinimalProcesses.Contains(p.Name))
            return new(ProtectionTier.Critical, $"{p.Name} is a kernel-managed pseudo-process with no image on disk.");

        // 2. HERO's own lineage. Killing an ancestor kills HERO mid-action, stranding a
        //    half-applied change with no undo. A compromised ancestor is a real scenario, and the
        //    correct response to it is to alert loudly, never to self-destruct up the chain.
        var lineage = _lineage;
        if (lineage.Contains((p.Pid, p.StartTimeUtc.Ticks)))
            return new(ProtectionTier.Self,
                p.Pid == OwnPid
                    ? "This is HERO itself."
                    : $"{p.FileName} is in HERO's own process lineage (ancestor or helper).");

        // 3. SYSTEM integrity. Nothing at this level is HERO's to touch unelevated, and elevating
        //    to reach it is exactly the escalation this design refuses to build.
        if (p.Integrity == IntegrityLevel.System)
            return new(ProtectionTier.Critical, $"{p.FileName} runs at SYSTEM integrity.");

        // 4. Session 0 is the service session. Nothing the user interacts with lives there.
        int session = SessionOf(p.Pid);
        if (session == 0)
            return new(ProtectionTier.Critical, $"{p.FileName} runs in session 0 (services).");

        // 5. Fail closed on identity. This MUST precede every name and path rule: unelevated,
        //    132 of 358 processes deny the handle that yields their path, and all of them are the
        //    higher-integrity set. Reaching the masquerade branch here would promote the entire
        //    Windows kernel-adjacent process table.
        if (p.PathUnavailable)
            return new(ProtectionTier.Unresolvable,
                $"HERO cannot read the image path for {p.Name} (PID {p.Pid}); without it there is no safe way to tell a system process from an impostor.");
        if (p.StartTimeUtc == default)
            return new(ProtectionTier.Unresolvable,
                $"HERO cannot read the start time for {p.Name} (PID {p.Pid}), so it cannot rule out PID reuse.");

        string canonical = Canonicalise(p.ImagePath);
        if (string.IsNullOrEmpty(canonical))
            return new(ProtectionTier.Unresolvable, $"The image path for {p.Name} could not be resolved.");

        bool inSystemDirs = Under(canonical, System32Dir) || Under(canonical, SysWow64Dir)
                         || Under(canonical, Path.Combine(WindowsDir, "WinSxS"));
        bool inWindows = Under(canonical, WindowsDir);

        // Not every Windows component lives under %WINDIR%. Windows Terminal ships from
        // Program Files\WindowsApps, so the OpenConsole.exe on the Tier 1 list would otherwise be
        // reported as a masquerade the moment the user opens a terminal — a false positive that
        // fires on this machine every day. WindowsApps is not writable by a medium-integrity
        // process, so it belongs on the "where that name belongs" side of the test.
        bool inStoreApps = WindowsAppsDir.Length > 0 && Under(canonical, WindowsAppsDir);
        bool whereItBelongs = inSystemDirs || inWindows || inStoreApps;

        // 6. Name lists, gated on the path being where that name belongs. A dropper called
        //    csrss.exe in %TEMP% must not inherit csrss's protection — but nor should it be
        //    actioned autonomously, because a benign vendor binary that happens to share a name
        //    would then be killed on a name collision alone.
        if (Tier0.Contains(p.FileName))
        {
            if (whereItBelongs)
                return new(ProtectionTier.Critical,
                    $"{p.FileName} is boot- or session-critical; terminating it bugchecks Windows (CRITICAL_PROCESS_DIED).");
            return new(ProtectionTier.NameMasquerade,
                $"{p.FileName} carries a system process name but runs from {canonical}, which is not where that binary belongs. That is worth investigating, but HERO will not act on a name collision alone.");
        }

        if (Tier1.Contains(p.FileName))
        {
            if (whereItBelongs)
                return new(ProtectionTier.Essential,
                    $"{p.FileName} is part of the security stack, the shell or the input/audio path; stopping it breaks the session rather than the threat.");
            return new(ProtectionTier.NameMasquerade,
                $"{p.FileName} carries a Windows component name but runs from {canonical}. Investigate, but a name match alone is not grounds for action.");
        }

        // 7. Anything else under %WINDIR%. Protection here is by path, not signature, precisely so
        //    a defect in signature verification cannot unprotect the operating system. The two
        //    carve-outs are the directories malware actually uses and boot does not.
        if (inWindows)
        {
            if (WindowsCarveOuts.Any(c => Under(canonical, c)))
                return new(ProtectionTier.NameMasquerade,
                    $"{p.FileName} runs from {canonical}. Windows\\Temp and Windows\\Tasks are not needed for boot or servicing, so this can be actioned — but only with your confirmation.");
            return new(ProtectionTier.Essential,
                $"{p.FileName} lives inside {WindowsDir}. HERO never acts autonomously on the Windows directory.");
        }

        if (HeroPaths.IsOwnState(canonical))
            return new(ProtectionTier.Self, "This file belongs to HERO's own state.");

        // 8. Suspending these corrupts a guest, an install or a backup.
        if (NeverSuspendNames.Contains(p.FileName))
            return new(ProtectionTier.NeverSuspend,
                $"{p.FileName} owns virtual-machine, installer or backup state that a suspend-and-resume cannot be trusted to restore.");

        if (KnownOddNames.Contains(p.FileName))
            return new(ProtectionTier.KnownOddSoftware,
                $"{p.FileName} is software on this machine that legitimately behaves the way malware does (remote access, tunnelling, or a rooted Android VM). HERO reports it but will not act on its own.");

        // 9. The user's working surface.
        if (p.Pid == ForegroundPid())
            return new(ProtectionTier.UserSurface,
                $"{p.FileName} owns the window you are using right now.");
        if (UserSurfaceNames.Contains(p.FileName))
            return new(ProtectionTier.UserSurface,
                $"{p.FileName} is a shell, terminal or editor. Killing one loses unsaved work, which no undo record can return.");

        // 10. Developer roots and toolchain caches.
        if (MatchDeveloperRoot(canonical) is { } devRoot)
            return new(ProtectionTier.DeveloperRoot,
                $"{p.FileName} runs from {devRoot}, a development root. Freshly built unsigned binaries are indistinguishable from malware by behaviour, so HERO reports but never acts by itself here.");

        return ProtectionResult.Clear;
    }

    /// <summary>
    /// The mandatory pre-action check, run immediately before anything destructive.
    ///
    /// <see cref="Classify"/> reasons from a record that may be seconds old; this opens a live
    /// handle and asks the kernel. All five layers must pass. Any failure is a veto — note in
    /// particular that "the query succeeded and said unprotected" is never an authorisation:
    /// audiodg reports protection byte 0x00 and killing it still silences all audio.
    ///
    /// The live layers run even when <see cref="Classify"/> has already returned a soft tier, and
    /// the reason is the PID-reuse check in layer 2. Callers let a user-initiated action through a
    /// soft tier (UserSurface, DeveloperRoot, KnownOddSoftware, NameMasquerade, NeverSuspend), so
    /// short-circuiting on any BlocksAutonomy result skipped the reuse check for exactly the rows a
    /// user is most likely to click — their editor, their terminal, a build output. A row that has
    /// been on screen for a few seconds is precisely where a recycled PID bites.
    /// </summary>
    internal ProtectionResult ProbeLive(ProcessRecord p)
    {
        var stat = Classify(p);
        // Nothing the kernel could add changes a hard refusal, and opening a handle to a Tier 0
        // process is pointless work.
        if (stat.BlocksEverything) return stat;

        // Layer 1 — the handle itself. Unelevated, OpenProcess with PROCESS_QUERY_LIMITED_
        // INFORMATION is denied with ERROR_ACCESS_DENIED for every PPL and SYSTEM process, and
        // there is no handle-free fallback. So handle-open failure IS the protection signal.
        IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, p.Pid);
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == ERROR_INVALID_PARAMETER)
                return new(ProtectionTier.Unresolvable, $"PID {p.Pid} no longer exists.");
            return new(ProtectionTier.Critical,
                $"Windows refused HERO a handle to {p.FileName} (error {err}). That refusal only happens for protected or higher-privileged processes, so HERO treats it as protection and stops.");
        }

        try
        {
            // Layer 2 — PID reuse. The record's identity must still hold.
            if (Native.GetProcessTimes(h, out long creation, out long exit, out _, out _))
            {
                if (exit != 0)
                    return new(ProtectionTier.Unresolvable, $"{p.FileName} (PID {p.Pid}) has already exited.");
                DateTime live;
                try { live = DateTime.FromFileTimeUtc(creation); } catch { live = default; }
                if (live != default && p.StartTimeUtc != default &&
                    Math.Abs((live - p.StartTimeUtc).TotalMilliseconds) > 50)
                    return new(ProtectionTier.Unresolvable,
                        $"PID {p.Pid} has been recycled since HERO looked at it — it is now a different process. Refusing to act.");
            }

            // Layer 3 — PS_PROTECTION. Type in bits 0-2: 0 None, 1 ProtectedLight, 2 Protected.
            // Any non-zero type means the kernel will refuse termination from usermode anyway,
            // even as SYSTEM with SeDebugPrivilege, so retrying elevated would be futile.
            byte protection = 0;
            if (NtQueryInformationProcessByte(h, ProcessProtectionInformation, out protection, 1, out _) == 0
                && (protection & 0x07) != 0)
            {
                return new(ProtectionTier.Critical,
                    $"{p.FileName} is a protected process (PPL/PP). The kernel refuses termination from usermode; this is not something elevation can fix.");
            }

            // Layer 4 — the critical flag. Necessary, nowhere near sufficient: measured FALSE for
            // explorer, audiodg, sihost, ctfmon and RuntimeBroker on this machine.
            if (IsProcessCritical(h, out bool critical) && critical)
                return new(ProtectionTier.Critical,
                    $"{p.FileName} is marked process-critical; terminating it bugchecks Windows.");
        }
        catch (Exception ex)
        {
            return new(ProtectionTier.Unresolvable,
                $"The safety check for {p.FileName} failed ({ex.GetType().Name}). HERO does not act when it cannot verify.");
        }
        finally
        {
            Native.CloseHandle(h);
        }

        // The kernel raised no objection, so the classification stands — Clear when it was clear,
        // and the soft tier when there was one, which is what still keeps autonomy out.
        return stat;
    }

    /// <summary>
    /// True when suspending this process specifically is forbidden. Suspension is otherwise the
    /// safest rung on the ladder, so this list is short and each entry earns its place.
    /// </summary>
    internal bool IsSuspendForbidden(ProcessRecord p, out string reason)
    {
        if (NeverSuspendNames.Contains(p.FileName))
        {
            reason = $"{p.FileName} owns virtual-machine, installer or backup state. Freezing it mid-transaction can corrupt a guest disk or leave an install unrepairable, and a timed auto-resume does not undo either.";
            return true;
        }
        var c = Classify(p);
        if (c.BlocksEverything) { reason = c.Reason; return true; }
        reason = "";
        return false;
    }

    // -------------------------------------------------------------- path checks

    /// <summary>True when this file must never be quarantined, renamed or moved.</summary>
    internal bool IsPathProtected(string path, out string reason)
    {
        var r = ClassifyPath(path);
        reason = r.Reason;
        return r.BlocksAutonomy;
    }

    internal ProtectionResult ClassifyPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return new(ProtectionTier.Unresolvable, "No path was supplied.");

        string canonical = Canonicalise(path);
        if (string.IsNullOrEmpty(canonical))
            return new(ProtectionTier.Unresolvable, $"{path} could not be resolved to a real location.");

        string leaf = Path.GetFileName(canonical);
        if (DeniedFileNames.Contains(leaf, StringComparer.OrdinalIgnoreCase))
            return new(ProtectionTier.Critical, $"{leaf} is a system file the machine cannot boot or run without.");

        // The WIDE check, because this overload gates what may be done TO A FILE — deleting it,
        // quarantining it — and HERO must not do either to its own legacy state or its own logs.
        // The process overload above uses the narrow one on purpose: refusing to act on a PROCESS
        // because of where its image sits is what turned a user-writable folder into a hiding
        // place. Acting on a file and accusing a process are different questions.
        if (HeroPaths.IsOwnStateOrDiagnostics(canonical))
            return new(ProtectionTier.Self, "This file belongs to HERO's own state.");

        foreach (var tree in DeniedTrees)
        {
            if (!Under(canonical, tree)) continue;

            // %WINDIR%\Temp and %WINDIR%\Tasks are inside the denied tree but are neither boot
            // nor servicing surfaces, and malware genuinely drops there. Prompt, do not refuse.
            if (WindowsCarveOuts.Any(c => Under(canonical, c)))
                return new(ProtectionTier.NameMasquerade,
                    $"{canonical} is under Windows\\Temp or Windows\\Tasks. Neither is needed for boot or servicing, so it can be quarantined — with your confirmation.");

            return new(ProtectionTier.Critical,
                $"{canonical} is inside {tree}. Moving anything out of that tree breaks boot, servicing or the security stack, so HERO refuses regardless of score.");
        }

        if (MatchDeveloperRoot(canonical) is { } devRoot)
            return new(ProtectionTier.DeveloperRoot,
                $"{canonical} is inside {devRoot}, a development root. HERO reports findings here but never quarantines by itself.");

        return ProtectionResult.Clear;
    }

    /// <summary>
    /// True when a firewall rule must not be bound to this image path.
    ///
    /// Windows Firewall ApplicationName rules are PATH-based, not PID-based, so a block on
    /// powershell.exe, rundll32.exe or svchost.exe blocks that image for the entire system and
    /// breaks Windows Update, the Store and the user's own tooling — weeks later, with no visible
    /// cause. Developer roots are included because a build output path is stable across rebuilds:
    /// blocking bin\Debug\Game.exe once blocks every future build of that project.
    /// </summary>
    internal bool IsFirewallTargetForbidden(string imagePath, out string reason)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            reason = "No image path was supplied for the firewall rule.";
            return true;
        }

        string canonical = Canonicalise(imagePath);
        if (string.IsNullOrEmpty(canonical))
        {
            reason = $"{imagePath} could not be resolved, and an unresolved path in a firewall rule blocks the wrong thing.";
            return true;
        }

        if (Under(canonical, WindowsDir))
        {
            reason = $"{canonical} is under {WindowsDir}. A path-based firewall rule there would block that Windows component for the whole machine. Contain by remote endpoint or by suspending the process instead.";
            return true;
        }

        if (MatchDeveloperRoot(canonical) is { } devRoot)
        {
            reason = $"{canonical} is inside {devRoot}. Build outputs reuse the same path every rebuild, so this rule would silently block future builds of the same project.";
            return true;
        }

        if (HeroPaths.IsOwnState(canonical))
        {
            reason = "HERO will not firewall its own binaries.";
            return true;
        }

        reason = "";
        return false;
    }

    // ------------------------------------------------------- persistence checks

    /// <summary>True when HERO must not remove or alter this persistence entry.</summary>
    internal bool IsProtected(PersistenceEntry entry, out string reason)
    {
        var r = Classify(entry);
        reason = r.Reason;
        return r.BlocksAutonomy;
    }

    internal ProtectionResult Classify(PersistenceEntry entry)
    {
        if (entry.AccessDenied)
            return new(ProtectionTier.Unresolvable,
                $"HERO could not read {entry.Location} without administrator rights, so it cannot say what is there — let alone change it.");

        switch (entry.Category)
        {
            case PersistenceCategory.Winlogon:
                // Deleting Userinit prevents logon outright, and an empty Shell leaves the user
                // with a black screen. These two are repair-only: HERO restores the known-good
                // value, it never removes the entry.
                if (entry.Name.Equals("Userinit", StringComparison.OrdinalIgnoreCase) ||
                    entry.Name.Equals("Shell", StringComparison.OrdinalIgnoreCase))
                    return new(ProtectionTier.Critical,
                        $"Winlogon\\{entry.Name} must always hold a value — deleting it prevents logon. HERO can only repair it back to the Windows default, never remove it.");
                break;

            case PersistenceCategory.ScheduledTask:
                // The \Microsoft\Windows\ folder is Windows' own maintenance schedule.
                if (entry.Name.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase))
                    return new(ProtectionTier.Critical,
                        $"{entry.Name} is one of Windows' own maintenance tasks. HERO never touches the \\Microsoft\\Windows\\ folder.");
                break;

            case PersistenceCategory.Service:
                return ClassifyService(entry.Name, entry.ImagePath);

            case PersistenceCategory.AppInitDll:
                return new(ProtectionTier.Essential,
                    "AppInit_DLLs is loaded into every user-mode process. Changing it unelevated is impossible and changing it wrongly destabilises every application at once, so this one is always escalated to you.");
        }

        if (!string.IsNullOrEmpty(entry.ImagePath))
        {
            var byPath = ClassifyPath(entry.ImagePath);
            if (byPath.BlocksAutonomy) return byPath;
        }
        else if (!string.IsNullOrWhiteSpace(entry.Target))
        {
            // A target that resolves to nothing is worth reporting, but HERO cannot verify what a
            // removal would break, so it will not remove it by itself.
            return new(ProtectionTier.NameMasquerade,
                $"HERO could not resolve an executable from \"{entry.Target}\", so it cannot verify what removing this entry would break.");
        }

        return ProtectionResult.Clear;
    }

    /// <summary>True when HERO must not stop, disable, delete or reconfigure this service.</summary>
    internal bool IsServiceProtected(string serviceName, string imagePath, out string reason)
    {
        var r = ClassifyService(serviceName, imagePath);
        reason = r.Reason;
        return r.BlocksAutonomy;
    }

    internal ProtectionResult ClassifyService(string serviceName, string imagePath)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
            return new(ProtectionTier.Unresolvable, "No service name was supplied.");

        if (ProtectedServiceNames.Contains(serviceName))
            return new(ProtectionTier.Critical,
                $"{serviceName} is a core Windows service. Several on that list — BFE and MpsSvc especially — are what a firewall bypass attacks first; HERO will never be the thing that stops them.");

        string canonical = string.IsNullOrWhiteSpace(imagePath) ? "" : Canonicalise(imagePath);
        if (string.IsNullOrEmpty(canonical))
            return new(ProtectionTier.Unresolvable,
                $"HERO could not resolve the binary behind service {serviceName}, so it cannot say what disabling it would break.");

        // A svchost-hosted service has svchost.exe as its ImagePath by construction, so an
        // ImagePath rule would protect every hosted service including a malicious one. HERO does
        // not pretend otherwise: this class is stated plainly as escalate-to-user, because the
        // real payload lives in the service's Parameters\ServiceDll and acting on it correctly
        // needs elevation and a far larger undo surface than this engine captures.
        if (Path.GetFileName(canonical).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
            return new(ProtectionTier.Essential,
                $"{serviceName} is hosted inside svchost.exe. Acting on the host would take out dozens of unrelated services, and acting on the hosted service safely needs administrator rights — so this one is always escalated to you with the evidence.");

        if (Under(canonical, System32Dir) || Under(canonical, SysWow64Dir))
            return new(ProtectionTier.Essential,
                $"{serviceName} runs from {canonical}, inside the Windows system directory. HERO does not reconfigure services that ship with the operating system.");

        if (Under(canonical, WindowsDir))
            return new(ProtectionTier.Essential,
                $"{serviceName} runs from inside {WindowsDir}.");

        if (KnownOddNames.Contains(Path.GetFileName(canonical)))
            return new(ProtectionTier.KnownOddSoftware,
                $"{serviceName} belongs to remote-access, tunnelling or virtualisation software installed on this machine. HERO reports it but does not act by itself.");

        if (MatchDeveloperRoot(canonical) is { } devRoot)
            return new(ProtectionTier.DeveloperRoot,
                $"{serviceName} runs from {devRoot}, a development root.");

        return ProtectionResult.Clear;
    }

    // ---------------------------------------------------------------- helpers

    private string? MatchDeveloperRoot(string canonical)
    {
        lock (_sync)
        {
            foreach (var root in _developerRoots)
                if (Under(canonical, root)) return root;
        }
        return null;
    }

    /// <summary>
    /// Directory containment. The trailing separator is load-bearing: without it
    /// "C:\Program Files\WindowsApps" matches the "C:\Windows" prefix and the whole Store tree
    /// inherits the wrong verdict.
    /// </summary>
    internal static bool Under(string path, string root)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(root)) return false;
        string r = root.TrimEnd('\\', '/');
        if (path.TrimEnd('\\', '/').Equals(r, StringComparison.OrdinalIgnoreCase)) return true;
        return path.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly ConcurrentDictionary<string, string> CanonicalCache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Resolves a path to its final DOS form, defeating 8.3 short names, junctions, symlinks and
    /// \\?\ prefixes. A raw string comparison against the denylist is bypassable by any of those,
    /// which would let a caller talk HERO into quarantining out of System32 via
    /// C:\PROGRA~1\..\Windows\System32.
    ///
    /// Falls back to <see cref="Path.GetFullPath(string)"/> when the file cannot be opened —
    /// deleted, locked, or denied. Callers treat an empty result as unresolvable and refuse.
    /// </summary>
    internal static string Canonicalise(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        if (CanonicalCache.TryGetValue(path, out var hit)) return hit;

        string result = "";
        IntPtr h = IntPtr.Zero;
        try
        {
            // Zero desired access asks only for metadata, which succeeds on files that deny read.
            // FILE_FLAG_BACKUP_SEMANTICS is required for the handle to be openable on directories.
            h = Native.CreateFile(path, 0,
                Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
                IntPtr.Zero, Native.OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);

            if (h != Native.INVALID_HANDLE_VALUE && h != IntPtr.Zero)
            {
                var sb = new StringBuilder(1024);
                uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, VOLUME_NAME_DOS);
                if (n > 0 && n < sb.Capacity) result = StripDevicePrefix(sb.ToString());
            }
        }
        catch { /* fall through to the managed path below */ }
        finally
        {
            if (h != IntPtr.Zero && h != Native.INVALID_HANDLE_VALUE) Native.CloseHandle(h);
        }

        if (string.IsNullOrEmpty(result))
        {
            try { result = Path.GetFullPath(path); } catch { result = ""; }
        }

        // Bounded so a long-running session cannot accumulate an unbounded map of transient paths.
        if (CanonicalCache.Count < 8192 && !string.IsNullOrEmpty(result))
            CanonicalCache[path] = result;

        return result;
    }

    private static string StripDevicePrefix(string s)
    {
        if (s.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + s[8..];
        if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) return s[4..];
        return s;
    }

    private static int SessionOf(int pid)
    {
        try { return ProcessIdToSessionId((uint)pid, out uint session) ? (int)session : -1; }
        catch { return -1; }
    }

    // -------------------------------------------------------------- P/Invoke
    // Declared privately rather than added to Hero.Interop.Native: this file owns these three
    // calls and nothing else needs them, so they cannot collide with the shared surface.

    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint VOLUME_NAME_DOS = 0x0;
    private const int ERROR_INVALID_PARAMETER = 87;

    /// <summary>ProcessProtectionInformation. Returns a single PS_PROTECTION byte.</summary>
    private const int ProcessProtectionInformation = 61;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(IntPtr hFile, StringBuilder lpszFilePath,
        uint cchFilePath, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessCritical(IntPtr hProcess,
        [MarshalAs(UnmanagedType.Bool)] out bool Critical);

    [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
    private static extern int NtQueryInformationProcessByte(IntPtr hProcess, int processInformationClass,
        out byte processInformation, int processInformationLength, out int returnLength);
}
