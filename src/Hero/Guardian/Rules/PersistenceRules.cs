using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Hero.Interop;

namespace Hero.Guardian.Rules;

/// <summary>Shared handling for persistence subjects.</summary>
internal static class PersistenceKit
{
    /// <summary>
    /// The entry this subject is about, or null when it is not persistence, is HERO's own, or is
    /// a placeholder recording that a location could not be read.
    ///
    /// An access-denied placeholder is deliberately never scored. It is the opposite of a
    /// finding: it means HERO does not know. <see cref="CoverageSignal"/> turns it into an honest
    /// statement instead.
    /// </summary>
    internal static PersistenceEntry? EntryOf(Subject subject)
    {
        if (subject is not PersistenceSubject ps) return null;
        var e = ps.Entry;
        if (e.AccessDenied) return null;
        if (e.ImagePath.Length > 0 && Core.HeroPaths.IsOwnState(e.ImagePath)) return null;
        return e;
    }

    /// <summary>Disabled autoruns do not execute, so they are recorded at a fraction of the
    /// weight rather than ignored — a disabled malicious entry is still evidence.</summary>
    internal static double ForEnabledState(PersistenceEntry entry, double weight) =>
        entry.Enabled ? weight : weight * 0.35;

    internal static string Where(PersistenceEntry e) => e.Category switch
    {
        PersistenceCategory.RunKey => "a startup registry key",
        PersistenceCategory.StartupFolder => "your Startup folder",
        PersistenceCategory.ScheduledTask => "a scheduled task",
        PersistenceCategory.Service => "a Windows service",
        PersistenceCategory.Winlogon => "the Windows logon settings",
        PersistenceCategory.ImageFileExecutionOptions => "a program-launch override",
        PersistenceCategory.AppInitDll => "the global DLL-injection setting",
        PersistenceCategory.ContextMenuHandler => "a shell extension",
        _ => "a startup location",
    };
}

/// <summary>
/// Something that starts automatically and is unsigned, or whose signature no longer validates.
///
/// The weights come straight from this machine's verified baseline, which contains at least four
/// entries a naive rule would call malicious: Windows Defender's own service runs from
/// %ProgramData%, Realtek's autorun points into the DriverStore with a random hex suffix, AMD
/// ships a third-party binary under System32\AMD, and one of the user's own scheduled tasks runs
/// an unsigned .bat out of his Documents folder.
/// </summary>
internal sealed class UnsignedPersistenceRule : IDetectionRule
{
    public string Id => "persist.unsigned-target";
    public string Description => "Something that starts automatically is unsigned or fails its signature check";

    private static readonly string[] ScriptExtensions =
        { ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".py", ".sh" };

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null || e.ImagePath.Length == 0) yield break;

        var identity = KnownSoftware.Classify(e.ImagePath);
        if (identity.Trust == TrustHint.SystemManaged) yield break;   // DriverStore, MSIX, System32

        var extension = Path.GetExtension(e.ImagePath) ?? "";
        bool isScript = ScriptExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);

        if (isScript)
        {
            // A script cannot carry an Authenticode signature in any meaningful sense, and the
            // verified baseline on this machine contains exactly this: a user-written .bat run
            // hourly by a scheduled task. It needs a review flow, not an accusation.
            yield return RuleKit.Emit(Id, "A script runs automatically",
                $"{e.Name} runs {Path.GetFileName(e.ImagePath)} automatically from " +
                $"{PersistenceKit.Where(e)}. Scripts are not signed, so HERO cannot tell yours from " +
                "someone else's — worth reading once and confirming it is yours.",
                PersistenceKit.ForEnabledState(e, 5), RuleKit.Families.Provenance, Severity.Low,
                KnownSoftware.Sanitise(e.Target, 200));
            yield break;
        }

        var sig = context.Signature(e.ImagePath);
        if (sig is null) yield break;                                  // not verified yet, say nothing

        if (sig.State == SignatureState.Invalid)
        {
            double invalidWeight = identity.Class == SoftwareClass.AndroidEmulator ? 5 : 20;
            yield return RuleKit.Emit(Id, "Auto-starting program has a broken signature",
                identity.Class == SoftwareClass.AndroidEmulator
                    ? $"{e.Name} starts a BlueStacks component whose signature no longer matches the " +
                      "file. That is expected if you patched it for root."
                    : $"{e.Name} starts {Path.GetFileName(e.ImagePath)} automatically, and that file " +
                      "no longer matches the signature it was published with. Either its updater " +
                      "patches it in place, or it has been altered.",
                PersistenceKit.ForEnabledState(e, invalidWeight), RuleKit.Families.Provenance,
                invalidWeight >= 18 ? Severity.High : Severity.Low,
                $"{sig.Describe()} · {e.ImagePath}");
            yield break;
        }

        if (sig.State != SignatureState.Unsigned) yield break;

        if (identity.IsRecognised)
        {
            yield return RuleKit.Emit(Id, "Unsigned, but recognised software",
                $"{e.Name} starts {identity.Label}, which ships unsigned. Recorded for context.",
                0, RuleKit.Families.Context, Severity.Safe, e.ImagePath);
            yield break;
        }

        double weight = KnownSoftware.IsVolatile(identity.Location) ? 14 : 8;

        yield return RuleKit.Emit(Id, "Unsigned program starts automatically",
            $"{e.Name} starts {Path.GetFileName(e.ImagePath)} from {PersistenceKit.Where(e)}, and that " +
            "file carries no digital signature. Plenty of legitimate software is unsigned, so this " +
            "only matters together with where it lives and what it does.",
            PersistenceKit.ForEnabledState(e, weight), RuleKit.Families.Provenance,
            weight >= 14 ? Severity.Medium : Severity.Low, e.ImagePath);
    }
}

/// <summary>
/// Persistence whose target lives somewhere the user — and therefore any program running as the
/// user — can rewrite.
///
/// Shares the provenance family with the signature rule on purpose. "Unsigned" and "in a writable
/// folder" are two descriptions of one file, and letting them stack is how an ordinary per-user
/// application accumulates enough points to look like an incident.
/// </summary>
internal sealed class PersistenceLocationRule : IDetectionRule
{
    public string Id => "persist.writable-target";
    public string Description => "An auto-start entry points into a folder anything can rewrite";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null || e.ImagePath.Length == 0) yield break;

        var identity = KnownSoftware.Classify(e.ImagePath);

        switch (identity.Location)
        {
            case PathClass.UserPrograms:
                // Opera GX, Discord, Slack, VS Code, GitHub Desktop and every other Squirrel or
                // Electron application on this machine installs here. Verified in the baseline.
                yield return RuleKit.Emit(Id, "Per-user installed app starts automatically",
                    $"{e.Name} starts a program installed just for you rather than for the whole PC. " +
                    "That is how most modern apps install themselves.",
                    0, RuleKit.Families.Context, Severity.Safe, e.ImagePath);
                yield break;

            case PathClass.ProgramData:
                // Windows Defender's own service runs from a version-stamped %ProgramData% path.
                // "Auto-start service under ProgramData" can therefore never be a strong rule.
                yield break;

            case PathClass.Temp:
            case PathClass.Downloads:
            case PathClass.Public:
            case PathClass.RecycleBin:
            {
                // A build tree hosted UNDER one of these wins the Downloads test before it ever
                // reaches the DevWorkspace test, so it arrives here having silently lost the
                // Recognised cover it would have had anywhere else in the profile. That matters
                // only for this arm, which is the highest-weight one in the rule and has no other
                // escape hatch — 18 at Severity.High for what is somebody's debug output.
                //
                // Same shape as the guard VolatileLocationRule already carries: re-test the raw
                // path rather than trusting a class that a prefix ordering has taken away.
                if (KnownSoftware.LooksLikeDevelopmentOutput(e.ImagePath)) yield break;

                double weight = identity.Location == PathClass.RecycleBin ? 22 : 18;
                yield return RuleKit.Emit(Id, "Auto-start points at a temporary folder",
                    $"{e.Name} starts a program from {UnsignedImageRule.Describe(identity.Location)} " +
                    "every time you log on. Installed software does not live there; things that want " +
                    "to be overlooked do.",
                    PersistenceKit.ForEnabledState(e, weight), RuleKit.Families.Provenance,
                    Severity.High, e.ImagePath);
                yield break;
            }

            case PathClass.UserData:
            {
                if (identity.IsRecognised) yield break;
                yield return RuleKit.Emit(Id, "Auto-start points into your profile",
                    $"{e.Name} starts a program stored in your user profile. Anything running as you " +
                    "can replace that file, so what starts at logon can be changed without an " +
                    "administrator prompt.",
                    PersistenceKit.ForEnabledState(e, 8), RuleKit.Families.Provenance,
                    Severity.Low, e.ImagePath);
                yield break;
            }

            case PathClass.Removable:
            case PathClass.Network:
                yield return RuleKit.Emit(Id, "Auto-start points off this PC",
                    $"{e.Name} starts a program stored on removable or network storage. Whatever is " +
                    "at that location at logon time is what runs.",
                    PersistenceKit.ForEnabledState(e, 14), RuleKit.Families.Provenance,
                    Severity.Medium, e.ImagePath);
                yield break;

            default:
                yield break;
        }
    }
}

/// <summary>
/// Autoruns that work by handing content to a Windows utility rather than by running a program.
///
/// rundll32, regsvr32, mshta and the script hosts are all Microsoft-signed, so a signature check
/// tells you nothing about what they are being asked to load. The argument is the payload, which
/// is why this rule reads the target string rather than the resolved image.
/// </summary>
internal sealed class LolBinPersistenceRule : IDetectionRule
{
    public string Id => "persist.lolbin-autorun";
    public string Description => "An auto-start entry runs code through a Windows utility";

    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    private static readonly Regex RemoteScriptlet = new(@"regsvr32[^\r\n]{0,160}/i:\s*https?://", Opts);
    private static readonly Regex HtaPayload = new(@"mshta[^\r\n]{0,160}(?:https?://|javascript:|vbscript:)", Opts);
    private static readonly Regex RundllEntryPoint = new(@"rundll32(?:\.exe)?[""\s]+([^,\r\n]+),\s*([^\s""]+)", Opts);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null || e.Target.Length == 0) yield break;

        var exe = KnownSoftware.NameKey(e.ImagePath.Length > 0 ? e.ImagePath : e.Target);
        bool lolbin = KnownSoftware.IsLolBin(exe);
        bool scriptHost = KnownSoftware.IsScriptHost(exe);
        if (!lolbin && !scriptHost) yield break;

        string title, explanation;
        double weight;

        if (RemoteScriptlet.IsMatch(e.Target))
        {
            title = "Auto-start downloads and runs a script";
            explanation = $"{e.Name} uses regsvr32 to fetch a script from a web address and run it at " +
                          "logon. There is no legitimate use for this shape.";
            weight = 24;
        }
        else if (HtaPayload.IsMatch(e.Target))
        {
            title = "Auto-start runs a web page as a program";
            explanation = $"{e.Name} uses mshta to run web content as a full program at logon. That " +
                          "bypasses every protection your browser gives you.";
            weight = 24;
        }
        else if (CommandLinePatterns.Encoded.IsMatch(e.Target) || CommandLinePatterns.LooksLikeFetchAndRun(e.Target))
        {
            title = "Auto-start runs a hidden or downloaded command";
            explanation = $"{e.Name} runs an encoded or downloaded command at logon rather than a " +
                          "program you could inspect.";
            weight = 20;
        }
        else if (RundllEntryPoint.IsMatch(e.Target))
        {
            // Resolution matters more than it looks. Nine in-box Windows tasks on this machine are
            // "%windir%\system32\rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask" — an
            // unexpanded variable or a bare module name. Classifying the raw string produced nine
            // high-severity false positives against Windows itself, on every scan.
            //
            // The module is taken from a quote-aware tokenisation rather than from the regex
            // capture. rundll32 accepts switches before the module ("rundll32 /d acproxy.dll,Entry")
            // AND the module may be a quoted path containing spaces; splitting the capture on
            // spaces and taking the last fragment handed the resolver "Files\Vendor\thing.dll" for
            // rundll32 "C:\Program Files\Common Files\Vendor\thing.dll",Entry — an unresolvable
            // relative path, scored at 20 with High severity.
            var tokens = KnownSoftware.SplitArguments(e.Target);
            int at = tokens.FindIndex(t => KnownSoftware.NameKey(t) == "rundll32");
            if (at < 0) at = 0;

            var moduleToken = "";
            for (int i = at + 1; i < tokens.Count; i++)
            {
                if (tokens[i].Length == 0 || tokens[i][0] is '/' or '-') continue;   // a switch
                moduleToken = KnownSoftware.FilePartOf(tokens[i]);
                break;
            }
            var module = KnownSoftware.ResolveModuleReference(moduleToken);
            if (module.Length == 0)
            {
                title = "Auto-start loads a DLL that cannot be found";
                explanation = $"{e.Name} uses rundll32 to load a module HERO cannot locate on this PC. " +
                              "A name that resolves nowhere is a slot waiting to be filled.";
                weight = 12;
            }
            else if (KnownSoftware.ClassifyPath(module) is PathClass.SystemProtected or PathClass.WindowsRoot
                     or PathClass.ProgramFiles or PathClass.DriverStore or PathClass.WindowsApps)
            {
                yield break;   // Windows running its own maintenance through its own utility
            }
            else
            {
                title = "Auto-start loads a DLL through rundll32";
                explanation = $"{e.Name} uses rundll32 to load {Path.GetFileName(module)} from outside " +
                              "the Windows folders at logon. Running a DLL this way leaves no program " +
                              "of its own in the task list.";
                weight = 20;
            }
        }
        else if (scriptHost)
        {
            // "%systemroot%\system32\cmd.exe /d /c %systemroot%\system32\hpatchmonTask.cmd" is an
            // in-box Windows task. When everything a script host is pointed at lives where only
            // Windows can write, the entry says nothing.
            if (KnownSoftware.AllReferencesProtected(e.Target)) yield break;

            title = "Auto-start runs a script";
            explanation = $"{e.Name} runs {exe} at logon. Script hosts are how a lot of software " +
                          "automates itself and also how a lot of malware persists; the argument is " +
                          "what matters.";
            weight = 10;
        }
        else
        {
            // A Windows utility with ordinary arguments. Common and usually benign — the AMD,
            // Realtek and Windows entries in this machine's baseline all look like this.
            yield break;
        }

        yield return RuleKit.Emit(Id, title, explanation,
            PersistenceKit.ForEnabledState(e, weight), RuleKit.Families.PersistenceTechnique,
            weight >= 20 ? Severity.High : Severity.Medium,
            KnownSoftware.Sanitise(e.Target, 240));
    }
}

/// <summary>
/// A RunOnce value whose name begins with <c>!</c> or <c>*</c>.
///
/// Explorer deletes RunOnce values before running them, unless the name starts with <c>!</c>,
/// which forces run-to-completion and survives failure; a <c>*</c> prefix makes the entry run in
/// Safe Mode too. Verified baseline on this machine: every RunOnce key is empty, and virtually no
/// legitimate installer uses either prefix. Very high precision, very low recall.
/// </summary>
internal sealed class RunOncePrefixRule : IDetectionRule
{
    public string Id => "persist.runonce-prefix";
    public string Description => "A one-time startup entry is marked to survive failure or Safe Mode";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null || e.Name.Length == 0) yield break;
        if (!e.Location.Contains("RunOnce", StringComparison.OrdinalIgnoreCase)) yield break;

        char prefix = e.Name[0];
        if (prefix is not ('!' or '*')) yield break;

        yield return RuleKit.Emit(Id, "Startup entry marked to always run",
            prefix == '*'
                ? $"The startup entry \"{e.Name}\" is marked to run even in Safe Mode. Safe Mode exists " +
                  "so you can start Windows without third-party software; entries that opt out of it " +
                  "are trying not to be removed."
                : $"The startup entry \"{e.Name}\" is marked to keep retrying until it succeeds. " +
                  "Installers almost never do this.",
            PersistenceKit.ForEnabledState(e, 14), RuleKit.Families.PersistenceTechnique,
            Severity.High, $"{e.Location}\\{e.Name} = {KnownSoftware.Sanitise(e.Target, 160)}");
    }
}

/// <summary>
/// An Image File Execution Options Debugger value: whatever it names runs INSTEAD of the program
/// it is attached to, with the original command line appended.
///
/// Verified on this machine: 59 IFEO subkeys exist and not one has a Debugger value, so the base
/// rate of a hit is genuinely zero. The exceptions that matter are graphics and native debugging
/// tools, which is exactly what this user runs — Visual Studio's just-in-time debugger, NVIDIA
/// Nsight, PIX, RenderDoc and Application Verifier all set Debugger legitimately during a
/// debugging session.
/// </summary>
internal sealed class IfeoDebuggerRule : IDetectionRule
{
    public string Id => "persist.ifeo-debugger";
    public string Description => "A program has been redirected to launch something else instead";

    private static readonly IReadOnlySet<string> KnownDebuggers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "vsjitdebugger", "devenv", "windbg", "windbgx", "cdb", "ntsd", "drwtsn32", "procdump",
        "appverif", "gflags", "nvnsight", "nsight", "nsightgraphics", "pixengine", "wpixengine",
        "renderdoc", "renderdoccmd", "vsdebugeng", "dbgsvc",
    };

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null || e.Category != PersistenceCategory.ImageFileExecutionOptions) yield break;

        var debugger = KnownSoftware.NameKey(e.ImagePath.Length > 0 ? e.ImagePath : e.Target);
        bool knownDebugger = KnownDebuggers.Contains(debugger);

        var sig = e.ImagePath.Length > 0 ? context.Signature(e.ImagePath) : null;
        bool signed = sig is { State: SignatureState.Valid };

        double weight = knownDebugger && signed ? 4 : knownDebugger ? 8 : 20;

        yield return RuleKit.Emit(Id, "A program launch has been redirected",
            knownDebugger
                ? $"Launching {e.Name} starts {debugger} first. That is how debuggers and graphics " +
                  "tools attach to a program, so it is expected during a debugging session and should " +
                  "be removed when you are finished."
                : $"Launching {e.Name} now starts {Path.GetFileName(e.ImagePath)} instead. This " +
                  "setting exists for debuggers; used any other way it means something else runs every " +
                  "time you open that program.",
            PersistenceKit.ForEnabledState(e, weight), RuleKit.Families.PersistenceTechnique,
            weight >= 20 ? Severity.Critical : Severity.Low,
            $"{e.Location} Debugger = {KnownSoftware.Sanitise(e.Target, 200)}");
    }
}

/// <summary>
/// A non-empty AppInit_DLLs value: every listed DLL loads into every process that links user32.
///
/// Verified baseline: AppInit_DLLs is an empty string and LoadAppInit_DLLs is 0. The scanner only
/// produces an entry when the value is non-empty, so presence is the whole signal. Historically
/// abused by legitimate-but-awful overlay and OEM software, which is why this prompts rather than
/// carrying enough weight to act alone.
/// </summary>
internal sealed class AppInitDllRule : IDetectionRule
{
    public string Id => "persist.appinit-dlls";
    public string Description => "A DLL is set to load into every program on this PC";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null || e.Category != PersistenceCategory.AppInitDll) yield break;
        if (e.Target.Trim().Length == 0) yield break;

        yield return RuleKit.Emit(Id, "A DLL loads into every program",
            $"Windows is configured to load {KnownSoftware.Sanitise(e.Target, 120)} into essentially " +
            "every program with a window. This setting is switched off on a clean Windows 11 and is " +
            "rarely used by modern software; it gives whatever is listed a view of everything you do.",
            22, RuleKit.Families.PersistenceTechnique, Severity.Critical,
            $"{e.Location} AppInit_DLLs = {KnownSoftware.Sanitise(e.Target, 200)}");
    }
}

/// <summary>
/// Winlogon Shell/Userinit tampering.
///
/// Both values are comma-separated lists that winlogon.exe executes at every interactive logon,
/// and the technique is appending, not replacing — so every element is checked, not just the
/// first. Verified clean baseline on this machine: Shell is exactly "explorer.exe" and Userinit
/// is exactly "C:\WINDOWS\system32\userinit.exe," including the mandatory trailing comma.
/// </summary>
internal sealed class WinlogonHijackRule : IDetectionRule
{
    public string Id => "persist.winlogon-hijack";
    public string Description => "The Windows logon sequence has been altered";

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null || e.Category != PersistenceCategory.Winlogon) yield break;

        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var value = e.Target.Trim();

        switch (e.Name.ToLowerInvariant())
        {
            case "userinit":
            {
                var extras = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(part => !IsExpected(part, Path.Combine(system32, "userinit.exe"), "userinit.exe"))
                    .ToList();
                if (extras.Count == 0) yield break;

                yield return RuleKit.Emit(Id, "Something extra runs at every logon",
                    $"Windows runs {string.Join(", ", extras.Select(x => KnownSoftware.Sanitise(x, 80)))} " +
                    "as part of signing you in, in addition to the normal logon program. Appending to " +
                    "this setting is a long-standing way of surviving every restart.",
                    26, RuleKit.Families.PersistenceTechnique, Severity.Critical,
                    $"Userinit = {KnownSoftware.Sanitise(value, 200)}");
                yield break;
            }

            case "shell":
            {
                var extras = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(part => !IsExpected(part, Path.Combine(Environment.GetFolderPath(
                        Environment.SpecialFolder.Windows), "explorer.exe"), "explorer.exe"))
                    .ToList();
                if (extras.Count == 0) yield break;

                yield return RuleKit.Emit(Id, "The Windows desktop shell has been changed",
                    $"Windows is set to start {string.Join(", ", extras.Select(x => KnownSoftware.Sanitise(x, 80)))} " +
                    "as part of your desktop. Normally this is only explorer.exe.",
                    26, RuleKit.Families.PersistenceTechnique, Severity.Critical,
                    $"Shell = {KnownSoftware.Sanitise(value, 200)}");
                yield break;
            }

            case "ginadll":
                yield return RuleKit.Emit(Id, "An obsolete logon component is configured",
                    "A GinaDLL logon component is configured. Windows has not supported these since " +
                    "Windows XP, so nothing legitimate sets this on Windows 11 — it is residue from a " +
                    "dropper or a very old tool.",
                    24, RuleKit.Families.PersistenceTechnique, Severity.Critical,
                    $"GinaDLL = {KnownSoftware.Sanitise(value, 200)}");
                yield break;

            case "taskman":
                yield return RuleKit.Emit(Id, "Task Manager has been replaced",
                    $"Pressing Ctrl+Shift+Esc will start {KnownSoftware.Sanitise(value, 120)} instead of " +
                    "Task Manager. That is a way of stopping you from seeing what is running.",
                    18, RuleKit.Families.PersistenceTechnique, Severity.High,
                    $"TaskMan = {KnownSoftware.Sanitise(value, 200)}");
                yield break;

            case "appsetup":
                yield return RuleKit.Emit(Id, "A program runs before your desktop appears",
                    $"{KnownSoftware.Sanitise(value, 120)} runs during logon, before your desktop is " +
                    "ready. This value is empty on a clean Windows 11.",
                    14, RuleKit.Families.PersistenceTechnique, Severity.High,
                    $"AppSetup = {KnownSoftware.Sanitise(value, 200)}");
                yield break;
        }
    }

    /// <summary>Compares one list element against the known-good value, tolerating quoting, case
    /// and the bare-filename form Windows also accepts.</summary>
    private static bool IsExpected(string element, string fullPath, string bareName)
    {
        var v = element.Trim().Trim('"');
        return v.Equals(fullPath, StringComparison.OrdinalIgnoreCase)
            || v.Equals(bareName, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// A service whose ImagePath is unquoted and contains spaces.
///
/// This is hardening advice, not a threat, and is scored that way — unquoted paths are endemic in
/// legitimate third-party installers and several are expected on this machine. It only becomes a
/// finding when a file actually exists at one of the hijack points, which means the attack is not
/// theoretical but already staged.
///
/// HERO never probes writability by creating a file. A probe file left at C:\Program.exe would be
/// a persistence artefact in its own right, and the next scan — or another security product —
/// would find it and be right to.
/// </summary>
internal sealed class UnquotedServicePathRule : IDetectionRule
{
    public string Id => "persist.unquoted-service-path";
    public string Description => "A service path is unquoted, so Windows may run the wrong file";

    private static readonly ConcurrentDictionary<string, string> HijackCache = new(StringComparer.OrdinalIgnoreCase);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null || e.Category != PersistenceCategory.Service) yield break;

        var raw = e.Target.Trim();
        if (raw.StartsWith(@"\??\", StringComparison.Ordinal)) raw = raw[4..];
        if (raw.StartsWith('"')) yield break;

        var image = e.ImagePath;
        if (image.Length == 0 || !image.Contains(' ')) yield break;

        // System32 is not user-writable, so an unquoted path there cannot be hijacked.
        if (KnownSoftware.ClassifyPath(image) is PathClass.SystemProtected or PathClass.WindowsRoot) yield break;

        var staged = HijackCache.GetOrAdd(image, static path =>
        {
            try
            {
                int at = path.IndexOf(' ');
                while (at > 0)
                {
                    var candidate = path[..at] + ".exe";
                    if (File.Exists(candidate)) return candidate;
                    at = path.IndexOf(' ', at + 1);
                }
            }
            catch { /* malformed path */ }
            return "";
        });

        if (staged.Length > 0)
        {
            yield return RuleKit.Emit(Id, "A file is waiting to hijack a service",
                $"The service {e.Name} has an unquoted path, and a file already exists at " +
                $"{staged} — which is what Windows will run instead of the real service. This is not a " +
                "theoretical weakness; something has been placed there.",
                20, RuleKit.Families.PersistenceTechnique, Severity.Critical, staged);
            yield break;
        }

        yield return RuleKit.Emit(Id, "Service path is missing its quotes",
            $"The service {e.Name} stores its program path without quotation marks, and the path " +
            "contains spaces. If anyone could create a file at one of the shorter paths, Windows " +
            "would run that instead. Nothing is there now — this is worth tidying, not worrying about.",
            3, RuleKit.Families.Hardening, Severity.Low, KnownSoftware.Sanitise(e.Target, 200));
    }
}

/// <summary>
/// Persistence that appeared while HERO was watching.
///
/// Snapshot-and-diff turns most of the 46 persistence surfaces from a noisy classification problem
/// into a near-noiseless change-detection problem, which is what makes precision achievable on a
/// machine carrying hundreds of legitimate autoruns.
///
/// Two honesty constraints are built in. HERO does not claim an entry is new merely because it has
/// not seen it before — after a restart, everything is unseen — so the entry must ALSO have a
/// target written in the last day, or be a freshly created Startup-folder file. And nothing is
/// reported during the first <see cref="SettleSeconds"/> of a session, which is the window in
/// which the first full scan populates the baseline.
/// </summary>
internal sealed class NewPersistenceRule : IDetectionRule
{
    public string Id => "persist.recently-created";
    public string Description => "Something new arranged to start itself automatically";

    private const int SettleSeconds = 120;
    private static readonly TimeSpan RecentWindow = TimeSpan.FromHours(24);

    private readonly ConcurrentDictionary<string, byte> _seen = new(StringComparer.OrdinalIgnoreCase);
    private long _startedTicks;

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var e = PersistenceKit.EntryOf(subject);
        if (e is null) yield break;

        if (_startedTicks == 0) _startedTicks = Environment.TickCount64;
        bool settling = Environment.TickCount64 - _startedTicks < SettleSeconds * 1000L;

        bool firstSight = _seen.TryAdd(e.Key, 0);
        if (!firstSight || settling) yield break;

        var now = DateTime.UtcNow;
        bool targetIsFresh = false;
        string when = "";

        if (e.ImagePath.Length > 0)
        {
            var fact = KnownSoftware.Stat(e.ImagePath);
            if (fact.Exists && fact.LastWriteUtc != default && now - fact.LastWriteUtc < RecentWindow)
            {
                targetIsFresh = true;
                when = $"target written {fact.LastWriteUtc:u}";
            }
        }

        if (!targetIsFresh && e.Category == PersistenceCategory.StartupFolder)
        {
            var fact = KnownSoftware.Stat(e.Target);
            if (fact.Exists && fact.CreationUtc != default && now - fact.CreationUtc < RecentWindow)
            {
                targetIsFresh = true;
                when = $"file created {fact.CreationUtc:u}";
            }
        }

        if (!targetIsFresh) yield break;

        yield return RuleKit.Emit(Id, "New auto-start entry",
            $"{e.Name} was added to {PersistenceKit.Where(e)} and its program was written in the last " +
            "day. Installers do this all the time; the question is whether you installed anything.",
            10, RuleKit.Families.PersistenceAge, Severity.Medium,
            $"{e.Location}\\{e.Name} · {when}");
    }
}
