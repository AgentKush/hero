using System.Diagnostics;
using Hero.Core;
using Microsoft.Win32;

namespace Hero.Guardian;

internal enum PersistenceCategory
{
    RunKey,
    StartupFolder,
    ScheduledTask,
    Service,
    Winlogon,
    ImageFileExecutionOptions,
    AppInitDll,
    ContextMenuHandler,
    Other,
}

/// <summary>A single way something has arranged to run again later.</summary>
internal sealed record PersistenceEntry
{
    internal required PersistenceCategory Category { get; init; }
    /// <summary>Human-readable location, e.g. the full registry key path.</summary>
    internal required string Location { get; init; }
    /// <summary>Value name / task name / service name.</summary>
    internal required string Name { get; init; }

    /// <summary>
    /// A service's DisplayName, empty for everything else.
    ///
    /// Carried because it is the ONLY thing that can attribute an Event 7045 to a registration.
    /// 7045 reports the display name, the registry is keyed by the short name, and nothing else in
    /// the event is unique: a command line identifies a BINARY, and binaries are shared — 41
    /// services behind `svchost.exe -k netsvcs -p`, six behind `lsass.exe`, two behind `tcpip.sys`
    /// on this machine. Matching on the command line attributes one install to every sibling.
    ///
    /// In-box Windows services store an indirect string here (`@%SystemRoot%\system32\x.dll,-100`)
    /// which will never equal the resolved name in the event. That is acceptable: those services
    /// are not newly installed on a running machine, and third-party installers — the case this
    /// rule exists for — write a literal display name. Verified against the Google Play Games and
    /// HERO Guardian registrations.
    /// </summary>
    internal string DisplayName { get; init; } = "";
    /// <summary>The raw command line or target as stored.</summary>
    internal required string Target { get; init; }
    /// <summary>Executable extracted from <see cref="Target"/>, when one could be resolved.</summary>
    internal string ImagePath { get; init; } = "";
    internal bool Enabled { get; init; } = true;
    /// <summary>True when reading this location needed rights HERO does not have.</summary>
    internal bool AccessDenied { get; init; }

    internal string Key => $"{Category}|{Location}|{Name}";
}

/// <summary>
/// Enumerates the places software arranges to start itself.
///
/// Everything here was confirmed readable without administrator rights on this machine:
/// HKCU/HKLM Run, 841 service keys, Winlogon, 59 IFEO subkeys and 299 scheduled tasks.
/// Registry reads are used in preference to WMI throughout, because System.Management is
/// not in-box on net10.0-windows and the WMI round-trip measured ~3 seconds.
/// </summary>
internal static class PersistenceScanner
{
    /// <summary>
    /// Registry autorun locations. Both the 64-bit and 32-bit views are read where the key
    /// is redirected, because a 32-bit installer writes under WOW6432Node and a scanner that
    /// only reads the native view is blind to it.
    /// </summary>
    private static readonly (RegistryHive Hive, string Path, PersistenceCategory Category)[] RunLocations =
    {
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run",                    PersistenceCategory.RunKey),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce",                PersistenceCategory.RunKey),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunServices",            PersistenceCategory.RunKey),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",        PersistenceCategory.RunKey),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",         PersistenceCategory.RunKey),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run",                    PersistenceCategory.RunKey),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce",                PersistenceCategory.RunKey),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunServices",            PersistenceCategory.RunKey),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",              PersistenceCategory.RunKey),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",  PersistenceCategory.RunKey),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",  PersistenceCategory.RunKey),
    };

    /// <summary>
    /// Winlogon values that are legitimate but whose CONTENT is the thing to check.
    /// Userinit and Shell have known-good defaults; anything appended after them is a
    /// classic hijack that survives every reboot.
    /// </summary>
    private static readonly string[] WinlogonValues = { "Userinit", "Shell", "AppSetup", "GinaDLL", "TaskMan" };

    /// <summary>
    /// One sweep's findings, and whether the sweep actually saw everything it was meant to.
    ///
    /// THE COVERAGE FLAG IS THE POINT. Each scanner used to swallow whatever went wrong and return
    /// the entries it had managed to collect, so a sweep that failed outright was indistinguishable
    /// from a machine with nothing to find — and the consumer treats absence as proof: anything
    /// with a persist: key that a completed sweep did not re-raise is deleted as stale. A failed
    /// registry read therefore did not merely hide new autoruns, it silently erased the findings
    /// HERO had already made about the old ones.
    ///
    /// So absence is only evidence when the sweep was complete, and now the sweep says which.
    /// </summary>
    internal sealed record PersistenceScan(List<PersistenceEntry> Entries, List<string> Failures)
    {
        /// <summary>True when every scanner ran to the end. Only then does "not found" mean "not there".</summary>
        internal bool Complete => Failures.Count == 0;
    }

    internal static PersistenceScan Scan()
    {
        var entries = new List<PersistenceEntry>(256);
        var failures = new List<string>();

        ScanRunKeys(entries);
        ScanStartupFolders(entries);
        ScanWinlogon(entries, failures);
        ScanImageFileExecutionOptions(entries, failures);
        ScanAppInitDlls(entries, failures);
        ScanServices(entries, failures);
        ScanScheduledTasks(entries, failures);

        return new PersistenceScan(entries, failures);
    }

    // ------------------------------------------------------------ run keys

    private static void ScanRunKeys(List<PersistenceEntry> into)
    {
        // Resolved once per sweep rather than per location: this is a handful of registry reads,
        // but there are eleven locations times two views.
        var users = UserHives.Loaded();

        foreach (var (hive, path, category) in RunLocations)
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                // The 32-bit view of an unredirected key returns the same data; deduplication
                // below removes the doubles rather than special-casing which keys redirect.
                if (hive == RegistryHive.CurrentUser)
                {
                    // NOT HKCU. Under the LocalSystem service HKCU is the service account's own
                    // hive, which has no Run keys and never will — so every per-user autorun on
                    // the machine went unseen and the page came back clean. Read each signed-in
                    // user's hive by SID instead. See UserHives.
                    foreach (var user in users) ReadUserValues(user, view, path, category, into);
                }
                else
                {
                    ReadValues(hive, view, path, category, into);
                }
            }
        }

        // Deduplicate. Most Run keys are NOT registry-redirected, so opening the 32-bit view
        // returns the identical row. The dedup key must therefore exclude the "(WOW64)" suffix
        // this scanner appends to Location — including it made every unredirected key appear
        // twice, which is exactly what happened to Steam, Opera GX and Edge on this machine.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        into.RemoveAll(e => e.Category == PersistenceCategory.RunKey &&
                            !seen.Add($"{e.Location.Replace(" (WOW64)", "")}|{e.Name}|{e.Target}"));
    }

    private static void ReadValues(RegistryHive hive, RegistryView view, string path,
                                   PersistenceCategory category, List<PersistenceEntry> into)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(path);
            if (key is null) return;

            string location = $"{HiveName(hive)}\\{path}" + (view == RegistryView.Registry32 ? " (WOW64)" : "");

            foreach (var name in key.GetValueNames())
            {
                var raw = key.GetValue(name)?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(raw)) continue;

                into.Add(new PersistenceEntry
                {
                    Category = category,
                    Location = location,
                    Name = name,
                    Target = raw,
                    ImagePath = ExtractExecutable(raw),
                    Enabled = IsStartupApproved(hive, path, name),
                });
            }
        }
        catch (System.Security.SecurityException)
        {
            into.Add(Denied(category, $"{HiveName(hive)}\\{path}"));
        }
        catch (UnauthorizedAccessException)
        {
            into.Add(Denied(category, $"{HiveName(hive)}\\{path}"));
        }
        catch { /* transient */ }
    }

    /// <summary>
    /// The per-user twin of <see cref="ReadValues"/>, reading one named user's hive under
    /// HKEY_USERS instead of whatever HKCU happens to mean to this process.
    ///
    /// The location string names the account rather than saying "HKCU", because on a machine with
    /// two people signed in "HKCU\...\Run" does not identify anything, and the whole point of a
    /// finding is that the user can go and look at the thing it names.
    /// </summary>
    private static void ReadUserValues(UserHive user, RegistryView view, string path,
                                       PersistenceCategory category, List<PersistenceEntry> into)
    {
        string location = $"{user.DisplayRoot}\\{path}" + (view == RegistryView.Registry32 ? " (WOW64)" : "");

        try
        {
            using var key = UserHives.Open(user, view, path);
            if (key is null) return;

            foreach (var name in key.GetValueNames())
            {
                var raw = key.GetValue(name)?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(raw)) continue;

                into.Add(new PersistenceEntry
                {
                    Category = category,
                    Location = location,
                    Name = name,
                    Target = raw,
                    ImagePath = ExtractExecutable(raw),
                    Enabled = IsUserStartupApproved(user, path, name),
                });
            }
        }
        catch (System.Security.SecurityException) { into.Add(Denied(category, location)); }
        catch (UnauthorizedAccessException) { into.Add(Denied(category, location)); }
        catch { /* transient */ }
    }

    /// <summary>
    /// <see cref="IsStartupApproved"/> for a named user's hive. StartupApproved is per-user, so
    /// reading it out of the service's own hive would have reported every user's disabled entry as
    /// enabled — the same defect as the Run keys themselves, one level down.
    /// </summary>
    private static bool IsUserStartupApproved(UserHive user, string runPath, string valueName)
    {
        try
        {
            using var key = UserHives.Open(user, RegistryView.Registry64,
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run");
            if (key?.GetValue(valueName) is byte[] { Length: > 0 } b)
                return b[0] != 2 && b[0] != 6;
        }
        catch { }
        return true;
    }

    /// <summary>
    /// Windows records user-disabled startup items in StartupApproved. An entry can be present
    /// in a Run key yet switched off in Task Manager; reporting it as active would be wrong.
    /// The first byte of the binary value is 2 or 6 when disabled.
    /// </summary>
    private static bool IsStartupApproved(RegistryHive hive, string runPath, string valueName)
    {
        try
        {
            if (!runPath.EndsWith(@"CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)) return true;

            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run");
            if (key?.GetValue(valueName) is byte[] { Length: > 0 } b)
                return b[0] != 2 && b[0] != 6;
        }
        catch { }
        return true;
    }

    // ------------------------------------------------------- startup folders

    private static void ScanStartupFolders(List<PersistenceEntry> into)
    {
        // CommonStartup is machine-wide, so it resolves correctly whoever HERO is running as and
        // is read straight from the environment. The per-user one is not: under the service
        // SpecialFolder.Startup lands in C:\Windows\system32\config\systemprofile, a directory
        // that exists, contains nothing, and reports a clean result for every account on the box.
        var folders = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) };
        folders.AddRange(UserHives.Loaded().Select(UserHives.StartupFolder));

        foreach (var folder in folders.Where(f => !string.IsNullOrEmpty(f)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                if (!Directory.Exists(folder)) continue;
                foreach (var file in Directory.EnumerateFiles(folder))
                {
                    var name = Path.GetFileName(file);
                    // desktop.ini is shell metadata, not an autorun.
                    if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                    into.Add(new PersistenceEntry
                    {
                        Category = PersistenceCategory.StartupFolder,
                        Location = folder,
                        Name = name,
                        Target = file,
                        ImagePath = file,
                    });
                }
            }
            catch { }
        }
    }

    // ------------------------------------------------------------- winlogon

    private static void ScanWinlogon(List<PersistenceEntry> into, List<string> failures)
    {
        const string path = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            if (key is null) return;
            foreach (var name in WinlogonValues)
            {
                if (key.GetValue(name)?.ToString() is not { Length: > 0 } raw) continue;
                into.Add(new PersistenceEntry
                {
                    Category = PersistenceCategory.Winlogon,
                    Location = $"HKLM\\{path}",
                    Name = name,
                    Target = raw,
                    ImagePath = ExtractExecutable(raw),
                });
            }
        }
        catch (Exception ex) { failures.Add($"Winlogon ({ex.GetType().Name})"); }
    }

    // ----------------------------------------------------------------- IFEO

    private static void ScanImageFileExecutionOptions(List<PersistenceEntry> into, List<string> failures)
    {
        const string path = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(path);
            if (root is null) return;

            foreach (var sub in root.GetSubKeyNames())
            {
                try
                {
                    using var k = root.OpenSubKey(sub);
                    // Only a Debugger value hijacks execution. The vast majority of IFEO keys
                    // exist for legitimate reasons (MitigationOptions, tracing flags) and must
                    // not be reported as persistence.
                    if (k?.GetValue("Debugger")?.ToString() is not { Length: > 0 } dbg) continue;

                    into.Add(new PersistenceEntry
                    {
                        Category = PersistenceCategory.ImageFileExecutionOptions,
                        Location = $"HKLM\\{path}\\{sub}",
                        Name = sub,
                        Target = dbg,
                        ImagePath = ExtractExecutable(dbg),
                    });
                }
                catch { /* one malformed subkey is not a failed sweep */ }
            }
        }
        catch (Exception ex) { failures.Add($"Image File Execution Options ({ex.GetType().Name})"); }
    }

    private static void ScanAppInitDlls(List<PersistenceEntry> into, List<string> failures)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var k = baseKey.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Windows");
                if (k?.GetValue("AppInit_DLLs")?.ToString() is not { Length: > 0 } dlls) continue;
                if (string.IsNullOrWhiteSpace(dlls)) continue;

                into.Add(new PersistenceEntry
                {
                    Category = PersistenceCategory.AppInitDll,
                    Location = @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"
                             + (view == RegistryView.Registry32 ? " (WOW64)" : ""),
                    Name = "AppInit_DLLs",
                    Target = dlls,
                    ImagePath = ExtractExecutable(dlls),
                });
            }
            catch (Exception ex) { failures.Add($"AppInit_DLLs ({ex.GetType().Name})"); }
        }
    }

    // --------------------------------------------------------------- services

    private static void ScanServices(List<PersistenceEntry> into, List<string> failures)
    {
        // System.ServiceProcess.ServiceController is not in-box on net10.0-windows, so the
        // service database is read straight out of the registry. Confirmed: 841 keys
        // enumerable without elevation.
        const string path = @"System\CurrentControlSet\Services";
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(path);
            if (root is null) return;

            foreach (var name in root.GetSubKeyNames())
            {
                try
                {
                    using var k = root.OpenSubKey(name);
                    if (k is null) continue;

                    // Start: 0=Boot 1=System 2=Automatic 3=Manual 4=Disabled.
                    //
                    // Boot, System and Automatic persist outright. Manual USUALLY does not —
                    // something has to ask for it — with one exception that matters: a service
                    // carrying a START TRIGGER is launched by Windows on the event it names. A
                    // device arriving, an IP address being assigned, a named pipe being opened, a
                    // firewall port opening, a group policy refresh. Nobody asks; it just runs.
                    // That is persistence by any honest definition.
                    //
                    // Skipping every Manual service hid 98 of them on this machine — a 41% blind
                    // spot in the service inventory, and one an attacker can sit in deliberately,
                    // because a trigger-started service is both quieter than an Automatic one and
                    // completely invisible here. Measured before including them: none of the 98
                    // produces a single signal from any rule in the catalogue, so this buys coverage
                    // at no cost in noise. Manual WITHOUT a trigger stays out: it genuinely does not
                    // start on its own, and 418 such services would be inventory, not persistence.
                    if (k.GetValue("Start") is not int start) continue;

                    bool triggered = start == 3 && HasStartTrigger(k);
                    if (start > 2 && !triggered) continue;

                    // Type 1/2/8 are drivers; 16/32 are win32 services. Both can persist,
                    // but drivers are reported separately because removing one is far riskier.
                    var image = k.GetValue("ImagePath")?.ToString() ?? "";
                    if (string.IsNullOrWhiteSpace(image)) continue;

                    into.Add(new PersistenceEntry
                    {
                        Category = PersistenceCategory.Service,
                        Location = $"HKLM\\{path}\\{name}",
                        Name = name,
                        DisplayName = ResolveDisplayName(k.GetValue("DisplayName")?.ToString() ?? ""),
                        Target = image,
                        ImagePath = ServiceExecutable(image),
                        // Exactly the inclusion condition above, restated rather than hard-coded to
                        // true, so that a future change to what gets scanned cannot silently leave
                        // a disabled entry claiming it will run.
                        Enabled = start <= 2 || triggered,
                    });
                }
                catch { /* one malformed service key is not a failed sweep */ }
            }
        }
        catch (Exception ex) { failures.Add($"Services ({ex.GetType().Name})"); }
    }

    /// <summary>
    /// The executable a service's registry ImagePath actually runs.
    ///
    /// ONE FUNCTION BECAUSE TWO PLACES MUST AGREE, and for a while they did not. This scanner built
    /// every service entry's ImagePath by normalising and extracting; ServiceInstalledRule then
    /// matched an Event 7045 to that entry by comparing the event's ImagePath property against it —
    /// but 7045 carries the raw COMMAND LINE, quoted and with arguments. So the rule compared
    ///
    ///     "C:\Program Files\HERO\HERO.exe" --service      (the event, raw)
    ///     C:\Program Files\HERO\HERO.exe                  (the entry, normalised)
    ///
    /// and matched nothing. Every correctly-installed service — quoted path, or any argument — was
    /// invisible to a rule in the EVASION family, while a service was detectable only if its
    /// registry value happened to be bare and unquoted. Measured on this machine: 31 of 287
    /// standalone-executable services could never be attributed, HERO's own among them. See
    /// docs/PLATFORM-FACTS.md section 34.
    ///
    /// Two copies of an identity function drift silently, because nothing fails — the comparison
    /// simply stops being true. Callers get this one.
    /// </summary>
    internal static string ServiceExecutable(string registryImagePath)
        => ExtractExecutable(NormaliseServiceImage(registryImagePath));

    /// <summary>
    /// Resolved indirect display names, keyed by the raw registry value.
    ///
    /// Cached because the scan runs every ten minutes over ~715 services and resolution is not free:
    /// each miss loads a module and pulls a string resource. The answer cannot change without the
    /// module changing, i.e. without a Windows update and a restart, so a process-lifetime cache is
    /// correct rather than merely convenient.
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string>
        ResolvedNames = new(StringComparer.Ordinal);

    /// <summary>
    /// A service's display name as everything else reports it.
    ///
    /// The registry usually holds an INDIRECT string — <c>@%SystemRoot%\system32\AarSvc.dll,-100</c>
    /// — while Event 7045, the SCM and Task Manager all show the resolved text ("Agent Activation
    /// Runtime"). 601 of 715 services on this machine are stored that way, so matching an event to a
    /// registration by name was blind to almost everything Windows ships.
    ///
    /// A value that does not begin with '@' is already literal and is returned untouched: that is
    /// how third-party installers write it, and those were the only ones that ever matched before.
    ///
    /// Failure returns the raw value rather than an empty string. An unresolvable name is still a
    /// name, and callers compare it for equality — a raw value that matches nothing is exactly the
    /// behaviour this had before, whereas an empty one would silently disable the caller's other
    /// checks.
    /// </summary>
    internal static string ResolveDisplayName(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";
        if (raw[0] != '@') return raw;

        return ResolvedNames.GetOrAdd(raw, static source =>
        {
            try
            {
                var buffer = new System.Text.StringBuilder(1024);
                // S_OK is 0. Anything else — missing module, missing resource id, a language with
                // no translation — leaves the buffer untrustworthy, so fall through.
                if (Interop.Native.SHLoadIndirectString(source, buffer, buffer.Capacity, IntPtr.Zero) == 0
                    && buffer.Length > 0)
                {
                    return buffer.ToString();
                }
            }
            catch { /* shlwapi is in-box, but a malformed source must not take the scan down */ }

            // THE INF FORM, which shlwapi does not resolve and which is most of them:
            //
            //     @1394.inf,%PCI\CC_0C0010.DeviceDesc%;1394 OHCI Compliant Host Controller
            //
            // Driver services are registered from an INF and Windows stores the localisation key
            // together with the ENGLISH TEXT IT STANDS FOR, after a semicolon, precisely so the name
            // survives when the INF cannot be consulted — which it cannot here, because the file
            // lives in %SystemRoot%\INF and the value names it without a path. Measured: 229 of 603
            // indirect names are this shape, and shlwapi returns a failure HRESULT for every one.
            //
            // The trailing text is Windows' own fallback, not a guess of ours.
            int semicolon = source.IndexOf(';');
            if (semicolon >= 0 && semicolon < source.Length - 1)
            {
                var fallback = source[(semicolon + 1)..];
                // NOT trimmed. The value must be byte-faithful to what Windows produces from the
                // same fallback, because the point of it is to equal what an event reports:
                // "Intel(R) Management Engine Interface " really does keep its trailing space in the
                // SCM, and trimming it here turned a match into a near-miss. Callers trim.
                if (fallback.Length > 0) return fallback;
            }

            return source;
        });
    }

    /// <summary>
    /// Whether a service carries at least one start trigger, which is what makes a Manual service
    /// start without anybody asking.
    ///
    /// The SUBKEYS are counted rather than TriggerInfo merely being tested for existence: Windows
    /// leaves empty TriggerInfo keys behind when triggers are removed, and treating one of those as
    /// a trigger would pull an ordinary on-demand service into the persistence inventory.
    /// </summary>
    private static bool HasStartTrigger(RegistryKey service)
    {
        try
        {
            using var triggers = service.OpenSubKey("TriggerInfo");
            return triggers is { SubKeyCount: > 0 };
        }
        catch { return false; }        // unreadable is not evidence of a trigger
    }

    /// <summary>
    /// Service ImagePath values use NT-style paths and may be unquoted with spaces.
    /// \??\C:\foo\bar.exe and \SystemRoot\System32\drivers\x.sys both occur.
    /// </summary>
    private static string NormaliseServiceImage(string raw)
    {
        var s = raw.Trim();
        if (s.StartsWith(@"\??\", StringComparison.Ordinal)) s = s[4..];
        if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            s = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), s[12..]);
        else if (s.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase))
            s = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), s);
        return s;
    }

    // -------------------------------------------------------- scheduled tasks

    private static void ScanScheduledTasks(List<PersistenceEntry> into, List<string> failures)
    {
        // The Task Scheduler COM API would avoid a process launch, but schtasks.exe is
        // in-box, needs no interop, and was measured returning all 299 tasks unelevated.
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", "/query /fo csv /v /nh")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
            };
            using var p = Process.Start(psi);
            if (p is null) return;

            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15000);

            foreach (var line in output.Split('\n'))
            {
                var fields = ParseCsvLine(line);
                // Verified layout on this machine: /v emits 28 fields for every one of the
                // 299 tasks. [1] TaskName, [3] Status (Ready/Disabled/Running),
                // [8] Task To Run, [11] Scheduled Task State (Enabled/Disabled).
                if (fields.Count < 9) continue;

                string taskName = fields[1];
                // [11] is the explicit enabled state and is more reliable than Status, which
                // reports transient run conditions such as "Running".
                string status = fields.Count > 11 && fields[11].Length > 0 ? fields[11] : fields[3];
                string toRun = fields[8];

                if (string.IsNullOrWhiteSpace(taskName) || taskName == "TaskName") continue;
                if (string.IsNullOrWhiteSpace(toRun) || toRun.Equals("N/A", StringComparison.OrdinalIgnoreCase)) continue;
                // COM-handler tasks run in-process and have no command line to inspect.
                if (toRun.StartsWith("COM handler", StringComparison.OrdinalIgnoreCase)) continue;

                into.Add(new PersistenceEntry
                {
                    Category = PersistenceCategory.ScheduledTask,
                    Location = "Task Scheduler",
                    Name = taskName,
                    Target = toRun,
                    ImagePath = ExtractExecutable(toRun),
                    Enabled = !status.Equals("Disabled", StringComparison.OrdinalIgnoreCase),
                });
            }
        }
        catch (Exception ex) { failures.Add($"Scheduled tasks ({ex.GetType().Name})"); }
    }

    /// <summary>Minimal RFC4180 field splitter — schtasks quotes fields containing commas.</summary>
    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        if (string.IsNullOrWhiteSpace(line)) return fields;

        var sb = new System.Text.StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQuotes = false;
                }
                else sb.Append(c);
            }
            else if (c == '"') inQuotes = true;
            else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else if (c != '\r') sb.Append(c);
        }
        fields.Add(sb.ToString());
        return fields;
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>
    /// Executable extensions worth recognising when splitting a command line. Ordered by
    /// nothing in particular; the regex alternation is anchored on the first match.
    /// </summary>
    private const string ExecutableExtensions =
        "exe|com|bat|cmd|scr|pif|ps1|vbs|vbe|js|jse|wsf|wsh|msc|msi|cpl|dll|sys";

    private static readonly System.Text.RegularExpressions.Regex ExecutablePattern =
        new($@"^(.*?\.(?:{ExecutableExtensions}))(?=\s|,|$)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
          | System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Pulls the executable out of a command line.
    ///
    /// The obvious implementation — split on the first space, then probe longer prefixes until
    /// one exists on disk — fails in exactly the case that matters. When the target does NOT
    /// exist (uninstalled software, a path typo, or malware that has already been removed) every
    /// probe misses and the result degrades to "C:\Program". Verified: that is precisely what
    /// happened to a dozen Office, Visual Studio and Google scheduled tasks on this machine.
    ///
    /// So extension matching comes first and needs no disk access at all; existence probing is
    /// only a fallback for extensionless targets. The non-greedy match takes the FIRST
    /// executable extension, so "C:\a b\host.exe C:\payload.dll" yields the host.
    /// </summary>
    internal static string ExtractExecutable(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return "";

        string s;
        try { s = Environment.ExpandEnvironmentVariables(commandLine.Trim()); }
        catch { s = commandLine.Trim(); }

        // 1. Quoted target — unambiguous by construction.
        if (s.StartsWith('"'))
        {
            int close = s.IndexOf('"', 1);
            return Resolve(close > 1 ? s[1..close] : s.Trim('"'));
        }

        // 2. Cut at the first executable extension. Handles spaces in the path without
        //    touching the filesystem, and works for targets that no longer exist.
        var m = ExecutablePattern.Match(s);
        if (m.Success) return Resolve(m.Groups[1].Value);

        // 3. No recognised extension: fall back to probing prefixes that do exist.
        int space = s.IndexOf(' ');
        if (space < 0) return Resolve(s);

        int idx = space;
        while (idx > 0 && idx < s.Length)
        {
            var probe = s[..idx];
            if (File.Exists(probe)) return probe;
            int next = s.IndexOf(' ', idx + 1);
            if (next < 0) break;
            idx = next;
        }
        return Resolve(s[..space]);
    }

    /// <summary>
    /// Turns a bare image name into a full path. Autoruns frequently store just "rundll32.exe"
    /// or "explorer.exe" and rely on PATH resolution; leaving those unrooted would make every
    /// downstream signature check fail with "file not found" and look like a threat.
    /// </summary>
    private static string Resolve(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return "";
        candidate = candidate.Trim().TrimEnd(',');

        if (Path.IsPathRooted(candidate)) return candidate;

        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var probe = Path.Combine(system32, candidate);
        if (File.Exists(probe)) return probe;

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        probe = Path.Combine(windows, candidate);
        if (File.Exists(probe)) return probe;

        return candidate;
    }

    private static PersistenceEntry Denied(PersistenceCategory category, string location) => new()
    {
        Category = category,
        Location = location,
        Name = "(access denied)",
        Target = "",
        AccessDenied = true,
    };

    private static string HiveName(RegistryHive hive) => hive switch
    {
        RegistryHive.CurrentUser => "HKCU",
        RegistryHive.LocalMachine => "HKLM",
        RegistryHive.ClassesRoot => "HKCR",
        RegistryHive.Users => "HKU",
        _ => hive.ToString(),
    };
}
