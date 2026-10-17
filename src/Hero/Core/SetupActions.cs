using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace Hero.Core;

/// <summary>
/// The privileged half of setup: copying HERO into %ProgramFiles%, registering the guardian
/// service, and putting HERO where Windows expects to find an installed program.
///
/// Everything here runs in an ELEVATED child of the setup window, launched once per button press,
/// so the user sees exactly one UAC prompt at the moment they ask for something — not at start-up,
/// and not once per step. <see cref="RunElevated"/> is the unelevated side that raises it.
///
/// Nothing here is clever. An installer that does something surprising is an installer nobody
/// trusts, and HERO's whole argument is that you can check what it did: the file copy is a file
/// copy, the service registration is the same --install-service the developer build uses, and the
/// uninstall entry is a documented set of registry values under a key named after the product.
/// </summary>
internal static class SetupActions
{
    /// <summary>Returned by <see cref="RunElevated"/> when the user dismissed the UAC prompt.</summary>
    internal const int ExitDeclined = -1;

    /// <summary>
    /// Returned by <see cref="Uninstall"/> when it ran to the end but could not remove everything.
    /// Distinct from 0 precisely because Windows and the setup window both treat 0 as "it is gone".
    /// </summary>
    internal const int ExitIncomplete = 6;

    /// <summary>
    /// Returned by --install-service, and then by <see cref="Install"/>, when the guardian service
    /// was registered but was not running when setup checked. The install itself is complete and
    /// removable — Apps entry, shortcuts and all — but the machine is not being watched yet, and the
    /// setup window has to say so rather than turn green.
    /// </summary>
    internal const int ExitInstalledNotStarted = 7;

    internal const string UninstallKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HERO";

    internal static string LogHint => $"See {Path.Combine(HeroPaths.Root, "install.log")}.";

    /// <summary>
    /// The unelevated process that raised this elevated child, or 0 when it was not told.
    ///
    /// Set from <see cref="App.SetupParentSwitch"/> before any privileged work begins. Setup has to
    /// clear HERO out of the install directory before it can copy over it, and it does that by
    /// killing every process named HERO — which included the setup window that launched it and was
    /// sitting on WaitForExit. The window disappeared the moment the user approved the prompt, and
    /// the result it existed to display was never shown.
    ///
    /// Sparing it is safe in both shapes an install takes. A setup window launched from the
    /// downloaded folder holds no file in the destination; one launched from the install directory
    /// makes the install in-place, where nothing is copied over. Neither can block the work, and
    /// the deferred directory removal waits for every HERO process by name rather than by PID, so
    /// an uninstall still cleans up after the spared parent exits.
    /// </summary>
    internal static int CallerProcessId { get; set; }

    /// <summary>True for a process setup must leave alone: itself, and the window that raised it.</summary>
    private static bool Spare(int pid) => pid == Environment.ProcessId
                                          || (CallerProcessId != 0 && pid == CallerProcessId);

    internal static string InstallDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "HERO");

    // Both are ALL-USERS locations, matching an all-users install under %ProgramFiles%. The
    // per-user folders would be wrong twice over: the elevated child may not be the signed-in
    // user, so its %USERPROFILE% is not necessarily theirs, and a machine-wide install that only
    // one account can launch is a support call waiting to happen.
    private static string StartMenuShortcut => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "HERO.lnk");

    private static string DesktopShortcut => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "HERO.lnk");

    // ---------------------------------------------------------------- elevation

    /// <summary>
    /// Re-launches this executable elevated with <paramref name="switchName"/> and waits.
    ///
    /// Verb "runas" is the only way to raise integrity from a running process, and a declined
    /// prompt arrives as a Win32Exception rather than a non-zero exit — distinguishing "the user
    /// said no" from "it failed" matters, because they need completely different messages.
    /// </summary>
    internal static int RunElevated(string switchName, params string[] extraArgs)
    {
        try
        {
            string exe = Environment.ProcessPath ?? "";
            if (exe.Length == 0) return 2;

            var info = new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(exe) ?? "",
            };
            info.ArgumentList.Add(switchName);
            foreach (var arg in extraArgs) info.ArgumentList.Add(arg);

            // Always, for every elevated child: this process is about to block on WaitForExit, and
            // the child's first act is to kill every other HERO. Without this it kills the caller.
            info.ArgumentList.Add(App.SetupParentSwitch);
            info.ArgumentList.Add(Environment.ProcessId.ToString());

            using var process = Process.Start(info);
            if (process is null) return 2;

            process.WaitForExit();
            return process.ExitCode;
        }
        // ONLY ERROR_CANCELLED IS THE USER SAYING NO. Every Win32Exception used to mean "declined",
        // which was harmless while the setup window erased its own messages and is a false
        // statement now that it does not: antivirus removing the extracted HERO.exe (ERROR_FILE_
        // NOT_FOUND, ERROR_VIRUS_INFECTED) or a policy that elevates only signed binaries would be
        // reported to the user as them having cancelled a prompt that never appeared.
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return ExitDeclined;                    // the consent dialog was dismissed
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Log($"could not launch the elevated step: {ex.Message} (error {ex.NativeErrorCode})");
            return 2;
        }
        catch { return 2; }
    }

    // ---------------------------------------------------------------- install

    /// <summary>
    /// Installs HERO. Runs in the ELEVATED child, so the shortcut choices have to arrive as
    /// arguments — the tick boxes live in a window belonging to a different, unelevated process.
    /// </summary>
    internal static int Install(bool startMenuShortcut = true, bool desktopShortcut = false)
    {
        bool stoppedBySetup = false;
        try
        {
            string source = Path.GetDirectoryName(Environment.ProcessPath)
                            ?? throw new InvalidOperationException("Could not determine HERO's own path.");
            string destination = InstallDirectory;

            Log($"=== install starting from {source} ===");

            // Running the installer FROM the install directory is a reinstall: the files are
            // already where they belong and copying a file over itself throws.
            bool inPlace = string.Equals(
                Path.GetFullPath(source).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase);

            // Read FIRST — before a pending removal is cancelled, before the guardian is stopped,
            // before a byte is copied — so a manifest that cannot be parsed fails with the machine
            // exactly as it was. An earlier version read it after ClearPendingRemoval, which made
            // "exactly as it was" untrue twice over: the cancelled removal stayed cancelled, and the
            // catch below could start a guardian the user had stopped on purpose.
            var published = inPlace ? null : PublishedFiles(source);

            // Before anything is written: cancel any delete a previous uninstall left pending.
            ClearPendingRemoval(destination);

            if (!inPlace)
            {
                // What the PREVIOUS install declared, read before the copy overwrites its manifest.
                //
                // Install copies forward and never used to delete, which was safe while every build
                // shipped the same file set. It stopped being safe when the shapes diverged. Measured:
                // a framework-dependent console app runs fine, and stops with 0x80008096 ("You must
                // install or update .NET") the moment a self-contained build's hostfxr.dll is copied
                // beside it — the apphost sees an app-local hostfxr and treats the folder as
                // self-contained. So installing a framework-dependent HERO over this release would
                // have left ~247 runtime files behind and a guardian that cannot start, with an
                // uninstall that cannot run either, since it is the same HERO.exe.
                //
                // HERO's own record decides what goes, never a guess: only names the old deps.json
                // declared and the new one does not. A stranger's file in Program Files is in
                // neither list. Unreadable is treated as empty — a missing previous manifest means a
                // single-file build or no install, and either way there is nothing of ours to remove.
                HashSet<string> previous;
                try { previous = PublishedFiles(destination); }
                catch { previous = new HashSet<string>(StringComparer.OrdinalIgnoreCase); }

                StopEverything();
                stoppedBySetup = true;
                Directory.CreateDirectory(destination);

                int copied = 0, skipped = 0;
                foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.TopDirectoryOnly))
                {
                    if (!IsProgramFile(file, published!)) { skipped++; continue; }
                    CopyWithRetry(file, Path.Combine(destination, Path.GetFileName(file)));
                    copied++;
                }
                Log($"copied {copied} files to {destination}" +
                    (skipped > 0 ? $"; left {skipped} unrelated file(s) where they were" : ""));

                int removed = 0;
                foreach (var stale in previous)
                {
                    if (published!.Contains(stale)) continue;
                    // GetFileName already reduced every declared name to a bare file name, so this
                    // cannot reach outside the install directory.
                    string path = Path.Combine(destination, stale);
                    try
                    {
                        if (File.Exists(path)) { File.Delete(path); removed++; }
                    }
                    catch (Exception e) { Log($"could not remove the previous build's {stale}: {e.Message}"); }
                }
                if (removed > 0) Log($"removed {removed} file(s) the previous build declared and this one does not");
            }
            else
            {
                Log("running from the install directory; treating this as a repair");
                StopEverything();
                stoppedBySetup = true;
            }

            // The service registration, the state directory and its lockdown all live in the
            // existing --install-service path. Setup deliberately does not reimplement them: two
            // implementations of "install the service" is how one of them silently rots.
            int code = RunSelf(destination, "--install-service");
            if (code != 0 && code != ExitInstalledNotStarted)
            {
                Log($"service registration failed with exit {code}");
                return code;
            }

            WriteUninstallEntry(destination);
            ApplyShortcuts(destination, startMenuShortcut, desktopShortcut);

            if (code == ExitInstalledNotStarted)
            {
                Log("=== install done, but the guardian service is not running; see " +
                    $"{Path.Combine(HeroPaths.Root, "service.log")} ===");
                return code;
            }

            Log("=== install done ===");
            return 0;
        }
        catch (Exception ex)
        {
            Log($"install failed: {ex.GetType().Name}: {ex.Message}");

            // Put back what the attempt took away. Setup stops the guardian before copying, so a
            // failure between those two points leaves the machine UNWATCHED — and silently, because
            // the only visible symptom is a service that is no longer running. Measured exactly
            // once, which was enough: a failed copy left HeroGuardian stopped and nothing said so.
            //
            // Only what SETUP stopped. A failure before that point — an unreadable manifest, say —
            // must not start a guardian the user had stopped themselves.
            //
            // Best effort by design: if the service cannot be restarted there is nothing more setup
            // can do about it, and the log is the record.
            try
            {
                if (stoppedBySetup && Service.ServiceControl.Query() is { Installed: true, Running: false })
                {
                    Service.ServiceControl.Start();
                    Log("restarted the guardian service after the failed install");
                }
            }
            catch (Exception restart) { Log($"could not restart the service: {restart.Message}"); }

            return 3;
        }
    }

    // ---------------------------------------------------------------- uninstall

    /// <summary>
    /// Removes HERO, and reports whether it actually managed to.
    ///
    /// ELEVATION IS RAISED HERE RATHER THAN ASSUMED. Settings &gt; Apps runs QuietUninstallString as
    /// the signed-in user, and HERO ships asInvoker, so nothing on that path arrives elevated.
    /// Unelevated, every step below fails on access — the service delete, the HKLM key, the
    /// all-users shortcuts, the Program Files removal — and this method used to catch each failure,
    /// log it, and return 0 regardless. Windows took that as success, removed its Apps entry, and
    /// told the user HERO was gone while a LocalSystem auto-start service kept running with no
    /// remaining way to remove it.
    ///
    /// So: raise the prompt if it is needed, and once elevated, keep going past a failed step but
    /// COUNT the failures. Tolerance is right — an uninstaller that stops at the first missing piece
    /// leaves the machine half-removed with no way forward — but tolerance is not the same as
    /// claiming success, and only the exit code can tell the caller which happened.
    /// </summary>
    internal static int Uninstall()
    {
        if (!Elevation.IsElevated)
        {
            Log("not elevated; raising a prompt and re-running the uninstall as administrator");
            int raised = RunElevated(App.SetupUninstallSwitch);
            Log(raised == 0 ? "the elevated uninstall reported success"
                : raised == ExitDeclined ? "the permission prompt was dismissed; nothing was removed"
                : $"the elevated uninstall returned {raised}");
            return raised;
        }

        Log("=== uninstall starting ===");
        var failed = new List<string>();

        // The service first, and its exit code is now READ. This call used to discard it, which is
        // half of why an uninstall that removed nothing still reported success.
        try
        {
            int code = RunSelf(InstallDirectory, "--uninstall-service");

            // ANY failure to run the installed HERO.exe falls back to removing the service from this
            // process, not only exit 4 ("there is no HERO.exe there to run", after a partial install
            // or a directory deleted by hand). A HERO.exe that exists but cannot START is the same
            // problem from the uninstaller's side — measured, a stray hostfxr.dll makes it exit
            // 0x80008096 — and treating that as "removal failed" left the LocalSystem service
            // registered with the one tool that knew how to remove it unable to run.
            if (code != 0)
            {
                Log($"the installed HERO.exe exited {code} (4 means it is missing); " +
                    "removing the service directly");
                if (Service.ServiceControl.Query().Installed)
                {
                    Service.ServiceControl.Stop();
                    Service.ServiceControl.Uninstall();
                }
                Log("service removed");
            }
            else Log("service removed");
        }
        // Covers the direct removal above as well: if Stop or Uninstall throws there, the service is
        // still registered, and this is what keeps the uninstall from reporting that it is gone.
        catch (Exception ex) { Log($"service removal: {ex.Message}"); failed.Add("the guardian service"); }

        try
        {
            StartupRegistration.DisableAll();
            Log("startup entries removed");
        }
        catch (Exception ex) { Log($"startup removal: {ex.Message}"); failed.Add("the startup entries"); }

        try
        {
            foreach (var p in Process.GetProcessesByName("HERO"))
            {
                if (Spare(p.Id)) continue;
                try { p.Kill(); p.WaitForExit(4000); } catch { }
            }
        }
        catch { }

        // Both, unconditionally: uninstall does not know which were asked for at install time, and
        // leaving a Desktop icon that launches a deleted binary is the most visible way to look
        // half-removed.
        foreach (var (link, label) in new[] { (StartMenuShortcut, "start menu"), (DesktopShortcut, "desktop") })
        {
            try
            {
                if (File.Exists(link)) { File.Delete(link); Log($"{label} shortcut removed"); }
            }
            catch (Exception ex) { Log($"{label} shortcut removal: {ex.Message}"); failed.Add($"the {label} shortcut"); }
        }

        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, throwOnMissingSubKey: false);
            Log("uninstall entry removed");
        }
        catch (Exception ex) { Log($"uninstall entry: {ex.Message}"); failed.Add("the Settings > Apps entry"); }

        // The program files go last, and this process is running from them. Deleting the directory
        // a running executable lives in fails on the executable itself, so the removal is handed to
        // a detached cmd that waits for every HERO process to exit first.
        try
        {
            if (Directory.Exists(InstallDirectory))
            {
                ScheduleDirectoryRemoval(InstallDirectory);
                Log($"scheduled removal of {InstallDirectory}");
            }
            else Log("no install directory to remove");
        }
        catch (Exception ex) { Log($"program files removal: {ex.Message}"); failed.Add("the program files"); }

        if (failed.Count > 0)
        {
            Log($"=== uninstall INCOMPLETE: could not remove {string.Join(", ", failed)} ===");
            return ExitIncomplete;
        }

        Log("=== uninstall done ===");
        return 0;
    }

    /// <summary>Dropped into the install directory when a deferred delete could not be renamed away.</summary>
    private const string UninstallMarker = ".hero-uninstalling";

    /// <summary>
    /// Removes the install directory after this process exits, because HERO cannot delete the
    /// executable it is currently running from.
    ///
    /// RENAMED FIRST, and that is what closes the race. The deferred delete used to target
    /// "C:\Program Files\HERO" by name, so anyone who uninstalled and then reinstalled before the
    /// timer fired would have their BRAND NEW install deleted out from under them by the tail end
    /// of the previous uninstall. Renaming to a unique sibling means the scheduled delete refers to
    /// a directory no future install will ever create, and a reinstall is free to recreate the real
    /// name immediately.
    ///
    /// The rename can fail — a handle on the directory itself rather than the files inside it — so
    /// the fallback deletes by the original name but only if <see cref="UninstallMarker"/> is still
    /// present. An install removes that marker as its first act, which turns "delete the folder"
    /// into "delete the folder only if nobody has re-installed since", and closes the same race by
    /// a slower road.
    /// </summary>
    private static void ScheduleDirectoryRemoval(string directory)
    {
        string target = directory;
        bool guarded = false;

        try
        {
            string moved = Path.Combine(
                Path.GetDirectoryName(directory.TrimEnd(Path.DirectorySeparatorChar))!,
                $"HERO.removing-{Environment.ProcessId}-{DateTime.UtcNow:HHmmssfff}");

            Directory.Move(directory, moved);
            target = moved;
            Log($"renamed the install directory to {Path.GetFileName(moved)} before scheduling its removal");
        }
        catch (Exception ex)
        {
            // Could not rename, so the delete has to name the real directory. Mark it, and have the
            // script check the mark still exists before removing anything.
            guarded = true;
            Log($"could not rename the install directory ({ex.GetType().Name}); using a guarded delete");
            try { File.WriteAllText(Path.Combine(directory, UninstallMarker), "uninstalling"); } catch { }
        }

        // A script rather than a one-line cmd /c. The previous version was
        //   for /l %i in (1,1,60) do (tasklist ... || (rmdir ... & exit)) & timeout /t 1 >nul
        // where the delay sat OUTSIDE the loop — so it spun sixty times in about a second and gave
        // up. It only ever appeared to work because the uninstaller happened to exit first.
        string script = Path.Combine(Path.GetTempPath(), $"hero-remove-{Environment.ProcessId}.cmd");
        string guard = guarded
            ? $"if not exist \"{Path.Combine(target, UninstallMarker)}\" goto done"
            : "rem unique directory; no guard needed";

        // Waits for EVERY HERO process, not just this one. When the uninstall is reached through
        // Settings > Apps it arrives unelevated and relaunches itself elevated, so there are two
        // HERO processes running from the install directory: this elevated child, and the
        // unelevated parent still blocked on WaitForExit. Watching only this PID meant the rmdir
        // fired while the parent still held HERO.exe mapped, and silently left the directory behind.
        File.WriteAllText(script,
            "@echo off\r\n" +
            "setlocal\r\n" +
            $"for /l %%i in (1,1,150) do (\r\n" +
            "  tasklist /fi \"IMAGENAME eq HERO.exe\" 2>nul | find /i \"HERO.exe\" >nul || goto gone\r\n" +
            "  ping -n 2 127.0.0.1 >nul\r\n" +
            ")\r\n" +
            ":gone\r\n" +
            guard + "\r\n" +
            $"rmdir /s /q \"{target}\" 2>nul\r\n" +
            ":done\r\n" +
            "del \"%~f0\" 2>nul\r\n");

        Process.Start(new ProcessStartInfo("cmd.exe", $"/c \"{script}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        });
    }

    /// <summary>
    /// Clears anything a previous uninstall left behind, before an install writes a single file.
    ///
    /// Two things: the marker that tells a pending guarded delete it may proceed — removing it is
    /// what makes that delete decide the directory has been re-installed and leave it alone — and
    /// any HERO.removing-* siblings whose script never ran, so a failed uninstall does not leave
    /// the parent directory accumulating copies of HERO forever.
    /// </summary>
    private static void ClearPendingRemoval(string destination)
    {
        try
        {
            string marker = Path.Combine(destination, UninstallMarker);
            if (File.Exists(marker)) { File.Delete(marker); Log("cleared a pending uninstall marker"); }
        }
        catch (Exception ex) { Log($"could not clear the uninstall marker: {ex.Message}"); }

        try
        {
            string parent = Path.GetDirectoryName(destination.TrimEnd(Path.DirectorySeparatorChar))!;
            foreach (var stale in Directory.EnumerateDirectories(parent, "HERO.removing-*"))
            {
                try { Directory.Delete(stale, recursive: true); Log($"removed stale {Path.GetFileName(stale)}"); }
                catch { /* its own script may still be counting down; harmless either way */ }
            }
        }
        catch { }
    }

    // ---------------------------------------------------------------- pieces

    /// <summary>
    /// Stops the service AND WAITS FOR IT TO ACTUALLY GO, then closes any running HERO windows.
    ///
    /// The waiting is the whole point. <see cref="Service.ServiceControl.Stop"/> sends
    /// SERVICE_CONTROL_STOP and returns immediately — the service process is still alive, and still
    /// holding HERO.dll, for some time afterwards. Without the wait the very next thing setup does
    /// is copy over that file, which failed exactly as you would expect:
    ///
    ///   install failed: IOException: The process cannot access the file
    ///   'C:\Program Files\HERO\HERO.dll' because it is being used by another process
    ///
    /// and left the machine with the service stopped and the install incomplete.
    ///
    /// The dashboard is closed too: it runs from the same directory and holds the same files.
    /// </summary>
    private static void StopEverything()
    {
        try
        {
            Service.ServiceControl.Stop();

            // Poll rather than sleep a fixed amount: a service that stops in 200ms should not cost
            // five seconds, and one that takes four should not be raced.
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < deadline)
            {
                if (!Service.ServiceControl.Query().Running) break;
                Thread.Sleep(200);
            }

            Log(Service.ServiceControl.Query().Running
                ? "the service did not stop within 20 seconds"
                : "existing service stopped");
        }
        catch { /* not installed yet, which is the ordinary case */ }

        // Any HERO still holding the install directory open, including the tray app.
        try
        {
            foreach (var process in Process.GetProcessesByName("HERO"))
            {
                if (Spare(process.Id)) continue;
                try
                {
                    process.CloseMainWindow();
                    if (!process.WaitForExit(3000)) { process.Kill(); process.WaitForExit(3000); }
                }
                catch { }
            }
        }
        catch { }

        // The handles are released a moment after the processes go.
        Thread.Sleep(500);
    }

    /// <summary>
    /// Whether one file next to HERO.exe is part of HERO and should be installed with it.
    ///
    /// SETUP USED TO COPY THE ENTIRE DIRECTORY TREE IT WAS LAUNCHED FROM, recursively. HERO is
    /// handed out as a zip, and people unzip into the folder they are already in — so a tester who
    /// unzipped into Downloads and ran the installer had the whole of Downloads copied into
    /// %ProgramFiles%\HERO. That is bad on its own, and worse afterwards: the service re-hashes
    /// everything in the install directory every five minutes, on a loop whose comment reads
    /// "Cheap: seven files, ~27 MB".
    ///
    /// Two rules, and they hold for every shape HERO ships in. TOP DIRECTORY ONLY, because a .NET
    /// publish output is flat — subdirectories belong to whatever else was in the folder, never to
    /// HERO. And a NAME TEST rather than an extension free-for-all: HERO's own files by prefix, and
    /// exactly the assemblies the publish itself declared, plus the three licence texts by exact
    /// name. Nothing else travels: not the "Install HERO.cmd" and "READ ME FIRST.txt" that ship in
    /// the release zip, not another installer, not any other document.
    ///
    /// The list is deliberately narrow. A file HERO genuinely needs and does not match here would
    /// fail loudly at start-up, which is recoverable; copying a stranger's files into Program Files
    /// is not.
    /// </summary>
    private static readonly HashSet<string> LicenceFiles =
        new(StringComparer.OrdinalIgnoreCase) { "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.txt" };

    private static bool IsProgramFile(string path, IReadOnlySet<string> published)
    {
        string name = Path.GetFileName(path);
        string extension = Path.GetExtension(name);

        // Anything the publish itself declared goes, whatever its extension. Not only the DLLs:
        // the runtime also lays down createdump.exe, its crash-dump writer, and a rule that
        // consulted the manifest for .dll alone left that behind — measured, when this ran
        // against a real self-contained publish and copied 253 of its 254 files.
        if (published.Contains(name)) return true;

        // A .dll ONLY IF THE PUBLISH ITSELF DECLARED IT. This used to accept any .dll at all, on
        // the reasoning that a self-contained build lays ~250 of them beside the executable — and
        // that reasoning stayed true while the rule quietly stopped being safe. The comment above
        // records testers unzipping into Downloads, and an extension test cannot tell HERO's
        // assemblies from whatever else is sitting there. Every one it admitted was copied by an
        // elevated process into the application directory of a LocalSystem service, recorded in
        // the integrity manifest as HERO's own, and placed first in the loader's search order for
        // the non-KnownDLL libraries HERO P/Invokes: dwmapi, iphlpapi, psapi, wintrust (checked
        // against HKLM\...\Session Manager\KnownDLLs; shlwapi is on that list, so it is not here).
        // A tool whose purpose is spotting a planted DLL would have planted one on the user's behalf.
        //
        // The allowlist comes from HERO.deps.json, which names every runtime and native asset the
        // publish emitted. Measured against a self-contained publish: 254 files on disk, 250
        // declared, and the four undeclared are HERO's own exe, pdb and two json files — the
        // prefix rule below. Measured against the framework-dependent build: its two DLLs,
        // Microsoft.Windows.SDK.NET and WinRT.Runtime, are both declared. A single-file build has
        // no deps.json beside it and needs no DLLs, so an empty set is the correct answer there.
        // Declared names were admitted above; reaching this line means the publish did not declare
        // this one.
        if (extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)) return false;

        // The licence texts, by exact name. A self-contained HERO embeds Microsoft's MIT-licensed
        // runtime, and that licence requires its notice to accompany every copy — which includes the
        // copy this installer makes in Program Files, not only the zip it came in. Exact names rather
        // than ".txt", so that a stranger's notes sitting in Downloads still cannot ride along.
        if (LicenceFiles.Contains(name)) return true;

        // HERO's own remaining files — but the NAME AND THE EXTENSION both have to agree. Matching
        // on the "HERO." prefix alone let hero.gif through when this was tested against a real
        // folder, and would equally have taken hero.zip or hero-notes.json along for the ride.
        if (!name.StartsWith("HERO.", StringComparison.OrdinalIgnoreCase)) return false;

        return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)     // HERO.exe
            || extension.Equals(".pdb", StringComparison.OrdinalIgnoreCase)     // symbols, for a readable stack trace
            || extension.Equals(".json", StringComparison.OrdinalIgnoreCase);   // deps + runtimeconfig
    }

    /// <summary>
    /// The file names HERO's own publish declared, read from the HERO.deps.json beside it.
    ///
    /// Both the "runtime" (managed) and "native" sections, from every library under every target:
    /// a self-contained publish puts the runtime pack's own assemblies under the runtime section of
    /// one library and the native host pieces under another, and missing either leaves an install
    /// that cannot start. Names are reduced to their file name because the publish is flat — a
    /// native asset declared as runtimes/win-x64/native/x.dll lands beside the executable as x.dll.
    ///
    /// No deps.json is not an error. It is what a single-file build looks like, and that build
    /// carries everything inside HERO.exe, so the empty set it returns copies exactly the right
    /// number of DLLs: none. A deps.json that is present but unreadable IS an error, and is allowed
    /// to throw — the caller reads this before stopping or writing anything, so the failure leaves
    /// the machine as it was, where guessing would leave an install with half a runtime.
    /// </summary>
    private static HashSet<string> PublishedFiles(string source)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string deps = Path.Combine(source, "HERO.deps.json");
        if (!File.Exists(deps)) return names;

        using var document = JsonDocument.Parse(File.ReadAllBytes(deps));
        if (!document.RootElement.TryGetProperty("targets", out var targets)) return names;

        foreach (var framework in targets.EnumerateObject())
        foreach (var library in framework.Value.EnumerateObject())
        foreach (var section in new[] { "runtime", "native" })
        {
            if (!library.Value.TryGetProperty(section, out var assets)) continue;
            foreach (var asset in assets.EnumerateObject())
                names.Add(Path.GetFileName(asset.Name));
        }

        return names;
    }

    /// <summary>
    /// Copies one file, retrying briefly on a sharing violation.
    ///
    /// Even after a process exits, Windows can hold its image mapped for a short while. Retrying is
    /// the difference between an install that works and one that fails on a machine that was simply
    /// busy.
    /// </summary>
    private static void CopyWithRetry(string source, string target)
    {
        const int attempts = 10;
        for (int i = 1; ; i++)
        {
            try { File.Copy(source, target, overwrite: true); return; }
            catch (IOException) when (i < attempts) { Thread.Sleep(300); }
            catch (UnauthorizedAccessException) when (i < attempts) { Thread.Sleep(300); }
        }
    }

    private static int RunSelf(string directory, string argument)
    {
        string exe = Path.Combine(directory, "HERO.exe");
        if (!File.Exists(exe)) { Log($"{exe} not found"); return 4; }

        var info = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = directory,
        };
        info.ArgumentList.Add(argument);

        using var process = Process.Start(info);
        if (process is null) return 4;
        process.WaitForExit(120_000);
        return process.HasExited ? process.ExitCode : 5;
    }

    /// <summary>
    /// Puts HERO in Settings &gt; Apps, so it can be removed the way every other program is.
    ///
    /// An application that installs itself and can only be removed by its own hidden switch is one
    /// people end up deleting by hand and leaving a service behind.
    /// </summary>
    private static void WriteUninstallEntry(string directory)
    {
        string exe = Path.Combine(directory, "HERO.exe");
        long sizeKb = 0;
        try
        {
            sizeKb = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                              .Sum(f => new FileInfo(f).Length) / 1024;
        }
        catch { }

        using var key = Registry.LocalMachine.CreateSubKey(UninstallKey, writable: true);
        if (key is null) { Log("could not create the uninstall entry"); return; }

        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0";

        key.SetValue("DisplayName", "HERO — Help Eliminate Rogue Oddities");
        key.SetValue("DisplayVersion", version);
        key.SetValue("Publisher", "HERO");
        key.SetValue("DisplayIcon", exe);
        key.SetValue("InstallLocation", directory);
        key.SetValue("UninstallString", $"\"{exe}\" {App.SetupSwitch}");
        key.SetValue("QuietUninstallString", $"\"{exe}\" {App.SetupUninstallSwitch}");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        key.SetValue("EstimatedSize", (int)Math.Max(1, sizeKb), RegistryValueKind.DWord);
        key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));

        Log("uninstall entry written");
    }

    /// <summary>
    /// Creates or removes the Start menu and Desktop shortcuts to match what was asked for.
    ///
    /// REMOVAL IS PART OF THE JOB, not an afterthought. Reinstalling with a box unticked has to
    /// take the shortcut away, or the choice is one-way and the second install silently disagrees
    /// with what the window says it did.
    /// </summary>
    private static void ApplyShortcuts(string directory, bool startMenu, bool desktop)
    {
        Apply(StartMenuShortcut, startMenu, "start menu");
        Apply(DesktopShortcut, desktop, "desktop");

        void Apply(string link, bool wanted, string label)
        {
            if (!wanted)
            {
                try
                {
                    if (File.Exists(link)) { File.Delete(link); Log($"{label} shortcut removed"); }
                }
                catch (Exception ex) { Log($"{label} shortcut could not be removed: {ex.Message}"); }
                return;
            }

            WriteShortcut(directory, link, label);
        }
    }

    /// <summary>
    /// Writes one shortcut via a throwaway WSH script.
    ///
    /// A .lnk is a COM-authored binary format, and the interop assembly for IShellLink is not in
    /// the shared framework — pulling in a package for one shortcut would break the project's
    /// zero-dependency rule for very little. wscript is present on every Windows install.
    /// </summary>
    private static void WriteShortcut(string directory, string link, string label)
    {
        string script = Path.Combine(Path.GetTempPath(),
            $"hero-shortcut-{label.Replace(' ', '-')}-{Environment.ProcessId}.vbs");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(link) ?? "");

            File.WriteAllText(script,
                "Set s = CreateObject(\"WScript.Shell\")\r\n" +
                $"Set l = s.CreateShortcut(\"{link}\")\r\n" +
                $"l.TargetPath = \"{Path.Combine(directory, "HERO.exe")}\"\r\n" +
                $"l.WorkingDirectory = \"{directory}\"\r\n" +
                $"l.IconLocation = \"{Path.Combine(directory, "HERO.exe")}\"\r\n" +
                "l.Description = \"HERO — Help Eliminate Rogue Oddities\"\r\n" +
                "l.Save\r\n");

            using var process = Process.Start(new ProcessStartInfo("wscript.exe")
            {
                Arguments = $"//B //NoLogo \"{script}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            process?.WaitForExit(15_000);
            Log(File.Exists(link) ? $"{label} shortcut written" : $"{label} shortcut not created");
        }
        catch (Exception ex) { Log($"{label} shortcut: {ex.Message}"); }
        finally { try { File.Delete(script); } catch { } }
    }

    private static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(HeroPaths.Root);
            File.AppendAllText(Path.Combine(HeroPaths.Root, "install.log"),
                $"{DateTime.Now:HH:mm:ss}  setup: {message}{Environment.NewLine}");
        }
        catch { }
    }
}
