using System.Diagnostics;
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

    internal const string UninstallKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HERO";

    internal static string LogHint => $"See {Path.Combine(HeroPaths.Root, "install.log")}.";

    internal static string InstallDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "HERO");

    private static string StartMenuShortcut => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "HERO.lnk");

    // ---------------------------------------------------------------- elevation

    /// <summary>
    /// Re-launches this executable elevated with <paramref name="switchName"/> and waits.
    ///
    /// Verb "runas" is the only way to raise integrity from a running process, and a declined
    /// prompt arrives as a Win32Exception rather than a non-zero exit — distinguishing "the user
    /// said no" from "it failed" matters, because they need completely different messages.
    /// </summary>
    internal static int RunElevated(string switchName)
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

            using var process = Process.Start(info);
            if (process is null) return 2;

            process.WaitForExit();
            return process.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return ExitDeclined;                    // the consent dialog was dismissed
        }
        catch { return 2; }
    }

    // ---------------------------------------------------------------- install

    internal static int Install()
    {
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

            // Before anything is written: cancel any delete a previous uninstall left pending.
            ClearPendingRemoval(destination);

            if (!inPlace)
            {
                StopEverything();
                Directory.CreateDirectory(destination);

                int copied = 0;
                foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
                {
                    string relative = Path.GetRelativePath(source, file);
                    string target = Path.Combine(destination, relative);
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    CopyWithRetry(file, target);
                    copied++;
                }
                Log($"copied {copied} files to {destination}");
            }
            else
            {
                Log("running from the install directory; treating this as a repair");
                StopEverything();
            }

            // The service registration, the state directory and its lockdown all live in the
            // existing --install-service path. Setup deliberately does not reimplement them: two
            // implementations of "install the service" is how one of them silently rots.
            int code = RunSelf(destination, "--install-service");
            if (code != 0) { Log($"service registration failed with exit {code}"); return code; }

            WriteUninstallEntry(destination);
            WriteStartMenuShortcut(destination);

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
            // Best effort by design: if the service cannot be restarted there is nothing more setup
            // can do about it, and the log is the record.
            try
            {
                if (Service.ServiceControl.Query() is { Installed: true, Running: false })
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

    internal static int Uninstall()
    {
        // Deliberately tolerant. An uninstaller that stops at the first missing piece leaves the
        // machine half-uninstalled and the user with no way forward, so each step is attempted and
        // recorded independently.
        Log("=== uninstall starting ===");

        try { RunSelf(InstallDirectory, "--uninstall-service"); }
        catch (Exception ex) { Log($"service removal: {ex.Message}"); }

        try
        {
            StartupRegistration.DisableAll();
            Log("startup entries removed");
        }
        catch (Exception ex) { Log($"startup removal: {ex.Message}"); }

        try
        {
            foreach (var p in Process.GetProcessesByName("HERO"))
            {
                if (p.Id == Environment.ProcessId) continue;
                try { p.Kill(); p.WaitForExit(4000); } catch { }
            }
        }
        catch { }

        try
        {
            if (File.Exists(StartMenuShortcut)) File.Delete(StartMenuShortcut);
            Log("start menu shortcut removed");
        }
        catch (Exception ex) { Log($"shortcut removal: {ex.Message}"); }

        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, throwOnMissingSubKey: false);
            Log("uninstall entry removed");
        }
        catch (Exception ex) { Log($"uninstall entry: {ex.Message}"); }

        // The program files go last, and this process is running from them. Deleting the directory
        // a running executable lives in fails on the executable itself, so the removal is handed to
        // a detached cmd that waits for this process to exit first.
        try
        {
            ScheduleDirectoryRemoval(InstallDirectory);
            Log($"scheduled removal of {InstallDirectory}");
        }
        catch (Exception ex) { Log($"program files removal: {ex.Message}"); }

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

        File.WriteAllText(script,
            "@echo off\r\n" +
            "setlocal\r\n" +
            $"for /l %%i in (1,1,150) do (\r\n" +
            $"  tasklist /fi \"PID eq {Environment.ProcessId}\" 2>nul | find \"{Environment.ProcessId}\" >nul || goto gone\r\n" +
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
                if (process.Id == Environment.ProcessId) continue;
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
    /// Writes a Start menu shortcut via a throwaway WSH script.
    ///
    /// A .lnk is a COM-authored binary format, and the interop assembly for IShellLink is not in
    /// the shared framework — pulling in a package for one shortcut would break the project's
    /// zero-dependency rule for very little. wscript is present on every Windows install.
    /// </summary>
    private static void WriteStartMenuShortcut(string directory)
    {
        string script = Path.Combine(Path.GetTempPath(), $"hero-shortcut-{Environment.ProcessId}.vbs");
        try
        {
            File.WriteAllText(script,
                "Set s = CreateObject(\"WScript.Shell\")\r\n" +
                $"Set l = s.CreateShortcut(\"{StartMenuShortcut}\")\r\n" +
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
            Log(File.Exists(StartMenuShortcut) ? "start menu shortcut written" : "start menu shortcut not created");
        }
        catch (Exception ex) { Log($"shortcut: {ex.Message}"); }
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
