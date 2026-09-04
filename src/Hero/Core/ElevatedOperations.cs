using System.Diagnostics;
using Microsoft.Win32;

namespace Hero.Core;

/// <summary>
/// The elevated child. HERO relaunches itself with <c>--elevated-op</c>, this performs exactly one
/// operation, and the process exits.
///
/// Everything here runs with an administrator token, so it is written defensively on the
/// assumption that the command line reaching it may not have come from HERO:
///
///   * every operation validates its own arguments and refuses anything it does not recognise;
///   * no operation takes a free-form command, a script path or a shell string — the only inputs
///     are a service name, a registry location, an executable path and a PID;
///   * registry writes are confined to the specific autorun locations HERO reports on, so a
///     crafted command line cannot use this to write an arbitrary HKLM value;
///   * nothing here is resident: the process does its job and leaves, so an administrator token
///     never sits in memory waiting to be borrowed.
///
/// The exit code is the result: 0 performed, 1 refused, 2 failed.
/// </summary>
internal static class ElevatedOperations
{
    internal const int ExitPerformed = 0;
    internal const int ExitRefused = 1;
    internal const int ExitFailed = 2;

    /// <summary>
    /// The only registry roots an elevated HERO will delete an autorun value from. Anything else
    /// is refused, so this cannot be turned into a general-purpose privileged registry editor.
    /// </summary>
    private static readonly string[] AllowedMachineAutorunKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    };

    internal static int Execute(ElevationRequest request)
    {
        try
        {
            return request.Operation switch
            {
                ElevatedOperation.ReconfigureService => ReconfigureService(request.Arguments),
                ElevatedOperation.RemoveMachinePersistence => RemoveMachinePersistence(request.Arguments),
                ElevatedOperation.BlockProcessNetwork => BlockProcessNetwork(request.Arguments),
                ElevatedOperation.TerminateProtectedProcess => TerminateProcess(request.Arguments),
                _ => Log(ExitRefused, $"Operation {request.Operation} is not implemented by the elevated helper."),
            };
        }
        catch (Exception ex)
        {
            return Log(ExitFailed, $"{request.Operation} failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>args: [serviceName, "disabled"|"demand"|"auto"]</summary>
    private static int ReconfigureService(IReadOnlyList<string> args)
    {
        if (args.Count != 2) return Log(ExitRefused, "ReconfigureService expects a service name and a start type.");

        string name = args[0];
        // A service name is a registry key name; anything with a separator in it is an attempt to
        // reach outside the Services key.
        if (name.Length == 0 || name.Length > 256 || name.IndexOfAny(new[] { '\\', '/', '"', '*', '?' }) >= 0)
            return Log(ExitRefused, "Refusing a service name containing a path separator or wildcard.");

        int start = args[1].ToLowerInvariant() switch
        {
            "disabled" => 4,
            "demand" or "manual" => 3,
            "auto" or "automatic" => 2,
            _ => -1,
        };
        if (start < 0) return Log(ExitRefused, $"Unrecognised start type '{args[1]}'.");

        using var key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{name}", writable: true);
        if (key is null) return Log(ExitRefused, $"No such service: {name}");

        // Boot and system-start drivers keep Windows able to boot. Refuse outright rather than
        // trusting the caller to have checked.
        if (key.GetValue("Start") is int current && current <= 1)
            return Log(ExitRefused,
                $"{name} is a boot or system-start driver. Changing it could stop Windows starting; refusing.");

        key.SetValue("Start", start, RegistryValueKind.DWord);
        return Log(ExitPerformed, $"Set {name} start type to {args[1]}.");
    }

    /// <summary>args: [subKeyPath, valueName]</summary>
    private static int RemoveMachinePersistence(IReadOnlyList<string> args)
    {
        if (args.Count != 2) return Log(ExitRefused, "RemoveMachinePersistence expects a key path and a value name.");

        string path = args[0].Trim('\\');
        string value = args[1];

        if (!AllowedMachineAutorunKeys.Any(k => string.Equals(k, path, StringComparison.OrdinalIgnoreCase)))
            return Log(ExitRefused, $"Refusing to modify {path}: not one of HERO's known autorun locations.");

        using var key = Registry.LocalMachine.OpenSubKey(path, writable: true);
        if (key is null) return Log(ExitRefused, $"Key not found: {path}");
        if (key.GetValue(value) is null) return Log(ExitPerformed, $"{value} was already absent from {path}.");

        // Winlogon values must never be deleted outright: Userinit and Shell are required for a
        // usable desktop. HERO only ever resets them to their documented defaults.
        if (path.EndsWith("Winlogon", StringComparison.OrdinalIgnoreCase))
        {
            string? restored = value.ToLowerInvariant() switch
            {
                "userinit" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "userinit.exe") + ",",
                "shell" => "explorer.exe",
                _ => null,
            };
            if (restored is null)
                return Log(ExitRefused, $"Refusing to delete Winlogon value {value}; only Userinit and Shell can be reset.");

            key.SetValue(value, restored, RegistryValueKind.String);
            return Log(ExitPerformed, $"Reset Winlogon {value} to its default.");
        }

        key.DeleteValue(value, throwOnMissingValue: false);
        return Log(ExitPerformed, $"Removed {value} from HKLM\\{path}.");
    }

    /// <summary>args: [exePath, ruleName]</summary>
    private static int BlockProcessNetwork(IReadOnlyList<string> args)
    {
        if (args.Count != 2) return Log(ExitRefused, "BlockProcessNetwork expects a program path and a rule name.");

        string exe = args[0];
        string rule = args[1];

        if (!File.Exists(exe)) return Log(ExitRefused, $"No such program: {exe}");
        if (!rule.StartsWith("HERO ", StringComparison.Ordinal))
            return Log(ExitRefused, "Refusing to create a firewall rule that is not tagged as HERO's, because HERO could not then find and remove it again.");

        int outbound = RunNetsh($"advfirewall firewall add rule name=\"{rule}\" dir=out action=block program=\"{exe}\" enable=yes");
        int inbound = RunNetsh($"advfirewall firewall add rule name=\"{rule}\" dir=in action=block program=\"{exe}\" enable=yes");

        return outbound == 0 && inbound == 0
            ? Log(ExitPerformed, $"Blocked inbound and outbound traffic for {exe}.")
            : Log(ExitFailed, $"netsh returned {outbound}/{inbound} while adding the rules.");
    }

    /// <summary>args: [pid]</summary>
    private static int TerminateProcess(IReadOnlyList<string> args)
    {
        if (args.Count != 1 || !int.TryParse(args[0], out int pid))
            return Log(ExitRefused, "TerminateProtectedProcess expects a single numeric process id.");
        if (pid <= 4) return Log(ExitRefused, "Refusing to terminate a core system process.");

        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill(entireProcessTree: true);
            return Log(ExitPerformed, $"Terminated pid {pid} and its children.");
        }
        catch (ArgumentException)
        {
            return Log(ExitPerformed, $"pid {pid} had already exited.");
        }
    }

    private static int RunNetsh(string arguments)
    {
        var psi = new ProcessStartInfo("netsh.exe", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi);
        if (p is null) return -1;
        p.StandardOutput.ReadToEnd();
        p.WaitForExit(30000);
        return p.ExitCode;
    }

    /// <summary>
    /// The elevated child has no window, so its only way to explain itself is the log. Every
    /// privileged operation writes one line whether it succeeded, refused or failed.
    ///
    /// Per-user, alongside the rest of the app's diagnostics. This child holds an Administrators
    /// token, so it COULD still write into the locked state directory — but it is acting for the
    /// signed-in user, on that user's request, and its account of itself is the user's to read.
    /// Keeping it here leaves %ProgramData%\HERO holding only what the guardian itself owns.
    /// </summary>
    private static int Log(int code, string message)
    {
        HeroPaths.WriteUserLog("elevated.log",
            $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{code}] {message}{Environment.NewLine}");
        return code;
    }
}
