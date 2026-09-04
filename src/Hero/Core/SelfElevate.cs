using System.Diagnostics;

namespace Hero.Core;

/// <summary>
/// Relaunching the whole of HERO with administrator rights.
///
/// This is deliberately separate from <see cref="Elevation.RunElevated"/>, which exists to
/// perform ONE operation in a short-lived child. This is the other case: the user has decided
/// they want HERO itself to run elevated for the session, because unelevated it cannot read
/// image paths, command lines or integrity levels for SYSTEM-integrity processes — 136 of 328
/// on this machine.
///
/// It stays opt-in and per-session rather than becoming the default. A tray app that demands
/// administrator rights at every logon trains the user to approve UAC prompts without reading
/// them, which costs more security than the extra visibility buys.
/// </summary>
internal static class SelfElevate
{
    /// <summary>What elevating would actually gain, in this machine's own numbers.</summary>
    internal static string DescribeBenefit(int unreadableProcesses) =>
        unreadableProcesses <= 0
            ? "HERO can already read every process on this machine."
            : $"{unreadableProcesses} processes cannot be fully read right now. Running as administrator " +
              "reveals their image paths, command lines and integrity levels, and lets HERO read the " +
              "Security event log, change service start types and add firewall rules without a further prompt. " +
              "A handful of protected-process components such as the Defender engine stay unreadable even then.";

    internal static bool AlreadyElevated => Elevation.IsElevated;

    /// <summary>
    /// Starts an elevated copy and asks the current one to exit.
    ///
    /// The order matters: the new process must be confirmed started before this one shuts down,
    /// or a cancelled UAC prompt would leave the machine with no HERO running at all.
    /// </summary>
    internal static (bool Started, string Message) Relaunch(bool tray)
    {
        if (Elevation.IsElevated)
            return (false, "HERO is already running with administrator rights.");

        var exe = StartupRegistration.ExePath;
        if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
            return (false, "HERO cannot determine its own executable path, so it cannot relaunch itself.");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                // --replace tells the incoming copy to WAIT for this one's single-instance mutex
                // instead of exiting on it. Without it the elevated copy started, hit the guard,
                // exited immediately, and this instance then shut down as well.
                Arguments = Elevation.ReplaceSwitch + (tray ? " --tray" : ""),
                UseShellExecute = true,   // required for the runas verb
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(exe) ?? "",
            };

            var started = Process.Start(psi);
            if (started is null)
                return (false, "Windows did not start the elevated copy.");

            return (true, "Elevated copy started. This one will now close.");
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // ERROR_CANCELLED: the user dismissed the UAC prompt. That is a decision, not a fault.
            return (false, "You cancelled the administrator prompt, so HERO is still running normally.");
        }
        catch (Exception ex)
        {
            return (false, $"Could not relaunch: {ex.GetType().Name}: {ex.Message}");
        }
    }
}
