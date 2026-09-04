namespace Hero.Service;

/// <summary>
/// The service's log.
///
/// It writes to %ProgramData%, not %LOCALAPPDATA%: a LocalSystem service's "local app data" is
/// <c>C:\Windows\System32\config\systemprofile\AppData\Local</c>, which the signed-in user cannot
/// browse to and would never think to look in. %ProgramData% is reachable by both.
///
/// Deliberately plain text and deliberately append-only. This is the file a person reads at
/// 2am when the service will not start, so it must be legible without HERO running.
/// </summary>
internal static class ServiceLog
{
    private static readonly object Gate = new();
    private static bool _protected;

    /// <summary>
    /// The same root <see cref="Core.HeroPaths"/> uses. Taken from there rather than recomputed,
    /// because two definitions of "where HERO's state lives" is exactly one too many.
    /// </summary>
    internal static string Directory => Core.HeroPaths.Root;

    private static string Path_ => Path.Combine(Directory, "service.log");

    /// <summary>Caps the log so a restart loop cannot fill the disk it is meant to protect.</summary>
    private const long MaxBytes = 2 * 1024 * 1024;

    internal static void Write(string message)
    {
        try
        {
            lock (Gate)
            {
                System.IO.Directory.CreateDirectory(Directory);

                var file = new FileInfo(Path_);
                if (file.Exists && file.Length > MaxBytes)
                {
                    // One generation of history is enough to see what happened before a fault.
                    string previous = Path_ + ".1";
                    File.Delete(previous);
                    File.Move(Path_, previous);
                }

                File.AppendAllText(Path_,
                    $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z  {message}{Environment.NewLine}");

                // The log carries the self-integrity findings, so a user-level process able to
                // truncate it would erase exactly the evidence it exists to preserve.
                //
                // Once per process, and deliberately NOT gated on "did this call create the
                // file". That was the first attempt and it failed in the ordinary upgrade case:
                // during a reinstall the OLD service was still running, recreated the log itself,
                // and the new build then saw a file that already existed and never protected it.
                // Measured after that upgrade — Users held inherited Modify on service.log.
                if (!_protected)
                {
                    _protected = true;
                    Core.HeroPaths.ProtectServiceOwnedFile(Path_);
                }
            }
        }
        catch
        {
            // A logger that throws takes the service down with it, which is precisely backwards.
        }
    }
}
