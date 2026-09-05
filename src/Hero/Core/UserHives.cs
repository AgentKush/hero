using Microsoft.Win32;
using System.Security.Principal;

namespace Hero.Core;

/// <summary>One signed-in account whose registry hive is currently loaded.</summary>
/// <param name="Sid">The account's SID, which is also its subkey name under HKEY_USERS.</param>
/// <param name="ProfilePath">Filesystem profile root, from ProfileList. Empty when unknown.</param>
/// <param name="Account">DOMAIN\user where it could be resolved, otherwise the SID.</param>
internal readonly record struct UserHive(string Sid, string ProfilePath, string Account)
{
    /// <summary>How this hive should be named in a finding: HKU\&lt;account&gt; reads better than a SID.</summary>
    internal string DisplayRoot => $"HKU\\{Account}";
}

/// <summary>
/// The signed-in users HERO should be looking at, rather than whoever HERO happens to be running as.
///
/// THIS EXISTS BECAUSE THE GUARDIAN MOVED INTO A SERVICE AND NOTHING FOLLOWED IT. Every
/// profile-relative lookup in the engine was written when HERO ran as the signed-in user, where
/// <c>Registry.CurrentUser</c> and <c>Environment.GetFolderPath</c> mean what you would expect.
/// Under LocalSystem they still resolve — silently, and to the wrong place: HKCU becomes the
/// service account's own hive, and the profile folders resolve inside
/// <c>C:\Windows\system32\config\systemprofile</c>. Nothing errors. The scan simply comes back
/// empty and reports a clean machine.
///
/// The cost of that was the whole point of the product: every per-user Run key and Startup folder
/// on the machine — which is the autorun surface that does not need administrator rights, and so
/// the one most malware actually uses — went unscanned in the shipping configuration.
///
/// ENUMERATING LOADED HIVES rather than resolving "the console user" is deliberate, and it is the
/// better answer for a scanner rather than merely the easier one. A machine can have several
/// people signed in at once, and an autorun belonging to the switched-out account is no less real
/// than one belonging to the person at the keyboard. It also needs no token and no privilege: the
/// same code gives the right answer when HERO runs as LocalSystem, and when the unelevated
/// in-process guardian runs it and can see only its own hive.
///
/// A hive is here because it is LOADED, which for a normal account means that user is signed in.
/// Users who are logged off are deliberately not scanned: their autoruns cannot run until they log
/// on, at which point their hive loads and the next sweep sees them.
/// </summary>
internal static class UserHives
{
    private const string ProfileList =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    /// <summary>
    /// Every loaded human account hive, newest lookup each call.
    ///
    /// Not cached: users sign in and out, and a scanner that cached this at start-up would keep
    /// reporting on a hive that had gone and miss one that arrived. The whole call is a handful of
    /// registry reads.
    /// </summary>
    internal static IReadOnlyList<UserHive> Loaded()
    {
        var result = new List<UserHive>(4);

        try
        {
            foreach (var sid in Registry.Users.GetSubKeyNames())
            {
                // S-1-5-21-… is the shape of an account issued by a local machine or a domain.
                // Everything else under HKEY_USERS is Windows' own: .DEFAULT, and the built-in
                // service accounts S-1-5-18/19/20 — one of which is the hive HERO was reading.
                if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) continue;

                // Every loaded hive has a _Classes companion holding HKCR. It is the same user.
                if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;

                result.Add(new UserHive(sid, ProfilePathOf(sid), AccountOf(sid)));
            }
        }
        catch { /* HKEY_USERS unreadable: fall through to the self fallback below */ }

        // Nothing enumerable — which happens when the process cannot read HKEY_USERS at all.
        // Fall back to the account HERO is running as, so an unelevated guardian still scans the
        // user it belongs to rather than scanning nothing.
        if (result.Count == 0)
        {
            try
            {
                using var me = WindowsIdentity.GetCurrent();
                if (me.User is { } sid && sid.Value.StartsWith("S-1-5-21-", StringComparison.Ordinal))
                    result.Add(new UserHive(sid.Value, ProfilePathOf(sid.Value), me.Name));
            }
            catch { }
        }

        return result;
    }

    /// <summary>
    /// Opens one user's hive under HKEY_USERS, in the requested view.
    ///
    /// Returns null rather than throwing when the hive cannot be opened — running unelevated, one
    /// user cannot read another's hive, and that is an ordinary outcome rather than an error.
    /// </summary>
    internal static RegistryKey? Open(UserHive user, RegistryView view, string subPath)
    {
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
            return users.OpenSubKey($"{user.Sid}\\{subPath}");
        }
        catch { return null; }
    }

    /// <summary>
    /// One user's Startup folder.
    ///
    /// Read from the user's own shell-folder registration rather than assembled from a convention,
    /// because a redirected profile — roaming, or a OneDrive-backed Known Folder — puts it
    /// somewhere the convention does not predict. The conventional path is the last resort, not
    /// the first guess.
    /// </summary>
    internal static string StartupFolder(UserHive user) =>
        ShellFolder(user, "Startup", @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");

    /// <summary>
    /// The six folders Controlled Folder Access guards, for one user.
    ///
    /// Resolved per user for the same reason as everything else here, and read from the shell
    /// registration rather than assembled: Documents and Pictures are the two folders Windows most
    /// often redirects into OneDrive, and a hand-built %USERPROFILE%\Documents would then name a
    /// directory Defender is not guarding while missing the one it is.
    /// </summary>
    internal static IEnumerable<string> ControlledFolders(UserHive user)
    {
        yield return ShellFolder(user, "Desktop", "Desktop");
        yield return ShellFolder(user, "Personal", "Documents");
        yield return ShellFolder(user, "My Pictures", "Pictures");
        yield return ShellFolder(user, "My Video", "Videos");
        yield return ShellFolder(user, "My Music", "Music");
        yield return ShellFolder(user, "Favorites", "Favorites");
    }

    /// <summary>
    /// One of a user's shell folders, by its registry value name.
    ///
    /// Shell Folders holds the already-expanded path, which is why it is tried first: expanding the
    /// %USERPROFILE% in User Shell Folders would expand it in HERO's environment, and under the
    /// service that is the systemprofile directory all over again.
    /// </summary>
    private static string ShellFolder(UserHive user, string valueName, string fallbackRelative)
    {
        using (var shell = Open(user, RegistryView.Registry64,
                   @"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"))
        {
            if (shell?.GetValue(valueName) is string { Length: > 0 } expanded)
                return expanded;
        }

        using (var unexpanded = Open(user, RegistryView.Registry64,
                   @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
        {
            if (unexpanded?.GetValue(valueName, null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames) is string { Length: > 0 } raw
                && user.ProfilePath.Length > 0)
            {
                // Substituted against THIS user's profile, never the environment's.
                return raw.Replace("%USERPROFILE%", user.ProfilePath, StringComparison.OrdinalIgnoreCase);
            }
        }

        return user.ProfilePath.Length > 0 ? Path.Combine(user.ProfilePath, fallbackRelative) : "";
    }

    /// <summary>
    /// Whether Defender's Controlled Folder Access is actually switched on.
    ///
    /// HERO used to ASSERT it was, in a message shown to the user after a failed quarantine, on no
    /// evidence beyond the path being inside a guarded folder. On a machine with the feature off
    /// that sent the user to a Windows Security page to fix something that was not the problem,
    /// and buried the real reason the move failed.
    ///
    /// 1 is enabled and 2 is audit-only, which blocks nothing — so only 1 counts. Policy wins over
    /// the local setting when both are present, which is how a managed machine behaves.
    /// </summary>
    internal static bool ControlledFolderAccessEnabled()
    {
        const string Policy =
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
        const string Local =
            @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";

        foreach (var path in new[] { Policy, Local })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key?.GetValue("EnableControlledFolderAccess") is int value) return value == 1;
            }
            catch { }
        }
        return false;
    }

    // ------------------------------------------------------------------ folder roots

    /// <summary>The profile-relative directories that mean something different for every account.</summary>
    /// <param name="Profile">Profile root, e.g. C:\Users\alice.</param>
    /// <param name="LocalAppData">…\AppData\Local.</param>
    /// <param name="RoamingAppData">…\AppData\Roaming.</param>
    /// <param name="Temp">…\AppData\Local\Temp.</param>
    /// <param name="Downloads">The user's Downloads, which is commonly redirected into OneDrive.</param>
    internal readonly record struct UserFolders(
        string Profile, string LocalAppData, string RoamingAppData, string Temp, string Downloads);

    private static readonly object FolderGate = new();
    private static IReadOnlyList<UserFolders>? _folders;
    private static DateTime _foldersUtc;

    /// <summary>
    /// Profile-relative roots for every signed-in user, cached briefly.
    ///
    /// Cached because path classification is on the hot path — every process start is classified —
    /// and rebuilding this means a registry walk. Cached only BRIEFLY because people sign in and
    /// out, and a root set fixed at start-up would classify a newly signed-in user's Downloads as
    /// an unrecognised location for the rest of the service's life.
    ///
    /// Thirty seconds is the compromise: three orders of magnitude cheaper than the per-classify
    /// cost it replaces, and far shorter than the ten-minute persistence sweep, so no sweep ever
    /// runs entirely against a stale set.
    /// </summary>
    internal static IReadOnlyList<UserFolders> Folders()
    {
        lock (FolderGate)
        {
            var now = DateTime.UtcNow;
            if (_folders is { } cached && now - _foldersUtc < TimeSpan.FromSeconds(30))
                return cached;

            var built = new List<UserFolders>(4);
            foreach (var user in Loaded())
            {
                if (user.ProfilePath.Length == 0) continue;
                string p = user.ProfilePath.TrimEnd('\\');
                built.Add(new UserFolders(
                    Profile: p,
                    LocalAppData: Path.Combine(p, @"AppData\Local"),
                    RoamingAppData: Path.Combine(p, @"AppData\Roaming"),
                    Temp: Path.Combine(p, @"AppData\Local\Temp"),
                    Downloads: DownloadsOf(user, p)));
            }

            _folders = built;
            _foldersUtc = now;
            return built;
        }
    }

    /// <summary>
    /// One user's Downloads folder, from their own shell-folder registration.
    ///
    /// Read rather than assembled because on Windows 11 Downloads is commonly redirected into
    /// OneDrive, and a hand-built %USERPROFILE%\Downloads would then name a folder nothing is ever
    /// downloaded into — which for a security tool is the folder that matters most.
    /// </summary>
    private static string DownloadsOf(UserHive user, string profile)
    {
        const string DownloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}";

        using (var shell = Open(user, RegistryView.Registry64,
                   @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
        {
            if (shell?.GetValue(DownloadsGuid, null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames) is string { Length: > 0 } raw)
            {
                // Against THIS user's profile, never the environment's — the same trap as
                // StartupFolder, and the reason both resolve by substitution rather than expansion.
                return raw.Replace("%USERPROFILE%", profile, StringComparison.OrdinalIgnoreCase);
            }
        }

        return Path.Combine(profile, "Downloads");
    }

    private static string ProfilePathOf(string sid)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{ProfileList}\{sid}");
            // Expanded here rather than left raw: ProfileImagePath is REG_EXPAND_SZ containing
            // %SystemDrive%, which is machine-wide and so means the same thing to every account.
            if (key?.GetValue("ProfileImagePath") is string { Length: > 0 } path)
                return Environment.ExpandEnvironmentVariables(path);
        }
        catch { }
        return "";
    }

    private static string AccountOf(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch
        {
            // An account from a domain this machine cannot reach, or one since deleted. The SID is
            // still a true and usable name for it.
            return sid;
        }
    }
}
