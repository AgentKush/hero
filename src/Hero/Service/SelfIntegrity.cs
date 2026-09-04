using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Hero.Service;

/// <summary>
/// Watches HERO's own installed files for modification.
///
/// This is the honest half of HERO's self-defence. Installing under %ProgramFiles% stops a
/// non-elevated process from rewriting the binaries at all; nothing stops an elevated one. So the
/// second line is not prevention but evidence: a manifest of SHA-256 hashes recorded at install
/// time, re-checked on a timer, with any divergence written to a log that lives outside the
/// install directory.
///
/// The manifest is not a signature and does not pretend to be. An attacker with administrator
/// rights can rewrite a binary AND the manifest, and this will report everything as fine. What it
/// catches is the far more common case: something modified a file and did not know, or did not
/// bother, to forge the record. Saying which of those two this defends against is the difference
/// between a security feature and a comfort blanket.
/// </summary>
internal static class SelfIntegrity
{
    private const string ManifestName = "integrity.json";

    /// <summary>How often the installed files are re-hashed. Cheap: seven files, ~27 MB.</summary>
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    private static string ManifestPath => Path.Combine(ServiceLog.Directory, ManifestName);

    internal sealed record Entry(string Name, long Length, string Sha256);

    /// <summary>
    /// <paramref name="InstallDirectoryUnsafe"/> records that the service was registered from a
    /// directory a standard user can modify, which is only reachable by passing
    /// <c>--allow-unsafe-install-dir</c>. It is written into the manifest rather than only logged
    /// because the manifest is the thing that survives, is protected from the user, and is read
    /// back later — a log line scrolls away, and this is a fact about how much the integrity
    /// record is worth. Hashes recorded for a directory the attacker can rewrite prove far less
    /// than hashes recorded for one they cannot.
    ///
    /// Defaulted so that manifests written by earlier builds still deserialise.
    /// </summary>
    internal sealed record Manifest(string InstallDirectory, DateTime RecordedUtc, List<Entry> Files)
    {
        public bool InstallDirectoryUnsafe { get; init; }
        public string? InstallDirectoryUnsafeReason { get; init; }
    }

    private static string? _installDirectory;
    private static bool _installDirectoryRead;

    /// <summary>
    /// Where HERO was installed, as recorded at install time. Null when there is no manifest.
    ///
    /// This is HERO's most trustworthy statement about its own location: the manifest is written
    /// while elevated and lives under %ProgramData%\HERO, which a non-elevated process cannot
    /// modify or delete (both verified). Self-recognition anchors on it so that HERO does not
    /// mistake its own service for an intruder just because a different build happens to be the
    /// one running — the mistake that put a "Quarantine target file" button next to HERO's own
    /// service on the Threats page.
    ///
    /// Read once. If someone with the rights to rewrite it does so mid-session, they already had
    /// the rights to stop the service outright, so re-reading would buy nothing.
    /// </summary>
    internal static string? RecordedInstallDirectory
    {
        get
        {
            if (_installDirectoryRead) return _installDirectory;
            _installDirectoryRead = true;

            try
            {
                if (File.Exists(ManifestPath))
                {
                    var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(ManifestPath));
                    _installDirectory = manifest?.InstallDirectory;
                }
            }
            catch { _installDirectory = null; }

            return _installDirectory;
        }
    }

    private static HashSet<string>? _recordedNames;

    /// <summary>
    /// Whether <paramref name="path"/> is one of the files HERO recorded as its own at install
    /// time: inside the recorded directory AND named in the manifest.
    ///
    /// SELF-RECOGNITION USED TO ANCHOR ON THE DIRECTORY ALONE, and that was too wide by exactly the
    /// margin an attacker needs. <c>StartupRegistration.IsOwnStartupArtifact</c> treats the service
    /// key <c>HeroGuardian</c> as HERO's own if its ImagePath resolves inside
    /// <see cref="RecordedInstallDirectory"/>, so an attacker who could write there could:
    ///
    ///   * drop <c>C:\Program Files\HERO\evil.exe</c>,
    ///   * repoint <c>HKLM\System\CurrentControlSet\Services\HeroGuardian</c> at it,
    ///
    /// and HERO's own service — LocalSystem, automatic start — would then run a foreign binary at
    /// every boot while the persistence scanner skipped the entry as "ours" and
    /// <c>IsImpersonation</c> reported nothing. Measured before this change: both behaved exactly
    /// that way. The window in which HERO could still have shouted "my own service now points at
    /// something that is not me" is precisely the window the directory anchor closed.
    ///
    /// It needs administrator rights, and so does installing any service — which is the point. The
    /// bar should not be lower for taking over HERO's identity than for anything else HERO reports.
    ///
    /// The manifest's file LIST is the right granularity. Hashes are deliberately not checked here:
    /// a legitimately updated HERO.exe has a new hash and is still HERO, and noticing changed
    /// content is <see cref="Check"/>'s job, not identity's.
    ///
    /// What this still cannot do is stated in this class's own summary: an attacker who rewrites the
    /// manifest as well is not caught by any of it.
    /// </summary>
    internal static bool IsRecordedFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (RecordedInstallDirectory is not { Length: > 0 } directory) return false;

        string full, root;
        try
        {
            full = Path.GetFullPath(path.Trim());
            root = Path.GetFullPath(directory.Trim());
        }
        catch { return false; }

        if (!root.EndsWith(Path.DirectorySeparatorChar)) root += Path.DirectorySeparatorChar;
        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;

        var names = _recordedNames ??= LoadRecordedNames();
        if (names.Count == 0) return false;      // no manifest is no evidence, not blanket trust

        // Entry.Name is the path relative to the install root, so compare on that.
        return names.Contains(full[root.Length..]);
    }

    private static HashSet<string> LoadRecordedNames()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (File.Exists(ManifestPath) &&
                JsonSerializer.Deserialize<Manifest>(File.ReadAllText(ManifestPath)) is { } manifest)
            {
                foreach (var entry in manifest.Files) names.Add(entry.Name);
            }
        }
        catch { }
        return names;
    }

    // ------------------------------------------------------------------ recording

    /// <summary>
    /// Records the hash of every file in the install directory. Called once, at install time,
    /// while the caller is still elevated.
    /// </summary>
    internal static void Record(string installDirectory, string? unsafeReason = null)
    {
        var manifest = new Manifest(installDirectory, DateTime.UtcNow, Hash(installDirectory))
        {
            InstallDirectoryUnsafe = !string.IsNullOrEmpty(unsafeReason),
            InstallDirectoryUnsafeReason = unsafeReason,
        };

        Directory.CreateDirectory(ServiceLog.Directory);
        File.WriteAllText(ManifestPath,
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);

        // The manifest is the service's evidence, not the app's state, so it does not inherit the
        // directory's user-writable ACL. Without this the tamper record can be forged by whatever
        // did the tampering.
        Core.HeroPaths.ProtectServiceOwnedFile(ManifestPath);

        ServiceLog.Write($"Integrity manifest recorded for {manifest.Files.Count} files in {installDirectory}.");
    }

    private static List<Entry> Hash(string directory)
    {
        var entries = new List<Entry>();

        foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                                      .OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                using var stream = File.OpenRead(file);
                byte[] digest = SHA256.HashData(stream);
                entries.Add(new Entry(
                    Path.GetRelativePath(directory, file),
                    new FileInfo(file).Length,
                    Convert.ToHexString(digest)));
            }
            catch (Exception ex)
            {
                ServiceLog.Write($"Could not hash {file}: {ex.GetType().Name}.");
            }
        }

        return entries;
    }

    // ------------------------------------------------------------------ watching

    /// <summary>Starts the periodic check on a background thread. Returns immediately.</summary>
    internal static void Begin(ManualResetEventSlim stopping)
    {
        var thread = new Thread(() => Loop(stopping))
        {
            IsBackground = true,
            Name = "HERO self-integrity",
        };
        thread.Start();
    }

    private static void Loop(ManualResetEventSlim stopping)
    {
        // Check once at start, then on the interval. The start-up check is the important one: it
        // runs after every SCM restart, which includes the restart that follows being killed.
        do
        {
            try { CheckOnce(); }
            catch (Exception ex) { ServiceLog.Write("Integrity check failed: " + ex.Message); }
        }
        while (!stopping.Wait(Interval));
    }

    /// <summary>Outcome of the most recent check, for the IPC layer to hand to the UI.</summary>
    internal sealed record Report(DateTime CheckedUtc, DateTime? RecordedUtc, int FileCount, List<string> Changes);

    /// <summary>Null until the first check completes. Written once per check, read by any thread.</summary>
    internal static Report? LastReport { get; private set; }

    private static void CheckOnce()
    {
        if (!File.Exists(ManifestPath))
        {
            ServiceLog.Write("No integrity manifest; nothing to compare against. " +
                             "Reinstall to record one.");
            LastReport = new Report(DateTime.UtcNow, null, 0,
                new List<string> { "No integrity manifest has been recorded." });
            return;
        }

        var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(ManifestPath));
        if (manifest is null || !Directory.Exists(manifest.InstallDirectory))
        {
            ServiceLog.Write("Integrity manifest is unreadable or its install directory is gone.");
            return;
        }

        var now = Hash(manifest.InstallDirectory).ToDictionary(e => e.Name, StringComparer.OrdinalIgnoreCase);
        var then = manifest.Files.ToDictionary(e => e.Name, StringComparer.OrdinalIgnoreCase);

        var changed = new List<string>();

        foreach (var (name, recorded) in then)
        {
            if (!now.TryGetValue(name, out var current)) { changed.Add($"MISSING  {name}"); continue; }
            if (!string.Equals(current.Sha256, recorded.Sha256, StringComparison.OrdinalIgnoreCase))
                changed.Add($"MODIFIED {name}  ({recorded.Length} -> {current.Length} bytes)");
        }

        foreach (var name in now.Keys.Where(n => !then.ContainsKey(n)))
            changed.Add($"ADDED    {name}");

        LastReport = new Report(DateTime.UtcNow, manifest.RecordedUtc, manifest.Files.Count, changed);

        if (changed.Count == 0) return;

        // Loud, and repeated on every check. A tamper report that scrolls away after one line is
        // one nobody sees.
        ServiceLog.Write($"*** SELF-INTEGRITY FAILURE: {changed.Count} change(s) since install ***");
        foreach (var line in changed) ServiceLog.Write("    " + line);
    }
}
