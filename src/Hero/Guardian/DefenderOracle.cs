using System.Diagnostics;

namespace Hero.Guardian;

internal enum OracleVerdict
{
    /// <summary>Defender scanned the file and found nothing.</summary>
    Clean,
    /// <summary>Defender identified a threat. <see cref="OracleResult.ThreatName"/> names it.</summary>
    Threat,
    /// <summary>The scan could not be performed (Defender busy, disabled, or replaced by another AV).</summary>
    Unavailable,
    /// <summary>The file vanished or could not be reached.</summary>
    Inaccessible,
}

internal sealed record OracleResult(
    OracleVerdict Verdict,
    string ThreatName,
    string Detail,
    TimeSpan Elapsed)
{
    internal bool IsThreat => Verdict == OracleVerdict.Threat;
}

/// <summary>
/// HERO's malware-intelligence source: Microsoft Defender, running locally on this machine.
///
/// The obvious instinct when a host tool needs reputation data is to reach for a cloud API.
/// That instinct is wrong here for three reasons:
///
///   * **Privacy.** Sending hashes to a third party leaks an inventory of everything installed on
///     the machine. HERO promises no network egress by default, and this keeps that promise.
///   * **Authority.** Defender ships with the OS, updates its signatures several times a day
///     (measured: 0 days old on this machine), and is the same engine that already quarantined
///     three real threats here today. A free-tier third-party API is not better informed.
///   * **Cost.** It is free, unlimited, and needs no API key, no account and no rate limiting.
///
/// Verified working UNELEVATED on this machine: scanning a file containing the standard EICAR
/// test string returned "found 1 threats", remediated it, and exited 0.
///
/// This is deliberately a second opinion, not the first. HERO's own heuristics catch behaviour
/// (beaconing, persistence, masquerading) that no signature scanner sees; Defender catches known
/// binaries HERO has never heard of. They are complementary, and asking Defender is reserved for
/// files that HERO already finds suspicious, because a scan costs seconds rather than milliseconds.
/// </summary>
internal static class DefenderOracle
{
    private static readonly string MpCmdRun = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "Windows Defender", "MpCmdRun.exe");

    internal static bool IsAvailable => File.Exists(MpCmdRun);

    /// <summary>
    /// Asks Defender to scan one specific file and waits for its verdict.
    ///
    /// NOTE: this is not a read-only query. If Defender finds a threat it will ACT on it under
    /// the machine's configured policy — on this machine that meant quarantining the test file
    /// outright. Callers must treat a Threat verdict as "the file may no longer be there", and
    /// must never call this speculatively across a large file set.
    /// </summary>
    internal static async Task<OracleResult> ScanFileAsync(string path, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        if (!IsAvailable)
            return new(OracleVerdict.Unavailable, "", "MpCmdRun.exe not present.", sw.Elapsed);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return new(OracleVerdict.Inaccessible, "", "File not found.", sw.Elapsed);

        try
        {
            var psi = new ProcessStartInfo(MpCmdRun)
            {
                // ScanType 3 is a custom scan of a single path.
                Arguments = $"-Scan -ScanType 3 -File \"{path}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null)
                return new(OracleVerdict.Unavailable, "", "Could not start MpCmdRun.", sw.Elapsed);

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);
            sw.Stop();

            // A concurrent scan makes MpCmdRun refuse outright. Observed repeatedly on this
            // machine while Defender was mid-sweep, so it must be handled as a normal outcome
            // rather than an error.
            if (stdout.Contains("already in progress", StringComparison.OrdinalIgnoreCase))
                return new(OracleVerdict.Unavailable, "", "Defender is busy with another scan.", sw.Elapsed);

            // Output is localised, so match on the numeric portion rather than the sentence.
            // Observed English form: "Scanning <path> found 1 threats."
            var found = System.Text.RegularExpressions.Regex.Match(stdout, @"found\s+(\d+)\s+threat");
            if (found.Success && int.TryParse(found.Groups[1].Value, out int n) && n > 0)
            {
                string name = await MostRecentThreatNameAsync(ct);
                return new(OracleVerdict.Threat, name,
                    $"Defender reported {n} threat(s) and applied its configured action.", sw.Elapsed);
            }

            // Exit code 0 with no threat line is a clean result.
            if (proc.ExitCode == 0)
                return new(OracleVerdict.Clean, "", "Defender found nothing.", sw.Elapsed);

            return new(OracleVerdict.Unavailable, "",
                $"MpCmdRun exited {proc.ExitCode}.", sw.Elapsed);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new(OracleVerdict.Unavailable, "", $"{ex.GetType().Name}: {ex.Message}", sw.Elapsed);
        }
    }

    /// <summary>
    /// The name Defender gave its most recent detection, read from its Operational log.
    /// MpCmdRun does not print the threat name, so this recovers it after the fact.
    /// </summary>
    private static async Task<string> MostRecentThreatNameAsync(CancellationToken ct)
    {
        try
        {
            return await Task.Run(() =>
            {
                var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                    "Microsoft-Windows-Windows Defender/Operational",
                    System.Diagnostics.Eventing.Reader.PathType.LogName,
                    "*[System[(EventID=1116 or EventID=1117)]]")
                { ReverseDirection = true };

                using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
                if (reader.ReadEvent() is not { } ev) return "";
                using (ev)
                {
                    var text = ev.FormatDescription() ?? "";
                    var m = System.Text.RegularExpressions.Regex.Match(text, @"Name:\s*(\S+)");
                    return m.Success ? m.Groups[1].Value : "";
                }
            }, ct);
        }
        catch { return ""; }
    }

    /// <summary>
    /// Defender's local detection history — a free, already-present threat database describing
    /// what has actually happened on THIS machine. HERO correlates it with its own timeline so a
    /// detection and the process that dropped the file appear as one incident.
    /// </summary>
    internal static List<DefenderDetection> RecentDetections(TimeSpan window)
    {
        var results = new List<DefenderDetection>();
        try
        {
            var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                "Microsoft-Windows-Windows Defender/Operational",
                System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[(EventID=1116 or EventID=1117)]]")
            { ReverseDirection = true };

            using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
            var cutoff = DateTime.Now - window;

            while (reader.ReadEvent() is { } ev)
            {
                using (ev)
                {
                    if (ev.TimeCreated is not { } when || when < cutoff) break;

                    var text = (ev.FormatDescription() ?? "").Replace("\r", " ").Replace("\n", " ");
                    results.Add(new DefenderDetection(
                        when,
                        Field(text, @"Name:\s*(\S+)"),
                        Field(text, @"Severity:\s*(\w+)"),
                        Field(text, @"Path:\s*(.+?)(?:\s+Detection Origin:|$)"),
                        Field(text, @"Action:\s*(\S+)"),
                        ev.Id == 1117));
                }
            }
        }
        catch { /* channel unavailable; caller shows this as unknown rather than clean */ }
        return results;
    }

    private static string Field(string text, string pattern)
    {
        var m = System.Text.RegularExpressions.Regex.Match(text, pattern);
        return m.Success ? m.Groups[1].Value.Trim() : "";
    }
}

internal sealed record DefenderDetection(
    DateTime When,
    string ThreatName,
    string Severity,
    string Path,
    string Action,
    bool ActionTaken);
