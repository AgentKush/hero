using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Hero.Core;
using Hero.Interop;
using Microsoft.Win32;

namespace Hero.Maintenance;

internal enum HealthState { Good, Watch, Problem, Unknown }

/// <summary>One thing worth saying about the machine's condition.</summary>
/// <param name="Access">Whether the underlying probe actually returned data. A finding with
/// <see cref="AccessState.AccessDenied"/> must render as "needs administrator", never as good news.</param>
internal sealed record HealthFinding(
    string Id, string Title, string Detail, HealthState State, AccessState Access = AccessState.Measured);

/// <summary>A mounted volume, with the media type that drives every optimisation decision.</summary>
internal sealed record VolumeHealth(
    string Root, string Label, long TotalBytes, long FreeBytes, bool SeekPenalty, HealthState State)
{
    internal double PercentFree => TotalBytes > 0 ? FreeBytes * 100.0 / TotalBytes : 0;

    /// <summary>
    /// TRIM is meaningless on a spinning disk and defragmentation is actively harmful on an SSD,
    /// so the advice inverts entirely on this one flag. Getting it backwards is the classic sign
    /// of a maintenance tool that does not know what hardware it is running on.
    /// </summary>
    internal string OptimisationAdvice => SeekPenalty
        ? "Spinning disk: defragmentation is meaningful here, but only above roughly 10% " +
          "fragmentation, and it is an overnight job — never something to run while you work."
        : "Solid-state: TRIM applies, defragmentation does not and only burns write endurance. " +
          "Windows already retrims SSDs weekly through its own scheduled task, so there is " +
          "nothing here for HERO to claim credit for.";
}

/// <summary>A physical disk. The reliability tier is admin-gated and says so.</summary>
internal sealed record PhysicalDiskHealth(
    string FriendlyName, string MediaType, string BusType, long SizeBytes, string HealthStatus,
    AccessState ReliabilityAccess, string ReliabilityNote);

/// <param name="ServicingInFlight">
/// True only when COMPONENT SERVICING itself is mid-transaction — the CBS RebootPending,
/// RebootInProgress or PackagesPending keys.
///
/// Separate from <paramref name="Pending"/> because the two mean very different things to anything
/// that wants to delete update payloads. CBS mid-transaction means files are staged and the restart
/// will consume them; removing the payload store then can genuinely strand it. Windows Update's own
/// RebootRequired means the opposite: the install already finished and is only waiting for a
/// restart to take effect, so the payloads in SoftwareDistribution\Download are spent.
///
/// Measured on this machine while it held 10.46 GB of update cache: CBS RebootPending absent,
/// WU RebootRequired present, TrustedInstaller and wuauserv both Stopped. Nothing was in flight,
/// and HERO refused to clear the cache anyway — correct as a blanket rule, wrong about the machine
/// in front of it.
/// </param>
internal sealed record PendingRebootStatus(
    bool Pending, string Summary, IReadOnlyList<string> Reasons, bool FileRenamesQueued, TimeSpan Uptime,
    bool ServicingInFlight = false);

internal sealed record DefenderStatus(
    AccessState Access, bool RealTimeEnabled, bool TamperProtected, string SignatureVersion,
    DateTime SignaturesUpdatedUtc, uint QuickScanAgeDays, uint FullScanAgeDays,
    bool SignaturesOutOfDate, string Note)
{
    /// <summary>
    /// Defender reports a scan age of 0xFFFFFFFF to mean "never scanned". Rendering that
    /// naively produces roughly 11.7 million years and destroys the credibility of every other
    /// figure on the page, so the sentinel is special-cased here rather than at each call site.
    /// </summary>
    private static string AgeText(uint days) =>
        days == uint.MaxValue ? "never" : days == 0 ? "today" : $"{days} days ago";

    internal string QuickScanDisplay => AgeText(QuickScanAgeDays);
    internal string FullScanDisplay => AgeText(FullScanAgeDays);
}

internal sealed record MemoryPressure(
    long PhysicalTotalBytes, long PhysicalAvailableBytes, long CommitBytes, long CommitLimitBytes)
{
    internal double CommitRatio => CommitLimitBytes > 0 ? (double)CommitBytes / CommitLimitBytes : 0;

    /// <summary>
    /// "Free RAM is low" is a meaningless alert on Windows: the standby list deliberately
    /// consumes nearly all free memory and is instantly reclaimable. Alerting on it would fire
    /// constantly and teach the user to ignore everything HERO says. The real pressure signal is
    /// commit charge against the commit limit — which is also exactly what an Unreal cook or a
    /// large Blender scene actually exhausts.
    /// </summary>
    internal HealthState State => CommitRatio switch
    {
        > 0.92 => HealthState.Problem,
        > 0.80 => HealthState.Watch,
        _ => HealthState.Good,
    };
}

/// <summary>A group of identical errors from one source.</summary>
internal sealed record EventCluster(
    string Provider, int EventId, int Count, DateTime FirstUtc, DateTime LastUtc,
    string SampleMessage, bool Suppressed, double Rank);

internal sealed record UpdateHistoryEntry(DateTime DateUtc, string Title, int ResultCode, int HResult)
{
    internal bool Failed => ResultCode == 4 || ResultCode == 5;
    internal string Outcome => ResultCode switch
    {
        2 => "succeeded",
        3 => "succeeded with errors",
        4 => $"failed (0x{HResult:X8})",
        5 => "aborted",
        _ => "in progress",
    };
}

/// <summary>The trend for one volume, or the honest admission that there is not enough data.</summary>
internal sealed record SpaceTrend(
    string VolumeRoot, int Samples, TimeSpan Span, long MedianDailyDeltaBytes, DateTime? ProjectedFullUtc, string Note);

/// <summary>Everything the health panel shows, assembled in one pass.</summary>
internal sealed record HealthReport
{
    internal required DateTime TakenUtc { get; init; }
    internal required IReadOnlyList<VolumeHealth> Volumes { get; init; }
    internal required IReadOnlyList<PhysicalDiskHealth> Disks { get; init; }
    internal required PendingRebootStatus Reboot { get; init; }
    internal required DefenderStatus Defender { get; init; }
    internal required MemoryPressure Memory { get; init; }
    internal required IReadOnlyList<EventCluster> Events { get; init; }
    internal required IReadOnlyList<UpdateHistoryEntry> Updates { get; init; }
    internal required IReadOnlyList<HealthFinding> Findings { get; init; }
    internal required int Score { get; init; }
    internal required string ScoreExplanation { get; init; }
}

/// <summary>
/// The read-only half of maintenance: what state is this machine actually in?
///
/// The organising principle is the admin boundary, and it was measured rather than guessed.
/// Working unelevated: Get-PhysicalDisk, Get-MpComputerStatus, the Microsoft.Update.Session COM
/// API, the System and Application event logs, the pending-reboot registry keys, fsutil queries,
/// and every per-user path. Confirmed FAILING unelevated: Get-StorageReliabilityCounter and the
/// root\wmi MSStorageDriver_* classes (both return an access error, not empty data), vssadmin
/// list shadowstorage, Get-ComputerRestorePoint, and the Diagnostics-Performance channel which
/// fails even to list.
///
/// So the panel is split into an available tier and a needs-admin tier, and nothing in the
/// second tier is ever rendered as a zero. A 0 °C, 0% wear SMART readout looks like a broken app
/// and is indistinguishable from a healthy drive, which is the worst possible failure mode for a
/// disk-health display.
/// </summary>
internal static class SystemHealth
{
    // ---------------------------------------------------------- media type

    private static readonly ConcurrentDictionary<string, bool> SeekPenaltyCache =
        new(StringComparer.OrdinalIgnoreCase);

    private const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
    private const int StorageDeviceSeekPenaltyProperty = 7;
    private const int PropertyStandardQuery = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct STORAGE_PROPERTY_QUERY
    {
        public int PropertyId;
        public int QueryType;
        public byte AdditionalParameters;
        public byte Pad1, Pad2, Pad3;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DEVICE_SEEK_PENALTY_DESCRIPTOR
    {
        public uint Version;
        public uint Size;
        [MarshalAs(UnmanagedType.U1)] public bool IncursSeekPenalty;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
        ref STORAGE_PROPERTY_QUERY lpInBuffer, int nInBufferSize,
        ref DEVICE_SEEK_PENALTY_DESCRIPTOR lpOutBuffer, int nOutBufferSize,
        out int lpBytesReturned, IntPtr lpOverlapped);

    /// <summary>
    /// True for a mechanical disk.
    ///
    /// This drives scan concurrency, so it is on the hot path and cached per volume. The IOCTL
    /// route is used rather than Get-PhysicalDisk because it needs no PowerShell launch and no
    /// WMI, and because opening the volume with dwDesiredAccess = 0 asks only for the device's
    /// attributes, which succeeds unelevated. When the query fails the answer defaults to FALSE:
    /// treating an unknown disk as solid-state costs some seek thrash, whereas treating an NVMe
    /// as mechanical would serialise every scan on the machine.
    /// </summary>
    internal static bool HasSeekPenalty(string volumeRoot)
    {
        if (string.IsNullOrWhiteSpace(volumeRoot)) return false;
        return SeekPenaltyCache.GetOrAdd(volumeRoot, ProbeSeekPenalty);
    }

    private static bool ProbeSeekPenalty(string volumeRoot)
    {
        string letter = volumeRoot.TrimEnd('\\', '/');
        if (letter.Length != 2 || letter[1] != ':') return false;

        IntPtr handle = Native.CreateFile($@"\\.\{letter}", 0,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE, IntPtr.Zero,
            Native.OPEN_EXISTING, 0, IntPtr.Zero);

        if (handle == Native.INVALID_HANDLE_VALUE) return false;

        try
        {
            var query = new STORAGE_PROPERTY_QUERY
            {
                PropertyId = StorageDeviceSeekPenaltyProperty,
                QueryType = PropertyStandardQuery,
            };
            var descriptor = default(DEVICE_SEEK_PENALTY_DESCRIPTOR);

            bool ok = DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY,
                ref query, Marshal.SizeOf<STORAGE_PROPERTY_QUERY>(),
                ref descriptor, Marshal.SizeOf<DEVICE_SEEK_PENALTY_DESCRIPTOR>(),
                out _, IntPtr.Zero);

            return ok && descriptor.IncursSeekPenalty;
        }
        finally
        {
            Native.CloseHandle(handle);
        }
    }

    // ------------------------------------------------------------- volumes

    internal static IReadOnlyList<VolumeHealth> Volumes()
    {
        var result = new List<VolumeHealth>();
        foreach (var drive in DiskCleanup.FixedDrives())
        {
            try
            {
                long total = drive.TotalSize;
                long free = drive.TotalFreeSpace;
                double pct = total > 0 ? free * 100.0 / total : 0;

                // 10% is the point at which Windows itself starts to misbehave: update staging
                // fails, Defender scans slow down and pagefile growth is constrained. C: sits at
                // 9.5% free on this machine, which is why it is the tightest resource here.
                var state = pct switch
                {
                    < 10 => HealthState.Problem,
                    < 15 => HealthState.Watch,
                    _ => HealthState.Good,
                };

                result.Add(new VolumeHealth(drive.Name, SafeLabel(drive), total, free,
                                            HasSeekPenalty(drive.Name), state));
            }
            catch { /* a volume that went away mid-enumeration */ }
        }
        return result;
    }

    private static string SafeLabel(DriveInfo drive)
    {
        try { return string.IsNullOrWhiteSpace(drive.VolumeLabel) ? drive.Name : drive.VolumeLabel; }
        catch { return drive.Name; }
    }

    // ------------------------------------------------------- physical disks

    /// <summary>
    /// Physical disk inventory.
    ///
    /// Get-PhysicalDisk works unelevated and returns FriendlyName, MediaType, BusType, Size and
    /// HealthStatus. Get-StorageReliabilityCounter — temperature, wear, power-on hours, error
    /// counts — does NOT: it fails with a CIM access error on every disk. Rather than render
    /// blanks, each row carries the reason its reliability tier is missing.
    ///
    /// One wording trap avoided deliberately: HealthStatus is a coarse Storage Spaces verdict,
    /// not a SMART reading. Presenting "Healthy" as "SMART OK" would be a fabrication.
    /// </summary>
    internal static IReadOnlyList<PhysicalDiskHealth> PhysicalDisks()
    {
        var disks = new List<PhysicalDiskHealth>();

        var result = Shell.Run("powershell.exe",
            "-NoProfile -NonInteractive -Command \"Get-PhysicalDisk | Select-Object FriendlyName," +
            "MediaType,BusType,Size,HealthStatus | ConvertTo-Json -Depth 2 -Compress\"", 20000);

        if (!result.Succeeded) return disks;

        string note = MaintenanceGuards.IsElevated
            ? "Wear, temperature and error counts need a further query that HERO has not run."
            : "Wear, temperature, power-on hours and error counts require administrator rights. " +
              "This machine returns an access error for them, not empty data, so nothing is shown " +
              "rather than a misleading zero.";

        foreach (var element in JsonObjects(result.StandardOutput))
        {
            disks.Add(new PhysicalDiskHealth(
                FriendlyName: StringOf(element, "FriendlyName"),
                MediaType: StringOf(element, "MediaType"),
                BusType: StringOf(element, "BusType"),
                SizeBytes: LongOf(element, "Size"),
                HealthStatus: StringOf(element, "HealthStatus"),
                ReliabilityAccess: MaintenanceGuards.IsElevated ? AccessState.NotMeasured : AccessState.AccessDenied,
                ReliabilityNote: note));
        }

        return disks;
    }

    // ------------------------------------------------------- pending reboot

    /// <summary>
    /// Pending-reboot detection, and the gate for anything that touches SoftwareDistribution.
    ///
    /// The CBS and Windows Update keys are weighted heavily. PendingFileRenameOperations is only
    /// corroboration: it is frequently non-empty for entirely benign reasons — an installer
    /// scheduling a temp-file delete for next boot — and treating it as a hard signal produces a
    /// permanent nagging banner that the user learns to ignore.
    /// </summary>
    internal static PendingRebootStatus PendingReboot()
    {
        var reasons = new List<string>();
        var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

        bool KeyExists(string path)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(path);
                return key is not null;
            }
            catch { return false; }
        }

        const string cbs = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\";
        bool servicing = false;
        if (KeyExists(cbs + "RebootPending")) { reasons.Add("component servicing is waiting for a restart"); servicing = true; }
        if (KeyExists(cbs + "RebootInProgress")) { reasons.Add("a servicing operation is mid-restart"); servicing = true; }
        if (KeyExists(cbs + "PackagesPending")) { reasons.Add("packages are staged and pending"); servicing = true; }
        if (KeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
            reasons.Add("Windows Update is waiting for a restart");
        if (KeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending"))
            reasons.Add("an update service registration is pending");

        bool renames = false;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager");
            renames = key?.GetValue("PendingFileRenameOperations") is string[] { Length: > 0 };
        }
        catch { }

        bool pending = reasons.Count > 0;
        string summary = pending
            ? string.Join("; ", reasons) + (uptime.TotalDays >= 7
                ? $"; you have been up for {(int)uptime.TotalDays} days"
                : "")
            : renames
                ? "no restart is required — some files are queued to be renamed at next boot, " +
                  "which is normal installer behaviour"
                : "no restart required";

        return new PendingRebootStatus(pending, summary, reasons, renames, uptime, servicing);
    }

    // ------------------------------------------------------------- Defender

    /// <summary>
    /// Defender freshness.
    ///
    /// Read through Get-MpComputerStatus rather than WMI, because System.Management is not in the
    /// shared framework for this target and there is no in-box managed WMI client. Measured on
    /// this machine: real-time protection on, tamper protection on, signatures updated today —
    /// but a quick scan 130 days old and a full scan age of 4294967295, which is the sentinel for
    /// "never", not a number.
    ///
    /// The honest presentation is to surface both and offer a quick scan, never to launch a full
    /// scan: a full scan across 12 TB of games and 1.8 million toolchain files saturates I/O for
    /// hours. And since HERO does its own detection, the wording must not imply Defender is
    /// failing when it is healthy.
    /// </summary>
    internal static DefenderStatus DefenderFreshness()
    {
        var result = Shell.Run("powershell.exe",
            "-NoProfile -NonInteractive -Command \"Get-MpComputerStatus | Select-Object " +
            "AMServiceEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureVersion," +
            "AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge,DefenderSignaturesOutOfDate | " +
            "ConvertTo-Json -Compress\"", 25000);

        if (!result.Succeeded)
        {
            return new DefenderStatus(AccessState.AccessDenied, false, false, "", DateTime.MinValue,
                uint.MaxValue, uint.MaxValue, false,
                "Defender status could not be read: " + Trim(result.StandardError));
        }

        var element = JsonObjects(result.StandardOutput).FirstOrDefault();
        if (element.ValueKind != JsonValueKind.Object)
        {
            return new DefenderStatus(AccessState.NotMeasured, false, false, "", DateTime.MinValue,
                uint.MaxValue, uint.MaxValue, false, "Defender returned no status object.");
        }

        return new DefenderStatus(
            Access: AccessState.Measured,
            RealTimeEnabled: BoolOf(element, "RealTimeProtectionEnabled"),
            TamperProtected: BoolOf(element, "IsTamperProtected"),
            SignatureVersion: StringOf(element, "AntivirusSignatureVersion"),
            SignaturesUpdatedUtc: DateOf(element, "AntivirusSignatureLastUpdated"),
            QuickScanAgeDays: UIntOf(element, "QuickScanAge"),
            FullScanAgeDays: UIntOf(element, "FullScanAge"),
            SignaturesOutOfDate: BoolOf(element, "DefenderSignaturesOutOfDate"),
            Note: "");
    }

    // --------------------------------------------------------------- memory

    [StructLayout(LayoutKind.Sequential)]
    private struct PERFORMANCE_INFORMATION
    {
        public uint cb;
        public IntPtr CommitTotal, CommitLimit, CommitPeak;
        public IntPtr PhysicalTotal, PhysicalAvailable, SystemCache;
        public IntPtr KernelTotal, KernelPaged, KernelNonpaged, PageSize;
        public uint HandleCount, ProcessCount, ThreadCount;
    }

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetPerformanceInfo(out PERFORMANCE_INFORMATION pPerformanceInformation, uint cb);

    /// <summary>
    /// Memory pressure from GetPerformanceInfo, which returns commit charge and the commit limit
    /// in one call with no counter-set warm-up cost and no WMI.
    /// </summary>
    internal static MemoryPressure Memory()
    {
        try
        {
            uint size = (uint)Marshal.SizeOf<PERFORMANCE_INFORMATION>();
            if (GetPerformanceInfo(out var info, size))
            {
                long page = info.PageSize.ToInt64();
                return new MemoryPressure(
                    info.PhysicalTotal.ToInt64() * page,
                    info.PhysicalAvailable.ToInt64() * page,
                    info.CommitTotal.ToInt64() * page,
                    info.CommitLimit.ToInt64() * page);
            }
        }
        catch { }
        return new MemoryPressure(0, 0, 0, 0);
    }

    // ---------------------------------------------------------- event logs

    /// <summary>
    /// Known-noisy (provider, id) pairs, suppressed from the ranking but never hidden.
    ///
    /// Every entry here was measured on this machine over seven days. AppModel-State 4 fired
    /// 28,833 times and is benign UWP state-repository chatter; ranking clusters by raw count
    /// would put it at the top of the very first weekly report and bury the two Volsnap events
    /// and the ten Windows Update failures that actually matter. Security-SPP and the Intel Wi-Fi
    /// roam/reset events are routine on healthy machines and are in the list from day one for the
    /// same reason.
    /// </summary>
    private static readonly HashSet<string> SuppressedEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft-Windows-AppModel-State/4",
        "Microsoft-Windows-Security-SPP/8211",
        "Microsoft-Windows-Security-SPP/8228",
        "Netwtw10/5002",
        "Netwtw10/5005",
        "Netwtw10/5032",
        "Microsoft-Windows-DistributedCOM/10016",
    };

    /// <summary>
    /// Error clusters from the System and Application logs over the last <paramref name="days"/>.
    ///
    /// The time bound goes INSIDE the XPath query. Filtering in managed code would deserialise
    /// hundreds of thousands of events first — 28,833 from a single provider here — which is both
    /// slow and pointless. Message text is formatted only once per cluster, because
    /// FormatDescription is expensive and can throw when the provider's resource DLL is gone.
    /// </summary>
    internal static IReadOnlyList<EventCluster> EventClusters(int days = 7, int maxClusters = 40)
    {
        var accumulator = new Dictionary<string, (string Provider, int Id, int Count, DateTime First, DateTime Last, string Sample, byte Level)>();
        long windowMs = (long)TimeSpan.FromDays(days).TotalMilliseconds;
        string xpath = $"*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= {windowMs}]]]";

        foreach (var log in new[] { "System", "Application" })
        {
            try
            {
                var query = new EventLogQuery(log, PathType.LogName, xpath) { TolerateQueryErrors = true };
                using var reader = new EventLogReader(query);

                for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
                {
                    using (record)
                    {
                        string provider = record.ProviderName ?? "unknown";
                        int id = record.Id;
                        var when = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
                        string key = provider + "/" + id;

                        if (accumulator.TryGetValue(key, out var acc))
                        {
                            accumulator[key] = (acc.Provider, acc.Id, acc.Count + 1,
                                when < acc.First ? when : acc.First,
                                when > acc.Last ? when : acc.Last,
                                acc.Sample, acc.Level);
                        }
                        else
                        {
                            string sample;
                            try { sample = Trim(record.FormatDescription() ?? ""); }
                            catch { sample = "(the provider's message resources are not available)"; }

                            accumulator[key] = (provider, id, 1, when, when, sample,
                                                (byte)(record.Level ?? 2));
                        }
                    }
                }
            }
            catch (EventLogNotFoundException) { }
            catch (UnauthorizedAccessException) { }
            catch (EventLogException) { }
        }

        var clusters = accumulator.Values.Select(v =>
        {
            bool suppressed = SuppressedEvents.Contains($"{v.Provider}/{v.Id}");
            return new EventCluster(v.Provider, v.Id, v.Count, v.First, v.Last, v.Sample, suppressed,
                                    Rank(v.Level, v.Count));
        });

        return clusters.OrderByDescending(c => c.Suppressed ? -1 : c.Rank)
                       .ThenByDescending(c => c.Count)
                       .Take(maxClusters)
                       .ToList();
    }

    /// <summary>
    /// Severity times rarity, stated explicitly: rank = severity x log10(count+1) x 1/(1+count/500).
    ///
    /// The rarity term is what stops a five-figure count of benign chatter from dominating. Two
    /// Volsnap errors score around 0.95 while 28,833 AppModel-State events score around 0.15, so
    /// the shadow-copy failure leads the report and the noise does not.
    /// </summary>
    private static double Rank(byte level, int count)
    {
        double severity = level switch { 1 => 3.0, 2 => 2.0, _ => 1.0 };
        double rarity = 1.0 / (1.0 + count / 500.0);
        return severity * Math.Log10(count + 1) * rarity;
    }

    // ------------------------------------------------------- Windows Update

    /// <summary>
    /// Update history through the in-box Microsoft.Update.Session COM API, which reads without
    /// administrator rights.
    ///
    /// Late-bound through reflection rather than a generated interop assembly, to keep the
    /// zero-dependency rule. Installation is deliberately NOT driven through this API: on Windows
    /// 11 that fights the Update Orchestrator and can leave downloads half-staged. HERO reports
    /// and defers to the Settings app.
    ///
    /// Get-HotFix is not used as a companion: Win32_QuickFixEngineering only enumerates
    /// MSU/QFE-registered hotfixes, so cumulative and feature updates delivered through CBS never
    /// appear and the list looks alarmingly short on a fully-patched machine.
    /// </summary>
    internal static IReadOnlyList<UpdateHistoryEntry> UpdateHistory(int maxEntries = 50)
    {
        var entries = new List<UpdateHistoryEntry>();
        try
        {
            var type = Type.GetTypeFromProgID("Microsoft.Update.Session");
            if (type is null) return entries;

            object? session = Activator.CreateInstance(type);
            if (session is null) return entries;

            object? searcher = Invoke(session, "CreateUpdateSearcher");
            if (searcher is null) return entries;

            int total = Convert.ToInt32(Invoke(searcher, "GetTotalHistoryCount") ?? 0);
            if (total <= 0) return entries;

            object? history = Invoke(searcher, "QueryHistory", 0, Math.Min(total, maxEntries));
            if (history is null) return entries;

            int count = Convert.ToInt32(GetProperty(history, "Count") ?? 0);
            for (int i = 0; i < count; i++)
            {
                object? item = Invoke(history, "Item", i);
                if (item is null) continue;

                entries.Add(new UpdateHistoryEntry(
                    DateUtc: Convert.ToDateTime(GetProperty(item, "Date") ?? DateTime.MinValue,
                                                CultureInfo.InvariantCulture).ToUniversalTime(),
                    Title: GetProperty(item, "Title") as string ?? "",
                    ResultCode: Convert.ToInt32(GetProperty(item, "ResultCode") ?? 0),
                    HResult: Convert.ToInt32(GetProperty(item, "HResult") ?? 0)));
            }
        }
        catch { /* the COM surface is optional; an empty history is reported as "unknown" */ }

        // The runtime callable wrappers are left to the finaliser rather than released here:
        // ReleaseComObject on a shared session object is exactly how a later call ends up talking
        // to a disconnected RCW, and this is a short-lived read.
        return entries.OrderByDescending(e => e.DateUtc).ToList();
    }

    private static object? Invoke(object target, string method, params object[] args) =>
        target.GetType().InvokeMember(method, BindingFlags.InvokeMethod, null, target, args);

    private static object? GetProperty(object target, string name) =>
        target.GetType().InvokeMember(name, BindingFlags.GetProperty, null, target, null);

    // ---------------------------------------------------------- time service

    /// <summary>
    /// The Windows Time service, reported honestly.
    ///
    /// On a workgroup Windows 11 client W32Time is Manual (Trigger Start) BY DESIGN: it starts on
    /// a trigger, disciplines the clock, and stops again. "w32tm /query /status" returning
    /// 0x80070426 is therefore the normal steady state, not a fault, and changing the start type
    /// to Automatic would be a configuration regression that fights the OS default. Only two
    /// things are genuinely wrong: the service being Disabled, or the last successful sync being
    /// weeks old.
    /// </summary>
    internal static HealthFinding TimeService()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\W32Time");
            if (key is null)
                return new HealthFinding("health.time", "Time synchronisation", "W32Time is not registered.",
                                         HealthState.Unknown);

            int start = Convert.ToInt32(key.GetValue("Start", 3));
            using var config = key.OpenSubKey("Config");
            DateTime lastGood = DateTime.MinValue;
            if (config?.GetValue("LastKnownGoodTime") is long fileTime && fileTime > 0)
            {
                try { lastGood = DateTime.FromFileTimeUtc(fileTime); } catch { }
            }

            if (start == 4)
                return new HealthFinding("health.time", "Time synchronisation",
                    "The Windows Time service is disabled, so the clock is not being corrected " +
                    "against any source. Clock drift breaks TLS validation, git commit ordering " +
                    "and one-time passcodes.", HealthState.Problem);

            if (lastGood != DateTime.MinValue && DateTime.UtcNow - lastGood > TimeSpan.FromDays(30))
                return new HealthFinding("health.time", "Time synchronisation",
                    $"The clock was last disciplined {Human.Age(DateTime.UtcNow - lastGood)} ago.",
                    HealthState.Watch);

            return new HealthFinding("health.time", "Time synchronisation",
                "Trigger-started, which is the correct configuration on Windows 11. The service " +
                "being stopped right now is normal and not a fault.", HealthState.Good);
        }
        catch
        {
            return new HealthFinding("health.time", "Time synchronisation",
                "Could not read the service configuration.", HealthState.Unknown, AccessState.AccessDenied);
        }
    }

    // --------------------------------------------------------- storage sense

    /// <summary>
    /// Storage Sense overlaps directly with several HERO items — Temp, Downloads and recycle-bin
    /// age-out. Two tools deleting the same paths on different schedules makes "bytes reclaimed"
    /// unattributable, and if its Downloads cleanup is enabled then HERO's "we never touch
    /// Downloads" promise is technically true and practically misleading.
    /// </summary>
    internal static HealthFinding StorageSense()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy");
            if (key is null)
                return new HealthFinding("health.storage-sense", "Storage Sense",
                    "Not configured. HERO is the only thing cleaning up here.", HealthState.Good);

            bool enabled = Convert.ToInt32(key.GetValue("01", 0)) != 0;
            int downloadDays = Convert.ToInt32(key.GetValue("32", 0));
            int binDays = Convert.ToInt32(key.GetValue("08", 0));

            if (!enabled)
                return new HealthFinding("health.storage-sense", "Storage Sense",
                    "Present but switched off.", HealthState.Good);

            var parts = new List<string> { "Storage Sense is on and cleans up on its own schedule" };
            if (downloadDays > 0)
                parts.Add($"including deleting Downloads older than {downloadDays} days — HERO never " +
                          "touches Downloads, but Windows does");
            if (binDays > 0)
                parts.Add($"and emptying the Recycle Bin after {binDays} days");

            return new HealthFinding("health.storage-sense", "Storage Sense",
                string.Join(", ", parts) + ". Reclaim figures from either tool are approximate " +
                "while both are running.", HealthState.Watch);
        }
        catch
        {
            return new HealthFinding("health.storage-sense", "Storage Sense",
                "Could not read the configuration.", HealthState.Unknown);
        }
    }

    // ----------------------------------------------------------- free-space trend

    private static string TrendDirectory => Path.Combine(HeroPaths.Root, "trends");

    /// <summary>Appends one free-space sample per volume. Cheap enough to call every 15 minutes;
    /// the store is line-delimited JSON so there is no database dependency and a corrupt tail
    /// costs one sample rather than the file.</summary>
    internal static void RecordSpaceSample()
    {
        try
        {
            Directory.CreateDirectory(TrendDirectory);
            foreach (var volume in Volumes())
            {
                string file = Path.Combine(TrendDirectory,
                    volume.Root.Replace(":", "").Replace("\\", "") + ".jsonl");
                string line = $"{{\"t\":\"{DateTime.UtcNow:O}\",\"free\":{volume.FreeBytes}," +
                              $"\"total\":{volume.TotalBytes}}}";
                File.AppendAllText(file, line + Environment.NewLine);
            }
        }
        catch { /* a trend is a nicety; failing to write one must never break a scan */ }
    }

    /// <summary>
    /// Free-space trend for one volume.
    ///
    /// The fit is the MEDIAN of daily deltas, not a least-squares line, and fewer than seven
    /// samples produce no projection at all. A single 111 GB engine install is otherwise enough
    /// to make a least-squares fit announce that the disk fills next Tuesday, which is the kind
    /// of confident wrongness that ends a tool's credibility. The daily-drop alarm the original
    /// design proposed is deliberately absent: on this machine an Unreal cook, a game install or
    /// a BlueStacks session would trip it on a normal Tuesday.
    /// </summary>
    internal static SpaceTrend Trend(string volumeRoot, int days = 30)
    {
        string file = Path.Combine(TrendDirectory,
            volumeRoot.Replace(":", "").Replace("\\", "") + ".jsonl");

        var samples = new List<(DateTime When, long Free)>();
        try
        {
            if (File.Exists(file))
            {
                var cutoff = DateTime.UtcNow.AddDays(-days);
                foreach (var line in File.ReadLines(file))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        var when = doc.RootElement.GetProperty("t").GetDateTime().ToUniversalTime();
                        if (when < cutoff) continue;
                        samples.Add((when, doc.RootElement.GetProperty("free").GetInt64()));
                    }
                    catch { /* skip a truncated tail line */ }
                }
            }
        }
        catch { }

        if (samples.Count < 7)
            return new SpaceTrend(volumeRoot, samples.Count, TimeSpan.Zero, 0, null,
                "Not enough history yet — HERO needs about a week of samples before it will " +
                "project anything.");

        samples.Sort((a, b) => a.When.CompareTo(b.When));
        var span = samples[^1].When - samples[0].When;
        if (span < TimeSpan.FromDays(7))
            return new SpaceTrend(volumeRoot, samples.Count, span, 0, null,
                "Samples do not yet span a week.");

        var deltas = new List<double>();
        for (int i = 1; i < samples.Count; i++)
        {
            double hours = (samples[i].When - samples[i - 1].When).TotalHours;
            if (hours <= 0) continue;
            deltas.Add((samples[i].Free - samples[i - 1].Free) / hours * 24.0);
        }
        if (deltas.Count == 0)
            return new SpaceTrend(volumeRoot, samples.Count, span, 0, null, "No usable intervals.");

        deltas.Sort();
        long median = (long)deltas[deltas.Count / 2];

        DateTime? projected = null;
        string note;
        if (median < 0)
        {
            double daysLeft = samples[^1].Free / (double)(-median);
            if (daysLeft is > 0 and < 3650)
            {
                projected = DateTime.UtcNow.AddDays(daysLeft);
                note = $"losing about {Human.Bytes(-median)} a day; at this rate it fills in " +
                       $"{(int)daysLeft} days.";
            }
            else note = $"losing about {Human.Bytes(-median)} a day.";
        }
        else
        {
            note = median == 0 ? "steady." : $"gaining about {Human.Bytes(median)} a day.";
        }

        return new SpaceTrend(volumeRoot, samples.Count, span, median, projected, note);
    }

    // ------------------------------------------------------------- the report

    /// <summary>
    /// Assembles the whole health picture, including the composite score.
    ///
    /// SCORE FORMULA, stated so it can be argued with. Start at 100 and subtract:
    ///   system volume under 10% free              -25   (Windows itself starts to misbehave here)
    ///   system volume under 15% free              -12
    ///   real-time protection off                  -30
    ///   Defender signatures out of date           -15
    ///   quick scan older than 90 days             -12   (130 days on this machine)
    ///   quick scan older than 30 days              -8
    ///   full scan never run                        -3   (small: a full scan across 12 TB is a
    ///                                                    genuinely expensive thing to demand)
    ///   a physical disk not reporting Healthy     -30
    ///   restart pending                            -8, or -15 if uptime already exceeds 7 days
    ///   commit charge above 92% of the limit      -10
    ///   commit charge above 80% of the limit       -4
    ///   each unsuppressed error cluster            -2, capped at -10
    ///   Windows Update failures in the last week   -6
    /// A missing measurement subtracts NOTHING. An admin-gated probe that could not run must
    /// never quietly lower — or raise — the score, or the number means something different
    /// depending on how HERO was launched.
    /// </summary>
    internal static HealthReport Report(CancellationToken ct = default)
    {
        var volumes = Volumes();
        var disks = PhysicalDisks();
        var reboot = PendingReboot();
        var defender = DefenderFreshness();
        var memory = Memory();
        IReadOnlyList<EventCluster> events =
            ct.IsCancellationRequested ? Array.Empty<EventCluster>() : EventClusters();
        IReadOnlyList<UpdateHistoryEntry> updates =
            ct.IsCancellationRequested ? Array.Empty<UpdateHistoryEntry>() : UpdateHistory();

        int score = 100;
        var deductions = new List<string>();
        var findings = new List<HealthFinding>();

        void Deduct(int points, string why)
        {
            score -= points;
            deductions.Add($"-{points} {why}");
        }

        string systemRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
        var systemVolume = volumes.FirstOrDefault(v =>
            string.Equals(v.Root, systemRoot, StringComparison.OrdinalIgnoreCase));

        if (systemVolume is not null)
        {
            var trend = Trend(systemVolume.Root);
            findings.Add(new HealthFinding("health.space", $"Free space on {systemVolume.Root}",
                $"{Human.Bytes(systemVolume.FreeBytes)} free of {Human.Bytes(systemVolume.TotalBytes)} " +
                $"({systemVolume.PercentFree:0.0}%) — {trend.Note}",
                systemVolume.State));

            if (systemVolume.PercentFree < 10) Deduct(25, "the system volume is below 10% free");
            else if (systemVolume.PercentFree < 15) Deduct(12, "the system volume is below 15% free");
        }

        if (defender.Access == AccessState.Measured)
        {
            if (!defender.RealTimeEnabled) Deduct(30, "Defender real-time protection is off");
            if (defender.SignaturesOutOfDate) Deduct(15, "Defender signatures are out of date");
            if (defender.QuickScanAgeDays != uint.MaxValue && defender.QuickScanAgeDays > 90)
                Deduct(12, $"the last quick scan was {defender.QuickScanAgeDays} days ago");
            else if (defender.QuickScanAgeDays != uint.MaxValue && defender.QuickScanAgeDays > 30)
                Deduct(8, $"the last quick scan was {defender.QuickScanAgeDays} days ago");
            if (defender.FullScanAgeDays == uint.MaxValue)
                Deduct(3, "no full scan has ever been recorded");

            findings.Add(new HealthFinding("health.defender", "Microsoft Defender",
                $"Real-time protection {(defender.RealTimeEnabled ? "on" : "OFF")}, signatures " +
                $"{defender.SignatureVersion} updated {defender.SignaturesUpdatedUtc:d}. " +
                $"Last quick scan: {defender.QuickScanDisplay}. Full scan: {defender.FullScanDisplay}. " +
                "A quick scan is worth running; a full scan across this machine's game libraries " +
                "and toolchains would saturate the disks for hours and should be scheduled " +
                "deliberately, overnight.",
                defender.RealTimeEnabled ? HealthState.Good : HealthState.Problem));
        }
        else
        {
            findings.Add(new HealthFinding("health.defender", "Microsoft Defender",
                defender.Note, HealthState.Unknown, defender.Access));
        }

        foreach (var disk in disks)
        {
            bool healthy = disk.HealthStatus.Equals("Healthy", StringComparison.OrdinalIgnoreCase);
            if (!healthy && disk.HealthStatus.Length > 0)
                Deduct(30, $"{disk.FriendlyName} reports {disk.HealthStatus}");

            findings.Add(new HealthFinding("health.disk." + disk.FriendlyName,
                disk.FriendlyName,
                $"{disk.MediaType} over {disk.BusType}, {Human.Bytes(disk.SizeBytes)}, reported " +
                $"{disk.HealthStatus}. Note this is Windows' coarse storage verdict, not a SMART " +
                $"reading. {disk.ReliabilityNote}",
                healthy ? HealthState.Good : HealthState.Watch, disk.ReliabilityAccess));
        }

        if (reboot.Pending)
            Deduct(reboot.Uptime.TotalDays >= 7 ? 15 : 8, "a restart is pending");
        findings.Add(new HealthFinding("health.reboot", "Pending restart", reboot.Summary,
            reboot.Pending ? HealthState.Watch : HealthState.Good));

        if (memory.CommitLimitBytes > 0)
        {
            if (memory.CommitRatio > 0.92) Deduct(10, "commit charge is above 92% of the limit");
            else if (memory.CommitRatio > 0.80) Deduct(4, "commit charge is above 80% of the limit");

            findings.Add(new HealthFinding("health.memory", "Memory",
                $"{Human.Bytes(memory.PhysicalAvailableBytes)} of " +
                $"{Human.Bytes(memory.PhysicalTotalBytes)} physical memory is free, and commit " +
                $"charge is {memory.CommitRatio * 100:0}% of the limit. Low free RAM is not a " +
                "problem on Windows — the cache deliberately fills it — so HERO watches commit " +
                "charge instead, and offers no 'free memory' button because trimming working " +
                "sets makes performance worse.",
                memory.State));
        }

        int noisy = events.Count(e => !e.Suppressed && e.Rank > 0.5);
        if (noisy > 0) Deduct(Math.Min(10, noisy * 2), $"{noisy} recurring error clusters in the logs");

        int failedUpdates = updates.Count(u => u.Failed && DateTime.UtcNow - u.DateUtc < TimeSpan.FromDays(7));
        if (failedUpdates > 0)
        {
            Deduct(6, $"{failedUpdates} Windows Update installs failed in the last week");
            findings.Add(new HealthFinding("health.updates", "Windows Update",
                $"{failedUpdates} update installs failed in the last seven days. Clearing the " +
                "Windows Update download cache is the standard remedy and is offered in the " +
                "cleanup list — the two are the same problem, not two findings.",
                HealthState.Problem));
        }

        findings.Add(TimeService());
        findings.Add(StorageSense());

        foreach (var volume in volumes)
            findings.Add(new HealthFinding("health.optimise." + volume.Root, $"Optimising {volume.Root}",
                volume.OptimisationAdvice, HealthState.Good));

        // Things HERO deliberately does not measure, said out loud. A tool that explains its
        // blind spots is trusted more than one that leaves a confident-looking gap.
        if (!MaintenanceGuards.IsElevated)
        {
            findings.Add(new HealthFinding("health.admin-tier", "Not measured without administrator",
                "Drive wear and temperature, shadow-copy sizing, restore points, the " +
                "boot-performance log, C:\\Windows\\Temp and the DISM component-store analysis all " +
                "require administrator rights. HERO runs unelevated on purpose — a tray app that " +
                "triggers a UAC prompt every boot teaches you to click through prompts — so these " +
                "are shown as unmeasured rather than guessed.",
                HealthState.Unknown, AccessState.AccessDenied));

            findings.Add(new HealthFinding("health.boot-time", "Startup impact",
                "No boot-timing data exists on this machine: the diagnostics channel that records " +
                "it is administrator-only and currently empty. HERO therefore shows the startup " +
                "inventory with no seconds figure attached, because any such figure would be " +
                "invented.",
                HealthState.Unknown, AccessState.AccessDenied));
        }

        if (score < 0) score = 0;

        return new HealthReport
        {
            TakenUtc = DateTime.UtcNow,
            Volumes = volumes,
            Disks = disks,
            Reboot = reboot,
            Defender = defender,
            Memory = memory,
            Events = events,
            Updates = updates,
            Findings = findings,
            Score = score,
            ScoreExplanation = deductions.Count == 0
                ? "100 — nothing measured warranted a deduction."
                : "Starting from 100: " + string.Join("; ", deductions) + ". Anything HERO could " +
                  "not measure deducts nothing, so the score does not change depending on whether " +
                  "HERO was launched with administrator rights.",
        };
    }

    // ------------------------------------------------------------- JSON helpers

    /// <summary>
    /// ConvertTo-Json emits a bare object for a single result and an array for several, so both
    /// shapes have to be accepted. Windows PowerShell has no -AsArray to normalise it.
    /// </summary>
    private static List<JsonElement> JsonObjects(string json)
    {
        var list = new List<JsonElement>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in doc.RootElement.EnumerateArray()) list.Add(item.Clone());
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                list.Add(doc.RootElement.Clone());
            }
        }
        catch { }
        return list;
    }

    private static string StringOf(JsonElement element, string name) =>
        element.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : element.TryGetProperty(name, out var n) && n.ValueKind == JsonValueKind.Number
                ? n.ToString()
                : "";

    private static long LongOf(JsonElement element, string name) =>
        element.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long l)
            ? l : 0;

    private static uint UIntOf(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number)
        {
            if (v.TryGetUInt32(out uint u)) return u;
            if (v.TryGetInt64(out long l) && l >= 0) return (uint)Math.Min(l, uint.MaxValue);
        }
        return uint.MaxValue;
    }

    private static bool BoolOf(JsonElement element, string name) =>
        element.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static DateTime DateOf(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var v)) return DateTime.MinValue;

        // PowerShell serialises DateTime either as an ISO string or as "/Date(ms)/".
        if (v.ValueKind == JsonValueKind.String)
        {
            var text = v.GetString() ?? "";
            if (text.StartsWith("/Date(", StringComparison.Ordinal))
            {
                int end = text.IndexOf(')');
                if (end > 6 && long.TryParse(text[6..end].Split('+', '-')[0], out long ms))
                    return DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime;
            }
            if (DateTime.TryParse(text, CultureInfo.InvariantCulture,
                                  DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeLocal, out var parsed))
                return parsed;
        }
        return DateTime.MinValue;
    }

    private static string Trim(string text)
    {
        text = text.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return text.Length <= 300 ? text : text[..300] + "...";
    }
}
