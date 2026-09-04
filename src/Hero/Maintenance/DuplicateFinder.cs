using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Hero.Interop;

namespace Hero.Maintenance;

/// <summary>
/// NTFS content identity: which physical file a path actually names.
///
/// Two paths with the same identity are two NAMES for one set of blocks. They are byte-identical
/// by construction and deleting one frees nothing, which is the single most important distinction
/// in this whole file. See <see cref="DuplicateFinder"/> for the WinSxS measurement that makes it
/// load-bearing rather than pedantic.
///
/// The id is 128 bits because ReFS needs it. GetFileInformationByHandle's nFileIndexHigh/Low pair
/// is only 64 bits and is documented as not guaranteed unique on ReFS, so
/// <c>GetFileInformationByHandleEx(FileIdInfo)</c> is asked first and the 64-bit index is the
/// fallback for volumes whose driver does not answer it.
/// </summary>
internal readonly record struct FileIdentity(ulong VolumeSerial, ulong FileIdLow, ulong FileIdHigh);

/// <summary>Identity plus the link count, which is the part that decides whether a deletion frees
/// anything. <paramref name="Resolved"/> is false when the file could not be opened at all.</summary>
internal readonly record struct FileLinkInfo(FileIdentity Identity, int LinkCount, bool Resolved);

/// <summary>Which pass the scan is in. Surfaced so a UI can say what it is waiting on — the
/// stages have wildly different durations and a single indeterminate spinner for all of them
/// looks like a hang during hashing.</summary>
internal enum DuplicateStage
{
    Counting,
    Collecting,
    Identity,
    Sampling,
    Hashing,
    Verifying,
    Building,
    Done,
}

/// <summary>Progress for one scan. Reported on a time throttle, never per file.</summary>
internal sealed record DuplicateProgress(
    DuplicateStage Stage, long FilesSeen, long Candidates, long BytesRead, long BytesToRead, string CurrentPath)
{
    /// <summary>Fraction of the current stage, or -1 when the stage has no known total. The
    /// enumeration passes genuinely do not know their total until they finish, and inventing a
    /// denominator produces a bar that jumps backwards.</summary>
    internal double Fraction => BytesToRead > 0 ? Math.Clamp((double)BytesRead / BytesToRead, 0, 1) : -1;
}

/// <summary>How a scan is scoped and how hard it works. Every default here is the conservative
/// choice; the aggressive settings are opt-in.</summary>
internal sealed record DuplicateScanOptions
{
    /// <summary>
    /// Smallest file worth considering, in logical bytes.
    ///
    /// The default is one 4 KB NTFS cluster because that is the smallest allocation that can
    /// actually come back. Below roughly 700-900 bytes NTFS stores the data resident in the MFT
    /// record itself, so such a file occupies no data clusters and deleting a "duplicate" of it
    /// frees literally nothing while still being a deletion the user has to think about.
    ///
    /// Lowering it is allowed; removing it is not. The walk clamps this to at least one byte so
    /// zero-length files can never enter a group whatever a caller sets — every empty file on the
    /// machine is byte-identical to every other one, they exist precisely because their NAME and
    /// presence is the payload (lock files, .keep, sentinels), and (n-1) x 0 is zero reclaim.
    /// </summary>
    internal long MinimumFileBytes { get; init; } = 4096;

    /// <summary>
    /// Head and tail window for the cheap discrimination pass, per end.
    ///
    /// 64 KB each end. The head catches container magic, headers and the first frame — where two
    /// files that happen to share a byte count almost always diverge. The tail is not symmetry for
    /// its own sake: a ZIP/JAR/APK central directory, an MP4 with a trailing moov, and a PE debug
    /// directory all live at the END, so two builds of the same artefact differing only in a
    /// timestamp or GUID are separated by the tail and by nothing else.
    /// </summary>
    internal int SampleBytes { get; init; } = 64 * 1024;

    /// <summary>The window actually used. Clamped because the sampler rents a buffer of twice this
    /// value and compares it against a file length, so an unbounded setting turns into an integer
    /// overflow and a buffer nobody intended to allocate.</summary>
    internal int EffectiveSampleBytes => Math.Clamp(SampleBytes, 4096, 8 * 1024 * 1024);

    /// <summary>
    /// Re-read both files and compare byte for byte before calling a group a duplicate.
    ///
    /// OFF by default. A SHA-256 match between two files that were both found by walking a local
    /// disk is not an adversarial situation, and verification doubles the read cost on exactly the
    /// bytes the user is about to be told they can delete. It is offered because this is the one
    /// feature in HERO whose output leads to deletion, and some users would rather pay the second
    /// read than trust a digest.
    /// </summary>
    internal bool VerifyByteForByte { get; init; }

    /// <summary>Ceiling on retained same-size candidates. Hit only by a pathological tree; the
    /// report says so rather than silently truncating.</summary>
    internal int MaxCandidateFiles { get; init; } = 500_000;

    /// <summary>Ceiling on returned groups. A result nobody can review is not a result.</summary>
    internal int MaxGroups { get; init; } = 5_000;

    /// <summary>Concurrent readers per solid-state volume. One per mechanical volume regardless —
    /// D: on this machine is a 12 TB WDC WD121KRYZ where parallel reads are net slower.</summary>
    internal int SolidStateWorkers { get; init; } = 4;

    /// <summary>
    /// Depth cap. Belt and braces behind FileWalk's unconditional reparse-point skip:
    /// <c>%LOCALAPPDATA%\Application Data</c> is a junction to its own parent, so any walker that
    /// ever follows one runs forever rather than merely slowly.
    /// </summary>
    internal int MaxDepth { get; init; } = 32;
}

/// <summary>
/// One physical file in a duplicate group, together with every name this scan found for it.
/// </summary>
/// <param name="Paths">Link aliases discovered inside the scanned roots. Usually one.</param>
/// <param name="LinkCount">NTFS hard link count for the underlying file.</param>
/// <param name="LogicalBytes">The length the directory entry reports.</param>
/// <param name="AllocatedBytes">What it occupies on disk, from GetCompressedFileSizeW.</param>
/// <param name="LastWriteUtc">Newest write time seen for this file. Feeds the keeper rule.</param>
/// <param name="Identity">Volume serial and file id — what makes this one physical file.</param>
internal sealed record DuplicateCopy(
    IReadOnlyList<string> Paths, int LinkCount, long LogicalBytes, long AllocatedBytes,
    DateTime LastWriteUtc, FileIdentity Identity)
{
    /// <summary>True when names exist outside what was scanned. See <see cref="FreesBytesIfRemoved"/>.</summary>
    internal bool HasLinksOutsideScan => LinkCount > Paths.Count;

    /// <summary>
    /// True when this physical file answers to more than one name inside the scan. Deleting any
    /// single one of them frees nothing.
    /// </summary>
    internal bool HasMultipleNamesInScan => Paths.Count > 1;

    /// <summary>
    /// What deleting THE ONE PATH a caller is offered would actually hand back.
    ///
    /// Zero in two cases, and the second was a real bug rather than caution.
    ///
    /// The first is links the scan never saw: the blocks survive on the strength of a name nobody
    /// is proposing to delete.
    ///
    /// The second is links the scan DID see. This previously returned the full allocated size
    /// whenever every alias was in scope, reasoning that deleting "this copy — every path listed"
    /// frees the file. But the only single-path accessor on this type is <see cref="PrimaryPath"/>,
    /// and that is what the rest of the class orders and chooses keepers by, so what a caller
    /// actually deletes is one name out of several. Demonstrated: one physical file with three
    /// in-scope aliases was offered as redundant with 1,048,576 bytes reclaimable, and deleting the
    /// nominated path produced a free-space delta of exactly zero.
    ///
    /// A figure that is only true if the caller deletes a set it was never handed is not a figure
    /// this type may report. <see cref="FreesBytesIfEveryNameRemoved"/> states that quantity
    /// separately, for a caller that genuinely removes all of them.
    /// </summary>
    internal long FreesBytesIfRemoved =>
        HasLinksOutsideScan || HasMultipleNamesInScan ? 0 : AllocatedBytes;

    /// <summary>
    /// What deleting EVERY in-scope name for this file would free. Still zero when links exist
    /// outside the scan, because those keep the blocks alive regardless.
    /// </summary>
    internal long FreesBytesIfEveryNameRemoved => HasLinksOutsideScan ? 0 : AllocatedBytes;

    /// <summary>
    /// True when this copy lives under a folder a sync client mirrors to other machines.
    /// Deleting here does not free space on one disk, it removes the file from every device the
    /// account touches, so the keeper rule steers deletions away from these.
    /// </summary>
    internal bool InCloudSyncFolder => DuplicateFinder.LooksCloudSynced(Paths);

    /// <summary>True when every known name sits in a cache, temp or build-output location, which
    /// makes this copy the derived one rather than the original.</summary>
    internal bool InDerivedLocation => DuplicateFinder.LooksDerived(Paths);

    /// <summary>
    /// On-disk is materially smaller than logical, i.e. NTFS compression is in play. Not a reason
    /// to exclude the file — reads decompress transparently, so the CONTENT still matches — but a
    /// reason the row's reclaim figure will not equal its displayed size.
    /// </summary>
    internal bool CompressedOnDisk => AllocatedBytes > 0 && AllocatedBytes < LogicalBytes - (LogicalBytes / 8);

    internal string PrimaryPath => Paths.Count > 0 ? Paths[0] : "";
}

/// <summary>
/// A set of byte-identical files, with exactly one copy nominated to survive.
///
/// The invariant that matters: <see cref="Redundant"/> can never contain every copy. A malformed
/// keeper index empties it rather than widening it, so no arrangement of this record can be
/// actioned into deleting the last instance of a file.
/// </summary>
internal sealed record DuplicateGroup
{
    /// <summary>Hex SHA-256 of the content, shared by every copy.</summary>
    internal required string Sha256 { get; init; }

    /// <summary>The logical length every copy shares. Display size.</summary>
    internal required long LogicalBytes { get; init; }

    internal required IReadOnlyList<DuplicateCopy> Copies { get; init; }

    /// <summary>Index into <see cref="Copies"/> of the copy HERO proposes to keep.</summary>
    internal required int KeepIndex { get; init; }

    /// <summary>The rule that picked the keeper, in words, because a nomination the user cannot
    /// interrogate is one they have to either trust blindly or ignore.</summary>
    internal required string KeepRationale { get; init; }

    /// <summary>
    /// What removing everything in <see cref="Redundant"/> would actually free: the sum of the
    /// redundant copies' ON-DISK sizes. In the ordinary case that is (copies - 1) x size, which is
    /// the honest figure; it is NOT the group total, which is how these tools routinely quote a
    /// number twice the size of the win.
    /// </summary>
    internal required long ReclaimableBytes { get; init; }

    /// <summary>
    /// The copies HERO would remove: everything except the keeper, minus any copy that would free
    /// nothing because links to it exist outside the scan. Empty if the keeper index is invalid.
    ///
    /// The second exclusion matters as much as the first. A deletion that frees no bytes is pure
    /// downside — all of the risk of removing a file, none of the reason for doing it — so such a
    /// copy is described in <see cref="Copies"/> and left out of the action list.
    /// </summary>
    internal required IReadOnlyList<DuplicateCopy> Redundant { get; init; }

    internal DuplicateCopy? Keep => KeepIndex >= 0 && KeepIndex < Copies.Count ? Copies[KeepIndex] : null;

    /// <summary>True when at least one copy carries names this scan did not see, so part of the
    /// group cannot be reclaimed however the keeper is chosen.</summary>
    internal bool HasPartiallyLinkedCopies => Copies.Any(c => c.HasLinksOutsideScan);

    /// <summary>Volumes the copies sit on. More than one means the reclaim lands on different
    /// disks, and a total that mixes them answers a question nobody asked.</summary>
    internal IReadOnlyList<string> Volumes =>
        Copies.Select(c => FileWalk.VolumeOf(c.PrimaryPath))
              .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>The caller's override. Rebuilds the derived figures so a hand-picked keeper can
    /// never leave a stale reclaim total attached, and refuses an out-of-range index outright.</summary>
    internal DuplicateGroup WithKeeper(int index) =>
        index < 0 || index >= Copies.Count
            ? this
            : DuplicateFinder.Rebuild(this with { KeepIndex = index, KeepRationale = "chosen by the operator" });

    internal string Display =>
        $"{Human.Bytes(LogicalBytes)} x {Copies.Count} copies — {Human.Bytes(ReclaimableBytes)} reclaimable, " +
        $"keeping {Keep?.PrimaryPath ?? "nothing (no valid keeper)"}";
}

/// <summary>
/// The result of one scan, including everything it declined to look at.
///
/// The excluded counts are not trivia. A duplicate finder that quietly skipped 224,647 files and
/// then reported a small number reads as "there is nothing here", which is a different and wrong
/// answer from "there is nothing here that HERO is willing to act on".
/// </summary>
internal sealed record DuplicateReport
{
    internal required AccessState State { get; init; }
    internal IReadOnlyList<DuplicateGroup> Groups { get; init; } = Array.Empty<DuplicateGroup>();
    internal IReadOnlyList<string> Roots { get; init; } = Array.Empty<string>();

    internal long FilesWalked { get; init; }
    internal long CandidateFiles { get; init; }
    internal long FilesHashed { get; init; }
    internal long BytesRead { get; init; }

    /// <summary>Sum over <see cref="Groups"/> with the keepers as nominated.</summary>
    internal long ReclaimableBytes { get; init; }

    /// <summary>Reclaim split by volume root, because free space is a per-volume quantity and a
    /// combined headline is useless to someone whose C: is full and whose E: is not.</summary>
    internal IReadOnlyDictionary<string, long> ReclaimableByVolume { get; init; }
        = new Dictionary<string, long>();

    /// <summary>Same-size sets that turned out to be one file wearing several names.</summary>
    internal int HardlinkSetsCollapsed { get; init; }
    internal long HardlinkPathsCollapsed { get; init; }

    /// <summary>Real duplicate content that would free nothing, so it is not offered.</summary>
    internal int GroupsWithNoReclaim { get; init; }

    internal long CloudPlaceholdersSkipped { get; init; }
    internal long SparseFilesSkipped { get; init; }
    internal long BelowSizeFloor { get; init; }
    internal long ExcludedByPolicy { get; init; }
    internal long UnreadableFiles { get; init; }
    internal int DeniedDirectories { get; init; }

    /// <summary>True when a cap was hit, so the figures are a floor rather than the answer.</summary>
    internal bool Truncated { get; init; }
    internal bool Cancelled { get; init; }
    internal TimeSpan Elapsed { get; init; }

    /// <summary>The headline, phrased so the caveats travel with the number instead of being
    /// available somewhere else for anyone who thinks to look.</summary>
    internal string Display
    {
        get
        {
            if (State == AccessState.NotPresent) return "no scannable paths";
            if (Groups.Count == 0)
                return CandidateFiles == 0
                    ? "no files matched on size, so nothing was hashed"
                    : $"nothing reclaimable: {Human.Count(CandidateFiles)} same-size candidates, no duplicate content";

            var head = $"{Human.Bytes(ReclaimableBytes)} reclaimable across {Human.Count(Groups.Count)} groups";
            if (HardlinkSetsCollapsed > 0)
                head += $"; {Human.Count(HardlinkPathsCollapsed)} paths collapsed to " +
                        $"{Human.Count(HardlinkSetsCollapsed)} hardlinked files and excluded — deleting a link frees nothing";
            if (GroupsWithNoReclaim > 0)
                head += $"; {Human.Count(GroupsWithNoReclaim)} duplicate sets withheld because every copy is linked elsewhere";
            if (CloudPlaceholdersSkipped > 0)
                head += $"; {Human.Count(CloudPlaceholdersSkipped)} cloud files not opened";

            // The two largest exclusion buckets, which this line used to omit entirely while
            // disclosing four smaller ones. Measured on a home-directory scan of this machine,
            // ProtectedPaths removes Documents (89,648 files / 30.10 GB), Pictures (1,405 / 1.18 GB),
            // Desktop, Videos, Music and Downloads. A user who sees "nothing reclaimable" while
            // 30 GB of their own documents were never looked at has been told something false by
            // omission, which is the failure mode this whole report exists to avoid.
            if (ExcludedByPolicy > 0)
                head += $"; {Human.Count(ExcludedByPolicy)} files in protected or structural-duplicate " +
                        "locations were never considered";
            if (BelowSizeFloor > 0)
                head += $"; {Human.Count(BelowSizeFloor)} files below the size floor";
            if (UnreadableFiles > 0 || DeniedDirectories > 0)
                head += $"; {Human.Count(UnreadableFiles)} files and {Human.Count(DeniedDirectories)} directories unreadable";
            if (Truncated) head += "; capped, so this is a lower bound";
            return head;
        }
    }
}

/// <summary>
/// Finds byte-identical files and says what removing the redundant copies would actually free.
///
/// This is the most dangerous read-only feature in HERO, because its output is a list of files
/// with a delete button implied next to them. Four things shape every decision here, and three of
/// them are measurements on this machine rather than opinions.
///
/// 1. HARDLINKS ARE NOT DUPLICATES. Sampling 4,000 files under C:\Windows\WinSxS found 4,000 with
///    NumberOfLinks &gt; 1 and zero single-link files — not "mostly hardlinked" as DiskCleanup.cs:866
///    puts it, but every single one. Against the 21.9 GB the Maintenance page reports for that
///    tree, a finder that ignores link identity would present essentially all of it as a duplicate
///    haul and free ZERO bytes. So identity is established before anything is called a duplicate,
///    and a same-size set that collapses to one identity is reported as a hardlink set, never as a
///    group. WinSxS is also pruned outright, so this is defence in depth rather than the only line.
///
/// 2. IDENTITY IS 36x THE COST OF METADATA, so it cannot happen during the walk. Measured on a
///    6,000-file sample: 654,622 files/s using only what enumeration already returns, against
///    17,966 files/s once each file needs a CreateFile plus GetFileInformationByHandle. At
///    0.056 ms per file that is 83 seconds of pure identity lookups on a 1.5M-file volume before
///    a byte is hashed. Hence the staging: group by size from metadata that costs nothing, then
///    take identity only on files that already have a same-size partner.
///
/// 3. SPARSE FILES MUST NOT BE HASHED OR RANKED. %LOCALAPPDATA%\Google\Play Games\...\userdata.img
///    is 512.0 GB logical and 191.2 MB on disk, a ratio of 2,741x. Reading it to hash would take
///    hours and ranking by its logical size would put a fantasy row at the top of the list. Files
///    carrying FileAttributes.SparseFile are dropped during the walk, which costs nothing because
///    the attribute is already in the directory entry. Everything that survives is RANKED AND
///    REPORTED BY ALLOCATED SIZE — GetCompressedFileSizeW, one syscall per surviving candidate,
///    never across the walk — so an NTFS-compressed duplicate quotes what it really hands back.
///    Logical length remains the MATCHING key, because that is what "same number of bytes" means.
///
/// 4. NOTHING HERE OPENS A CLOUD PLACEHOLDER FOR ITS CONTENT. A dehydrated OneDrive file is
///    hydrated by any read, so a "scan" would silently download gigabytes onto the volume it was
///    asked to analyse. Identity IS taken on placeholders where they appear, which is safe: the
///    handle asks for FILE_READ_ATTRIBUTES (0x80) with FILE_FLAG_BACKUP_SEMANTICS and no read
///    access at all, so the filter has nothing to recall. Only the content read is forbidden, and
///    a placeholder therefore never reaches the sampling stage.
///
/// Nothing in this file deletes, and it deliberately does not produce a <see cref="CleanupPlan"/>.
/// A plan is the only input <see cref="CleanupExecutor"/> accepts and it can only come from
/// <see cref="CleanupTarget.Preview"/>; manufacturing one here would create precisely the
/// "here is a list of paths, delete them" shortcut that arrangement exists to prevent.
/// </summary>
internal static class DuplicateFinder
{
    // ------------------------------------------------------------------ interop

    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    /// <summary>FILE_INFO_BY_HANDLE_CLASS.FileIdInfo.</summary>
    private const int FileIdInfo = 18;

    // Every field is a DWORD, including both halves of each FILETIME. Declaring the FILETIMEs as
    // long instead would let the CLR insert four bytes of padding after dwFileAttributes to reach
    // 8-byte alignment, and every field after that would be read from the wrong offset — a bug
    // that presents as plausible-looking garbage identities rather than as a failure.
    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public uint CreationTimeLow, CreationTimeHigh;
        public uint LastAccessTimeLow, LastAccessTimeHigh;
        public uint LastWriteTimeLow, LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh, FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh, FileIndexLow;
    }

    /// <summary>FILE_ID_INFO: a 64-bit volume serial and FILE_ID_128, laid out here as the two
    /// halves of that 16-byte identifier.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_ID_INFO
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(IntPtr hFile, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(IntPtr hFile, int infoClass,
                                                            out FILE_ID_INFO info, uint bufferSize);

    /// <summary>
    /// Identity and link count for one path, without reading a byte of it.
    ///
    /// Returns Resolved = false rather than throwing for the ordinary failures — the file was
    /// deleted between the walk and now, or its ACL refuses even attribute access — because one
    /// unreadable file must not abort a scan of a million.
    /// </summary>
    internal static FileLinkInfo IdentityOf(string path)
    {
        IntPtr handle = Native.CreateFile(path, FILE_READ_ATTRIBUTES,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
            IntPtr.Zero, Native.OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);

        if (handle == Native.INVALID_HANDLE_VALUE) return default;

        try
        {
            // NumberOfLinks only comes from the older call, and it is the field the reclaim
            // arithmetic depends on, so this one is not optional.
            if (!GetFileInformationByHandle(handle, out var basic)) return default;

            int links = (int)Math.Max(1u, basic.NumberOfLinks);

            // Preferred: the 128-bit id, which is the only one ReFS guarantees. On volumes whose
            // driver does not implement the class this fails and the 64-bit NTFS index — unique
            // per volume there — is widened into the same shape.
            if (GetFileInformationByHandleEx(handle, FileIdInfo, out var wide,
                                             (uint)Marshal.SizeOf<FILE_ID_INFO>()))
            {
                return new FileLinkInfo(
                    new FileIdentity(wide.VolumeSerialNumber, wide.FileIdLow, wide.FileIdHigh), links, true);
            }

            ulong index = ((ulong)basic.FileIndexHigh << 32) | basic.FileIndexLow;
            return new FileLinkInfo(new FileIdentity(basic.VolumeSerialNumber, index, 0), links, true);
        }
        finally
        {
            Native.CloseHandle(handle);
        }
    }

    // ---------------------------------------------------------------- exclusions

    /// <summary>
    /// Directory names never descended into. Pruning by name is free — the predicate runs once per
    /// directory, before the walk enters it — whereas the same exclusion applied per file costs a
    /// string scan on every one of a million paths.
    ///
    /// Each entry is here because a duplicate inside it is STRUCTURAL rather than waste:
    ///
    /// .git            — the object store is content-addressed; identical blobs across repositories
    ///                   are the design, and ProtectedPaths refuses the path anyway.
    /// WinSxS          — 4,000 of 4,000 sampled files hardlinked into System32. Zero reclaim.
    /// System32,
    /// SysWOW64        — the other end of those links, and the executor refuses both.
    /// Installer,
    /// assembly        — cached MSI/MSP and the GAC. Deleting a cached patch makes a product
    ///                   impossible to repair or uninstall, permanently.
    /// WindowsApps     — TrustedInstaller-owned; package servicing breaks if it is disturbed.
    /// node_modules    — the same package version installed in ten projects is ten identical copies
    ///                   ON PURPOSE, and each project needs its own. pnpm goes further and hardlinks
    ///                   its store into every tree, so those are not copies at all.
    /// cache dirs      — a cache's contents are derived, its duplicates are its own bookkeeping, and
    ///                   the owning tool's prune command already reclaims them properly. The uv
    ///                   cache alone is 6.70 GB across 224,647 files and npm's 3.40 GB across
    ///                   174,367; hashing those to rediscover that a content-addressed store
    ///                   contains related blobs is pure waste.
    /// $RECYCLE.BIN    — a copy in the bin IS the undo for the live file it matches. E:\$RECYCLE.BIN
    ///                   holds 107.4 GB across 226,184 files, all of which would pair up as
    ///                   "duplicates" of things the user just deleted.
    /// System Volume
    /// Information     — shadow copies and the search index. Not readable, not ours.
    /// </summary>
    private static readonly string[] PrunedDirectoryNames =
    {
        // Matched case-insensitively on the leaf, so each name appears once in whichever casing
        // reads clearest.
        ".git", "node_modules", "WinSxS", "System32", "SysWOW64", "Installer", "assembly",
        "WindowsApps", "$RECYCLE.BIN", "System Volume Information", "$Extend",
        "cache", "caches", "CachedData", "GPUCache", "Code Cache", "CacheStorage",
        "npm-cache", "pnpm-store", "v3-cache", "DerivedDataCache", "Intermediate",
    };

    /// <summary>
    /// Package stores whose duplicate-looking contents are a versioned index rather than waste, and
    /// which cannot be excluded by leaf name without also excluding innocent directories called
    /// "packages" or "registry". Checked per file, so the list is kept short and is consulted last,
    /// after the size floor has already discarded most of the tree.
    /// </summary>
    private static readonly string[] ExcludedPathFragments =
    {
        @"\.nuget\packages\",
        @"\.m2\repository\",
        @"\.cargo\registry\",
        @"\.gradle\",
        @"\Yarn\",
        @"\Microsoft\VisualStudio\Packages\",
        @"\Microsoft\VisualStudio\Setup\",
        @"\Package Cache\",
    };

    /// <summary>Sync roots. A deletion inside one is not a local reclaim: it propagates to every
    /// device on the account, so the keeper rule prefers to leave these alone.</summary>
    private static readonly string[] CloudSyncFragments =
    {
        @"\OneDrive", @"\Dropbox", @"\Google Drive", @"\GoogleDrive", @"\iCloudDrive", @"\Nextcloud",
    };

    /// <summary>Locations whose contents are derived from something else, so a copy here is the
    /// generated one. Used only to choose a keeper, never to exclude.</summary>
    private static readonly string[] DerivedFragments =
    {
        @"\Temp\", @"\tmp\", @"\AppData\Local\Temp\", @"\obj\", @"\bin\Debug\", @"\bin\Release\",
        @"\build\", @"\dist\", @"\out\", @"\target\", @"\Saved\", @"\Binaries\", @"\.vs\",
    };

    internal static bool LooksCloudSynced(IReadOnlyList<string> paths) =>
        paths.Count > 0 && paths.Any(p => ContainsAny(p, CloudSyncFragments));

    internal static bool LooksDerived(IReadOnlyList<string> paths) =>
        paths.Count > 0 && paths.All(p => ContainsAny(p, DerivedFragments));

    private static bool ContainsAny(string path, string[] fragments)
    {
        for (int i = 0; i < fragments.Length; i++)
            if (path.Contains(fragments[i], StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    // -------------------------------------------------------------------- scan

    /// <summary>
    /// Scans <paramref name="roots"/> and returns the duplicate groups worth acting on.
    ///
    /// Cancellable at every stage and non-throwing: a scan that dies on one bad file is worse than
    /// one that reports the file as unreadable and carries on, because the user re-runs it and hits
    /// the same file again.
    /// </summary>
    internal static DuplicateReport Scan(IReadOnlyList<string> roots,
                                         DuplicateScanOptions? options = null,
                                         IProgress<DuplicateProgress>? progress = null,
                                         CancellationToken ct = default)
    {
        var o = options ?? new DuplicateScanOptions();
        var sw = Stopwatch.StartNew();
        var reporter = new Throttle(progress);

        var scanRoots = NormaliseRoots(roots);
        if (scanRoots.Count == 0)
            return new DuplicateReport { State = AccessState.NotPresent, Elapsed = sw.Elapsed };

        var stats = new Counters();

        // PASS 1 — size census. Only sizes are retained, so this costs a dictionary entry per
        // DISTINCT length rather than one per file, and a 1.5M-file volume stays in single-digit
        // megabytes. The alternative (one pass, remembering every file until its size is known to
        // be shared) has to hold a path string for every file on the volume, which is hundreds of
        // megabytes for an answer that is mostly "this size is unique".
        var census = new Dictionary<long, int>();
        int denied = 0;
        foreach (var root in scanRoots)
        {
            if (ct.IsCancellationRequested) break;
            var m = WalkOne(root, o, stats, recordTotals: true, ct, f =>
            {
                census.TryGetValue(f.Length, out int n);
                census[f.Length] = n + 1;
                reporter.Maybe(() => new DuplicateProgress(
                    DuplicateStage.Counting, stats.FilesWalked, 0, 0, 0, f.Path));
            });
            denied += m.DeniedDirectories;
        }

        // PASS 2 — collect only the files whose length already has a partner. The second walk is
        // metadata-only at the measured 654,622 files/s, i.e. cheap against the hashing that
        // follows, and it is the price of never materialising the whole tree.
        //
        // The tree can change between passes. A file created in the gap is simply not a candidate,
        // and a bucket that lost a member collapses to one and is dropped. Both errors are misses
        // rather than false positives, which is the only direction a deletion-adjacent feature may
        // ever be wrong in.
        var buckets = new Dictionary<long, List<ScannedFile>>();
        long collected = 0;
        bool truncated = false;
        foreach (var root in scanRoots)
        {
            if (ct.IsCancellationRequested) break;
            WalkOne(root, o, stats, recordTotals: false, ct, f =>
            {
                if (!census.TryGetValue(f.Length, out int n) || n < 2) return;
                if (collected >= o.MaxCandidateFiles) { truncated = true; return; }
                if (!buckets.TryGetValue(f.Length, out var list))
                    buckets[f.Length] = list = new List<ScannedFile>(n);
                list.Add(f);
                collected++;
                reporter.Maybe(() => new DuplicateProgress(
                    DuplicateStage.Collecting, stats.FilesWalked, collected, 0, 0, f.Path));
            });
        }
        census.Clear();

        foreach (var key in buckets.Where(b => b.Value.Count < 2).Select(b => b.Key).ToList())
            buckets.Remove(key);

        stats.Candidates = buckets.Sum(b => (long)b.Value.Count);

        // STAGE — identity. First point at which a file is opened, and the first at which the walk's
        // apparent duplicates start disappearing: a same-size set that resolves to one identity is
        // one file with several names.
        var candidates = CollapseByIdentity(buckets, o, stats, reporter, ct);
        buckets.Clear();

        // STAGE — head/tail sample, then full digest. Both are content reads, so cloud placeholders
        // never get this far.
        var survivors = Discriminate(candidates, o, stats, reporter, ct);

        // STAGE — on-disk sizes. One GetCompressedFileSizeW per surviving candidate, which is a
        // trivial set by now, and the only figure the reclaim total is allowed to be built from.
        foreach (var c in survivors)
        {
            if (ct.IsCancellationRequested) break;
            long allocated = FileWalk.AllocatedBytes(c.Paths[0]);
            c.AllocatedBytes = allocated >= 0 ? allocated : c.Length;
        }

        var groups = BuildGroups(survivors, o, stats, reporter, ct);
        if (groups.Count > o.MaxGroups)
        {
            groups = groups.Take(o.MaxGroups).ToList();
            truncated = true;
        }

        var byVolume = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var g in groups)
            foreach (var c in g.Redundant)
            {
                string vol = FileWalk.VolumeOf(c.PrimaryPath);
                byVolume.TryGetValue(vol, out long acc);
                byVolume[vol] = acc + c.FreesBytesIfRemoved;
            }

        sw.Stop();
        reporter.Force(new DuplicateProgress(DuplicateStage.Done, stats.FilesWalked, stats.Candidates,
                                             stats.BytesRead, stats.BytesRead, ""));

        return new DuplicateReport
        {
            // The same tri-state the rest of the maintenance half uses: a scan that could not read
            // part of the tree reports a lower bound, and says so, rather than a clean number.
            State = denied > 0 ? AccessState.PartiallyMeasured : AccessState.Measured,
            Groups = groups,
            Roots = scanRoots,
            FilesWalked = stats.FilesWalked,
            CandidateFiles = stats.Candidates,
            FilesHashed = stats.FilesHashed,
            BytesRead = stats.BytesRead,
            ReclaimableBytes = groups.Sum(g => g.ReclaimableBytes),
            ReclaimableByVolume = byVolume,
            HardlinkSetsCollapsed = stats.HardlinkSets,
            HardlinkPathsCollapsed = stats.HardlinkPaths,
            GroupsWithNoReclaim = stats.GroupsWithNoReclaim,
            CloudPlaceholdersSkipped = stats.CloudPlaceholders,
            SparseFilesSkipped = stats.SparseFiles,
            BelowSizeFloor = stats.BelowFloor,
            ExcludedByPolicy = stats.ExcludedByPolicy,
            UnreadableFiles = stats.Unreadable,
            DeniedDirectories = denied,
            Truncated = truncated,
            Cancelled = ct.IsCancellationRequested,
            Elapsed = sw.Elapsed,
        };
    }

    /// <summary>
    /// Drops absent roots, and roots nested inside another root — the same file reached twice would
    /// otherwise arrive as two paths for one identity, which the collapse handles but which wastes
    /// an entire second walk to discover.
    /// </summary>
    /// <summary>
    /// A path with exactly one trailing separator, for prefix containment tests. "C:\" must not
    /// become "C:\\" — a volume root already carries its separator, and doubling it makes the
    /// nesting check silently fail to match anything on that volume.
    /// </summary>
    private static string WithSeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) ? path : path + Path.DirectorySeparatorChar;

    private static List<string> NormaliseRoots(IReadOnlyList<string> roots)
    {
        var full = new List<string>();
        foreach (var r in roots)
        {
            if (string.IsNullOrWhiteSpace(r)) continue;

            string raw = r.Trim();

            // "D:" is DRIVE-RELATIVE, not a volume root: Path.GetFullPath("D:") returned
            // "D:\My projects" here — the process's per-drive current directory. A user asking to
            // scan a drive would silently have scanned whatever directory this process last sat in.
            if (raw.Length == 2 && raw[1] == ':') raw += Path.DirectorySeparatorChar;

            string p;
            try { p = Path.GetFullPath(raw); }
            catch { continue; }

            // Trim the trailing separator EXCEPT on a volume root. Trimming it unconditionally
            // turned "C:\" into "C:", and every subsequent comparison then treated the most
            // important root a user can pick as something else entirely.
            string root = Path.GetPathRoot(p) ?? "";
            bool isVolumeRoot = p.Equals(root, StringComparison.OrdinalIgnoreCase);
            if (!isVolumeRoot) p = p.TrimEnd(Path.DirectorySeparatorChar);

            if (FileWalk.Probe(p, out bool isDirectory) != AccessState.Measured || !isDirectory) continue;

            // ProtectedPaths.IsForbidden is NOT consulted here, and that is the fix rather than an
            // oversight. It answers "may this be DELETED", and it refuses volume roots by design —
            // so using it to gate a read-only scan root made "find duplicates on C:" return
            // "no scannable paths", silently, for the single most obvious thing to ask for.
            // Measured: IsForbidden("C:\") and IsForbidden("D:\") are both true.
            //
            // Nothing is weakened by dropping it. It still guards every deletion, PrunedDirectoryNames
            // still keeps the walk out of the structural-duplicate trees, and a scan is a read.
            full.Add(p);
        }

        var distinct = full.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return distinct
            .Where(p => !distinct.Any(other =>
                 !other.Equals(p, StringComparison.OrdinalIgnoreCase) &&
                 p.StartsWith(WithSeparator(other), StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    /// <summary>
    /// One root, one walk, one thread.
    ///
    /// ScanRoots parallelises across volumes and, on solid-state ones, within a volume — so a
    /// predicate handed several roots at once would be called concurrently. Passing exactly one
    /// root takes the single-threaded branch inside it (one group, one item), which lets the
    /// accumulator above run without a lock. DevCaches.NewestWrite relies on the same property.
    /// The parallelism that matters for this feature is in the hashing, not the walk.
    /// </summary>
    /// <param name="recordTotals">True on the first of the two passes. Both passes apply exactly
    /// the same filter — they must, or the second could collect a file the first never counted —
    /// but only the first records the totals, so nothing is counted twice.</param>
    private static Measurement WalkOne(string root, DuplicateScanOptions o, Counters stats, bool recordTotals,
                                       CancellationToken ct, Action<ScannedFile> onFile)
    {
        var options = new WalkOptions
        {
            MaxDepth = o.MaxDepth,
            PruneDirectoryNames = PrunedDirectoryNames,
            SolidStateWorkers = 1,
        };

        // A caller may lower the floor; it may not remove it. Every zero-length file on the machine
        // is byte-identical to every other one, they exist because their NAME is the payload, and
        // (n-1) x 0 bytes is not a reclaim — so a floor of at least one byte is not negotiable.
        long floor = Math.Max(1, o.MinimumFileBytes);

        return FileWalk.ScanRoots(new[] { root }, options, null, 0, f =>
        {
            if (recordTotals) stats.FilesWalked++;

            // Ordered cheapest-first. The size floor discards the long tail of tiny files before
            // anything has to scan a path string, and both attribute tests read a field the
            // directory entry already contained.
            if (f.Length < floor) { if (recordTotals) stats.Bump(ref stats.BelowFloor); return false; }

            // Logical length here is 512.0 GB for a file that occupies 191.2 MB. Hashing it would
            // read half a terabyte of holes and ranking by it would put a phantom at the top of the
            // list, so sparse files leave the scan at the cheapest possible moment.
            if ((f.Attributes & FileAttributes.SparseFile) != 0)
            { if (recordTotals) stats.Bump(ref stats.SparseFiles); return false; }

            if (f.IsCloudPlaceholder) { if (recordTotals) stats.Bump(ref stats.CloudPlaceholders); return false; }

            if (ContainsAny(f.Path, ExcludedPathFragments))
            { if (recordTotals) stats.Bump(ref stats.ExcludedByPolicy); return false; }

            // The executor's own floor, applied here rather than at the end. Offering a duplicate
            // under Pictures or Downloads would be a promise the rest of HERO refuses to keep:
            // CleanupExecutor.Validate rejects those paths outright. That deliberately removes the
            // places a user would most like a duplicate finder to look, and the honest answer is
            // that HERO does not delete there at all, not that it found nothing.
            if (ProtectedPaths.IsForbidden(f.Path, out _))
            { if (recordTotals) stats.Bump(ref stats.ExcludedByPolicy); return false; }

            onFile(f);
            return false;   // nothing is collected by ScanRoots itself; the accumulator above owns it
        }, ct);
    }

    // --------------------------------------------------------------- identity

    /// <summary>One physical file and everything learned about it, mutated in place across the
    /// stages so no stage has to rebuild the collection.</summary>
    private sealed class Candidate
    {
        internal FileIdentity Identity;
        internal readonly List<string> Paths = new(1);
        internal long Length;
        internal long AllocatedBytes;
        internal DateTime LastWriteUtc;
        internal int LinkCount = 1;
        internal string? SampleKey;
        internal string? ContentKey;
        /// <summary>The sample read the entire file, so it IS the content digest.</summary>
        internal bool Conclusive;
        internal bool Failed;

        internal string Volume => FileWalk.VolumeOf(Paths[0]);
    }

    /// <summary>
    /// Turns same-size path sets into same-size PHYSICAL FILE sets.
    ///
    /// This is where WinSxS-shaped input stops being a duplicate haul. Paths sharing one identity
    /// are folded into a single candidate carrying all of its names; a bucket left with one
    /// candidate had no duplicates in it at all, only aliases, and is counted as a hardlink set.
    /// </summary>
    private static List<Candidate> CollapseByIdentity(Dictionary<long, List<ScannedFile>> buckets,
                                                      DuplicateScanOptions o, Counters stats,
                                                      Throttle reporter, CancellationToken ct)
    {
        var perSize = new Dictionary<long, Dictionary<FileIdentity, Candidate>>();
        var flat = buckets.SelectMany(b => b.Value).ToList();
        var gate = new object();

        RunPerVolume(flat, f => FileWalk.VolumeOf(f.Path), o, ct, f =>
        {
            var info = IdentityOf(f.Path);
            if (!info.Resolved) { stats.Bump(ref stats.Unreadable); return; }

            lock (gate)
            {
                if (!perSize.TryGetValue(f.Length, out var byIdentity))
                    perSize[f.Length] = byIdentity = new Dictionary<FileIdentity, Candidate>();

                if (byIdentity.TryGetValue(info.Identity, out var existing))
                {
                    if (!existing.Paths.Contains(f.Path, StringComparer.OrdinalIgnoreCase))
                        existing.Paths.Add(f.Path);
                    return;
                }

                var candidate = new Candidate
                {
                    Identity = info.Identity,
                    Length = f.Length,
                    LastWriteUtc = f.LastWriteUtc,
                    LinkCount = info.LinkCount,
                };
                candidate.Paths.Add(f.Path);
                byIdentity[info.Identity] = candidate;
            }

            reporter.Maybe(() => new DuplicateProgress(
                DuplicateStage.Identity, stats.FilesWalked, stats.Candidates, 0, 0, f.Path));
        });

        var survivors = new List<Candidate>();
        foreach (var (_, byIdentity) in perSize)
        {
            if (byIdentity.Count >= 2) { survivors.AddRange(byIdentity.Values); continue; }

            // One identity, several names: one file, zero reclaim. Counted so the report can say
            // what it threw away, because silently discarding 21.9 GB of apparent duplicates and
            // reporting nothing looks like a broken scan.
            foreach (var c in byIdentity.Values)
            {
                if (c.Paths.Count <= 1) continue;
                stats.HardlinkSets++;
                stats.HardlinkPaths += c.Paths.Count;
            }
        }
        return survivors;
    }

    // -------------------------------------------------------------- discriminate

    /// <summary>
    /// The two content passes, cheapest first.
    ///
    /// Sampling exists because same-size files usually differ, and proving that costs 128 KB rather
    /// than the whole file. Files at or below the sample window are read once in full instead —
    /// two opens to sample then re-read a 100 KB file is slower than one open that reads all of it,
    /// and the digest that comes out is already conclusive.
    /// </summary>
    private static List<Candidate> Discriminate(List<Candidate> candidates, DuplicateScanOptions o,
                                                Counters stats, Throttle reporter, CancellationToken ct)
    {
        if (candidates.Count == 0) return candidates;

        long total = candidates.Sum(c => Math.Min(c.Length, (long)o.EffectiveSampleBytes * 2));
        RunPerVolume(candidates, c => c.Volume, o, ct, c =>
        {
            c.SampleKey = Sample(c, o, stats);
            if (c.SampleKey is null) c.Failed = true;
            reporter.Maybe(() => new DuplicateProgress(
                DuplicateStage.Sampling, stats.FilesWalked, stats.Candidates, stats.BytesRead, total, c.Paths[0]));
        });

        // Regroup on (length, sample). Length stays in the key because a sample digest from a
        // whole-file read and one from a head/tail pair are not comparable quantities.
        var afterSample = candidates
            .Where(c => !c.Failed && c.SampleKey is not null)
            .GroupBy(c => (c.Length, c.SampleKey))
            .Where(g => g.Count() >= 2)
            .SelectMany(g => g)
            .ToList();

        var needFull = afterSample.Where(c => !c.Conclusive).ToList();
        long fullTotal = needFull.Sum(c => c.Length);
        RunPerVolume(needFull, c => c.Volume, o, ct, c =>
        {
            c.ContentKey = FullHash(c, stats);
            if (c.ContentKey is null) c.Failed = true;
            reporter.Maybe(() => new DuplicateProgress(
                DuplicateStage.Hashing, stats.FilesWalked, stats.Candidates, stats.BytesRead, fullTotal, c.Paths[0]));
        });

        foreach (var c in afterSample)
            if (c.Conclusive) c.ContentKey = c.SampleKey;

        var matched = afterSample
            .Where(c => !c.Failed && c.ContentKey is not null)
            .GroupBy(c => (c.Length, c.ContentKey))
            .Where(g => g.Count() >= 2)
            .SelectMany(g => g)
            .ToList();

        if (!o.VerifyByteForByte || matched.Count == 0) return matched;

        // Opt-in second read. Compares every member of a set against the first, and evicts any file
        // that disagrees rather than dropping the whole set, so one flaky read cannot silently
        // discard a genuine group.
        var verified = new List<Candidate>();
        foreach (var g in matched.GroupBy(c => (c.Length, c.ContentKey)))
        {
            if (ct.IsCancellationRequested) break;
            var members = g.ToList();
            var reference = members[0];
            var kept = new List<Candidate> { reference };
            for (int i = 1; i < members.Count; i++)
            {
                reporter.Maybe(() => new DuplicateProgress(
                    DuplicateStage.Verifying, stats.FilesWalked, stats.Candidates,
                    stats.BytesRead, 0, members[i].Paths[0]));
                if (SameBytes(reference.Paths[0], members[i].Paths[0], stats, ct)) kept.Add(members[i]);
            }
            if (kept.Count >= 2) verified.AddRange(kept);
        }
        return verified;
    }

    /// <summary>
    /// Head and tail digest. Returns null when the file could not be read, which removes it from
    /// consideration entirely — an unreadable file is never assumed to match anything.
    /// </summary>
    private static string? Sample(Candidate c, DuplicateScanOptions o, Counters stats)
    {
        int window = o.EffectiveSampleBytes;
        try
        {
            // FileShare.ReadWrite | Delete so a file another process holds open still hashes;
            // SequentialScan tells the cache manager not to keep these pages, which matters when a
            // scan streams tens of gigabytes past a machine that is doing something else.
            using var fs = new FileStream(c.Paths[0], FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);

            if (c.Length <= (long)window * 2)
            {
                // The window covers the file, so this read IS the content and there is nothing for
                // a second pass to add.
                byte[] whole = ArrayPool<byte>.Shared.Rent((int)c.Length);
                try
                {
                    int read = ReadFully(fs, whole, 0, (int)c.Length);
                    stats.Add(ref stats.BytesRead, read);
                    stats.Bump(ref stats.FilesHashed);
                    c.Conclusive = true;
                    return Convert.ToHexString(SHA256.HashData(whole.AsSpan(0, read)));
                }
                finally { ArrayPool<byte>.Shared.Return(whole); }
            }

            byte[] buffer = ArrayPool<byte>.Shared.Rent(window * 2);
            try
            {
                int head = ReadFully(fs, buffer, 0, window);
                fs.Seek(-window, SeekOrigin.End);
                int tail = ReadFully(fs, buffer, head, window);
                stats.Add(ref stats.BytesRead, head + tail);
                return Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, head + tail)));
            }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
        }
        catch (IOException) { stats.Bump(ref stats.Unreadable); return null; }
        catch (UnauthorizedAccessException) { stats.Bump(ref stats.Unreadable); return null; }
        catch (Exception) { stats.Bump(ref stats.Unreadable); return null; }
    }

    private static string? FullHash(Candidate c, Counters stats)
    {
        try
        {
            using var fs = new FileStream(c.Paths[0], FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
            var hash = SHA256.HashData(fs);
            stats.Add(ref stats.BytesRead, c.Length);
            stats.Bump(ref stats.FilesHashed);
            return Convert.ToHexString(hash);
        }
        catch (IOException) { stats.Bump(ref stats.Unreadable); return null; }
        catch (UnauthorizedAccessException) { stats.Bump(ref stats.Unreadable); return null; }
        catch (Exception) { stats.Bump(ref stats.Unreadable); return null; }
    }

    private static bool SameBytes(string left, string right, Counters stats, CancellationToken ct)
    {
        const int Chunk = 1 << 20;
        byte[] a = ArrayPool<byte>.Shared.Rent(Chunk);
        byte[] b = ArrayPool<byte>.Shared.Rent(Chunk);
        try
        {
            using var fa = new FileStream(left, FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
            using var fb = new FileStream(right, FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
            if (fa.Length != fb.Length) return false;

            while (!ct.IsCancellationRequested)
            {
                int na = ReadFully(fa, a, 0, Chunk);
                int nb = ReadFully(fb, b, 0, Chunk);
                if (na != nb) return false;
                if (na == 0) return true;
                stats.Add(ref stats.BytesRead, na * 2);
                if (!a.AsSpan(0, na).SequenceEqual(b.AsSpan(0, nb))) return false;
            }
            return false;
        }
        catch { stats.Bump(ref stats.Unreadable); return false; }
        finally
        {
            ArrayPool<byte>.Shared.Return(a);
            ArrayPool<byte>.Shared.Return(b);
        }
    }

    /// <summary>A single Read can return short for reasons that have nothing to do with EOF, and a
    /// short head would produce a digest that matches nothing.</summary>
    private static int ReadFully(Stream stream, byte[] buffer, int offset, int count)
    {
        int total = 0;
        while (total < count)
        {
            int n = stream.Read(buffer, offset + total, count - total);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    // ------------------------------------------------------------------ groups

    /// <summary>
    /// Assembles the reviewable result and nominates a keeper for each group.
    /// </summary>
    private static List<DuplicateGroup> BuildGroups(List<Candidate> survivors, DuplicateScanOptions o,
                                                    Counters stats, Throttle reporter, CancellationToken ct)
    {
        var groups = new List<DuplicateGroup>();

        foreach (var g in survivors.GroupBy(c => (c.Length, c.ContentKey)))
        {
            if (ct.IsCancellationRequested) break;

            var copies = g.Select(c => new DuplicateCopy(
                                      c.Paths.ToList(), c.LinkCount, c.Length, c.AllocatedBytes,
                                      c.LastWriteUtc, c.Identity))
                          // Deterministic ordering so two runs over an unchanged tree produce the
                          // same rows in the same order; a keeper that moves between runs is how a
                          // user deletes copy A on Monday and copy B on Tuesday.
                          .OrderBy(c => c.PrimaryPath, StringComparer.OrdinalIgnoreCase)
                          .ToList();

            if (copies.Count < 2) continue;

            // Every copy carries names outside the scan, so nothing here can be freed however the
            // keeper is chosen. Genuinely duplicate content, genuinely zero win — withheld rather
            // than shown, because a row offering nothing still invites a deletion.
            if (copies.All(c => c.FreesBytesIfRemoved == 0)) { stats.GroupsWithNoReclaim++; continue; }

            int keep = ChooseKeeper(copies, out string rationale);
            groups.Add(Rebuild(new DuplicateGroup
            {
                Sha256 = g.Key.ContentKey ?? "",
                LogicalBytes = g.Key.Length,
                Copies = copies,
                KeepIndex = keep,
                KeepRationale = rationale,
                ReclaimableBytes = 0,
                Redundant = Array.Empty<DuplicateCopy>(),
            }));

            reporter.Maybe(() => new DuplicateProgress(
                DuplicateStage.Building, stats.FilesWalked, stats.Candidates,
                stats.BytesRead, stats.BytesRead, copies[0].PrimaryPath));
        }

        return groups.OrderByDescending(x => x.ReclaimableBytes)
                     .ThenByDescending(x => x.LogicalBytes)
                     .ToList();
    }

    /// <summary>
    /// Recomputes the derived figures from the keeper index. Called by the builder and by
    /// <see cref="DuplicateGroup.WithKeeper"/>, so the two can never drift.
    ///
    /// An index outside the range yields an EMPTY redundant list and zero reclaim. That direction
    /// is not arbitrary: the opposite failure — treating an invalid keeper as "keep nothing" —
    /// produces a group whose every copy is proposed for deletion.
    /// </summary>
    internal static DuplicateGroup Rebuild(DuplicateGroup g)
    {
        if (g.KeepIndex < 0 || g.KeepIndex >= g.Copies.Count)
            return g with { Redundant = Array.Empty<DuplicateCopy>(), ReclaimableBytes = 0 };

        var redundant = new List<DuplicateCopy>(g.Copies.Count - 1);
        for (int i = 0; i < g.Copies.Count; i++)
        {
            if (i == g.KeepIndex) continue;
            // Removing a copy that still has a name elsewhere frees nothing, so it is not proposed.
            // Listing it would put a row in front of the user whose best possible outcome is that
            // they lose a file and gain no space.
            if (g.Copies[i].FreesBytesIfRemoved <= 0) continue;
            redundant.Add(g.Copies[i]);
        }

        return g with
        {
            Redundant = redundant,
            ReclaimableBytes = redundant.Sum(c => c.FreesBytesIfRemoved),
        };
    }

    /// <summary>
    /// Picks the copy to keep, by a stated rule in a fixed order.
    ///
    /// Deliberately NOT "whichever choice maximises the reclaim figure". Copies can differ in
    /// on-disk size when one is NTFS-compressed, so a keeper chosen to flatter the headline would
    /// systematically nominate the cheaper copy for survival and the expensive one for deletion —
    /// a tool tuning its own advertised number is exactly what makes these features untrustworthy.
    ///
    /// 1. A copy with links outside the scan. Deleting it frees nothing, so proposing it is pure
    ///    downside; it survives by default.
    /// 2. A copy inside a sync folder. A deletion there is not a local reclaim — it removes the
    ///    file from every device on the account, which is a far larger action than the user asked
    ///    for.
    /// 3. A copy outside cache, temp and build-output directories, when one exists. Between an
    ///    original and something generated from it, the generated one is the safe casualty.
    /// 4. The oldest last-write time — the likeliest original, and the one other things point at.
    /// 5. Shortest path, then ordinal comparison. Pure tie-breaking, present so the answer is
    ///    stable across runs rather than dependent on enumeration order.
    /// </summary>
    private static int ChooseKeeper(IReadOnlyList<DuplicateCopy> copies, out string rationale)
    {
        int best = 0;
        rationale = "";
        for (int i = 1; i < copies.Count; i++)
            if (Better(copies[i], copies[best])) best = i;

        var k = copies[best];
        rationale =
            k.HasLinksOutsideScan ? "kept: other hard links to this file exist outside the scan, so removing it would free nothing"
            : k.InCloudSyncFolder ? "kept: it is inside a synced folder, where a deletion would propagate to every device"
            : !k.InDerivedLocation && copies.Any(c => c.InDerivedLocation)
                ? "kept: the other copies are in cache, temp or build-output locations"
            : copies.All(c => c.LastWriteUtc >= k.LastWriteUtc)
                ? $"kept: oldest copy, last written {Human.Age(DateTime.UtcNow - k.LastWriteUtc)} ago"
            : "kept: shortest path, as a stable tie-break";
        return best;

        static bool Better(DuplicateCopy a, DuplicateCopy b)
        {
            if (a.HasLinksOutsideScan != b.HasLinksOutsideScan) return a.HasLinksOutsideScan;
            if (a.InCloudSyncFolder != b.InCloudSyncFolder) return a.InCloudSyncFolder;
            if (a.InDerivedLocation != b.InDerivedLocation) return !a.InDerivedLocation;
            if (a.LastWriteUtc != b.LastWriteUtc) return a.LastWriteUtc < b.LastWriteUtc;
            if (a.PrimaryPath.Length != b.PrimaryPath.Length) return a.PrimaryPath.Length < b.PrimaryPath.Length;
            return string.CompareOrdinal(a.PrimaryPath, b.PrimaryPath) < 0;
        }
    }

    // ----------------------------------------------------------------- plumbing

    /// <summary>
    /// Runs <paramref name="body"/> over items grouped by volume, one worker per mechanical volume
    /// and several per solid-state one.
    ///
    /// The same rule FileWalk applies for the same measured reason: the three NVMe drives here
    /// sustain 113,753 files/s under concurrency while D: is a 12 TB WDC WD121KRYZ where parallel
    /// access is seek thrash and is net SLOWER than a single reader. Volumes run against each other
    /// regardless, since they are independent devices.
    /// </summary>
    private static void RunPerVolume<T>(IReadOnlyList<T> items, Func<T, string> volumeOf,
                                        DuplicateScanOptions o, CancellationToken ct, Action<T> body)
    {
        if (items.Count == 0) return;

        var groups = items.GroupBy(volumeOf, StringComparer.OrdinalIgnoreCase).ToList();
        try
        {
            Parallel.ForEach(groups, new ParallelOptions { CancellationToken = CancellationToken.None }, g =>
            {
                int workers = SystemHealth.HasSeekPenalty(g.Key) ? 1 : Math.Max(1, o.SolidStateWorkers);
                if (workers == 1)
                {
                    foreach (var item in g)
                    {
                        if (ct.IsCancellationRequested) return;
                        body(item);
                    }
                    return;
                }

                Parallel.ForEach(g, new ParallelOptions { MaxDegreeOfParallelism = workers }, item =>
                {
                    if (!ct.IsCancellationRequested) body(item);
                });
            });
        }
        catch (AggregateException)
        {
            // A body that threw despite its own try/catch must not take the scan with it; the
            // affected files simply never acquire a hash and drop out of every later stage.
        }
    }

    /// <summary>
    /// Scan counters.
    ///
    /// The identity, sampling and hashing stages all run several threads per solid-state volume, so
    /// everything they touch goes through Interlocked. <see cref="FilesWalked"/> is the exception
    /// and is a plain increment: the walk is single-threaded by construction (see WalkOne), and an
    /// interlocked increment executed 1.5 million times to serialise against nobody is not free.
    /// <see cref="HardlinkSets"/> and <see cref="GroupsWithNoReclaim"/> are likewise written only
    /// from the single-threaded phases that follow each parallel stage.
    /// </summary>
    private sealed class Counters
    {
        internal long FilesWalked;
        internal long Candidates;
        internal long FilesHashed;
        internal long BytesRead;
        internal long BelowFloor;
        internal long SparseFiles;
        internal long CloudPlaceholders;
        internal long ExcludedByPolicy;
        internal long Unreadable;
        internal int HardlinkSets;
        internal long HardlinkPaths;
        internal int GroupsWithNoReclaim;

        internal void Bump(ref long field) => Interlocked.Increment(ref field);
        internal void Add(ref long field, long value) => Interlocked.Add(ref field, value);
    }

    /// <summary>
    /// Time-based progress gate.
    ///
    /// Per-file reporting on a 1.5M-file walk marshals more than a million callbacks onto the UI
    /// thread, which costs more than the scan. Two hundred milliseconds is faster than a person
    /// perceives as lag and roughly four orders of magnitude fewer calls.
    /// </summary>
    private sealed class Throttle
    {
        private readonly IProgress<DuplicateProgress>? _sink;
        private readonly Stopwatch _since = Stopwatch.StartNew();
        private long _lastMs;

        internal Throttle(IProgress<DuplicateProgress>? sink) => _sink = sink;

        /// <summary>Takes a factory rather than a value so a suppressed report costs nothing but
        /// the elapsed-time check — no record allocation, no string interpolation.</summary>
        internal void Maybe(Func<DuplicateProgress> build)
        {
            if (_sink is null) return;
            long now = _since.ElapsedMilliseconds;
            if (now - Interlocked.Read(ref _lastMs) < 200) return;
            Interlocked.Exchange(ref _lastMs, now);
            _sink.Report(build());
        }

        internal void Force(DuplicateProgress p) => _sink?.Report(p);
    }
}
