using System.Diagnostics;

namespace Hero.Maintenance;

/// <summary>
/// Where the space actually went.
///
/// The Maintenance page answers "what can I safely delete". This answers the different and more
/// common question: "930 GB is full and I do not know why". Those need different machinery —
/// Maintenance walks a fixed catalogue of known locations, this walks whatever the user points at
/// and reports what it finds, including things nobody would ever put in a cleanup catalogue.
///
/// THE MEASUREMENT DECISION, STATED ONCE AND APPLIED EVERYWHERE:
///
/// Every figure here is LOGICAL length, except for sparse files, which are corrected to their
/// on-disk size. That combination is deliberate.
///
///  * Logical is free. FileWalk already has it from the directory entry, and taking allocated size
///    for every file costs a second syscall each — the difference between a 13-second walk of 1.5M
///    files and minutes (PLATFORM-FACTS §17). An analyzer nobody waits for is not an analyzer.
///  * Sparse files make logical a lie. Measured on this machine:
///    %LOCALAPPDATA%\Google\Play Games\...\userdata.img reports 512.0 GB and occupies 191.2 MB —
///    a 2,741x over-report, on a volume with about 200 GB free. Ranked by logical length that one
///    file would be the entire answer, and the answer would be nonsense.
///  * The correction is cheap because sparseness is FREE to detect: FileAttributes.SparseFile is
///    already in the directory entry that FileWalk read. Only those files pay for a second call,
///    and there are a handful of them on a normal machine.
///
/// Compressed files are NOT corrected, and that is a different judgement rather than an oversight.
/// A compressed file's logical size is what it costs you to keep — decompression is transparent, so
/// the number the user reasons about is the logical one. A sparse file's holes are not stored at
/// all, so its logical size is fiction. <see cref="FileUsage.IsSparse"/> marks the corrected ones.
/// </summary>
internal static class DiskAnalyzer
{
    /// <summary>
    /// How deep the folder roll-up goes.
    ///
    /// Every file adds its size to each ancestor up to this depth, so the cost is (depth) dictionary
    /// operations per file rather than (its own depth). Three levels answers "which folder is
    /// eating the disk" for every real case — C:\Users\<user>\AppData is depth 3 — while keeping a
    /// 1.5M-file walk to roughly 4.5M cheap operations instead of an unbounded number.
    /// </summary>
    private const int RollupDepth = 3;

    /// <summary>How many of the biggest files to keep. Bounded so a full-volume walk cannot grow
    /// a list of every file it has ever seen.</summary>
    private const int LargestFilesKept = 200;

    // ------------------------------------------------------------------ results

    internal sealed record DirectoryUsage(string Path, long Bytes, long FileCount, int Depth)
    {
        internal string Name => System.IO.Path.GetFileName(Path) is { Length: > 0 } n ? n : Path;
    }

    internal sealed record FileUsage(
        string Path, long Bytes, long LogicalBytes, DateTime LastWriteUtc, bool IsSparse)
    {
        internal string Name => System.IO.Path.GetFileName(Path);

        /// <summary>True when the logical length materially overstates what the file occupies.
        /// Only sparse files reach this, and only they are corrected.</summary>
        internal bool Overstated => IsSparse && LogicalBytes > Bytes * 2;
    }

    internal sealed record TypeUsage(string Category, long Bytes, long FileCount);

    internal sealed record AnalyzeProgress(long FilesSeen, long BytesSeen, string CurrentRoot);

    internal sealed record DiskUsageReport
    {
        internal required string Root { get; init; }
        internal required AccessState State { get; init; }

        internal long TotalBytes { get; init; }
        internal long FileCount { get; init; }

        internal IReadOnlyList<DirectoryUsage> TopDirectories { get; init; } = Array.Empty<DirectoryUsage>();
        internal IReadOnlyList<FileUsage> LargestFiles { get; init; } = Array.Empty<FileUsage>();
        internal IReadOnlyList<TypeUsage> ByType { get; init; } = Array.Empty<TypeUsage>();

        /// <summary>
        /// Raw extensions, biggest first, alongside the friendly categories.
        ///
        /// Categories alone were not an answer. Measured on E: of this machine, the largest
        /// category was "Other" at 1.71 TB of 2.61 TB — the map does not know Steam's formats, and
        /// no map ever will know all of them. Telling a user that two thirds of their drive is
        /// "Other" is barely better than telling them nothing. The extension list needs no
        /// vocabulary: whatever is actually there shows up under its own name.
        /// </summary>
        internal IReadOnlyList<TypeUsage> ByExtension { get; init; } = Array.Empty<TypeUsage>();

        /// <summary>Sparse files whose logical length was corrected, and by how much in total.
        /// Surfaced rather than hidden: a user comparing this to Explorer deserves to know why the
        /// numbers differ.</summary>
        internal int SparseFilesCorrected { get; init; }
        internal long SparseBytesReclaimedFromLie { get; init; }

        internal int DeniedDirectories { get; init; }
        internal bool Cancelled { get; init; }
        internal TimeSpan Elapsed { get; init; }

        /// <summary>Volume free/total when the root is a whole volume, so the page can show what
        /// share of the disk was actually accounted for. Zero when the root is a subdirectory.</summary>
        internal long VolumeFreeBytes { get; init; }
        internal long VolumeTotalBytes { get; init; }

        internal string Display
        {
            get
            {
                if (State == AccessState.NotPresent) return "that path does not exist";
                if (State == AccessState.AccessDenied) return "that path could not be opened";

                var head = $"{Human.Bytes(TotalBytes)} across {Human.Count(FileCount)} files";

                if (VolumeTotalBytes > 0)
                {
                    long used = VolumeTotalBytes - VolumeFreeBytes;
                    if (used > 0)
                        head += $", {(int)Math.Round(100.0 * TotalBytes / used)}% of what is used on this volume";
                }

                if (SparseFilesCorrected > 0)
                    head += $"; {Human.Count(SparseFilesCorrected)} sparse files corrected from " +
                            $"{Human.Bytes(TotalBytes + SparseBytesReclaimedFromLie)} apparent";

                if (DeniedDirectories > 0)
                    head += $"; {Human.Count(DeniedDirectories)} folders could not be read";

                if (Cancelled) head += "; stopped early, so this is a lower bound";
                return head;
            }
        }
    }

    // ------------------------------------------------------------------ the walk

    /// <summary>
    /// Walks one root and reports what is using the space.
    ///
    /// Never follows reparse points and caps depth, because %LOCALAPPDATA%\Application Data is a
    /// junction to its own parent on this machine — a walker that follows them does not terminate.
    /// FileWalk already skips them; MaxDepth is the belt behind that brace.
    ///
    /// A directory that cannot be read is counted and stepped over. A partial answer that says it
    /// is partial is worth far more here than an exception: the interesting folders on a Windows
    /// volume are frequently the ones an unelevated process cannot fully enumerate.
    /// </summary>
    internal static DiskUsageReport Analyze(string root,
                                            IProgress<AnalyzeProgress>? progress = null,
                                            CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        string normalised = Normalise(root);
        var state = FileWalk.Probe(normalised, out bool isDirectory);
        if (state is AccessState.NotPresent || !isDirectory)
            return new DiskUsageReport { Root = normalised, State = AccessState.NotPresent, Elapsed = sw.Elapsed };
        if (state == AccessState.AccessDenied)
            return new DiskUsageReport { Root = normalised, State = AccessState.AccessDenied, Elapsed = sw.Elapsed };

        var byDirectory = new Dictionary<string, (long Bytes, long Files)>(StringComparer.OrdinalIgnoreCase);
        var byType = new Dictionary<string, (long Bytes, long Files)>(StringComparer.OrdinalIgnoreCase);
        var byExtension = new Dictionary<string, (long Bytes, long Files)>(StringComparer.OrdinalIgnoreCase);
        var largest = new List<FileUsage>(LargestFilesKept + 64);

        long total = 0, count = 0;
        int sparseCorrected = 0;
        long sparseLie = 0;
        long smallestKept = 0;

        int rootLength = normalised.TrimEnd(Path.DirectorySeparatorChar).Length;

        // The predicate is the per-file hook. Returning false means "do not collect this into the
        // caller's list" — the aggregation below is the whole point, and materialising 1.5M
        // ScannedFile records to walk them a second time would cost hundreds of megabytes.
        //
        // Exactly one root is passed to ScanRoots, which takes its single-threaded branch (one
        // volume group, one item), so this closure is never called concurrently and needs no lock.
        // DevCaches.NewestWrite and DuplicateFinder both rely on the same property.
        bool OnFile(ScannedFile file)
        {
            if (ct.IsCancellationRequested) return false;

            long size = file.Length;

            // Sparse correction. FileAttributes.SparseFile came free with the directory entry, so
            // only the rare sparse file pays for the extra syscall.
            bool sparse = (file.Attributes & FileAttributes.SparseFile) != 0;
            if (sparse)
            {
                long onDisk = FileWalk.AllocatedBytes(file.Path);
                if (onDisk >= 0 && onDisk < size)
                {
                    sparseCorrected++;
                    sparseLie += size - onDisk;
                    size = onDisk;
                }
            }

            total += size;
            count++;

            Rollup(byDirectory, file.Path, rootLength, size);
            Add(byType, CategoryOf(file.Path), size);

            // The extension verbatim, lower-cased. No vocabulary, no guessing — whatever is on the
            // disk appears under its own name, which is what makes this useful where the category
            // map has nothing to say.
            string ext = Path.GetExtension(file.Path);
            Add(byExtension, ext.Length > 0 ? ext.ToLowerInvariant() : "(no extension)", size);

            if (largest.Count < LargestFilesKept || size > smallestKept)
            {
                largest.Add(new FileUsage(file.Path, size, file.Length, file.LastWriteUtc, sparse));
                if (largest.Count > LargestFilesKept + 48)
                {
                    largest.Sort((a, b) => b.Bytes.CompareTo(a.Bytes));
                    largest.RemoveRange(LargestFilesKept, largest.Count - LargestFilesKept);
                    smallestKept = largest[^1].Bytes;
                }
            }

            if ((count & 0x3FFF) == 0)
                progress?.Report(new AnalyzeProgress(count, total, normalised));

            return false;
        }

        var options = new WalkOptions { MaxDepth = 32 };
        var measurement = FileWalk.ScanRoots(new[] { normalised }, options, null, 0, OnFile, ct);

        largest.Sort((a, b) => b.Bytes.CompareTo(a.Bytes));
        if (largest.Count > LargestFilesKept) largest.RemoveRange(LargestFilesKept, largest.Count - LargestFilesKept);

        long free = 0, capacity = 0;
        if (IsVolumeRoot(normalised))
        {
            free = FileWalk.FreeBytes(normalised);
            capacity = FileWalk.TotalBytes(normalised);
        }

        return new DiskUsageReport
        {
            Root = normalised,

            // Derived from what was actually produced, NOT copied from the walk.
            //
            // ScanRoots reports AccessDenied when it met denied directories anywhere in the tree,
            // which on C:\ is guaranteed — System Volume Information alone does it. Propagating
            // that verbatim made a completed walk of 2.1 million files announce itself as "that
            // path could not be opened", with a full set of results sitting underneath the
            // sentence. Denial deep in a tree is a partial answer; only a root that never opened
            // is a failure, and that case already returned above.
            State = count > 0
                ? (measurement.DeniedDirectories > 0 ? AccessState.PartiallyMeasured : AccessState.Measured)
                : measurement.State,
            TotalBytes = total,
            FileCount = count,
            TopDirectories = byDirectory
                .Select(kv => new DirectoryUsage(kv.Key, kv.Value.Bytes, kv.Value.Files, DepthOf(kv.Key, rootLength)))
                .OrderByDescending(d => d.Bytes)
                .Take(200)
                .ToList(),
            LargestFiles = largest,
            ByType = byType
                .Select(kv => new TypeUsage(kv.Key, kv.Value.Bytes, kv.Value.Files))
                .OrderByDescending(t => t.Bytes)
                .ToList(),
            ByExtension = byExtension
                .Select(kv => new TypeUsage(kv.Key, kv.Value.Bytes, kv.Value.Files))
                .OrderByDescending(t => t.Bytes)
                .Take(20)
                .ToList(),
            SparseFilesCorrected = sparseCorrected,
            SparseBytesReclaimedFromLie = sparseLie,
            DeniedDirectories = measurement.DeniedDirectories,
            Cancelled = ct.IsCancellationRequested,
            Elapsed = sw.Elapsed,
            VolumeFreeBytes = free,
            VolumeTotalBytes = capacity,
        };
    }

    // ------------------------------------------------------------------ aggregation

    /// <summary>
    /// Adds a file's size to each of its ancestor folders, down to <see cref="RollupDepth"/> levels
    /// below the scanned root. Bounded on purpose — see the constant.
    /// </summary>
    private static void Rollup(Dictionary<string, (long Bytes, long Files)> into,
                               string filePath, int rootLength, long size)
    {
        int from = rootLength;
        for (int level = 0; level < RollupDepth; level++)
        {
            int next = filePath.IndexOf(Path.DirectorySeparatorChar, from + 1);
            if (next < 0) break;

            string dir = filePath[..next];
            into.TryGetValue(dir, out var acc);
            into[dir] = (acc.Bytes + size, acc.Files + 1);

            from = next;
        }
    }

    private static void Add(Dictionary<string, (long Bytes, long Files)> into, string key, long size)
    {
        into.TryGetValue(key, out var acc);
        into[key] = (acc.Bytes + size, acc.Files + 1);
    }

    private static int DepthOf(string path, int rootLength)
    {
        int depth = 0;
        for (int i = rootLength; i < path.Length; i++)
            if (path[i] == Path.DirectorySeparatorChar) depth++;
        return depth;
    }

    // ------------------------------------------------------------------ classification

    /// <summary>
    /// Extension to a human category.
    ///
    /// Grouped by what the user would DO about it rather than by format family: "video" and
    /// "disk images" are separable decisions, "mp4 vs mkv" is not. Anything unrecognised lands in
    /// Other rather than being invented into a category, because a wrong label on a 40 GB row is
    /// worse than no label.
    /// </summary>
    private static string CategoryOf(string path)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".mp4" or ".mkv" or ".avi" or ".mov" or ".wmv" or ".flv" or ".webm" or ".m4v" => "Video",
            ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".webp" or ".tif" or ".tiff"
                or ".heic" or ".raw" or ".cr2" or ".nef" or ".dng" or ".psd" or ".svg" => "Images",
            ".mp3" or ".flac" or ".wav" or ".aac" or ".ogg" or ".m4a" or ".wma" => "Audio",
            ".zip" or ".7z" or ".rar" or ".tar" or ".gz" or ".bz2" or ".xz" or ".zst" or ".cab" => "Archives",
            ".iso" or ".vhd" or ".vhdx" or ".vmdk" or ".vdi" or ".qcow2" or ".img" => "Disk images",
            ".msi" or ".msix" or ".appx" or ".exe" or ".dll" or ".sys" or ".pyd" or ".node" => "Programs",
            ".pdf" or ".docx" or ".doc" or ".xlsx" or ".xls" or ".pptx" or ".ppt"
                or ".txt" or ".md" or ".rtf" or ".odt" or ".epub" => "Documents",
            ".cs" or ".js" or ".ts" or ".py" or ".rs" or ".go" or ".java" or ".c" or ".cpp" or ".h"
                or ".json" or ".xml" or ".yml" or ".yaml" or ".html" or ".css" or ".sql" => "Code and data",
            ".pak" or ".uasset" or ".umap" or ".bsa" or ".ba2" or ".vpk" or ".acf" or ".bin" => "Game data",
            ".log" or ".etl" or ".dmp" or ".tmp" or ".temp" or ".bak" or ".old" => "Logs and temporary",
            "" => "No extension",
            _ => "Other",
        };
    }

    // ------------------------------------------------------------------ paths

    /// <summary>
    /// Keeps a volume root's trailing separator and expands a drive-relative "D:".
    ///
    /// The same trap the duplicate finder hit: Path.GetFullPath("D:") returns the process's
    /// per-drive current directory — "D:\My projects" here — not the volume root, so a user asking
    /// to analyse a drive would silently have analysed a folder.
    /// </summary>
    private static string Normalise(string path)
    {
        string raw = path.Trim();
        if (raw.Length == 2 && raw[1] == ':') raw += Path.DirectorySeparatorChar;

        try
        {
            string full = Path.GetFullPath(raw);
            string root = Path.GetPathRoot(full) ?? "";
            return full.Equals(root, StringComparison.OrdinalIgnoreCase)
                ? full
                : full.TrimEnd(Path.DirectorySeparatorChar);
        }
        catch { return raw; }
    }

    private static bool IsVolumeRoot(string path)
    {
        string root = Path.GetPathRoot(path) ?? "";
        return path.Equals(root, StringComparison.OrdinalIgnoreCase);
    }
}
