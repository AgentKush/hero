using System.IO.Enumeration;
using System.Runtime.InteropServices;
using Hero.Core;
using Hero.Interop;

namespace Hero.Maintenance;

/// <summary>
/// Whether a number on screen is real.
///
/// This tri-state exists because of a specific measured failure: reading
/// <c>C:\Windows\Temp</c> unelevated returns "0 files" rather than an error, and
/// <c>C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache</c> fails even a
/// Test-Path. Rendering either as "0 B reclaimable" is a lie that discredits every other
/// figure on the page, so no measurement may be displayed without its state.
/// </summary>
internal enum AccessState
{
    /// <summary>No attempt has been made yet.</summary>
    NotMeasured,
    /// <summary>Walked completely. The figure is trustworthy.</summary>
    Measured,
    /// <summary>Walked, but some directories were unreadable. The figure is a lower bound.</summary>
    PartiallyMeasured,
    /// <summary>The root itself could not be opened. Almost always "needs admin".</summary>
    AccessDenied,
    /// <summary>The path does not exist. Render no row at all — see NotPresent handling below.</summary>
    NotPresent,
}

/// <summary>
/// How much trust an action needs before it may run.
///
/// The line that matters is <see cref="Regenerable"/> versus everything else: a regenerable
/// item can be re-fetched from the network or rebuilt locally with no user decision, so it may
/// be deleted outright and never enters the vault. Everything else is user data until proven
/// otherwise, because misclassifying a cache as user data merely wastes vault space whereas
/// the reverse is unrecoverable.
/// </summary>
internal enum CleanupRisk
{
    Regenerable,
    Low,
    Medium,
    High,
    /// <summary>HERO measures and explains this, and deliberately refuses to clean it.</summary>
    NeverClean,
}

internal enum CleanupCategory
{
    WindowsTemp,
    WindowsUpdate,
    Diagnostics,
    ShellCache,
    BrowserCache,
    AppCache,
    RecycleBin,
    PackageManagerCache,
    BuildOutput,
    EngineCache,
    VirtualDisk,
    Logs,
    /// <summary>Surfaced for information only; there is no action attached.</summary>
    Informational,
}

/// <summary>
/// Where an item sits on the autonomy line.
///
/// The rule, inherited from the Guardian half: act without asking only when the action is
/// fully reversible or purely regenerative AND nothing needs elevation. Elevation is the hard
/// part — a scheduled task running as SYSTEM doing recursive deletions under C:\Windows with
/// no user present is the single most dangerous construct this design could produce, so
/// anything <see cref="CleanupTarget.NeedsAdmin"/> is forced to <see cref="Prompt"/> no matter
/// what the target declares.
/// </summary>
internal enum AutomationTier { Automatic, Prompt, ReadOnly }

/// <summary>Why an item was not deleted.</summary>
internal enum SkipReason { None, InUse, AccessDenied, AlreadyGone, OutsideTarget, Protected, PathTooLong, Unknown }

/// <summary>One file as seen by the walker. Everything here comes from the directory entry
/// already in hand, so constructing it costs no extra syscall.</summary>
internal readonly record struct ScannedFile(string Path, long Length, DateTime LastWriteUtc, FileAttributes Attributes,
                                           string DisplayPath = "")
{
    /// <summary>
    /// What to show the user, when that is not the path being deleted.
    ///
    /// Exists for the recycle bin and nothing else so far. There the file on disk is
    /// <c>$RECYCLE.BIN\&lt;sid&gt;\$RABCDEF.txt</c>, which tells a person nothing, while the name they
    /// need is the path it was deleted from. Every other target deletes the file it shows, so
    /// DisplayPath is empty and <see cref="Display"/> falls back to Path.
    /// </summary>
    internal string Display => DisplayPath.Length > 0 ? DisplayPath : Path;

    /// <summary>The preview renders this. Without it a record struct prints its whole shape.</summary>
    public override string ToString() => Display;

    // Not in the FileAttributes enum, so declared as raw values from winnt.h.
    private const FileAttributes RecallOnOpen = (FileAttributes)0x00040000;
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000;

    /// <summary>
    /// True for a dehydrated cloud file (OneDrive and friends). Enumeration never hydrates
    /// one — FindNextFile reads metadata only — but anything that OPENS the file does, so a
    /// hasher or a content comparer must skip these or a "scan" silently downloads gigabytes
    /// onto the volume it was asked to clean.
    /// </summary>
    internal bool IsCloudPlaceholder =>
        (Attributes & (FileAttributes.Offline | RecallOnOpen | RecallOnDataAccess)) != 0;

    internal bool IsReadOnly => (Attributes & FileAttributes.ReadOnly) != 0;
}

/// <summary>The result of measuring one target, with the honesty state attached.</summary>
internal sealed record Measurement
{
    internal required AccessState State { get; init; }
    internal long Bytes { get; init; }
    internal long Files { get; init; }
    /// <summary>Directories the walk could not open. Non-zero forces PartiallyMeasured.</summary>
    internal int DeniedDirectories { get; init; }
    internal TimeSpan Elapsed { get; init; }
    internal string Note { get; init; } = "";

    internal static Measurement NotPresent(string note = "") =>
        new() { State = AccessState.NotPresent, Note = note };

    internal static Measurement Denied(string note) =>
        new() { State = AccessState.AccessDenied, Note = note };

    /// <summary>What the UI shows. Never renders a byte count for a state that has none.</summary>
    internal string Display => State switch
    {
        AccessState.NotPresent => "not present",
        AccessState.AccessDenied => "requires administrator to read",
        AccessState.NotMeasured => "not measured",
        AccessState.PartiallyMeasured =>
            $"at least {Human.Bytes(Bytes)} in {Human.Count(Files)} files ({DeniedDirectories} directories unreadable)",
        _ => $"{Human.Bytes(Bytes)} in {Human.Count(Files)} files",
    };
}

/// <summary>Something standing between the plan and running it.</summary>
/// <param name="Reason">Short machine-ish key, e.g. "process-running".</param>
/// <param name="Detail">One sentence the user can act on.</param>
/// <param name="Blocking">False for an advisory the user may override.</param>
internal sealed record CleanupBlocker(string Reason, string Detail, bool Blocking = true)
{
    /// <summary>
    /// Whether this blocker is meaningful to re-evaluate WHILE a deletion is running.
    ///
    /// The executor re-checks blockers every batch, and the reason it does is to catch a
    /// conflicting process that STARTED mid-run — a build kicking off inside a package cache HERO
    /// is halfway through emptying. That check is worth its cost for anything that observes other
    /// programs.
    ///
    /// It is actively harmful for anything that observes FILE TIMESTAMPS, because HERO's own
    /// deleting changes them. Measured: the Windows Update cache aborted itself after 511 of
    /// 734,915 files with "the newest item here was written moments ago, so an update may be in
    /// flight" — the moments-ago writer being HERO, removing files from that very folder. A
    /// heuristic that trips on its own footprints will never finish anything.
    ///
    /// So timestamp-derived blockers are evaluated once, before the run starts, where they mean
    /// what they say.
    /// </summary>
    internal bool RecheckDuringRun { get; init; } = true;
}

/// <summary>
/// The exact set of things an execution would remove.
///
/// A plan is the only input <see cref="CleanupExecutor"/> accepts, and it can only be produced
/// by <see cref="CleanupTarget.Preview"/>. That is deliberate: there is no code path from
/// "here is a directory" to "delete it" that does not pass through a reviewable list first.
/// </summary>
internal sealed record CleanupPlan
{
    internal required string TargetId { get; init; }
    internal required IReadOnlyList<ScannedFile> Files { get; init; }
    internal required Measurement Measurement { get; init; }
    internal IReadOnlyList<CleanupBlocker> Blockers { get; init; } = Array.Empty<CleanupBlocker>();

    /// <summary>True when the item list was capped. Totals still come from the full walk.</summary>
    internal bool Truncated { get; init; }

    /// <summary>Roots re-validated at execution time. A path outside these is refused.</summary>
    internal required IReadOnlyList<string> Roots { get; init; }

    /// <summary>Remove directories left empty by the deletion (never the roots themselves).</summary>
    internal bool PruneEmptyDirectories { get; init; } = true;

    internal long Bytes => Measurement.Bytes;
    internal bool CanRun => Blockers.All(b => !b.Blocking) && Files.Count > 0;
}

/// <summary>What actually happened. Reports what was deleted AND what the volume did, because
/// they differ whenever a shadow copy still references the freed blocks.</summary>
internal sealed record CleanupOutcome
{
    internal required string TargetId { get; init; }
    internal long BytesDeleted { get; init; }
    internal long FilesDeleted { get; init; }
    internal long DirectoriesRemoved { get; init; }
    internal IReadOnlyList<(string Path, SkipReason Reason)> Skipped { get; init; }
        = Array.Empty<(string, SkipReason)>();
    internal bool Cancelled { get; init; }
    internal bool AbortedByBlocker { get; init; }
    internal string AbortReason { get; init; } = "";
    internal TimeSpan Elapsed { get; init; }

    /// <summary>
    /// The file this run had most recently reached, for progress reporting. Empty on the final
    /// outcome — it means nothing once the run is over.
    ///
    /// Carried so a caller can say WHAT is being removed rather than only how much. Deleting the
    /// 171,544-file npm cache takes minutes, and a line that reads "Cleaning 2 of 22: npm cache…"
    /// for all of them is indistinguishable from a hang — which is the same complaint this
    /// screen's measuring phase already had, arriving again one phase later.
    /// </summary>
    internal string CurrentPath { get; init; } = "";

    /// <summary>Files the plan expects to remove, so a caller can show a fraction.</summary>
    internal long FilesPlanned { get; init; }

    /// <summary>Free-space change per volume root, measured either side of the run.</summary>
    internal IReadOnlyDictionary<string, long> FreeSpaceDelta { get; init; }
        = new Dictionary<string, long>();

    /// <summary>
    /// The honest headline. When the volume delta is materially smaller than the bytes deleted
    /// the difference is almost always a VSS shadow copy still holding the blocks, and saying so
    /// is better than reporting a reclaim the user cannot see in Explorer.
    /// </summary>
    internal string Display
    {
        get
        {
            long delta = FreeSpaceDelta.Values.Sum();
            string head = $"{Human.Bytes(BytesDeleted)} deleted ({Human.Count(FilesDeleted)} files)";
            if (BytesDeleted > 0 && delta < BytesDeleted - (BytesDeleted / 10))
                head += $"; volume free space rose by only {Human.Bytes(Math.Max(0, delta))} — " +
                        "the remainder is still referenced by a shadow copy and returns when it ages out";
            if (Skipped.Count > 0) head += $"; {Human.Count(Skipped.Count)} skipped";
            return head;
        }
    }
}

/// <summary>
/// One reclaimable thing: a named set of paths, a risk rating, and the two read-only operations
/// (<see cref="Measure"/>, <see cref="Preview"/>) that describe it.
///
/// Nothing on this type deletes. Removal lives on <see cref="CleanupExecutor"/> and takes a
/// <see cref="CleanupPlan"/>, so the sequence is always measure, preview, show, approve, execute.
/// </summary>
internal class CleanupTarget
{
    internal required string Id { get; init; }
    internal required CleanupCategory Category { get; init; }
    internal required string DisplayName { get; init; }

    /// <summary>What this is, in plain words, including what it costs to lose it.</summary>
    internal required string Description { get; init; }

    /// <summary>Every path this target touches. The executor refuses anything outside them.</summary>
    internal required IReadOnlyList<string> Paths { get; init; }

    internal CleanupRisk Risk { get; init; } = CleanupRisk.Medium;
    internal bool NeedsAdmin { get; init; }

    /// <summary>Declared tier. <see cref="EffectiveTier"/> is what actually applies.</summary>
    internal AutomationTier Tier { get; init; } = AutomationTier.Prompt;

    /// <summary>One line: what breaks if HERO is wrong about this. Shown next to every action.</summary>
    internal string WhatBreaksIfWrong { get; init; } = "";

    /// <summary>How the user gets it back, e.g. "npm re-downloads on next install".</summary>
    internal string RestoreHint { get; init; } = "";

    /// <summary>Only items older than this are eligible. Zero disables the gate.</summary>
    internal TimeSpan MinimumAge { get; init; } = TimeSpan.Zero;

    /// <summary>Extra per-file predicate, applied identically by Measure and Preview so the two
    /// can never disagree about what is in scope.</summary>
    internal Func<ScannedFile, bool>? Filter { get; init; }

    /// <summary>Directory names never descended into, matched case-insensitively on the leaf.</summary>
    internal IReadOnlyList<string> PruneDirectoryNames { get; init; } = Array.Empty<string>();

    /// <summary>Absolute sub-paths excluded outright — the named-exclusion list the generic
    /// sweepers must consult, not just the per-app items.</summary>
    internal IReadOnlyList<string> ExcludeSubPaths { get; init; } = Array.Empty<string>();

    /// <summary>Extra checks run at preview time and re-run between execution batches.</summary>
    internal Func<IReadOnlyList<CleanupBlocker>>? BlockerProbe { get; init; }

    internal bool PruneEmptyDirectories { get; init; } = true;

    /// <summary>
    /// The owning tool's own command, where one exists.
    ///
    /// Preferred over deleting the tree by hand for anything that keeps an index — npm, uv, pip
    /// and NuGet all do — because a hand-deleted cache leaves the tool's bookkeeping describing
    /// files that are no longer there. <see cref="Measure"/> and <see cref="Preview"/> still walk
    /// the directory, so the user sees a real size either way.
    /// </summary>
    internal ToolCommand? PreferredCommand { get; init; }

    /// <summary>
    /// An admin-gated item can never be automatic. A scheduled deletion running elevated with
    /// nobody watching is precisely the footgun this project exists to avoid, so the constraint
    /// is enforced here rather than trusted to each declaration site.
    /// </summary>
    internal AutomationTier EffectiveTier =>
        Risk == CleanupRisk.NeverClean ? AutomationTier.ReadOnly
        : NeedsAdmin && Tier == AutomationTier.Automatic ? AutomationTier.Prompt
        : Tier;

    /// <summary>Reclaimable bytes and file count. Read-only, cancellable, never throws.</summary>
    internal virtual Measurement Measure(CancellationToken ct = default) => Walk(null, 0, ct);

    /// <summary>
    /// The exact items that would be removed, capped at <paramref name="maxItems"/> for display.
    /// Totals still come from the complete walk, so a truncated preview never understates.
    /// </summary>
    internal virtual CleanupPlan Preview(int maxItems = 5000, CancellationToken ct = default)
    {
        var items = new List<ScannedFile>(Math.Min(maxItems, 4096));
        var m = Walk(items, maxItems, ct);
        return new CleanupPlan
        {
            TargetId = Id,
            Files = items,
            Measurement = m,
            Truncated = m.Files > items.Count,
            Roots = Paths,
            PruneEmptyDirectories = PruneEmptyDirectories,
            Blockers = CurrentBlockers(),
        };
    }

    /// <summary>Everything standing in the way right now.</summary>
    internal IReadOnlyList<CleanupBlocker> CurrentBlockers()
    {
        var list = new List<CleanupBlocker>();
        if (Risk == CleanupRisk.NeverClean)
            list.Add(new("policy", "HERO deliberately does not clean this. " + WhatBreaksIfWrong));
        if (NeedsAdmin && !MaintenanceGuards.IsElevated)
            list.Add(new("needs-admin", "Requires administrator rights, which HERO does not have."));
        if (BlockerProbe is not null)
        {
            try { list.AddRange(BlockerProbe()); } catch { /* a probe failure must not hide the row */ }
        }
        return list;
    }

    /// <summary>True when at least one declared path exists. Rows for absent software are not
    /// rendered at all — a cleaner listing caches for tools you do not have reads as generic.</summary>
    internal bool Exists => Paths.Any(p => FileWalk.Probe(p) is AccessState.Measured or AccessState.AccessDenied);

    // Taken by value rather than by 'in' so the method group converts directly to the
    // Func<ScannedFile, bool> the walker expects; ScannedFile is four fields wide, so there is
    // nothing to save by passing it by reference.
    private bool Eligible(ScannedFile f)
    {
        if (MinimumAge > TimeSpan.Zero && DateTime.UtcNow - f.LastWriteUtc < MinimumAge) return false;
        for (int i = 0; i < ExcludeSubPaths.Count; i++)
            if (f.Path.Contains(ExcludeSubPaths[i], StringComparison.OrdinalIgnoreCase)) return false;
        if (Filter is not null && !Filter(f)) return false;
        return true;
    }

    private Measurement Walk(List<ScannedFile>? collect, int limit, CancellationToken ct) =>
        FileWalk.ScanRoots(Paths, new WalkOptions { PruneDirectoryNames = PruneDirectoryNames },
                           collect, limit, Eligible, ct);
}

/// <summary>
/// The recycle bin, which the shell sizes instantly and which must never be emptied
/// automatically.
///
/// SHQueryRecycleBin returns size and item count without enumerating anything, which matters:
/// E:\$RECYCLE.BIN holds 107.4 GB across 226,184 files on this machine and a directory walk of
/// it would take minutes for a number the shell already has. The bin is also the only item in
/// the whole catalogue with no vault behind it — it IS the vault — so it is permanently
/// prompt-only and previewing means parsing the $I index files rather than deleting anything.
/// </summary>
internal sealed class RecycleBinTarget : CleanupTarget
{
    /// <summary>Volume root, e.g. "E:\".</summary>
    internal required string VolumeRoot { get; init; }

    internal override Measurement Measure(CancellationToken ct = default)
    {
        var info = new Native.SHQUERYRBINFO { cbSize = Marshal.SizeOf<Native.SHQUERYRBINFO>() };
        int hr = Native.SHQueryRecycleBin(VolumeRoot, ref info);
        if (hr != 0) return Measurement.Denied($"SHQueryRecycleBin returned 0x{hr:X8} for {VolumeRoot}.");
        return new Measurement
        {
            State = AccessState.Measured,
            Bytes = info.i64Size,
            Files = info.i64NumItems,
            Note = "Emptying is permanent: the recycle bin is the undo, so there is nothing behind it.",
        };
    }

    /// <summary>
    /// Reads the $I index files so the user sees original paths and deletion dates rather than
    /// a bare byte count. Deleting anything is a separate, explicit operation.
    /// </summary>
    internal override CleanupPlan Preview(int maxItems = 5000, CancellationToken ct = default)
    {
        var items = new List<ScannedFile>();
        var m = Measure(ct);
        string binRoot = Path.Combine(VolumeRoot, "$RECYCLE.BIN");

        int recycled = 0;

        if (FileWalk.Probe(binRoot) == AccessState.Measured)
        {
            foreach (var entry in RecycleBinIndex.Read(binRoot, maxItems, ct))
            {
                recycled++;

                // THE PATH HAS TO BE THE FILE ON DISK. This listed entry.OriginalPath, which is
                // where the file used to live — C:\Users\<u>\Desktop\thing.txt — and the plan
                // declares $RECYCLE.BIN as its only root. CleanupExecutor.Validate accepts a file
                // only when its path starts with a declared root, so every single item was skipped
                // as OutsideTarget and this target could never delete anything. The original path
                // is what the user needs to READ, which is what DisplayPath is for.
                items.Add(new ScannedFile(entry.DataPath, entry.Size, entry.DeletedUtc,
                                          FileAttributes.Normal, DisplayPath: entry.OriginalPath));

                // One recycled item is two files: the $R payload holding the bytes and the $I
                // index describing it. Deleting only the payload leaves the bin showing a phantom
                // entry of zero bytes that the user cannot get rid of, so both go.
                if (IndexPathFor(entry.DataPath) is { Length: > 0 } index)
                    items.Add(new ScannedFile(index, 0, entry.DeletedUtc,
                                              FileAttributes.Normal, DisplayPath: entry.OriginalPath + "  (index)"));
            }
        }

        return new CleanupPlan
        {
            TargetId = Id,
            Files = items,
            Measurement = m,
            // Against RECYCLED ITEMS, not against the file list, which now holds two entries per
            // item. Comparing to items.Count would report every full read as truncated.
            Truncated = m.Files > recycled,
            Roots = new[] { binRoot },
            PruneEmptyDirectories = false,
            Blockers = CurrentBlockers()
                .Append(new CleanupBlocker("irreversible",
                    "Emptying a recycle bin cannot be undone and HERO will not do it unattended.",
                    Blocking: false))
                .ToList(),
        };
    }

    /// <summary>
    /// The $I index file that pairs with a $R payload.
    ///
    /// The two names differ by exactly those two characters and nothing else — $RABC123.txt is
    /// described by $IABC123.txt in the same directory — which is the pairing the format is built
    /// on. Returns empty rather than guessing when the name is not that shape.
    /// </summary>
    private static string IndexPathFor(string dataPath)
    {
        try
        {
            string name = Path.GetFileName(dataPath);
            if (!name.StartsWith("$R", StringComparison.OrdinalIgnoreCase)) return "";

            string dir = Path.GetDirectoryName(dataPath) ?? "";
            return dir.Length == 0 ? "" : Path.Combine(dir, "$I" + name[2..]);
        }
        catch { return ""; }
    }
}

/// <summary>One entry recovered from a $I index file.</summary>
internal sealed record RecycledItem(string OriginalPath, long Size, DateTime DeletedUtc, string DataPath);

/// <summary>
/// Parser for the $I index files that pair with each $R payload in a recycle bin.
///
/// Windows 10/11 writes format version 2, which is NOT the fixed 520-byte layout most sample
/// code implements: after the FILETIME there is a 4-byte little-endian path length in UTF-16
/// characters (terminator included) and then a variable-length path. Parsing v2 with the v1
/// layout yields garbage paths, which would then be shown to the user next to a delete button.
/// Both versions are handled explicitly.
/// </summary>
internal static class RecycleBinIndex
{
    internal static List<RecycledItem> Read(string binRoot, int maxItems, CancellationToken ct = default)
    {
        var results = new List<RecycledItem>();
        try
        {
            // One subdirectory per user SID. Enumerating only the current user's is tempting,
            // but a bin can hold entries from a stale profile and those consume space too.
            foreach (var sidDir in Directory.EnumerateDirectories(binRoot))
            {
                if (ct.IsCancellationRequested) return results;
                IEnumerable<string> indexFiles;
                try { indexFiles = Directory.EnumerateFiles(sidDir, "$I*"); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var idx in indexFiles)
                {
                    if (results.Count >= maxItems || ct.IsCancellationRequested) return results;
                    if (Parse(idx) is { } item) results.Add(item);
                }
            }
        }
        catch (UnauthorizedAccessException) { /* another user's subtree */ }
        catch (IOException) { }
        return results;
    }

    private static RecycledItem? Parse(string indexPath)
    {
        try
        {
            var bytes = File.ReadAllBytes(indexPath);
            if (bytes.Length < 24) return null;

            long version = BitConverter.ToInt64(bytes, 0);
            long size = BitConverter.ToInt64(bytes, 8);
            long deletedFileTime = BitConverter.ToInt64(bytes, 16);

            DateTime deleted;
            try { deleted = DateTime.FromFileTimeUtc(deletedFileTime); }
            catch { deleted = DateTime.MinValue; }

            string original;
            if (version == 2)
            {
                if (bytes.Length < 28) return null;
                int chars = BitConverter.ToInt32(bytes, 24);
                // The length includes the NUL terminator, so one character is dropped.
                if (chars <= 1 || 28 + (chars * 2) > bytes.Length) return null;
                original = System.Text.Encoding.Unicode.GetString(bytes, 28, (chars - 1) * 2);
            }
            else
            {
                // Version 1: a fixed 520-byte (260 wchar) buffer, NUL-padded.
                if (bytes.Length < 24 + 520) return null;
                original = System.Text.Encoding.Unicode.GetString(bytes, 24, 520).TrimEnd('\0');
            }

            // $I<suffix> pairs with $R<suffix>, same directory.
            string name = Path.GetFileName(indexPath);
            string data = Path.Combine(Path.GetDirectoryName(indexPath) ?? "", "$R" + name[2..]);

            return new RecycledItem(original, size, deleted, data);
        }
        catch { return null; }
    }
}

/// <summary>Options for one walk.</summary>
internal sealed record WalkOptions
{
    /// <summary>
    /// Depth cap. Belt-and-braces behind the reparse-point skip: on this machine
    /// <c>%LOCALAPPDATA%\Application Data</c> is a junction to its own parent, so a walker that
    /// ever follows reparse points loops forever rather than merely being slow.
    /// </summary>
    internal int MaxDepth { get; init; } = 64;

    internal IReadOnlyList<string> PruneDirectoryNames { get; init; } = Array.Empty<string>();

    /// <summary>Workers per NVMe volume. One per HDD volume regardless — see <see cref="FileWalk"/>.</summary>
    internal int SolidStateWorkers { get; init; } = 6;
}

/// <summary>
/// Directory enumeration, built on <see cref="FileSystemEnumerator{TResult}"/> because it is the
/// only in-box API that can actually PRUNE a walk.
///
/// Three decisions here are load-bearing and were all forced by measurement on this machine:
///
/// 1. <c>AttributesToSkip = ReparsePoint</c> is mandatory, not an optimisation.
///    <c>C:\Users\finla\CrossDevice\OnePlus 13\storage\</c> is a tagless, targetless reparse
///    point served by Phone Link; walking it enumerates the user's phone over the wire — an
///    unbounded stall and a privacy incident. With the skip in place it correctly costs nothing.
///    Note the side effect: overriding the default mask means Hidden and System directories ARE
///    walked, which is right for disk accounting but must be stated next to any published figure.
///
/// 2. <c>IgnoreInaccessible = false</c>, with <c>ContinueOnError</c> counting and continuing.
///    The convenient default swallows access-denied silently, which makes the "N directories
///    unreadable" disclosure the honest UI depends on impossible to produce.
///
/// 3. Concurrency follows the physical disk, not the core count. D: is a 12 TB WDC WD121KRYZ
///    spinning disk; parallel enumeration there causes seek thrash and is net SLOWER, while the
///    three NVMe drives measured 113,753 files/s. One worker per HDD volume, several per NVMe.
///
/// Only the logical length is read, straight from the directory entry already fetched. Allocated
/// size and hardlink identity would each cost an extra syscall per file — three instead of one —
/// which is what turns a 13-second walk of 1.5M files into minutes. Where those numbers are
/// genuinely needed they are taken per-item on a preview list, never across a whole volume.
/// </summary>
internal static class FileWalk
{
    private const int ERROR_FILE_NOT_FOUND = 2;
    private const int ERROR_PATH_NOT_FOUND = 3;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_SHARING_VIOLATION = 32;
    private const int INVALID_FILE_ATTRIBUTES = -1;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFileAttributesW")]
    private static extern int GetFileAttributesNative(string lpFileName);

    /// <summary>
    /// Distinguishes "absent" from "unreadable" at the root, which Directory.Exists cannot:
    /// it returns false for both. FontCache is denied even to a stat, C:\Windows.old is simply
    /// gone, and the two must render differently.
    /// </summary>
    internal static AccessState Probe(string path) => Probe(path, out _);

    /// <inheritdoc cref="Probe(string)"/>
    /// <param name="path">Path to test.</param>
    /// <param name="isDirectory">True when the path exists and is a directory. Targets are
    /// allowed to name individual files — a virtual disk image, a dump — so the walker has to
    /// know the difference rather than handing a file to a directory enumerator.</param>
    internal static AccessState Probe(string path, out bool isDirectory)
    {
        isDirectory = false;
        if (string.IsNullOrWhiteSpace(path)) return AccessState.NotPresent;

        int attrs = GetFileAttributesNative(path);
        if (attrs != INVALID_FILE_ATTRIBUTES)
        {
            isDirectory = ((FileAttributes)attrs & FileAttributes.Directory) != 0;
            return AccessState.Measured;
        }

        int err = Marshal.GetLastWin32Error();
        return err == ERROR_ACCESS_DENIED ? AccessState.AccessDenied : AccessState.NotPresent;
    }

    internal static EnumerationOptions EnumOptions() => new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = false,
        AttributesToSkip = FileAttributes.ReparsePoint,
        BufferSize = 65536,
        ReturnSpecialDirectories = false,
    };

    /// <summary>Walks several roots, grouping by volume so each physical disk gets the right
    /// number of workers. Results are merged; a root that is absent contributes nothing.</summary>
    internal static Measurement ScanRoots(IReadOnlyList<string> roots, WalkOptions options,
                                          List<ScannedFile>? collect, int collectLimit,
                                          Func<ScannedFile, bool>? predicate, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        long bytes = 0, files = 0;
        int denied = 0, present = 0, deniedRoots = 0;
        var gate = new object();

        var groups = roots
            .Select(r => (Root: r, Volume: VolumeOf(r)))
            .GroupBy(x => x.Volume, StringComparer.OrdinalIgnoreCase)
            .ToList();

        void RunOne(string root)
        {
            var state = Probe(root, out bool isDirectory);
            if (state == AccessState.NotPresent) return;
            if (state == AccessState.AccessDenied)
            {
                Interlocked.Increment(ref deniedRoots);
                return;
            }
            Interlocked.Increment(ref present);

            long localBytes = 0, localFiles = 0;
            int localDenied = 0;
            List<ScannedFile>? localCollect = collect is null ? null : new List<ScannedFile>();

            // A target may legitimately name a single file rather than a directory — a virtual
            // disk image, a specific dump. Handing that to a directory enumerator would throw and
            // then be misreported as an unreadable directory.
            if (!isDirectory)
            {
                try
                {
                    var info = new FileInfo(root);
                    var single = new ScannedFile(info.FullName, info.Length,
                                                 info.LastWriteTimeUtc, info.Attributes);
                    if (predicate is null || predicate(single))
                    {
                        localBytes = single.Length;
                        localFiles = 1;
                        localCollect?.Add(single);
                    }
                }
                catch (UnauthorizedAccessException) { localDenied++; }
                catch (IOException) { localDenied++; }

                lock (gate)
                {
                    bytes += localBytes;
                    files += localFiles;
                    denied += localDenied;
                    if (localCollect is not null && collect is not null && collect.Count < collectLimit)
                        collect.AddRange(localCollect);
                }
                return;
            }

            try
            {
                using var walker = new EntryWalker(root, options);
                while (walker.MoveNext())
                {
                    if (ct.IsCancellationRequested) break;
                    var entry = walker.Current;
                    if (predicate is not null && !predicate(entry)) continue;
                    localBytes += entry.Length;
                    localFiles++;
                    if (localCollect is not null && localCollect.Count < collectLimit)
                        localCollect.Add(entry);
                }
                localDenied = walker.DeniedDirectories;
            }
            catch (DirectoryNotFoundException) { }
            catch (UnauthorizedAccessException) { localDenied++; }
            catch (IOException) { localDenied++; }

            lock (gate)
            {
                bytes += localBytes;
                files += localFiles;
                denied += localDenied;
                if (localCollect is not null && collect is not null)
                {
                    int room = collectLimit - collect.Count;
                    if (room > 0) collect.AddRange(localCollect.Take(room));
                }
            }
        }

        // Volumes run concurrently; within a volume the worker count is dictated by whether the
        // disk has a seek penalty. Nested parallelism is intentional and bounded on both levels.
        Parallel.ForEach(groups, new ParallelOptions { CancellationToken = CancellationToken.None }, g =>
        {
            int workers = SystemHealth.HasSeekPenalty(g.Key) ? 1 : Math.Max(1, options.SolidStateWorkers);
            if (workers == 1 || g.Count() == 1)
            {
                foreach (var item in g) { if (ct.IsCancellationRequested) return; RunOne(item.Root); }
            }
            else
            {
                Parallel.ForEach(g, new ParallelOptions { MaxDegreeOfParallelism = workers }, item =>
                {
                    if (!ct.IsCancellationRequested) RunOne(item.Root);
                });
            }
        });

        sw.Stop();

        if (present == 0)
            return deniedRoots > 0
                ? Measurement.Denied("Every path for this item requires administrator rights to read.")
                : Measurement.NotPresent();

        int deniedTotal = denied + deniedRoots;

        // A root that opened but yielded nothing because every directory beneath it was refused is
        // an access failure, not an empty folder. This is the C:\Windows\Temp and Prefetch case:
        // GetFileAttributesW succeeds on the directory, so Probe reports Measured, and only the
        // enumeration handle is denied. Left as PartiallyMeasured it renders "at least 0 B in 0
        // files", which is the same lie as a clean zero — just phrased more carefully.
        if (files == 0 && bytes == 0 && deniedTotal > 0)
            return new Measurement
            {
                State = AccessState.AccessDenied,
                DeniedDirectories = deniedTotal,
                Elapsed = sw.Elapsed,
                Note = "Nothing under this path was readable; it needs administrator rights.",
            };

        return new Measurement
        {
            State = deniedTotal > 0 ? AccessState.PartiallyMeasured : AccessState.Measured,
            Bytes = bytes,
            Files = files,
            DeniedDirectories = deniedTotal,
            Elapsed = sw.Elapsed,
        };
    }

    /// <summary>Volume root for grouping, e.g. "D:\". Falls back to the path itself for UNC.</summary>
    internal static string VolumeOf(string path)
    {
        try { return Path.GetPathRoot(Path.GetFullPath(path)) ?? path; }
        catch { return path; }
    }

    /// <summary>
    /// Shared plumbing: pruning, the depth cap and error accounting. Two concrete walkers derive
    /// from it so the measurement path can avoid materialising a string per file when it does not
    /// need one.
    /// </summary>
    private abstract class WalkerBase<T> : FileSystemEnumerator<T>
    {
        private readonly int _maxDepth;
        private readonly IReadOnlyList<string> _prune;

        internal int DeniedDirectories;
        internal int OtherErrors;

        protected WalkerBase(string root, WalkOptions options) : base(root, EnumOptions())
        {
            _maxDepth = options.MaxDepth;
            _prune = options.PruneDirectoryNames;
        }

        protected override bool ShouldIncludeEntry(ref FileSystemEntry entry) => !entry.IsDirectory;

        protected override bool ShouldRecurseIntoEntry(ref FileSystemEntry entry)
        {
            // Real pruning: the predicate is consulted BEFORE descending, so a matched
            // node_modules or DerivedDataCache costs nothing rather than being enumerated in
            // full and discarded afterwards.
            for (int i = 0; i < _prune.Count; i++)
                if (MemoryExtensions.Equals(entry.FileName, _prune[i], StringComparison.OrdinalIgnoreCase))
                    return false;

            return Depth(ref entry) < _maxDepth;
        }

        protected override bool ContinueOnError(int error)
        {
            if (error is ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION) DeniedDirectories++;
            else OtherErrors++;
            // One unreadable directory must never abort a multi-terabyte scan; it is counted
            // and disclosed instead.
            return true;
        }

        private static int Depth(ref FileSystemEntry entry)
        {
            var dir = entry.Directory;
            var root = entry.RootDirectory;
            if (dir.Length <= root.Length) return 0;
            int depth = 1;
            for (int i = root.Length; i < dir.Length; i++)
                if (dir[i] == Path.DirectorySeparatorChar || dir[i] == Path.AltDirectorySeparatorChar)
                    depth++;
            return depth;
        }
    }

    private sealed class EntryWalker : WalkerBase<ScannedFile>
    {
        internal EntryWalker(string root, WalkOptions options) : base(root, options) { }

        protected override ScannedFile TransformEntry(ref FileSystemEntry entry) =>
            new(entry.ToFullPath(), entry.Length, entry.LastWriteTimeUtc.UtcDateTime, entry.Attributes);
    }

    private sealed class DirectoryWalker : WalkerBase<string>
    {
        private readonly IReadOnlyList<string> _names;

        internal DirectoryWalker(string root, IReadOnlyList<string> names, WalkOptions options)
            : base(root, options) => _names = names;

        protected override bool ShouldIncludeEntry(ref FileSystemEntry entry)
        {
            if (!entry.IsDirectory) return false;
            for (int i = 0; i < _names.Count; i++)
                if (MemoryExtensions.Equals(entry.FileName, _names[i], StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        protected override string TransformEntry(ref FileSystemEntry entry) => entry.ToFullPath();
    }

    /// <summary>
    /// Finds directories by name without descending into what it finds.
    ///
    /// The obvious alternative — Directory.EnumerateDirectories with RecurseSubdirectories and a
    /// search pattern — has no recursion predicate, so it enumerates the entire contents of every
    /// matched node_modules before the caller can discard the results. On a real project tree
    /// that is the dominant cost of the whole scan, i.e. the exact opposite of the intent.
    /// FileSystemEnumerator's ShouldRecurseIntoEntry is the only in-box way to actually prune.
    /// </summary>
    internal static List<string> FindDirectories(string root, IReadOnlyList<string> names,
                                                 WalkOptions options, int limit = 10000,
                                                 CancellationToken ct = default)
    {
        var found = new List<string>();
        if (Probe(root, out bool isDirectory) != AccessState.Measured || !isDirectory) return found;

        // Matched names are added to the prune list so the walk stops at each hit, and the extra
        // names the caller supplied (.git, obj, DerivedDataCache) stop it wandering into places
        // that cannot contain another match.
        var prune = names.Concat(options.PruneDirectoryNames)
                         .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        try
        {
            using var walker = new DirectoryWalker(root, names, options with { PruneDirectoryNames = prune });
            while (walker.MoveNext())
            {
                if (ct.IsCancellationRequested || found.Count >= limit) break;
                found.Add(walker.Current);
            }
        }
        catch (DirectoryNotFoundException) { }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        return found;
    }

    /// <summary>Finds files by extension, pruning the directories the caller names.</summary>
    internal static List<ScannedFile> FindFiles(string root, IReadOnlyList<string> extensions,
                                                WalkOptions options, int limit = 10000,
                                                CancellationToken ct = default)
    {
        var found = new List<ScannedFile>();
        if (Probe(root, out bool isDirectory) != AccessState.Measured || !isDirectory) return found;

        try
        {
            using var walker = new EntryWalker(root, options);
            while (walker.MoveNext())
            {
                if (ct.IsCancellationRequested || found.Count >= limit) break;
                var entry = walker.Current;
                foreach (var ext in extensions)
                {
                    if (entry.Path.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                    {
                        found.Add(entry);
                        break;
                    }
                }
            }
        }
        catch (DirectoryNotFoundException) { }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        return found;
    }

    // ------------------------------------------------------------------ disk space

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetDiskFreeSpaceExW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(string lpDirectoryName,
        out ulong lpFreeBytesAvailableToCaller, out ulong lpTotalNumberOfBytes, out ulong lpTotalNumberOfFreeBytes);

    /// <summary>Free bytes on the volume containing <paramref name="path"/>, or -1.</summary>
    internal static long FreeBytes(string path)
    {
        try
        {
            if (GetDiskFreeSpaceEx(VolumeOf(path), out ulong free, out _, out _)) return (long)free;
        }
        catch { }
        return -1;
    }

    /// <summary>Total bytes on the volume containing <paramref name="path"/>, or -1.</summary>
    internal static long TotalBytes(string path)
    {
        try
        {
            if (GetDiskFreeSpaceEx(VolumeOf(path), out _, out ulong total, out _)) return (long)total;
        }
        catch { }
        return -1;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetCompressedFileSizeW")]
    private static extern uint GetCompressedFileSizeNative(string lpFileName, out uint lpFileSizeHigh);

    /// <summary>
    /// On-disk (allocated) size, which differs from the logical length for sparse and compressed
    /// files. Costs a syscall per file, so it is used on preview lists only — never across a
    /// volume walk — and exists so HERO never presents a sparse file's logical size as space it
    /// can hand back.
    /// </summary>
    internal static long AllocatedBytes(string path)
    {
        try
        {
            uint low = GetCompressedFileSizeNative(path, out uint high);
            if (low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0) return -1;
            return ((long)high << 32) | low;
        }
        catch { return -1; }
    }
}

/// <summary>
/// The only code in the maintenance half that deletes.
///
/// It accepts a <see cref="CleanupPlan"/> and nothing else, re-validates every path against the
/// plan's roots and a hard protected-path floor, deletes file by file with per-item failure
/// tolerance, and re-checks the target's blockers between batches. Directory.Delete(recursive)
/// appears nowhere: it aborts an entire tree on the first locked file, has no progress, no
/// cancellation and no partial result, which is unusable for the 307,372-file Windows Update
/// cache or the 224,647-file uv cache.
/// </summary>
internal static class CleanupExecutor
{
    /// <summary>Files between blocker re-checks. Small enough that a build starting mid-run is
    /// caught within a fraction of a second, large enough that the check is not the cost.</summary>
    private const int BatchSize = 512;

    internal static CleanupOutcome Execute(CleanupTarget target, CleanupPlan plan,
                                           IProgress<CleanupOutcome>? progress = null,
                                           CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var skipped = new List<(string, SkipReason)>();
        long bytes = 0, count = 0, dirs = 0;
        bool aborted = false;
        string abortReason = "";

        if (!string.Equals(plan.TargetId, target.Id, StringComparison.Ordinal))
        {
            return new CleanupOutcome
            {
                TargetId = target.Id,
                AbortedByBlocker = true,
                AbortReason = "The plan does not belong to this target.",
                Elapsed = sw.Elapsed,
            };
        }

        // Matching ids is not enough. CleanupPlan has init-only setters and is visible to the whole
        // assembly, so "only Preview can produce a plan" is a convention rather than a guarantee —
        // and every file check downstream measures against plan.Roots, which means a plan carrying
        // a wider root than the target declares would widen the blast radius rather than be caught.
        // Pin the roots to the target's own declared paths here, where the target is in hand.
        if (!RootsBelongToTarget(target, plan))
        {
            return new CleanupOutcome
            {
                TargetId = target.Id,
                AbortedByBlocker = true,
                AbortReason = "The plan names a root this item does not declare, so HERO will not run it.",
                Elapsed = sw.Elapsed,
            };
        }

        if (target.Risk == CleanupRisk.NeverClean)
        {
            return new CleanupOutcome
            {
                TargetId = target.Id,
                AbortedByBlocker = true,
                AbortReason = "This item is read-only by policy. " + target.WhatBreaksIfWrong,
                Elapsed = sw.Elapsed,
            };
        }

        // The plan's blockers were evaluated when Preview ran, which may have been minutes ago and
        // on the other side of a UI approval. Re-running the probe here closes the window in which
        // the user previews a browser-cache clean, reopens the browser, and only then presses go —
        // without this the first BatchSize files are deleted under a live process before the
        // in-loop re-check ever fires.
        var blocking = plan.Blockers.Concat(target.CurrentBlockers())
                                    .Where(b => b.Blocking)
                                    .ToList();
        if (blocking.Count > 0)
        {
            return new CleanupOutcome
            {
                TargetId = target.Id,
                AbortedByBlocker = true,
                AbortReason = string.Join(" ", blocking.Select(b => b.Detail).Distinct()),
                Elapsed = sw.Elapsed,
            };
        }

        // Free space either side, per volume, so the report can distinguish bytes deleted from
        // bytes the user actually gets back.
        var volumes = plan.Files.Select(f => FileWalk.VolumeOf(f.Path))
                                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var before = volumes.ToDictionary(v => v, FileWalk.FreeBytes, StringComparer.OrdinalIgnoreCase);

        var touchedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int inBatch = 0;
        string lastPath = "";

        foreach (var file in plan.Files)
        {
            if (ct.IsCancellationRequested) break;

            lastPath = file.Path;

            if (++inBatch >= BatchSize)
            {
                inBatch = 0;
                // The "is anything using this?" test is inherently point-in-time. Re-running it
                // per batch is the practical interlock: on a developer machine a build starts
                // seconds after the check passes, and continuing to delete inside a package cache
                // at that moment is exactly how a cleaner earns a reputation for breaking builds.
                // RecheckDuringRun filters out the timestamp-derived ones: HERO's own deleting
                // moves those timestamps, so re-evaluating them mid-run makes the run abort itself.
                var now = target.CurrentBlockers().Where(b => b.Blocking && b.RecheckDuringRun).ToList();
                if (now.Count > 0)
                {
                    aborted = true;
                    abortReason = string.Join(" ", now.Select(b => b.Detail));
                    break;
                }
                progress?.Report(Snapshot());
            }

            if (!Validate(file.Path, plan, out var refusal))
            {
                skipped.Add((file.Path, refusal));
                continue;
            }

            switch (DeleteOne(file))
            {
                case SkipReason.None:
                    bytes += file.Length;
                    count++;
                    var parent = Path.GetDirectoryName(file.Path);
                    if (!string.IsNullOrEmpty(parent)) touchedDirs.Add(parent);
                    break;
                case SkipReason.AlreadyGone:
                    // Not a failure and not a reclaim: something else removed it between the
                    // preview and now, which is normal for a temp directory.
                    break;
                case var reason:
                    skipped.Add((file.Path, reason));
                    break;
            }
        }

        if (plan.PruneEmptyDirectories && !ct.IsCancellationRequested && !aborted)
            dirs = PruneEmpty(touchedDirs, plan);

        sw.Stop();
        var after = volumes.ToDictionary(v => v, FileWalk.FreeBytes, StringComparer.OrdinalIgnoreCase);
        var delta = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in volumes)
            if (before[v] >= 0 && after[v] >= 0) delta[v] = after[v] - before[v];

        return Snapshot() with
        {
            DirectoriesRemoved = dirs,
            Cancelled = ct.IsCancellationRequested,
            AbortedByBlocker = aborted,
            AbortReason = abortReason,
            Elapsed = sw.Elapsed,
            FreeSpaceDelta = delta,
        };

        CleanupOutcome Snapshot() => new()
        {
            TargetId = target.Id,
            BytesDeleted = bytes,
            FilesDeleted = count,
            Skipped = skipped.ToList(),
            CurrentPath = lastPath,
            FilesPlanned = plan.Files.Count,
        };
    }

    /// <summary>
    /// True when every root in the plan is one of the target's own declared paths, and the plan
    /// declares at least one. Compared on canonical full paths so a trailing separator or a
    /// relative segment cannot smuggle a wider root past the check.
    /// </summary>
    private static bool RootsBelongToTarget(CleanupTarget target, CleanupPlan plan)
    {
        if (plan.Roots.Count == 0) return false;

        static string Canonical(string p)
        {
            try { return Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar); }
            catch { return ""; }
        }

        var declared = new HashSet<string>(target.Paths.Select(Canonical), StringComparer.OrdinalIgnoreCase);
        declared.Remove("");

        foreach (var root in plan.Roots)
        {
            var canonical = Canonical(root);
            if (canonical.Length == 0 || !declared.Contains(canonical)) return false;
        }
        return true;
    }

    /// <summary>
    /// Re-validates a path at the moment of deletion rather than trusting the plan.
    ///
    /// The plan may have crossed a UI boundary, and one day an elevated helper will execute it.
    /// A deleter that accepts whatever path it is handed is a privilege-escalation primitive, so
    /// the roots and the protected floor are both re-checked here.
    /// </summary>
    private static bool Validate(string path, CleanupPlan plan, out SkipReason reason)
    {
        reason = SkipReason.None;
        string full;
        try { full = Path.GetFullPath(path); }
        catch { reason = SkipReason.Unknown; return false; }

        if (full.Length >= 32000) { reason = SkipReason.PathTooLong; return false; }

        bool inside = false;
        foreach (var root in plan.Roots)
        {
            string r;
            try { r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar); }
            catch { continue; }
            if (full.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            { inside = true; break; }
        }
        if (!inside) { reason = SkipReason.OutsideTarget; return false; }

        if (ProtectedPaths.IsForbidden(full, out _)) { reason = SkipReason.Protected; return false; }

        // Credentials, payment cards and bookmarks, refused by name at the point of deletion so
        // that no target's metadata can authorise them. See ProtectedPaths.NeverDeletableNames.
        if (ProtectedPaths.IsNeverDeletableName(full)) { reason = SkipReason.Protected; return false; }
        return true;
    }

    private static SkipReason DeleteOne(in ScannedFile file)
    {
        try
        {
            File.Delete(file.Path);
            return SkipReason.None;
        }
        catch (FileNotFoundException) { return SkipReason.AlreadyGone; }
        catch (DirectoryNotFoundException) { return SkipReason.AlreadyGone; }
        catch (UnauthorizedAccessException)
        {
            // Read-only is recoverable; an ACL denial is not. Clearing the attribute is only
            // attempted once and only when the attribute is actually set, so HERO never quietly
            // strips protection from a file it then fails to delete anyway.
            if (file.IsReadOnly)
            {
                try
                {
                    File.SetAttributes(file.Path, FileAttributes.Normal);
                    File.Delete(file.Path);
                    return SkipReason.None;
                }
                catch { /* fall through */ }
            }
            return SkipReason.AccessDenied;
        }
        catch (IOException)
        {
            // Sharing violation: an installer staging a payload, an IDE holding a lock, a
            // service mid-operation. Attempting the delete and catching this is one syscall with
            // no race window, which an open-then-close probe cannot claim.
            return SkipReason.InUse;
        }
        catch { return SkipReason.Unknown; }
    }

    /// <summary>Removes directories emptied by the run, deepest first, never a declared root.</summary>
    private static long PruneEmpty(HashSet<string> candidates, CleanupPlan plan)
    {
        long removed = 0;
        var roots = new HashSet<string>(
            plan.Roots.Select(r => { try { return Path.GetFullPath(r).TrimEnd(Path.DirectorySeparatorChar); } catch { return r; } }),
            StringComparer.OrdinalIgnoreCase);

        foreach (var dir in candidates.OrderByDescending(d => d.Length))
        {
            var current = dir;
            // Walk upward: emptying a leaf usually empties its parents too.
            for (int i = 0; i < 32; i++)
            {
                if (string.IsNullOrEmpty(current)) break;
                var trimmed = current.TrimEnd(Path.DirectorySeparatorChar);
                if (roots.Contains(trimmed)) break;
                if (ProtectedPaths.IsForbidden(trimmed, out _)) break;
                // Only ever walk up as far as a declared root; the same containment rule the
                // file deleter applies, so pruning cannot climb out of the target's own tree.
                if (!roots.Any(r => trimmed.StartsWith(r + Path.DirectorySeparatorChar,
                                                       StringComparison.OrdinalIgnoreCase))) break;

                try
                {
                    if (Directory.EnumerateFileSystemEntries(trimmed).Any()) break;
                    Directory.Delete(trimmed, recursive: false);
                    removed++;
                }
                catch { break; }

                current = Path.GetDirectoryName(trimmed) ?? "";
            }
        }
        return removed;
    }
}

/// <summary>
/// The floor beneath every deletion.
///
/// These refusals are not policy the UI can override; they are the answer to "what if a bug
/// upstream hands the executor the wrong path". Note what is deliberately NOT here: the whole
/// of C:\Windows. Panther, Logs\CBS and Windows\Temp are legitimate targets, so the floor names
/// the specific subtrees that must never be touched rather than blanket-banning the directory.
/// </summary>
internal static class ProtectedPaths
{
    // Not named "Windows": the Windows SDK projections put a root namespace of that name in
    // scope, and a field shadowing it reads as a mistake even where the compiler copes.
    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string Profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string[] Forbidden =
    {
        Path.Combine(WindowsDir, "System32"),
        Path.Combine(WindowsDir, "SysWOW64"),
        Path.Combine(WindowsDir, "WinSxS"),
        // Deleting a cached MSI/MSP makes the product impossible to repair, patch or uninstall
        // forever. Multiple Visual Studio installs on this machine make that a live risk.
        Path.Combine(WindowsDir, "Installer"),
        Path.Combine(WindowsDir, "assembly"),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        // TrustedInstaller-owned by design; taking ownership to force a delete permanently
        // breaks package servicing.
        @"C:\Program Files\WindowsApps",
        Path.Combine(Profile, "Documents"),
        Path.Combine(Profile, "Desktop"),
        Path.Combine(Profile, "Pictures"),
        Path.Combine(Profile, "Videos"),
        Path.Combine(Profile, "Music"),
        // Downloads is a de-facto document folder. HERO surfaces its size and never deletes here.
        Path.Combine(Profile, "Downloads"),
        // A tagless reparse point serving the user's phone. Never a deletion target, and its
        // paths must not reach the report store either.
        Path.Combine(Profile, "CrossDevice"),
    };

    /// <summary>True when <paramref name="fullPath"/> must never be deleted.</summary>
    internal static bool IsForbidden(string fullPath, out string why)
    {
        why = "";
        if (string.IsNullOrWhiteSpace(fullPath)) { why = "empty path"; return true; }

        // The wider check here, and only here. This is the one call site that is about refusing to
        // DELETE something, so it should cover every directory HERO writes — including the per-user
        // diagnostics. The detection sites use the narrow IsOwnState, because promising never to
        // investigate a user-writable folder is a different and much worse promise.
        if (HeroPaths.IsOwnStateOrDiagnostics(fullPath)) { why = "HERO's own state"; return true; }

        // A volume root, or something suspiciously close to one.
        var root = FileWalk.VolumeOf(fullPath);
        if (string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar),
                          root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
        { why = "volume root"; return true; }

        // Git metadata is never build output, no matter which heuristic pointed at it.
        if (fullPath.Contains(@"\.git\", StringComparison.OrdinalIgnoreCase) ||
            fullPath.EndsWith(@"\.git", StringComparison.OrdinalIgnoreCase))
        { why = "git metadata"; return true; }

        foreach (var f in Forbidden)
        {
            if (string.IsNullOrEmpty(f)) continue;
            var trimmed = f.TrimEnd(Path.DirectorySeparatorChar);
            if (fullPath.Equals(trimmed, StringComparison.OrdinalIgnoreCase) ||
                fullPath.StartsWith(trimmed + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            { why = trimmed; return true; }
        }

        return false;
    }

    /// <summary>
    /// The browser-profile files that a cache cleaner must never be able to reach. Held here so
    /// a single test can assert that no delete planner ever emits one of these names — the
    /// allowlist discipline in <see cref="DiskCleanup"/> is the mechanism, and this is the assertion.
    /// </summary>
    internal static readonly string[] BrowserProfileNames =
    {
        "Cookies", "Login Data", "Login Data For Account", "Web Data", "History", "Bookmarks",
        "Local State", "Local Storage", "Session Storage", "IndexedDB", "Preferences",
        "Secure Preferences", "Network", "sessionData", "Affiliation Database", "Favicons",
    };

    /// <summary>
    /// File names that no cleanup target may ever delete, whatever it declares.
    ///
    /// This is deliberately NOT <see cref="BrowserProfileNames"/>, which is a wider tripwire for
    /// the CACHE targets. That list names Cookies, Local Storage, Session Storage and IndexedDB —
    /// which the browser privacy rows exist to delete on purpose — so banning it outright at the
    /// delete path would break the feature. The list below is the subset that is never a
    /// legitimate deletion in any row HERO ships: credentials, payment cards, bookmarks and the
    /// profile indexes.
    ///
    /// It exists because the read-only credential row collects its paths through a helper that
    /// deliberately skips the name guard, relying on Risk = NeverClean to keep the executor away.
    /// That is true today and it is one token deep: changing NeverClean to High on that row would
    /// turn it into a working password and bookmark shredder, with its Paths already aimed at
    /// every credential store on the machine. A guard at the point of deletion cannot be edited
    /// away by a change to a target's metadata.
    /// </summary>
    private static readonly string[] NeverDeletableNames =
    {
        // Chromium
        "Login Data", "Login Data For Account", "Web Data", "Bookmarks", "Bookmarks.bak",
        "Bookmarks.msbak", "Preferences", "Secure Preferences", "Local State",
        // Gecko
        "logins.json", "logins-backup.json", "key4.db", "cert9.db", "places.sqlite",
        "favicons.sqlite", "prefs.js", "profiles.ini", "persdict.dat",
    };

    /// <summary>
    /// True when the file's own name is one that must survive every target. Checked at the point
    /// of deletion, so it holds regardless of which target asked or what risk it declared.
    /// </summary>
    internal static bool IsNeverDeletableName(string fullPath)
    {
        var name = Path.GetFileName(fullPath);
        if (name.Length == 0) return false;

        foreach (var n in NeverDeletableNames)
            if (name.Equals(n, StringComparison.OrdinalIgnoreCase)) return true;

        return false;
    }

    /// <summary>True when a path contains any browser profile artefact. Used as a tripwire in
    /// the cache targets, not as their primary defence — the allowlist is that.</summary>
    internal static bool TouchesBrowserProfile(string path)
    {
        foreach (var n in BrowserProfileNames)
            if (path.Contains(Path.DirectorySeparatorChar + n + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(Path.DirectorySeparatorChar + n, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}

/// <summary>Shared preconditions used by target declarations.</summary>
internal static class MaintenanceGuards
{
    private static readonly Lazy<bool> Elevated = new(() =>
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    });

    /// <summary>HERO ships asInvoker, so this is false in normal operation. Every admin-gated
    /// item must degrade to "requires administrator" rather than to "clean".</summary>
    internal static bool IsElevated => Elevated.Value;

    /// <summary>True when any process with one of these names is running.</summary>
    internal static bool AnyRunning(params string[] processNames)
    {
        foreach (var name in processNames)
        {
            try
            {
                var found = Process.GetProcessesByName(name);
                foreach (var p in found) p.Dispose();
                if (found.Length > 0) return true;
            }
            catch { /* a denied query is not evidence of absence, but it is not a blocker either */ }
        }
        return false;
    }

    /// <summary>A blocker when the named program is running, otherwise nothing.</summary>
    internal static CleanupBlocker? RunningBlocker(string friendlyName, string action, params string[] processNames)
    {
        if (!AnyRunning(processNames)) return null;
        return new CleanupBlocker("process-running",
            $"{friendlyName} is running. Close it and HERO can {action}; deleting underneath it " +
            "either fails or is silently undone as the app recreates the files.");
    }

    /// <summary>Refuses an action that needs working room on a volume that has none.</summary>
    internal static CleanupBlocker? FreeSpaceBlocker(string volumeRoot, long requiredBytes)
    {
        long free = FileWalk.FreeBytes(volumeRoot);
        if (free < 0 || free >= requiredBytes) return null;
        return new CleanupBlocker("free-space",
            $"{volumeRoot} has {Human.Bytes(free)} free but this needs about " +
            $"{Human.Bytes(requiredBytes)} of working room. Reclaim something smaller first.");
    }
}

/// <summary>A command belonging to the tool that owns a cache.</summary>
/// <param name="FileName">Executable, resolved on PATH.</param>
/// <param name="Arguments">Fixed arguments. Never interpolated from user input.</param>
/// <param name="Explanation">What it does and why it beats deleting the directory.</param>
/// <param name="ViaShell">True for a .cmd/.bat shim such as npm, which CreateProcess cannot
/// launch directly.</param>
internal sealed record ToolCommand(string FileName, string Arguments, string Explanation, bool ViaShell = false)
{
    /// <summary>What to show the user, and what they could type themselves.</summary>
    internal string Display => $"{FileName} {Arguments}";

    /// <summary>Runs it. Separate from every measurement path: nothing here happens implicitly.</summary>
    internal ShellResult Execute(int timeoutMs = 300000) =>
        ViaShell ? Shell.RunShim($"{FileName} {Arguments}", timeoutMs)
                 : Shell.Run(FileName, Arguments, timeoutMs);
}

internal sealed record ShellResult(bool Launched, int ExitCode, string StandardOutput, string StandardError)
{
    internal bool Succeeded => Launched && ExitCode == 0;
}

/// <summary>
/// Process shell-outs.
///
/// HERO prefers in-box APIs, but several things here have no API worth the code — winget, DISM,
/// fsutil, and each package manager's own cache command. Output is captured as UTF-8 because
/// winget in particular emits box-drawing characters and CJK package names that the console's
/// default code page mangles.
/// </summary>
internal static class Shell
{
    internal static ShellResult Run(string fileName, string arguments, int timeoutMs = 30000)
    {
        try
        {
            var psi = new ProcessStartInfo(fileName, arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding = System.Text.Encoding.UTF8,
            };

            using var p = Process.Start(psi);
            if (p is null) return new ShellResult(false, -1, "", "Process did not start.");

            // Read both streams before waiting. Waiting first deadlocks the moment a child fills
            // a pipe buffer, which DISM and winget both do.
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                return new ShellResult(true, -1, "", $"{fileName} did not finish within {timeoutMs} ms.");
            }

            return new ShellResult(true, p.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // The usual cause is "not installed", which is information rather than an error.
            return new ShellResult(false, -1, "", $"{fileName} is not available on PATH.");
        }
        catch (Exception ex)
        {
            return new ShellResult(false, -1, "", $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>Runs a .cmd/.bat shim such as npm, which CreateProcess cannot launch directly.
    /// Arguments are compile-time constants throughout this module; nothing user-supplied is
    /// ever interpolated into a command line.</summary>
    internal static ShellResult RunShim(string command, int timeoutMs = 30000) =>
        Run("cmd.exe", "/d /c " + command, timeoutMs);

    /// <summary>True when an executable resolves on PATH.</summary>
    internal static bool Exists(string fileName)
    {
        var r = Run("where.exe", fileName, 5000);
        return r.Succeeded && r.StandardOutput.Trim().Length > 0;
    }
}

/// <summary>Number formatting shared by the whole maintenance half.</summary>
internal static class Human
{
    private static readonly string[] Units = { "B", "KB", "MB", "GB", "TB", "PB" };

    internal static string Bytes(long value)
    {
        if (value < 0) return "unknown";
        double v = value;
        int unit = 0;
        while (v >= 1024 && unit < Units.Length - 1) { v /= 1024; unit++; }
        return unit == 0 ? $"{value} B" : $"{v:0.##} {Units[unit]}";
    }

    internal static string Count(long value) => value.ToString("N0");

    /// <summary>"3 days", "14 hours" — for ages where a precise figure adds nothing.</summary>
    internal static string Age(TimeSpan span)
    {
        if (span.TotalDays >= 2) return $"{(int)span.TotalDays} days";
        if (span.TotalHours >= 2) return $"{(int)span.TotalHours} hours";
        if (span.TotalMinutes >= 2) return $"{(int)span.TotalMinutes} minutes";
        return "moments";
    }
}
