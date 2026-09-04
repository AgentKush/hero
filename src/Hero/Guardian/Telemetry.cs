using Hero.Interop;

namespace Hero.Guardian;

/// <summary>One complete observation of the machine at an instant.</summary>
internal sealed class Snapshot
{
    internal required DateTime TakenUtc { get; init; }
    internal required IReadOnlyList<ProcessRecord> Processes { get; init; }
    internal required IReadOnlyList<Connection> Connections { get; init; }
    internal required double IdleSeconds { get; init; }
    internal required int ForegroundPid { get; init; }

    private Dictionary<int, ProcessRecord>? _byPid;
    internal Dictionary<int, ProcessRecord> ByPid => _byPid ??= BuildByPid();

    private Dictionary<int, ProcessRecord> BuildByPid()
    {
        // PIDs are unique among live processes, but a Toolhelp walk can race process exit and
        // reuse, so duplicates are tolerated rather than allowed to throw.
        var map = new Dictionary<int, ProcessRecord>(Processes.Count);
        foreach (var p in Processes) map[p.Pid] = p;
        return map;
    }

    /// <summary>
    /// Walks up the parent chain, newest first. Guarded against cycles, which do occur once
    /// PIDs are recycled and a "parent" ends up pointing at a descendant.
    /// </summary>
    internal IEnumerable<ProcessRecord> Ancestry(ProcessRecord of, int maxDepth = 8)
    {
        var seen = new HashSet<int> { of.Pid };
        var current = of;
        for (int i = 0; i < maxDepth; i++)
        {
            if (!ByPid.TryGetValue(current.ParentPid, out var parent)) yield break;
            if (!seen.Add(parent.Pid)) yield break;

            // A parent that started after its child is a recycled PID, not a real ancestor.
            if (parent.StartTimeUtc != default && current.StartTimeUtc != default &&
                parent.StartTimeUtc > current.StartTimeUtc) yield break;

            yield return parent;
            current = parent;
        }
    }
}

/// <summary>What changed between two consecutive snapshots.</summary>
internal sealed class SnapshotDelta
{
    internal required Snapshot Previous { get; init; }
    internal required Snapshot Current { get; init; }
    internal required IReadOnlyList<ProcessRecord> StartedProcesses { get; init; }
    internal required IReadOnlyList<ProcessRecord> ExitedProcesses { get; init; }
    internal required IReadOnlyList<Connection> NewConnections { get; init; }

    internal bool IsQuiet => StartedProcesses.Count == 0
                          && ExitedProcesses.Count == 0
                          && NewConnections.Count == 0;
}
