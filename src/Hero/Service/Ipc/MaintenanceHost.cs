using Hero.Maintenance;

namespace Hero.Service.Ipc;

/// <summary>
/// Runs cleanup targets inside the guardian service, on behalf of the unelevated dashboard.
///
/// WHY THIS EXISTS. HERO already holds every right it needs — the guardian service is LocalSystem
/// and has been since boot — but the maintenance half ran entirely in the dashboard, which is the
/// signed-in user. So six targets on this machine could not even be MEASURED, let alone cleaned:
/// roughly 11.5 GB of Windows Update download cache, setup and upgrade logs, Delivery Optimization,
/// font cache and crash dumps, all showing "needs admin" forever. The rights were there; nothing
/// asked for them.
///
/// The alternative was to elevate the dashboard, and that is worse in every direction: a UAC prompt
/// on every launch, an always-on high-integrity UI process as permanent attack surface, and a
/// contradiction of HERO's own rule that the dashboard must not need administrator rights to be
/// useful. Asking a service that is already running costs the user nothing and adds no new
/// privilege to the machine.
///
/// THE RULE THIS FILE OBEYS. A request names a target by ID. The id is resolved against the
/// service's OWN catalogue — the same compile-time declarations the dashboard renders — and a path
/// never crosses the pipe. There is no request shape here that can express "delete this directory";
/// the worst an attacker can ask for is one of the things HERO would have offered the user anyway.
/// That is the same discipline the guardian commands follow, restated for a different noun.
/// </summary>
internal static class MaintenanceHost
{
    /// <summary>
    /// The catalogue, built once and reused.
    ///
    /// Enumerate() probes the filesystem for every declared target, so rebuilding it per request
    /// would put a directory walk on the pipe's critical path. Targets are compile-time
    /// declarations; the set cannot change while the service runs.
    /// </summary>
    private static readonly Lazy<IReadOnlyList<CleanupTarget>> Catalogue =
        new(() => DiskCleanup.Enumerate().ToList(), LazyThreadSafetyMode.ExecutionAndPublication);

    private sealed class Job
    {
        internal required string Id { get; init; }
        internal required string TargetId { get; init; }
        internal long BytesDeleted;
        internal long FilesDeleted;
        internal long FilesPlanned;
        internal string CurrentPath = "";
        internal volatile bool Finished;
        internal string Message = "";
        internal DateTime StartedUtc = DateTime.UtcNow;
    }

    private static readonly object Gate = new();
    private static readonly Dictionary<string, Job> Jobs = new(StringComparer.Ordinal);

    /// <summary>
    /// Only one clean at a time, service-wide. Two concurrent recursive deletions competing for the
    /// same disk is slower than doing them in turn, and the blocker re-checks that make cleanup
    /// safe are per-target — running several at once would let one target's "a build just started"
    /// abort go unnoticed by the others.
    /// </summary>
    private static string? _activeJobId;

    private static CleanupTarget? Find(string targetId) =>
        Catalogue.Value.FirstOrDefault(t => string.Equals(t.Id, targetId, StringComparison.Ordinal));

    // ---------------------------------------------------------------- measure

    internal static MaintenanceMeasureReply Measure(string targetId)
    {
        var target = Find(targetId);
        if (target is null) return new MaintenanceMeasureReply { TargetId = targetId, Found = false };

        var m = target.Measure();
        return new MaintenanceMeasureReply
        {
            TargetId = targetId,
            Found = true,
            Bytes = m.Bytes,
            Files = m.Files,
            State = m.State.ToString(),
        };
    }

    // ---------------------------------------------------------------- clean

    /// <summary>
    /// True when cleaning this target destroys something a person might later need in order to
    /// work out what happened, rather than something that simply rebuilds itself.
    ///
    /// Those require an elevated caller. The distinction matters because everything else on this
    /// surface is merely destructive-to-caches — irritating to lose, no help to an attacker — while
    /// crash dumps and setup logs are the machine's account of itself. An unelevated process being
    /// able to ask SYSTEM to erase the evidence of what it just did is an anti-forensics primitive,
    /// and it would be a poor trade to open one in the course of freeing disk space.
    /// </summary>
    private static bool DestroysEvidence(CleanupTarget target) =>
        target.Category is CleanupCategory.Logs or CleanupCategory.Diagnostics;

    internal static MaintenanceJobReply Clean(string targetId, bool callerElevated)
    {
        var target = Find(targetId);
        if (target is null)
            return new MaintenanceJobReply { TargetId = targetId, Message = "No such cleanup target." };

        if (target.EffectiveTier == AutomationTier.ReadOnly || target.Risk == CleanupRisk.NeverClean)
        {
            return new MaintenanceJobReply
            {
                TargetId = targetId,
                Message = "HERO measures this and deliberately refuses to clean it.",
            };
        }

        if (DestroysEvidence(target) && !callerElevated)
        {
            return new MaintenanceJobReply
            {
                TargetId = targetId,
                Message = "Removing diagnostic records needs administrator rights.",
            };
        }

        lock (Gate)
        {
            if (_activeJobId is not null && Jobs.TryGetValue(_activeJobId, out var running) && !running.Finished)
            {
                return new MaintenanceJobReply
                {
                    TargetId = targetId,
                    Message = $"Already cleaning {running.TargetId}.",
                };
            }

            // Ordinal, not random: Guid would be fine but the id is also written to the service log
            // and a readable one makes a support question answerable.
            string jobId = $"{targetId}:{DateTime.UtcNow:HHmmssfff}";
            var job = new Job { Id = jobId, TargetId = targetId };
            Jobs[jobId] = job;
            _activeJobId = jobId;

            Prune();

            _ = Task.Run(() => Run(target, job));

            return new MaintenanceJobReply
            {
                JobId = jobId, TargetId = targetId, Accepted = true, Running = true,
                Message = "Started.",
            };
        }
    }

    private static void Run(CleanupTarget target, Job job)
    {
        try
        {
            var plan = target.Preview(int.MaxValue);
            job.FilesPlanned = plan.Files.Count;

            var blocking = plan.Blockers.Where(b => b.Blocking).ToList();
            if (blocking.Count > 0)
            {
                job.Message = "Cannot clean this right now: " +
                              string.Join("; ", blocking.Select(b => $"{b.Reason} — {b.Detail}"));
                return;
            }

            if (plan.Measurement.Files == 0) { job.Message = "Nothing to remove."; return; }

            var progress = new Progress<CleanupOutcome>(o =>
            {
                job.BytesDeleted = o.BytesDeleted;
                job.FilesDeleted = o.FilesDeleted;
                job.CurrentPath = o.CurrentPath;
            });

            var outcome = CleanupExecutor.Execute(target, plan, progress);

            job.BytesDeleted = outcome.BytesDeleted;
            job.FilesDeleted = outcome.FilesDeleted;
            job.CurrentPath = "";
            job.Message = outcome.AbortedByBlocker ? $"Stopped: {outcome.AbortReason}" : outcome.Display;

            ServiceLog.Write($"Maintenance cleaned {target.Id}: {outcome.FilesDeleted:N0} files, " +
                             $"{outcome.BytesDeleted:N0} bytes.");
        }
        catch (Exception ex)
        {
            job.Message = $"Failed: {ex.GetType().Name}";
            ServiceLog.Write($"Maintenance clean of {target.Id} failed: {ex.Message}");
        }
        finally
        {
            job.Finished = true;
            lock (Gate) { if (_activeJobId == job.Id) _activeJobId = null; }
        }
    }

    internal static MaintenanceJobReply Status(string jobId)
    {
        lock (Gate)
        {
            if (!Jobs.TryGetValue(jobId, out var job))
                return new MaintenanceJobReply { JobId = jobId, Message = "No such job." };

            return new MaintenanceJobReply
            {
                JobId = job.Id,
                TargetId = job.TargetId,
                Accepted = true,
                Running = !job.Finished,
                Finished = job.Finished,
                BytesDeleted = Interlocked.Read(ref job.BytesDeleted),
                FilesDeleted = Interlocked.Read(ref job.FilesDeleted),
                FilesPlanned = Interlocked.Read(ref job.FilesPlanned),
                CurrentPath = job.CurrentPath,
                Message = job.Message,
            };
        }
    }

    /// <summary>Drops finished jobs older than an hour so the table cannot grow without bound.</summary>
    private static void Prune()
    {
        var cutoff = DateTime.UtcNow.AddHours(-1);
        foreach (var stale in Jobs.Where(kv => kv.Value.Finished && kv.Value.StartedUtc < cutoff)
                                  .Select(kv => kv.Key).ToList())
        {
            Jobs.Remove(stale);
        }
    }
}
