using System.Diagnostics;
using Hero.Interop;

namespace Hero.Guardian;

/// <summary>
/// The continuous observation loop.
///
/// Cadence is chosen from measured cost, not guesswork: a process walk is 21ms and a socket
/// walk is 4ms on this machine, so a one-second poll costs roughly 2.5% of a single core —
/// about 0.1% of a 24-thread CPU. Signature verification (~22ms per unseen image) is
/// explicitly excluded from this loop and handed to a separate background worker.
///
/// The loop backs off when nothing is happening and the user is away, so an idle machine
/// is not kept awake by a security tool. It snaps back to the fast cadence the moment
/// anything starts.
/// </summary>
internal sealed class MonitorEngine : IAsyncDisposable
{
    internal TimeSpan FastInterval { get; init; } = TimeSpan.FromSeconds(1);
    internal TimeSpan IdleInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>User inactivity beyond this allows the slower cadence.</summary>
    internal TimeSpan UserIdleThreshold { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Consecutive quiet polls required before backing off.</summary>
    internal int QuietPollsBeforeBackoff { get; init; } = 15;

    /// <summary>Raised on a background thread for every completed poll.</summary>
    internal event Action<SnapshotDelta>? Observed;

    /// <summary>Raised when the loop throws, so failures are visible rather than silent.</summary>
    internal event Action<Exception>? Faulted;

    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;
    private int _quietPolls;

    // Rolling diagnostics surfaced in the UI so the user can see what HERO costs them.
    internal double LastPollMilliseconds { get; private set; }
    internal double AveragePollMilliseconds { get; private set; }
    internal long PollCount { get; private set; }
    internal Snapshot? Latest { get; private set; }

    /// <summary>
    /// Polls that threw in a row, and when the last one did.
    ///
    /// COUNTED BECAUSE A FAULTED POLL OBSERVES NOTHING. The catch below keeps the loop alive, which
    /// is right — one bad poll must not take the guardian down — but it also skips Observed, so
    /// nothing is ingested or scored for that tick. A probe that fails every time therefore
    /// produces a guardian that watches attentively, records nothing, and reports itself healthy,
    /// which is the failure this product is least entitled to have.
    ///
    /// Reset by the first poll that succeeds, so this is "is it failing NOW" rather than a running
    /// total of everything that has ever gone wrong.
    /// </summary>
    internal int ConsecutiveFaults { get; private set; }

    /// <summary>When the most recent faulted poll happened, or null if none has.</summary>
    internal DateTime? LastFaultUtc { get; private set; }

    /// <summary>
    /// Installs a snapshot taken elsewhere and returns how it differs from the one before it.
    /// Used only when the dashboard is reading from the guardian service over IPC: in that mode
    /// this engine never polls, and every page still reads <see cref="Latest"/> exactly as it did
    /// in-process, so no page needed changing.
    ///
    /// The delta is returned rather than discarded because the caller has to raise
    /// <c>Observed</c> with it. This method used to be <c>Latest = snapshot</c> and nothing more,
    /// which quietly froze the entire dashboard: <c>Observed</c> is what drives the window's
    /// per-tick refresh, the local poll loop is the only thing that ever raised it, and that loop
    /// does not run in remote mode. Every page therefore showed whatever it had rendered the
    /// moment it was opened, for as long as it stayed open.
    /// </summary>
    internal SnapshotDelta AcceptRemote(Snapshot snapshot)
    {
        // First snapshot of the session: diff against itself so the delta is empty rather than
        // reporting every process on the machine as newly started.
        var previous = Latest ?? snapshot;
        Latest = snapshot;
        return Diff(previous, snapshot);
    }

    internal void Start()
    {
        if (_loop is not null) return;
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    private async Task RunAsync(CancellationToken ct)
    {
        var previous = Take();
        Latest = previous;

        while (!ct.IsCancellationRequested)
        {
            var interval = ChooseInterval(previous);
            try
            {
                await Task.Delay(interval, ct);
            }
            catch (OperationCanceledException) { return; }

            try
            {
                var sw = Stopwatch.StartNew();
                var current = Take();
                var delta = Diff(previous, current);
                sw.Stop();

                LastPollMilliseconds = sw.Elapsed.TotalMilliseconds;
                PollCount++;
                // Exponential moving average keeps this cheap and drift-free.
                AveragePollMilliseconds = PollCount == 1
                    ? LastPollMilliseconds
                    : AveragePollMilliseconds * 0.9 + LastPollMilliseconds * 0.1;

                _quietPolls = delta.IsQuiet ? _quietPolls + 1 : 0;

                Latest = current;
                previous = current;

                ConsecutiveFaults = 0;

                // A SUBSCRIBER MUST NOT BE ABLE TO KILL THE LOOP, and one could. Observed was
                // invoked inside this try, so a handler that threw was treated as a failed poll and
                // routed to Faulted — and if Faulted's handler then threw, that exception left the
                // catch block below and ended the polling task outright. Silently: the task is
                // fire-and-forget, so nothing observed the guardian stopping. Reproduced while
                // instrumenting this loop from outside, where both handlers were foreign code.
                //
                // The loop's own work and its listeners' work are now separate failures, which they
                // always were in fact.
                Notify(delta);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // A single bad poll must never take the guardian down.
                ConsecutiveFaults++;
                LastFaultUtc = DateTime.UtcNow;
                RaiseFaulted(ex);
            }
        }
    }

    /// <summary>
    /// Hands one poll to the listeners, absorbing anything they throw.
    ///
    /// A subscriber failing is the subscriber's problem, not a failed poll: the snapshot was taken,
    /// Latest is already updated, and treating it as a poll failure would both misreport the
    /// guardian's health and — before this existed — end the loop.
    /// </summary>
    private void Notify(SnapshotDelta delta)
    {
        try { Observed?.Invoke(delta); }
        catch (Exception ex) { RaiseFaulted(ex); }
    }

    /// <summary>
    /// Raises Faulted without letting a failing listener escape.
    ///
    /// This one is called from inside a catch block, so an exception leaving it is not caught by
    /// anything and takes the polling task with it.
    /// </summary>
    private void RaiseFaulted(Exception ex)
    {
        try { Faulted?.Invoke(ex); }
        catch { /* nowhere left to report to, and the loop must continue regardless */ }
    }

    private TimeSpan ChooseInterval(Snapshot last)
    {
        bool userAway = last.IdleSeconds > UserIdleThreshold.TotalSeconds;
        bool settled = _quietPolls >= QuietPollsBeforeBackoff;
        return userAway && settled ? IdleInterval : FastInterval;
    }

    private static Snapshot Take() => new()
    {
        TakenUtc = DateTime.UtcNow,
        Processes = ProcessProbe.Snapshot(),
        Connections = NetworkProbe.Snapshot(),
        IdleSeconds = ProcessProbe.IdleSeconds(),
        ForegroundPid = ProcessProbe.ForegroundPid(),
    };

    /// <summary>
    /// Diffs two snapshots.
    ///
    /// Identity is (pid, start time) rather than pid alone. Windows recycles PIDs aggressively,
    /// and on a machine that spawns hundreds of short-lived build and test processes a
    /// pid-only diff would regularly report a brand-new process as "still running" — exactly
    /// the blind spot a dropper would slip through.
    /// </summary>
    private static SnapshotDelta Diff(Snapshot previous, Snapshot current)
    {
        static (int Pid, long Start) Key(ProcessRecord p) => (p.Pid, p.StartTimeUtc.Ticks);

        var before = previous.Processes.ToDictionary(Key, p => p);
        var after = current.Processes.ToDictionary(Key, p => p);

        var started = after.Where(kv => !before.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList();
        var exited = before.Where(kv => !after.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList();

        // A connection is "new" by (pid, peer, local port). Local port keeps repeated
        // short-lived requests to the same host distinguishable, which is what beacon
        // interval analysis needs.
        var seen = new HashSet<(int, string, int)>(previous.Connections
            .Where(c => c.RemoteAddress is not null)
            .Select(c => (c.Pid, c.PeerKey, c.LocalPort)));

        var newConns = current.Connections
            .Where(c => c.RemoteAddress is not null && c.Pid != 0)
            .Where(c => !seen.Contains((c.Pid, c.PeerKey, c.LocalPort)))
            .ToList();

        return new SnapshotDelta
        {
            Previous = previous,
            Current = current,
            StartedProcesses = started,
            ExitedProcesses = exited,
            NewConnections = newConns,
        };
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        if (_loop is not null)
        {
            try { await _loop.ConfigureAwait(false); } catch { /* cancellation */ }
        }
        _cts.Dispose();
    }
}
