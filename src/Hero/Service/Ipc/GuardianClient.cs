using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Hero.Service.Ipc;

/// <summary>
/// The tray application's end of the pipe.
///
/// Every call is short-lived: connect, ask, read, disconnect. A persistent connection would be
/// fewer syscalls, but it would also mean the UI holding an open handle to a LocalSystem service
/// across sleep, service restarts and the SCM's recovery actions — and the guardian is expected
/// to be restarted out from under this process, so a connection that survives is a connection
/// that lies. Reconnecting per call makes "the service is not there" an ordinary, visible result
/// instead of a stale cache.
/// </summary>
internal static class GuardianClient
{
    /// <summary>
    /// Short on purpose. This runs on a UI-adjacent path, and a guardian that is not answering is
    /// information the user should see immediately rather than a frozen window.
    /// </summary>
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// How long a connected service gets to answer an ordinary read.
    ///
    /// Deliberately much longer than <see cref="ConnectTimeout"/>: once the pipe is connected the
    /// service demonstrably exists, so the question is no longer "is it there" but "has it finished
    /// building the answer" — and the answer is half a megabyte assembled under whatever load the
    /// machine happens to be under. The poll runs once a second, so a slow reply simply merges with
    /// the next tick rather than stacking up.
    /// </summary>
    private static readonly TimeSpan ReplyTimeout = TimeSpan.FromSeconds(20);

    private static int _nextId;

    /// <summary>True when the service answered a ping. Never throws.</summary>
    internal static async Task<PingReply?> PingAsync(CancellationToken token = default)
        => await CallAsync<PingReply>(GuardianProtocol.OpPing, token).ConfigureAwait(false);

    internal static async Task<IntegrityReply?> IntegrityAsync(CancellationToken token = default)
        => await CallAsync<IntegrityReply>(GuardianProtocol.OpIntegrity, token).ConfigureAwait(false);

    /// <summary>What HERO has concluded from the user's corrections. Read-only; the reset is a command.</summary>
    internal static async Task<LearningReply?> LearningAsync(CancellationToken token = default)
        => await CallAsync<LearningReply>(GuardianProtocol.OpLearning, token).ConfigureAwait(false);

    // ---- maintenance, performed by the service because it is the one with the rights
    //
    // Measuring a machine-wide target can walk 734,915 files, so it gets the command budget rather
    // than the read one. Cleaning does NOT: it returns as soon as the job is accepted, and progress
    // arrives through MaintenanceStatusAsync, so no call here holds a pipe instance for minutes.

    internal static async Task<MaintenanceMeasureReply?> MaintenanceMeasureAsync(
        string targetId, CancellationToken token = default)
    {
        var args = JsonSerializer.SerializeToElement(new { targetId }, GuardianProtocol.Json);
        return await CallAsync<MaintenanceMeasureReply>(
            GuardianProtocol.OpMaintenanceMeasure, token, args, CommandTimeout).ConfigureAwait(false);
    }

    internal static async Task<MaintenanceJobReply?> MaintenanceCleanAsync(
        string targetId, CancellationToken token = default)
    {
        var args = JsonSerializer.SerializeToElement(new { targetId }, GuardianProtocol.Json);
        return await CallAsync<MaintenanceJobReply>(
            GuardianProtocol.OpMaintenanceClean, token, args).ConfigureAwait(false);
    }

    internal static async Task<MaintenanceJobReply?> MaintenanceStatusAsync(
        string jobId, CancellationToken token = default)
    {
        var args = JsonSerializer.SerializeToElement(new { jobId }, GuardianProtocol.Json);
        return await CallAsync<MaintenanceJobReply>(
            GuardianProtocol.OpMaintenanceStatus, token, args).ConfigureAwait(false);
    }

    /// <summary>
    /// One consistent view of everything the dashboard renders.
    ///
    /// The version arguments say what this process already holds, so the service can omit the
    /// persistence inventory and the recent-starts list when neither has changed — together about
    /// 39% of the payload, re-sent every second for data that changes every ten minutes.
    /// </summary>
    internal static async Task<StateReply?> StateAsync(int havePersistence = -1, int haveRecent = -1,
                                                       CancellationToken token = default)
    {
        var args = JsonSerializer.SerializeToElement(
            new { have = new { persistence = havePersistence, recentStarts = haveRecent } },
            GuardianProtocol.Json);

        return await CallAsync<StateReply>(GuardianProtocol.OpState, token, args).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a command and waits for what it changed.
    ///
    /// Returns a refusal rather than null when the service is unreachable, because the caller is a
    /// button the user just pressed: "HERO could not be reached" has to appear on screen, and a
    /// null that every call site has to remember to handle would eventually be forgotten by one
    /// of them and show nothing at all.
    /// </summary>
    internal static async Task<CommandReply> CommandAsync(string op, object arguments,
                                                          CancellationToken token = default)
    {
        var args = JsonSerializer.SerializeToElement(arguments, GuardianProtocol.Json);
        var reply = await CallAsync<CommandReply>(op, token, args, CommandTimeout).ConfigureAwait(false);

        return reply ?? new CommandReply
        {
            Acted = false,
            Refused = true,
            Rung = "Observe",
            Outcome = "Refused",
            Message = "The HERO guardian service did not respond, so nothing was changed.",
        };
    }

    /// <summary>
    /// Performs a response action. Answers with the engine's own record, or null when the service
    /// could not be reached.
    /// </summary>
    internal static async Task<Guardian.ResponseResult?> ActAsync(object arguments,
                                                                  CancellationToken token = default)
    {
        var args = JsonSerializer.SerializeToElement(arguments, GuardianProtocol.Json);
        return await CallAsync<Guardian.ResponseResult>(
            GuardianProtocol.OpAct, token, args, CommandTimeout).ConfigureAwait(false);
    }

    /// <summary>
    /// Asks the service to verify these images. Fire-and-forget: the answer arrives in a later
    /// state poll rather than in this reply, which is why the caller never waits on it.
    /// </summary>
    internal static void RequestVerify(IReadOnlyCollection<string> paths)
    {
        if (paths.Count == 0) return;

        _ = Task.Run(async () =>
        {
            try
            {
                var args = JsonSerializer.SerializeToElement(new { paths }, GuardianProtocol.Json);
                await CallAsync<object>(GuardianProtocol.OpVerify, CancellationToken.None, args)
                    .ConfigureAwait(false);
            }
            catch { /* the next refresh asks again */ }
        });
    }

    /// <summary>
    /// Sends one operation and returns its typed reply, or null if the service is absent, not
    /// answering, or refused. Null is a normal outcome — the tray app must work perfectly well on
    /// a machine where the service was never installed — so this never throws.
    /// </summary>
    /// <summary>
    /// Commands get far longer than reads. A read that has not answered in two seconds is a
    /// service that is not there, but a quarantine copies a file and a kill-tree walks a process
    /// tree — measured in seconds, not milliseconds. Timing those out at two seconds would abort
    /// the client while the service carried on doing the work, which is the worst of both.
    /// </summary>
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(60);

    private static async Task<T?> CallAsync<T>(string op, CancellationToken token,
                                               JsonElement? args = null,
                                               TimeSpan? deadline = null) where T : class
    {
        try
        {
            // TokenImpersonationLevel.Impersonation, not the default of None, and this is load-
            // bearing rather than boilerplate: it is what lets the service ask WHO is calling.
            //
            // The service refuses changes to how the guardian responds unless the caller holds an
            // elevated token, and it establishes that by impersonating the client. A client that
            // does not grant impersonation cannot be impersonated, so the check fails closed and
            // every caller looks unprivileged — including an administrator who deliberately ran
            // HERO elevated to make exactly that change. Measured before this line existed: an
            // elevated client was refused.
            //
            // Granting it costs nothing here. The server is LocalSystem, so it is already strictly
            // more privileged than any client; impersonation lets it act as LESS. And a hostile
            // client withholding it only makes itself look unprivileged, which denies it the
            // guarded operations rather than granting them.
            using var pipe = new NamedPipeClientStream(
                ".", GuardianProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                System.Security.Principal.TokenImpersonationLevel.Impersonation);

            // See ServerIsLocalSystem below, called immediately after connecting: the grant above is
            // only defensible once the thing being granted to has been identified.

            // CONNECTING and ANSWERING get separate budgets, and conflating them was a real bug.
            //
            // One two-second deadline used to cover the whole exchange: connect, the service
            // assembling and serialising its state, and this side reading it back. A state reply is
            // ~540 KB on this machine, and the service builds it while the same machine may be
            // doing something heavy — measuring 75 cleanup targets, or deleting the 171,544 files
            // in the npm cache. Under that load every poll blew the budget, CallAsync returned null
            // for each one, no snapshot was ever applied, and the dashboard sat blank with a score
            // ring reading zero. Measured: a dashboard process ran for six minutes without a single
            // "first state applied" line while the service happily answered the same request from
            // an idle prompt.
            //
            // The dashboard going blind exactly when the machine is busiest is the worst possible
            // time for a security tool to stop showing what is running.
            //
            // Connect stays short, because "nothing is listening" really is answerable in two
            // seconds and a frozen window while HERO decides is the thing that budget protects
            // against. The reply gets its own, longer one.
            using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            connectTimeout.CancelAfter(ConnectTimeout);
            await pipe.ConnectAsync(connectTimeout.Token).ConfigureAwait(false);

            // WHO ANSWERED? Asked before a single byte is written, and this is the other half of
            // the impersonation grant above.
            //
            // The comment above argues the grant is free "because the server is LocalSystem" — and
            // nothing established that. A pipe name is not a principal: the guardian's name is
            // unowned on a machine where the service was never installed, and briefly unowned
            // across a service restart, so anything that creates it first is the server. Winning
            // one connection was enough, because the tray latches into remote mode on its first
            // successful ping and then polls that same channel every second for the life of the
            // process — handing an impersonation token to the squatter each time, and rendering
            // whatever verdicts it chose to invent.
            //
            // Verified against the SERVER PROCESS'S OWN TOKEN rather than the identity it reports
            // in its ping reply, because a liar would report whatever was asked of it.
            if (!ServerIsLocalSystem(pipe))
            {
                Core.HeroPaths.WriteUserLog("app.log",
                    $"IPC: the process answering the guardian pipe (pid {ServerPid(pipe)}) is not " +
                    "LocalSystem. Refusing to talk to it.");
                return null;
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(deadline ?? ReplyTimeout);

            var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            using var writer = new StreamWriter(pipe, encoding, 8192, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, encoding, false, 8192, leaveOpen: true);

            int id = Interlocked.Increment(ref _nextId);
            await writer.WriteLineAsync(
                GuardianProtocol.Serialise(new IpcRequest { Id = id, Op = op, Args = args })).ConfigureAwait(false);

            string? line = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
            if (string.IsNullOrEmpty(line)) return null;

            var response = JsonSerializer.Deserialize<IpcResponse>(line, GuardianProtocol.Json);
            if (response is null || !response.Ok || response.Data is null) return null;

            return response.Data.Value.Deserialize<T>(GuardianProtocol.Json);
        }
        catch
        {
            // Absent service, refused ACL, timeout, malformed reply — all the same answer to the
            // caller: no, the guardian did not tell me anything.
            return null;
        }
    }

    /// <summary>
    /// Whether the process on the server end of <paramref name="pipe"/> is running as LocalSystem.
    ///
    /// The SID comes from the server process's own token, obtained from its PID. Deliberately not
    /// from the ping reply's Identity field: that is the server describing itself, which is exactly
    /// what a process pretending to be the guardian would do.
    ///
    /// PROCESS_QUERY_LIMITED_INFORMATION is the right access for this and is the reason it works at
    /// all from an unelevated dashboard — the full QUERY_INFORMATION right would be refused against
    /// a SYSTEM process, and asking for it would have made the honest case fail while leaving the
    /// dishonest one to be caught by accident.
    ///
    /// Every failure is false. This decides whether to hand an impersonation token to a stranger,
    /// so "I could not tell" and "no" have to be the same answer.
    /// </summary>
    private static bool ServerIsLocalSystem(NamedPipeClientStream pipe)
    {
        try
        {
            // THE PIPE'S OWNER, not the server process's token.
            //
            // Reading the token was the obvious approach and it does not work, which is worth
            // recording because it looks like it should. Measured against the live service from an
            // unelevated dashboard: GetNamedPipeServerProcessId succeeds, and
            // OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) on that pid then fails with
            // ERROR_ACCESS_DENIED — a standard user cannot open a SYSTEM service's process at all.
            // Since the unelevated dashboard is the PRIMARY client, a check built that way refuses
            // the legitimate service every time and takes the whole UI down with it.
            //
            // The owner of the pipe object answers the same question and is readable, because
            // PipeAccessRights.Read includes ReadPermissions and the ACL grants Interactive users
            // read. It is also the property that actually matters: a process cannot create an
            // object owned by LocalSystem unless it is LocalSystem, so an unprivileged squatter's
            // pipe carries the squatter's own SID. An attacker who could set SYSTEM as the owner
            // would already be SYSTEM, at which point there is nothing left for this check to
            // protect. Verified against the running service: S-1-5-18.
            var security = pipe.GetAccessControl();

            return security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier))
                       is System.Security.Principal.SecurityIdentifier owner
                   && owner.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid);
        }
        catch
        {
            // Cannot read the owner, cannot trust the server. This gates whether to hand an
            // impersonation token to a stranger, so "I could not tell" and "no" are the same answer.
            return false;
        }
    }

    /// <summary>The PID answering the pipe, for diagnostics only. Zero when it cannot be read.</summary>
    private static uint ServerPid(NamedPipeClientStream pipe)
    {
        try
        {
            return Interop.Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint pid) ? pid : 0;
        }
        catch { return 0; }
    }
}
