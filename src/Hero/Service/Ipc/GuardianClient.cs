using System.Buffers;
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

    /// <summary>
    /// Buffers for one framed reply, rented per call.
    ///
    /// THE READ PATH USED TO BE THE DASHBOARD'S LARGEST SOURCE OF GARBAGE, and this pool plus
    /// <see cref="IpcResponse{T}"/> is what stopped it. Measured: the tray process grew from 97 MB
    /// to 262 MB of private commit over six and a half hours with its window never once shown, at
    /// roughly 26 MB an hour, while the service — same binary, same payload, same second-by-second
    /// cadence — stayed flat. Nothing was being retained. The whole of that growth was churn.
    ///
    /// The old path materialised the same reply four times per poll, every copy far above the
    /// 85,000-byte threshold that puts an allocation on the large object heap:
    ///
    ///   1. StreamReader.ReadLineAsync returned the reply as one UTF-16 string — 540 KB of JSON
    ///      becomes a ~1.03 MB string. (Only the final string, not the builder chunks it was
    ///      assembled from: StringBuilder caps a chunk at 8000 chars, so those are gen0.)
    ///   2. Deserialize&lt;IpcResponse&gt;(string) then had to transcode that back to UTF-8, renting
    ///      three bytes per char. THIS IS THE ONE THAT MATTERS, because ArrayPool&lt;byte&gt;.Shared
    ///      refuses to pool anything over 1,048,576 bytes: past that it hands back a bare array
    ///      and silently drops it on return. The cliff falls at a payload of 349,525 chars and an
    ///      ordinary reply here is well past it, so a 1.2–1.6 MB buffer was allocated and
    ///      abandoned every second with the pool structurally unable to help.
    ///   3. Data being a JsonElement meant a second parse into a JsonDocument the caller never
    ///      receives and so cannot dispose — its buffers are dropped, not returned.
    ///   4. Deserialize&lt;T&gt; on that element wrote the subtree back out and parsed it a third time.
    ///
    /// Step 2 is also the answer to the obvious objection: the SERVICE serialises the same payload
    /// at the same cadence from the same binary and stays flat. The difference is not how many
    /// copies each side makes. It is that only the client made an above-the-ceiling, unpoolable
    /// rent whose size moved with every poll.
    ///
    /// The large object heap is swept on gen2 collections but never compacted unless asked, and
    /// this app sets no GC configuration at all. Sizes vary every poll as processes and sockets
    /// come and go, which is the worst case for fragmentation: the hole left by a 1.03 MB string
    /// will not host the next 1.07 MB one, so committed bytes ratchet upward while live bytes do
    /// not. That is the shape of the measurement — steady commit growth, flat handle and thread
    /// counts, and a working set that swings either way as Windows trims it.
    ///
    /// Reading UTF-8 bytes straight off the pipe keeps the payload in ONE buffer at its wire size,
    /// which is a little over half what the UTF-16 string cost, and typing the envelope removes the
    /// other three copies outright.
    ///
    /// A private pool rather than <see cref="ArrayPool{T}.Shared"/> for two reasons. The shared
    /// pool's 1 MB ceiling is the exact cliff that made the old path so expensive, and a reply
    /// scales with how many processes and sockets the machine has, so it is not a size this code
    /// gets to assume stays small. And renting half a megabyte once a second out of the shared
    /// pool's large buckets would evict whatever else in the process — WPF, System.Text.Json —
    /// depends on them.
    ///
    /// What that costs, stated rather than glossed: unlike the shared pool, the one Create returns
    /// does not release its buffers under GC pressure. Two arrays per bucket are held for the life
    /// of the process. On this machine, where a reply fits the first rent and the growth ladder
    /// never runs, that is one bucket and about 2 MB. It is NOT 2 MB in general, and saying so
    /// would contradict the paragraph above: every rung the ladder climbs populates a bucket of its
    /// own and none is ever released, so replies that settle around 3 MB park 2 × (1 + 2 + 4) =
    /// 14 MB. That is the real number, and it is why <see cref="_frameHint"/> exists — converging
    /// on the size this machine actually produces keeps the ladder from being climbed at all.
    ///
    /// The trade is deliberate either way: a stable buffer reused every second, in place of a fresh
    /// unpoolable one allocated and thrown away every second.
    ///
    /// Buffers are also returned WITHOUT being cleared, which is the right default for cost but
    /// worth naming in a security tool: a pooled buffer still holds the previous reply's image
    /// paths and command lines until it is overwritten. Nothing leaves the process — this is the
    /// same data, in the same address space, that the dashboard exists to display — and clearing a
    /// megabyte every second to hide it from ourselves would be paying for nothing.
    /// </summary>
    private static readonly ArrayPool<byte> Frames =
        ArrayPool<byte>.Create(maxArrayLength: MaxFrameBytes, maxArraysPerBucket: 2);

    /// <summary>
    /// Big enough that an ordinary reply needs no growth step at all. Measured on this machine at
    /// 340 processes and 381 sockets, a state reply is ~540 KB on the wire, and ~330 KB once the
    /// version gating in <see cref="StateAsync"/> has dropped the persistence inventory and the
    /// recent-starts list. Starting here means the common case is one rent and one read.
    /// </summary>
    private const int InitialFrameBytes = 1 << 20;          // 1 MB

    /// <summary>
    /// Refusal point for a reply that never ends.
    ///
    /// The old code had no bound either — ReadLineAsync would grow until the process died — so this
    /// is not a regression, but a client that has just satisfied itself the server is LocalSystem
    /// should still not agree to allocate without limit on its say-so. 64 MB is two orders of
    /// magnitude above the largest plausible reply, so nothing legitimate can reach it.
    /// </summary>
    private const int MaxFrameBytes = 64 << 20;             // 64 MB

    /// <summary>
    /// The largest buffer a reply has needed so far, and therefore the size the next read rents up
    /// front. Only ever grows, and never past <see cref="MaxFrameBytes"/>.
    ///
    /// WITHOUT THIS, A MACHINE WHOSE REPLIES EXCEED THE FIRST RENT RE-PAYS THE COST THIS WHOLE
    /// CHANGE EXISTS TO REMOVE. The growth ladder is per-call: a 3 MB reply rents 1 MB, copies it
    /// into 2 MB, copies that into 4 MB — every poll, once a second, forever. Two large copies and
    /// three rents to read one message. Remembering the size that worked turns the steady state
    /// back into a single rent and a single read, which is the entire point.
    ///
    /// A plain int read and written under <see cref="Volatile"/> rather than a lock: concurrent
    /// callers racing here can only mean one of them briefly rents a size that was already big
    /// enough, and paying for a lock once a second to prevent that would cost more than it saves.
    /// </summary>
    private static int _frameHint = InitialFrameBytes;

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

            int id = Interlocked.Increment(ref _nextId);
            await writer.WriteLineAsync(
                GuardianProtocol.Serialise(new IpcRequest { Id = id, Op = op, Args = args })).ConfigureAwait(false);

            // The request is tens of bytes and stays a string; the REPLY is the one that matters, and
            // it is read as raw UTF-8 and parsed exactly once. See Frames above for the measurement.
            byte[]? frame = null;
            try
            {
                int length;
                (frame, length) = await ReadFrameAsync(pipe, timeout.Token).ConfigureAwait(false);

                // Zero is an empty line, negative is the pipe closing mid-frame. Both were
                // string.IsNullOrEmpty(line) before, and both mean the same thing to the caller.
                if (length <= 0) return null;

                var response = JsonSerializer.Deserialize<IpcResponse<T>>(
                    new ReadOnlySpan<byte>(frame, 0, length), GuardianProtocol.Json);

                return response is { Ok: true } ? response.Data : null;
            }
            finally
            {
                // Only if the read actually handed a buffer back. When it throws it has already
                // returned its own, and returning the same array twice corrupts the pool.
                if (frame is not null) Frames.Return(frame);
            }
        }
        catch
        {
            // Absent service, refused ACL, timeout, malformed reply — all the same answer to the
            // caller: no, the guardian did not tell me anything.
            return null;
        }
    }

    /// <summary>
    /// Reads one newline-framed message off the pipe as raw UTF-8, into a buffer the caller must
    /// return to <see cref="Frames"/>.
    ///
    /// Length is the JSON only: the framing newline is excluded, and so is the carriage return in
    /// front of it, because the other end writes with StreamWriter.WriteLineAsync and that emits
    /// Environment.NewLine — "\r\n" on Windows. A negative length means the pipe closed before the
    /// frame ended.
    ///
    /// Scanning for a single '\n' is the same framing StreamReader.ReadLineAsync applied here
    /// before, and it is safe for the same reason the protocol has always relied on: the pipe is
    /// PipeTransmissionMode.Byte, and GuardianProtocol.Serialise never writes indented JSON, so
    /// every newline inside a payload is escaped to "\\n" by JSON string escaping.
    /// </summary>
    private static async Task<(byte[] Buffer, int Length)> ReadFrameAsync(
        Stream pipe, CancellationToken token)
    {
        byte[] buffer = Frames.Rent(Volatile.Read(ref _frameHint));
        int filled = 0;

        try
        {
            while (true)
            {
                if (filled == buffer.Length)
                {
                    if (buffer.Length >= MaxFrameBytes)
                    {
                        throw new InvalidDataException(
                            $"The guardian's reply passed {MaxFrameBytes >> 20} MB without ending.");
                    }

                    byte[] bigger = Frames.Rent(Math.Min(buffer.Length * 2, MaxFrameBytes));
                    Array.Copy(buffer, bigger, filled);
                    Frames.Return(buffer);
                    buffer = bigger;
                }

                int read = await pipe.ReadAsync(buffer.AsMemory(filled), token).ConfigureAwait(false);
                if (read == 0) return (buffer, -1);

                // Only the bytes that just arrived: everything before `filled` was searched on a
                // previous pass, and re-scanning it would make a long reply quadratic.
                int newline = Array.IndexOf(buffer, (byte)'\n', filled, read);
                filled += read;

                if (newline < 0) continue;

                // What the MESSAGE needed, never what the pool happened to hand out. Rent is
                // allowed to return a buffer larger than asked for, and recording buffer.Length
                // here made the hint ratchet: a 33-byte frame that landed in an oversized buffer
                // raised the hint to that buffer's size, the next rent then came back larger
                // still, and the harness watched it climb 1 → 2 → 4 → 8 → 16 → 32 MB. Left in,
                // the dashboard would end up renting 64 MB to read half a megabyte.
                if (filled > Volatile.Read(ref _frameHint))
                {
                    Volatile.Write(ref _frameHint, filled);
                }

                int length = newline;
                if (length > 0 && buffer[length - 1] == (byte)'\r') length--;
                return (buffer, length);
            }
        }
        catch
        {
            Frames.Return(buffer);
            throw;
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
