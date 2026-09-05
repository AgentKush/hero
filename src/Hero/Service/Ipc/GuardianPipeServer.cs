using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Hero.Service.Ipc;

/// <summary>
/// The service's end of the pipe.
///
/// ACCESS CONTROL IS THE WHOLE DESIGN HERE. This pipe is created by a LocalSystem process and
/// answers questions about the machine's security posture, so who may open it is not a detail:
///
///   * LocalSystem and Administrators — full control.
///   * <b>Interactive</b> users — read and write. Not "Authenticated Users", which would let any
///     local account, including a service account a compromised application is running under,
///     interrogate the guardian. The Interactive SID is only present in a token that logged on at
///     the console or over RDP, which is exactly the population entitled to a desktop UI.
///   * Nobody else. A named pipe is reachable remotely as \\host\pipe\name, and a remote caller
///     carries the Network SID rather than Interactive, so remote access is excluded by the same
///     rule rather than by a separate check that could be forgotten.
///
/// The pipe IS a control channel. It was not when this class was written — the comment here said
/// so for a long time after it stopped being true, which is its own lesson — and the guardian
/// moving into the service brought suspend, kill, quarantine and persistence removal with it.
///
/// So the ACL is the floor and not the answer. Every operation declares what a caller must hold in
/// <see cref="GuardianProtocol.AccessFor"/>, and <see cref="Handle"/> enforces that before
/// dispatch: an operation added without a row in that table is refused rather than published. A
/// pipe a user can open is not a pipe whose messages can be trusted just because the ACL is right.
/// </summary>
internal sealed class GuardianPipeServer
{
    private readonly CancellationTokenSource _stopping = new();
    private Task? _loop;

    /// <summary>True once this process has successfully created the first instance of the pipe.</summary>
    private bool _claimed;

    internal static DateTime StartedUtc { get; } = DateTime.UtcNow;

    internal void Start()
    {
        _loop = Task.Run(() => AcceptLoopAsync(_stopping.Token));
        ServiceLog.Write($"IPC listening on \\\\.\\pipe\\{GuardianProtocol.PipeName}");
    }

    internal void Stop()
    {
        try { _stopping.Cancel(); } catch { }
        try { _loop?.Wait(TimeSpan.FromSeconds(3)); } catch { }
    }

    /// <summary>
    /// How long a connected client may stay silent before its pipe instance is reclaimed.
    ///
    /// Generous by an order of magnitude for anything legitimate: a real client writes its request
    /// in the same breath as connecting. This exists purely so holding connections open cannot deny
    /// the pipe to everyone else.
    /// </summary>
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(15);

    private static PipeSecurity BuildSecurity()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));

        return security;
    }

    private async Task AcceptLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                // FirstPipeInstance on the FIRST instance only, which is what claims the name.
                //
                // Without it the service would happily join a pipe something else already owned:
                // CreateNamedPipe succeeds as an additional instance, and the squatter — having
                // created the name first — answers the connections it wins. Any process that can
                // run before the service can therefore impersonate the guardian to the dashboard,
                // feed it fabricated verdicts, and collect an impersonation token from every poll.
                //
                // With it, that arrangement fails loudly at startup instead: creation returns
                // ERROR_ACCESS_DENIED, which the catch below logs. A guardian that cannot own its
                // own channel must say so rather than quietly share it.
                bool first = !_claimed;

                pipe = NamedPipeServerStreamAcl.Create(
                    GuardianProtocol.PipeName,
                    PipeDirection.InOut,
                    GuardianProtocol.MaxServerInstances,
                    PipeTransmissionMode.Byte,
                    first ? PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance
                          : PipeOptions.Asynchronous,
                    inBufferSize: 0,
                    outBufferSize: 0,
                    BuildSecurity(),
                    HandleInheritability.None,
                    additionalAccessRights: default);

                // Only after a successful create: the name is now ours for as long as this process
                // holds at least one instance, so later instances must not ask for it again.
                _claimed = true;

                await pipe.WaitForConnectionAsync(token).ConfigureAwait(false);

                // One task per client. The tray app is normally the only one, but a second
                // instance mid-handover must not be made to wait behind the first.
                var accepted = pipe;
                pipe = null;
                _ = Task.Run(() => ServeAsync(accepted, token), CancellationToken.None);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                ServiceLog.Write("IPC accept failed: " + ex.Message);
                pipe?.Dispose();

                // Back off rather than spin: if the pipe name is unusable this loop would
                // otherwise burn a core reporting the same failure thousands of times a second.
                try { await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    private static async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        try
        {
            using (pipe)
            {
                var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
                using var reader = new StreamReader(pipe, encoding, false, 8192, leaveOpen: true);
                using var writer = new StreamWriter(pipe, encoding, 8192, leaveOpen: true) { AutoFlush = true };

                // Established once per connection: a client cannot change identity mid-conversation,
                // and impersonating on every line would be pure cost.
                bool callerElevated = ClientIsElevatedAdministrator(pipe);

                while (!token.IsCancellationRequested && pipe.IsConnected)
                {
                    // A connection that says nothing is dropped.
                    //
                    // Every legitimate client writes its request immediately and disconnects after
                    // one reply — GuardianClient opens a fresh pipe per call. So nothing real waits
                    // here, and without a bound a client could connect and simply hold, which with
                    // a small instance cap is all it takes to stop the service answering anyone.
                    using var idle = CancellationTokenSource.CreateLinkedTokenSource(token);
                    idle.CancelAfter(IdleTimeout);

                    string? line;
                    try { line = await reader.ReadLineAsync(idle.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                    {
                        break;                                  // idle too long; reclaim the instance
                    }

                    if (line is null) break;                    // client hung up
                    if (line.Length == 0) continue;

                    string reply = Handle(line, callerElevated);
                    await writer.WriteLineAsync(reply).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { /* the client went away mid-sentence; ordinary */ }
        catch (Exception ex) { ServiceLog.Write("IPC connection failed: " + ex.Message); }
    }

    /// <summary>
    /// True when the client at the other end of <paramref name="pipe"/> holds an ELEVATED
    /// administrator token.
    ///
    /// The pipe grants the Interactive SID read/write, which is what makes the dashboard work
    /// without administrator rights — and it means "can open this pipe" is not evidence of
    /// anything. Every caller is equally privileged as far as the transport is concerned, so
    /// commands that need more than that have to ask here.
    ///
    /// Impersonation is the only honest way to ask. Under UAC a filtered administrator token
    /// carries the Administrators group as DENY-ONLY, so <c>IsInRole</c> returns false for an
    /// administrator who has not elevated — which is exactly the distinction wanted. A standard
    /// user and an un-elevated administrator both get false; only a genuinely elevated caller
    /// gets true.
    ///
    /// Failure is false. A check that cannot be performed must not grant the privilege it guards.
    /// </summary>
    private static bool ClientIsElevatedAdministrator(NamedPipeServerStream pipe)
    {
        bool elevated = false;
        try
        {
            pipe.RunAsClient(() =>
            {
                try
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch { elevated = false; }
            });
        }
        catch { elevated = false; }
        return elevated;
    }

    /// <summary>
    /// Turns one request line into one response line. Never throws: a malformed message from a
    /// client must produce an error response, not take down the listener that every other client
    /// is sharing.
    /// </summary>
    private static string Handle(string line, bool callerElevated)
    {
        IpcRequest? request = null;
        try
        {
            request = JsonSerializer.Deserialize<IpcRequest>(line, GuardianProtocol.Json);
        }
        catch (JsonException)
        {
            return GuardianProtocol.Serialise(new IpcResponse
            { Id = 0, Ok = false, Error = "Request was not valid JSON." });
        }

        if (request is null || string.IsNullOrWhiteSpace(request.Op))
        {
            return GuardianProtocol.Serialise(new IpcResponse
            { Id = request?.Id ?? 0, Ok = false, Error = "Request had no operation." });
        }

        // AUTHORISATION BEFORE DISPATCH, from one table, for every operation — including the
        // read-only ones, so that adding an operation without adding a row denies it rather than
        // publishing it. The individual arms still make their own finer-grained checks; this is the
        // floor none of them can be written to skip.
        if (GuardianProtocol.AccessFor(request.Op) == GuardianProtocol.OpAccess.Elevated && !callerElevated)
        {
            return GuardianProtocol.Serialise(new IpcResponse
            {
                Id = request.Id,
                Ok = false,
                Error = $"'{request.Op}' changes how HERO defends this machine, or destroys data, so it " +
                        "needs administrator rights. Run HERO as administrator and try again.",
            });
        }

        try
        {
            object payload = request.Op switch
            {
                GuardianProtocol.OpPing => Ping(),
                GuardianProtocol.OpIntegrity => Integrity(),
                GuardianProtocol.OpState => State(request.Args),
                GuardianProtocol.OpVerify => Verify(request.Args),

                // Everything else is a command. They share one entry point so that the rule they
                // all obey — resolve the target through the verdict set, never trust the caller's
                // — lives in exactly one place and cannot be forgotten by the next operation.
                _ => GuardianCommands.Execute(request.Op, request.Args, callerElevated),
            };

            return GuardianProtocol.Serialise(new IpcResponse
            {
                Id = request.Id,
                Ok = true,
                Data = JsonSerializer.SerializeToElement(payload, GuardianProtocol.Json),
            });
        }
        catch (Exception ex)
        {
            return GuardianProtocol.Serialise(new IpcResponse
            { Id = request.Id, Ok = false, Error = ex.Message });
        }
    }

    private static PingReply Ping() => new()
    {
        Version = typeof(GuardianPipeServer).Assembly.GetName().Version?.ToString() ?? "unknown",
        Pid = Environment.ProcessId,
        Identity = WindowsIdentity.GetCurrent().Name,
        UptimeSeconds = Math.Round((DateTime.UtcNow - StartedUtc).TotalSeconds, 1),
        InstallDirectory = SelfIntegrity.RecordedInstallDirectory ?? "",
        StateDirectory = Core.HeroPaths.Root,
    };

    /// <summary>
    /// Assembles one consistent view for the dashboard.
    ///
    /// Signatures are narrowed to the paths present in this snapshot rather than dumping the whole
    /// cache: the cache grows to every image the machine has ever run, and the dashboard only ever
    /// renders what is running now.
    /// </summary>
    private static StateReply State(System.Text.Json.JsonElement? args)
    {
        var guardian = Guardian.GuardianService.Current;
        var snapshot = guardian.Engine.Latest;

        // What the client says it already holds. Absent means "nothing", so a fresh client — or
        // one reconnecting after the service restarted — gets everything.
        int Have(string name)
        {
            if (args is { } element
                && element.TryGetProperty("have", out var have)
                && have.TryGetProperty(name, out var value)
                && value.ValueKind == JsonValueKind.Number)
            {
                return value.GetInt32();
            }
            return -1;
        }

        int persistenceVersion = guardian.PersistenceVersion;
        int recentVersion = guardian.RecentStartsVersion;

        var reply = new StateReply
        {
            Snapshot = snapshot,
            Verdicts = guardian.Verdicts.ToList(),
            PersistenceScannedUtc = guardian.PersistenceScannedUtc,
            PersistenceVersion = persistenceVersion,
            RecentStartsVersion = recentVersion,

            // Sent only when the client's copy is out of date. Null is "keep what you have".
            Persistence = Have("persistence") == persistenceVersion ? null : guardian.Persistence.ToList(),
            RecentStarts = Have("recentStarts") == recentVersion ? null : guardian.RecentStarts.ToList(),
        };

        if (snapshot is null) return reply;

        void AddSignature(string path)
        {
            if (string.IsNullOrEmpty(path) || reply.Signatures.ContainsKey(path)) return;
            var signature = guardian.Verifier.TryGetCached(path);
            if (signature is not null) reply.Signatures[path] = signature;
        }

        foreach (var process in snapshot.Processes) AddSignature(process.ImagePath);

        // Signatures are keyed off the persistence inventory whether or not it was re-sent this
        // time — the client still renders it, so it still needs the signatures for it. This is
        // also why signatures are NOT version-gated: an image verified long ago can appear in a
        // snapshot at any moment, and withholding its signature because "nothing changed" would
        // put the row back to "still checking", which is the bug this all started with.
        foreach (var entry in guardian.Persistence) AddSignature(entry.ImagePath);

        // Strictly parallel to snapshot.Connections. The client zips the two together, so this
        // loop must not skip or reorder anything.
        foreach (var connection in snapshot.Connections)
        {
            snapshot.ByPid.TryGetValue(connection.Pid, out var owner);
            var signature = owner is { PathUnavailable: false }
                ? guardian.Verifier.TryGetCached(owner.ImagePath)
                : null;

            reply.ConnectionVerdicts.Add(
                guardian.Peers.Assess(connection, owner, signature, guardian.Baseline));
        }

        return reply;
    }

    /// <summary>
    /// Queues image paths for signature verification.
    ///
    /// The one message a client can send that causes work, so it is bounded. A caller that asks
    /// for ten thousand paths gets the first two hundred: the pipe is reachable by any interactive
    /// user, and "please verify this list" is exactly the shape of request that turns a helpful
    /// service into a disk-thrashing one. Two hundred comfortably covers every image on a busy
    /// machine's connection list.
    /// </summary>
    private static object Verify(System.Text.Json.JsonElement? args)
    {
        const int Limit = 200;

        if (args is not { } element
            || !element.TryGetProperty("paths", out var list)
            || list.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("verify requires a 'paths' array.");
        }

        var paths = new List<string>();
        foreach (var item in list.EnumerateArray())
        {
            if (paths.Count >= Limit) break;
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } path
                && IsLocalFilePath(path))
                paths.Add(path);
        }

        Guardian.GuardianService.Current.RequestVerification(paths);
        return new { queued = paths.Count };
    }

    /// <summary>
    /// Whether a caller-supplied path is one the service may safely open.
    ///
    /// THE COUNT WAS BOUNDED AND THE CONTENT WAS NOT. Verification opens each path and reads it, as
    /// LocalSystem — so a UNC path handed in here made the machine account authenticate to a server
    /// of the caller's choosing. That is a coerced-authentication primitive: any signed-in user
    /// could point the guardian at \\attacker\share and collect an NTLM exchange from the computer
    /// account, which is a far more valuable credential than their own.
    ///
    /// A device path is refused for the same reason one step lower down — \\?\UNC\ and \\.\ reach
    /// the same places while looking nothing like them — and a relative path is refused because
    /// what it resolves against is the service's working directory, which is System32.
    ///
    /// This is a whitelist: rooted, local, no redirection. Signature verification has no business
    /// anywhere else, and the paths a legitimate client sends all come from a snapshot the service
    /// itself produced.
    /// </summary>
    private static bool IsLocalFilePath(string path)
    {
        var p = path.Trim();
        if (p.Length < 3) return false;

        // \\server\share, \\?\..., \\.\... — every form that leaves this machine or bypasses
        // normalisation begins the same way.
        if (p.StartsWith(@"\\", StringComparison.Ordinal)) return false;

        // A drive-relative path ("C:file") resolves against a per-drive current directory, which is
        // not something a service should be resolving a caller's string against.
        if (p[1] != ':' || p[2] != '\\') return false;
        if (!char.IsAsciiLetter(p[0])) return false;

        try
        {
            // Rejects the remaining shapes cheaply and without touching the disk: invalid
            // characters, and anything Path cannot make sense of.
            return Path.IsPathFullyQualified(p) && p.IndexOfAny(Path.GetInvalidPathChars()) < 0;
        }
        catch { return false; }
    }

    private static IntegrityReply Integrity()
    {
        var report = SelfIntegrity.LastReport;
        return new IntegrityReply
        {
            ManifestPresent = SelfIntegrity.RecordedInstallDirectory is { Length: > 0 },
            FileCount = report?.FileCount ?? 0,
            RecordedUtc = report?.RecordedUtc,
            LastCheckedUtc = report?.CheckedUtc,
            Changes = report?.Changes ?? new List<string>(),
        };
    }
}
