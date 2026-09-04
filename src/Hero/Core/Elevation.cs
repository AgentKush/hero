using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Hero.Interop;

namespace Hero.Core;

/// <summary>What Windows says about the current token's elevation.</summary>
internal enum TokenElevationKind
{
    /// <summary>Could not be determined. Treat as "not elevated" and say so.</summary>
    Unknown = 0,
    /// <summary>TokenElevationTypeDefault: UAC off, or an ordinary standard-user token.</summary>
    Default = 1,
    /// <summary>TokenElevationTypeFull: this process is running elevated.</summary>
    Full = 2,
    /// <summary>TokenElevationTypeLimited: a filtered administrator token. Consent is enough.</summary>
    Limited = 3,
}

/// <summary>
/// The complete set of things HERO is allowed to ask for administrator rights to do.
///
/// This is deliberately an enum and not a command string. The elevated child is HERO's own
/// executable relaunched with <c>--elevated-op</c>, so anything that can reach that argument
/// parser inherits a UAC-approved token; a free-form command would turn HERO into a general
/// purpose escalation service for anything that can write to the same settings file.
/// </summary>
internal enum ElevatedOperation
{
    None = 0,
    /// <summary>Read image path, integrity and modules for a process medium IL cannot open.</summary>
    InspectProtectedProcess,
    /// <summary>Suspend or terminate a process owned by SYSTEM or another user.</summary>
    TerminateProtectedProcess,
    /// <summary>Remove an HKLM autorun value (Run, IFEO Debugger, Winlogon).</summary>
    RemoveMachinePersistence,
    /// <summary>Change a service start type, or stop a running service.</summary>
    ReconfigureService,
    /// <summary>Add a Windows Firewall rule blocking one executable's traffic.</summary>
    BlockProcessNetwork,
    /// <summary>Read the Security channel (4688 process creation).</summary>
    ReadSecurityLog,
    /// <summary>Read SMART / NVMe health from a physical drive.</summary>
    ReadDiskHealth,
    /// <summary>Run DISM / SFC component-store repair.</summary>
    RepairSystemFiles,
    /// <summary>Enable an event channel that ships disabled (e.g. TaskScheduler/Operational).</summary>
    EnableEventChannel,
}

/// <summary>One row of the "what needs admin and what does not" table.</summary>
internal sealed record ElevationRequirement
{
    internal required ElevatedOperation Operation { get; init; }
    internal required string Display { get; init; }
    /// <summary>The measured reason, citing what was actually observed on this machine.</summary>
    internal required string Why { get; init; }
    /// <summary>What HERO does instead when the user declines. Never "reports clean".</summary>
    internal required string Degraded { get; init; }
}

internal enum ElevationOutcome
{
    /// <summary>The elevated helper ran and exited zero.</summary>
    Completed,
    /// <summary>HERO is already elevated; the caller should just do the work in-process.</summary>
    NotRequired,
    /// <summary>The user dismissed the UAC prompt. Not an error, and not something to retry.</summary>
    Cancelled,
    /// <summary>The helper ran and failed, or could not be started.</summary>
    Failed,
    /// <summary>The helper was started but did not finish inside the timeout.</summary>
    TimedOut,
    /// <summary>The request was malformed or the operation is not one HERO will elevate for.</summary>
    Refused,
}

internal sealed record ElevationResult(ElevationOutcome Outcome, string Message)
{
    internal int ExitCode { get; init; }
    internal bool Ok => Outcome is ElevationOutcome.Completed or ElevationOutcome.NotRequired;
}

/// <summary>
/// A single, explicit, privileged job. Constructed by HERO, encoded into a command line, and
/// re-validated by the elevated child before anything happens.
/// </summary>
internal sealed record ElevationRequest(ElevatedOperation Operation, IReadOnlyList<string> Arguments)
{
    internal ElevationRequest(ElevatedOperation op, params string[] args)
        : this(op, (IReadOnlyList<string>)args) { }
}

/// <summary>
/// Elevation detection and the narrow, per-action escalation path.
///
/// <para>HERO ships <c>asInvoker</c> and runs at medium integrity. That is a deliberate product
/// decision, not an oversight: a tray app that fires UAC at every logon teaches its user to click
/// through prompts, which is a net security loss. Elevation is therefore requested on demand, for
/// one named operation at a time, and declining it must never be reported as "clean".</para>
///
/// <para><b>Threat model, stated plainly.</b> HERO at medium IL is not a security boundary against
/// code already running as this user. Such code can already kill HERO, edit its settings, empty
/// its vault, or replace its executable. Everything below is defence in depth, not a boundary —
/// including the install-location check, which narrows a real window but cannot close it, since
/// the file could be swapped between the check and ShellExecute.</para>
/// </summary>
internal static class Elevation
{
    /// <summary>TOKEN_ELEVATION_TYPE. Not in Native.cs, which owns TokenElevation (20) only.</summary>
    private const int TokenElevationType = 18;

    /// <summary>GetCurrentProcess() is the pseudo-handle (HANDLE)-1; no handle to close.</summary>
    private static readonly IntPtr CurrentProcess = new(-1);

    /// <summary>ERROR_CANCELLED — the user clicked No on the UAC prompt.</summary>
    private const int ErrorCancelled = 1223;
    /// <summary>ERROR_ELEVATION_REQUIRED — runas was refused before a prompt appeared.</summary>
    private const int ErrorElevationRequired = 740;

    private static readonly Lazy<bool> _elevated = new(QueryElevated, LazyThreadSafetyMode.ExecutionAndPublication);
    private static readonly Lazy<TokenElevationKind> _kind = new(QueryKind, LazyThreadSafetyMode.ExecutionAndPublication);
    private static readonly Lazy<bool> _admin = new(QueryAdministrator, LazyThreadSafetyMode.ExecutionAndPublication);
    private static readonly Lazy<bool> _writableInstall = new(ProbeInstallDirectory, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    /// True when this process holds an elevated token. Queried once via TokenElevation; the
    /// answer cannot change for the life of a process, so caching it is safe.
    /// </summary>
    internal static bool IsElevated => _elevated.Value;

    /// <summary>Split-token state, which is what decides whether a UAC prompt can succeed.</summary>
    internal static TokenElevationKind Kind => _kind.Value;

    /// <summary>Group membership. False for a filtered admin token, which is why Kind exists.</summary>
    internal static bool IsAdministrator => _admin.Value;

    /// <summary>
    /// True when a UAC consent prompt raised from this session can put HERO at high integrity
    /// using this account alone.
    ///
    /// A filtered administrator (<see cref="TokenElevationKind.Limited"/>) needs only consent.
    /// A genuine standard user can still elevate, but only by typing an administrator's password
    /// — see <see cref="RequiresAnotherAccount"/>, which the UI must say out loud rather than
    /// showing a prompt the user cannot satisfy.
    /// </summary>
    internal static bool CanElevate => Kind switch
    {
        TokenElevationKind.Full => true,
        TokenElevationKind.Limited => true,
        // UAC disabled: either already administrator (nothing to gain) or a standard user
        // (nothing available without other credentials).
        _ => IsAdministrator,
    };

    /// <summary>True when elevating would demand credentials for a different account.</summary>
    internal static bool RequiresAnotherAccount =>
        !IsElevated && Kind == TokenElevationKind.Default && !IsAdministrator;

    /// <summary>
    /// True when HERO's own directory can be written by anything running as this user. It can:
    /// the development build lives under D:\My projects. A UAC prompt HERO raises blesses whatever
    /// is at that path at the moment the shell launches it, so the consent dialog must say so.
    /// </summary>
    internal static bool InstallDirectoryIsUserWritable => _writableInstall.Value;

    /// <summary>Non-null when the user should be warned before HERO raises a UAC prompt.</summary>
    internal static string? ConsentWarning => InstallDirectoryIsUserWritable
        ? "HERO is installed in a folder that any program running as you can modify. Approving this "
        + "prompt grants administrator rights to whatever is at that path. Installing HERO under "
        + "Program Files closes most of that window."
        : null;

    /// <summary>
    /// True when someone who is NOT an administrator can modify <paramref name="directory"/>, with
    /// <paramref name="reason"/> naming the principal and right that make it so.
    ///
    /// Distinct from <see cref="InstallDirectoryIsUserWritable"/>, and it has to be. That property
    /// answers "can THIS PROCESS write here" by attempting a write, which is exactly the wrong
    /// question at service-install time: the installer runs elevated, so the probe succeeds in
    /// %ProgramFiles% and would report the safest directory on the machine as user-writable. The
    /// question here is about the directory's permissions, not the caller's token, so it reads the
    /// DACL instead of testing it.
    ///
    /// Ownership counts as write access. An owner holds WRITE_DAC implicitly and can grant itself
    /// anything else at will, so a directory owned by a standard user is a directory that user
    /// controls regardless of its ACEs.
    ///
    /// Inherit-only entries are skipped. A CREATOR OWNER ACE says "whoever creates a file here owns
    /// it", which matters only if creation is possible — and that is decided by the other ACEs,
    /// which are checked. Counting it would flag almost every directory on Windows.
    ///
    /// Not walked: ancestors above the immediate parent. A user who can rename a grandparent can
    /// still swap the directory out from under the service. That is a real gap and is left as one
    /// rather than papered over — the checks below catch the case that actually occurs, which is
    /// HERO being registered from a build output folder under a user's own profile or data drive.
    /// </summary>
    internal static bool DirectoryWritableByNonAdministrators(string directory, out string reason)
    {
        reason = "";

        // Rights that let someone change what is in the directory, or change who may. Read and
        // execute are deliberately absent: a service binary the world can READ is not a problem.
        const System.Security.AccessControl.FileSystemRights Dangerous =
            System.Security.AccessControl.FileSystemRights.WriteData |       // CreateFiles
            System.Security.AccessControl.FileSystemRights.AppendData |      // CreateDirectories
            System.Security.AccessControl.FileSystemRights.Delete |
            System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles |
            System.Security.AccessControl.FileSystemRights.ChangePermissions |
            System.Security.AccessControl.FileSystemRights.TakeOwnership;

        try
        {
            var info = new DirectoryInfo(directory);
            if (!info.Exists) { reason = "the directory does not exist"; return true; }

            var security = info.GetAccessControl(
                System.Security.AccessControl.AccessControlSections.Access |
                System.Security.AccessControl.AccessControlSections.Owner);

            var owner = security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier))
                        as System.Security.Principal.SecurityIdentifier;
            if (owner is not null && !IsTrustedInstaller(owner))
            {
                reason = $"it is owned by {Describe(owner)}, who can therefore rewrite its permissions";
                return true;
            }

            foreach (System.Security.AccessControl.FileSystemAccessRule rule in
                     security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
            {
                if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                if ((rule.PropagationFlags & System.Security.AccessControl.PropagationFlags.InheritOnly) != 0) continue;
                if ((rule.FileSystemRights & Dangerous) == 0) continue;
                if (rule.IdentityReference is not System.Security.Principal.SecurityIdentifier sid) continue;
                if (IsTrustedInstaller(sid)) continue;

                reason = $"{Describe(sid)} may write to it";
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            // Cannot read the DACL, so cannot claim the directory is safe.
            reason = $"its permissions could not be read ({ex.GetType().Name})";
            return true;
        }
    }

    /// <summary>SYSTEM, the Administrators group, and TrustedInstaller. Nobody else.</summary>
    private static bool IsTrustedInstaller(System.Security.Principal.SecurityIdentifier sid)
        => sid.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid)
        || sid.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid)
        // NT SERVICE\TrustedInstaller has no WellKnownSidType; it owns %ProgramFiles% on a stock
        // install, so omitting it would flag the one directory this check exists to approve.
        || sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private static string Describe(System.Security.Principal.SecurityIdentifier sid)
    {
        try { return sid.Translate(typeof(System.Security.Principal.NTAccount)).Value; }
        catch { return sid.Value; }
    }

    /// <summary>One sentence describing the current state, for the UI's capability panel.</summary>
    internal static string ExplainState()
    {
        if (IsElevated) return "HERO is running with administrator rights.";
        if (RequiresAnotherAccount)
            return "HERO is running as a standard user. Privileged checks need an administrator's password.";
        if (CanElevate)
            return "HERO is running without administrator rights. Privileged checks will ask for permission when needed.";
        return "HERO is running without administrator rights, and this account cannot elevate. Privileged checks are unavailable.";
    }

    // ------------------------------------------------------- what needs admin

    /// <summary>
    /// Every operation that genuinely needs elevation on this machine, with the measurement behind
    /// the claim and what HERO does when it cannot have it. Nothing here is speculative: each row
    /// corresponds to an access-denied that was observed at medium integrity.
    /// </summary>
    internal static IReadOnlyList<ElevationRequirement> Requirements { get; } = new ElevationRequirement[]
    {
        new()
        {
            Operation = ElevatedOperation.InspectProtectedProcess,
            Display = "Inspect a protected process",
            Why = "OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION was denied for 132 of 358 processes "
                + "(37%) at medium integrity. Those are protected, PPL and other-session processes.",
            Degraded = "Those processes are listed as 'not assessable'. They are never scored, and never "
                     + "counted as clean.",
        },
        new()
        {
            Operation = ElevatedOperation.TerminateProtectedProcess,
            Display = "Stop a system-owned process",
            Why = "Terminating or suspending a process owned by SYSTEM or another user requires a handle "
                + "medium integrity cannot obtain.",
            Degraded = "HERO reports the finding and offers a one-click elevated action rather than "
                     + "silently failing to act.",
        },
        new()
        {
            Operation = ElevatedOperation.RemoveMachinePersistence,
            Display = "Remove machine-wide startup entries",
            Why = "HKLM is readable unelevated (all 841 service keys were enumerated) but not writable. "
                + "Removing an HKLM Run value, an IFEO Debugger or a Winlogon hijack is a write.",
            Degraded = "The entry is shown with an explanation and an elevated 'remove' button. HERO never "
                     + "pretends to have removed something it could not.",
        },
        new()
        {
            Operation = ElevatedOperation.ReconfigureService,
            Display = "Disable or stop a service",
            Why = "Service enumeration works unelevated; ChangeServiceConfig and ControlService do not.",
            Degraded = "The service is reported. Disabling it needs consent.",
        },
        new()
        {
            Operation = ElevatedOperation.BlockProcessNetwork,
            Display = "Block a program's network access",
            Why = "Windows Firewall rule creation requires administrator rights.",
            Degraded = "HERO can show the connections but cannot cut them. Quarantining the executable is "
                     + "offered as the unprivileged alternative.",
        },
        new()
        {
            Operation = ElevatedOperation.ReadSecurityLog,
            Display = "Read the Security event log",
            Why = "The Security channel (including 4688 process creation) requires Administrators or Event "
                + "Log Readers membership. Access was denied at medium integrity.",
            Degraded = "HERO watches the System and Defender channels instead, and marks the Security "
                     + "channel unavailable rather than reporting its silence as clean.",
        },
        new()
        {
            Operation = ElevatedOperation.ReadDiskHealth,
            Display = "Read drive health (SMART / NVMe)",
            Why = "IOCTL_STORAGE_QUERY_PROPERTY succeeds with dwDesiredAccess=0 and returned the drive "
                + "model unelevated, but SMART needs GENERIC_READ|GENERIC_WRITE on \\\\.\\PhysicalDriveN, "
                + "which returned error 5 (access denied).",
            Degraded = "Model, serial and capacity are shown; health is marked 'requires elevation'. "
                     + "'SMART unavailable' is never presented as a drive problem.",
        },
        new()
        {
            Operation = ElevatedOperation.RepairSystemFiles,
            Display = "Repair Windows component store",
            Why = "DISM and SFC require administrator rights by design.",
            Degraded = "Offered as an explicit maintenance action the user starts, never automatically.",
        },
        new()
        {
            Operation = ElevatedOperation.EnableEventChannel,
            Display = "Turn on a disabled event log channel",
            Why = "Microsoft-Windows-TaskScheduler/Operational is disabled by default on this machine "
                + "(IsEnabled=False). Enabling a channel writes channel configuration, which needs admin.",
            Degraded = "The channel is reported as unavailable. HERO falls back to polling the task tree "
                     + "and never treats an unwatched channel as a quiet one.",
        },
    };

    /// <summary>
    /// The measured list of things HERO does NOT need administrator rights for. Kept next to the
    /// list above so the capability panel can be honest in both directions, and so nobody adds a
    /// UAC prompt to an operation that was already proven to work.
    /// </summary>
    internal static IReadOnlyList<string> WorksWithoutElevation { get; } = new[]
    {
        "Enumerate every running process (all 358) with parent, thread count and start time.",
        "Read image path and integrity level for 226 of 358 processes.",
        "Read command lines for 221 of 358 processes.",
        "Read the full per-PID TCP/UDP socket table (all 143 rows).",
        "Read HKCU and HKLM autorun keys, Winlogon, IFEO and all 841 service keys.",
        "Enumerate scheduled tasks (299 were listed via schtasks /query).",
        "Verify Authenticode and catalog signatures.",
        "Subscribe to the System and Windows Defender/Operational event channels.",
        "Write HKCU: the startup Run entry and the toast AppUserModelId key.",
        "Suspend, terminate and quarantine processes and files owned by this user.",
        "Send a file to the Recycle Bin.",
        "Read drive model, serial and bus type via IOCTL_STORAGE_QUERY_PROPERTY.",
    };

    /// <summary>True when <paramref name="operation"/> cannot be done at medium integrity.</summary>
    internal static bool Requires(ElevatedOperation operation) =>
        operation != ElevatedOperation.None && Requirements.Any(r => r.Operation == operation);

    internal static ElevationRequirement? Describe(ElevatedOperation operation) =>
        Requirements.FirstOrDefault(r => r.Operation == operation);

    // ------------------------------------------------------------- relaunch

    /// <summary>The switch that puts the child into single-operation mode.</summary>
    internal const string ElevatedOpSwitch = "--elevated-op";

    /// <summary>
    /// Tells an incoming instance to WAIT for the running one to release the single-instance
    /// mutex rather than exiting on it. Lives here rather than on the App class so Core does not
    /// depend on the WPF entry point.
    /// </summary>
    internal const string ReplaceSwitch = "--replace";

    /// <summary>
    /// Relaunches HERO elevated to perform exactly one operation, then waits for it to finish.
    ///
    /// This blocks, so callers on the UI thread must wrap it in <c>Task.Run</c>. It must not be
    /// called for anything not in <see cref="Requirements"/>: an escalation path is only as narrow
    /// as the smallest thing that goes through it.
    /// </summary>
    internal static ElevationResult RunElevated(ElevationRequest request, TimeSpan timeout)
    {
        if (request.Operation == ElevatedOperation.None)
            return new ElevationResult(ElevationOutcome.Refused, "No operation specified.");

        if (!Requires(request.Operation))
            return new ElevationResult(ElevationOutcome.Refused,
                $"{request.Operation} does not require elevation and will not be run this way.");

        if (IsElevated)
            return new ElevationResult(ElevationOutcome.NotRequired,
                "HERO already has administrator rights; do the work in-process.");

        if (!TryBuildArguments(request, out var arguments, out var reason))
            return new ElevationResult(ElevationOutcome.Refused, reason);

        var exe = StartupRegistration.ExePath;
        if (exe.Length == 0)
            return new ElevationResult(ElevationOutcome.Failed,
                "HERO cannot determine its own executable path, so it cannot relaunch itself.");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = arguments,
                // runas requires the shell; ArgumentList is not used because a single explicitly
                // quoted string is easier to audit than trusting the runtime's joining rules for
                // the one command line that gets an administrator token.
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = Path.GetDirectoryName(exe) ?? "",
            };

            using var child = Process.Start(psi);
            if (child is null)
                return new ElevationResult(ElevationOutcome.Failed, "Windows did not start the elevated helper.");

            if (!child.WaitForExit((int)Math.Clamp(timeout.TotalMilliseconds, 1000, 600000)))
                return new ElevationResult(ElevationOutcome.TimedOut,
                    "The elevated helper is still running. HERO will not assume it succeeded.");

            int code = child.ExitCode;
            return code == 0
                ? new ElevationResult(ElevationOutcome.Completed, "Completed with administrator rights.") { ExitCode = 0 }
                : new ElevationResult(ElevationOutcome.Failed,
                    $"The elevated helper exited with code {code}.") { ExitCode = code };
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            // The single most common outcome, and not a failure. Nothing was done; say exactly
            // that, and never retry automatically — a re-prompt after a decline is how users are
            // trained to click Yes without reading.
            return new ElevationResult(ElevationOutcome.Cancelled,
                "Permission was declined, so this check was not run. It is still listed as not assessable.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorElevationRequired)
        {
            return new ElevationResult(ElevationOutcome.Failed,
                "Windows refused to elevate HERO. Administrator rights are unavailable in this session.");
        }
        catch (Win32Exception ex)
        {
            return new ElevationResult(ElevationOutcome.Failed,
                $"Elevation failed ({ex.NativeErrorCode}): {ex.Message}");
        }
        catch (Exception ex)
        {
            return new ElevationResult(ElevationOutcome.Failed, "Elevation failed: " + ex.Message);
        }
    }

    // ------------------------------------------------ command line contract

    /// <summary>
    /// Encodes a request as <c>--elevated-op &lt;Operation&gt; [args...]</c>.
    ///
    /// Arguments are validated, not escaped. Anything containing a double quote, a control
    /// character, or a newline is rejected outright: an argument that needs clever escaping to
    /// survive is an argument that should not be crossing a privilege boundary.
    /// </summary>
    internal static bool TryBuildArguments(ElevationRequest request, out string arguments, out string reason)
    {
        arguments = "";
        reason = "";

        foreach (var a in request.Arguments)
        {
            if (string.IsNullOrEmpty(a)) { reason = "An empty argument was supplied."; return false; }
            if (a.Length > 1024) { reason = "An argument was too long."; return false; }
            foreach (var c in a)
            {
                if (c == '"' || c == '^' || char.IsControl(c))
                {
                    reason = "An argument contained a character HERO will not pass across an elevation boundary.";
                    return false;
                }
            }

            // An argument that needs quoting and ends in an ODD number of backslashes is the one
            // remaining way to break out of the quoting below without using a quote character:
            // CommandLineToArgvW reads the final \" as an escaped quote, so the argument never
            // closes and swallows everything after it. Registry key paths and directory paths
            // written with a trailing separator hit this by accident, which is precisely why it
            // must be caught rather than assumed away. Consistent with the rule above, this is
            // rejected rather than escaped.
            if (a.Contains(' '))
            {
                int trailing = 0;
                for (int k = a.Length - 1; k >= 0 && a[k] == '\\'; k--) trailing++;
                if (trailing % 2 == 1)
                {
                    reason = "An argument contains a space and ends in a backslash, which cannot be quoted "
                           + "safely. Pass it without the trailing separator.";
                    return false;
                }
            }
        }

        var parts = new List<string>(request.Arguments.Count + 2)
        {
            ElevatedOpSwitch,
            request.Operation.ToString(),
        };
        parts.AddRange(request.Arguments.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));
        arguments = string.Join(' ', parts);
        return true;
    }

    /// <summary>
    /// The child side. Recognises the elevated-operation command line and validates it before the
    /// caller does anything privileged.
    ///
    /// Wire this into App.OnStartup ahead of the tray and the monitor engine: an elevated HERO
    /// should do its one job and exit, never sit resident with an administrator token.
    /// </summary>
    internal static bool TryParseRequest(string[] args, out ElevationRequest? request)
    {
        request = null;
        if (args is null) return false;

        int i = Array.FindIndex(args, a => a.Equals(ElevatedOpSwitch, StringComparison.OrdinalIgnoreCase));
        if (i < 0 || i + 1 >= args.Length) return false;

        if (!Enum.TryParse<ElevatedOperation>(args[i + 1], ignoreCase: true, out var op)
            || !Enum.IsDefined(op)
            || !Requires(op))
        {
            // An unknown or non-privileged verb reaching this parser is either a bug or an attempt
            // to use HERO as an escalation service. Refuse rather than guess.
            return false;
        }

        request = new ElevationRequest(op, args.Skip(i + 2).ToArray());
        return true;
    }

    // ----------------------------------------------------------------- probes

    private static bool QueryElevated()
    {
        // TOKEN_ELEVATION is a single DWORD: non-zero means the token is elevated.
        var value = QueryTokenInt(Native.TokenElevation);
        return value is > 0;
    }

    private static TokenElevationKind QueryKind()
    {
        var value = QueryTokenInt(TokenElevationType);
        return value switch
        {
            1 => TokenElevationKind.Default,
            2 => TokenElevationKind.Full,
            3 => TokenElevationKind.Limited,
            _ => TokenElevationKind.Unknown,
        };
    }

    /// <summary>
    /// Reads a 4-byte token information class. Both TokenElevation (20) and TokenElevationType
    /// (18) are DWORD-sized, so no two-pass sizing is needed for either.
    /// </summary>
    private static int? QueryTokenInt(int informationClass)
    {
        IntPtr token = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!Native.OpenProcessToken(CurrentProcess, Native.TOKEN_QUERY, out token) || token == IntPtr.Zero)
                return null;

            buffer = Marshal.AllocHGlobal(sizeof(int));
            if (!Native.GetTokenInformation(token, informationClass, buffer, sizeof(int), out _))
                return null;

            return Marshal.ReadInt32(buffer);
        }
        catch
        {
            return null;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero) Native.CloseHandle(token);
        }
    }

    private static bool QueryAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>
    /// Probes whether HERO's own directory is writable by this user, by actually writing. There is
    /// no reliable way to answer this from the DACL alone once inherited ACEs, group membership
    /// and mandatory labels are involved, and a wrong answer here would either hide a real risk or
    /// nag about a safe install.
    /// </summary>
    private static bool ProbeInstallDirectory()
    {
        try
        {
            var dir = Path.GetDirectoryName(StartupRegistration.ExePath);
            if (string.IsNullOrEmpty(dir)) return true; // unknown: assume the riskier answer

            var probe = Path.Combine(dir, $".hero-write-probe-{Environment.ProcessId}.tmp");
            using (var fs = new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                                           bufferSize: 1, FileOptions.DeleteOnClose))
            {
                // FileOptions.DeleteOnClose removes the probe even if HERO is killed mid-check,
                // so a crash here cannot litter the install directory.
                return true;
            }
        }
        catch (UnauthorizedAccessException) { return false; }
        catch (IOException) { return false; }
        catch { return true; }
    }
}
