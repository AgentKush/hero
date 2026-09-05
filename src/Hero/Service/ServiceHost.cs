using System.Runtime.InteropServices;

namespace Hero.Service;

/// <summary>
/// The service side of HERO: what runs when the SCM launches HERO.exe with <c>--service</c>.
///
/// This hosts the guardian engine, and the move is the whole point of the service: detection runs
/// in a process user-level malware cannot stop, and sees the machine with SYSTEM's reach.
///
/// It did not always, and this comment said so for a long time after it stopped being true — it
/// described the design that state made impossible (two brains writing two baselines, a hash chain
/// with two writers) and the plan to fix it. The plan happened: state moved to %ProgramData%, the
/// UI moved to the other end of an IPC pipe, and <see cref="Guardian.GuardianService.Start"/> is
/// called below. Leaving the old paragraph in place made this file's own summary the least
/// reliable description of it in the repository.
///
/// The cost of that move is what the identity work exists to pay: everything profile-relative —
/// HKCU, the Startup folder, %LOCALAPPDATA%, %TEMP% — means the service account here rather than
/// the signed-in user, and resolves silently to the wrong place rather than failing. See
/// <see cref="Core.UserHives"/>.
/// </summary>
internal static class ServiceHost
{
    // The SCM calls back into these. If they are collected, the callback lands in freed memory
    // and the service dies with a hard-to-read access violation, so both are rooted for the
    // lifetime of the process.
    private static Native.ServiceMain? _mainCallback;
    private static Native.HandlerEx? _handlerCallback;

    private static IntPtr _statusHandle;
    private static int _checkPoint;
    private static Ipc.GuardianPipeServer? _ipc;
    private static readonly ManualResetEventSlim Stopping = new(false);

    /// <summary>
    /// Hands the process to the SCM. Blocks until the service stops, so this never returns while
    /// HERO is running as a service.
    /// </summary>
    internal static int Run()
    {
        _mainCallback = ServiceMain;

        var table = new[]
        {
            new Native.SERVICE_TABLE_ENTRY
            {
                lpServiceName = ServiceControl.ServiceName,
                lpServiceProc = Marshal.GetFunctionPointerForDelegate(_mainCallback),
            },
            // The table is terminated by an all-zero row, not by its length.
            new Native.SERVICE_TABLE_ENTRY { lpServiceName = null, lpServiceProc = IntPtr.Zero },
        };

        if (!Native.StartServiceCtrlDispatcherW(table))
        {
            int err = Marshal.GetLastWin32Error();
            ServiceLog.Write($"StartServiceCtrlDispatcher failed with {err}. " +
                             "Error 1063 means HERO.exe was run with --service from a console " +
                             "rather than launched by the service control manager.");
            return err;
        }

        return 0;
    }

    private static void ServiceMain(int argc, IntPtr argv)
    {
        _handlerCallback = Handler;
        _statusHandle = Native.RegisterServiceCtrlHandlerExW(
            ServiceControl.ServiceName, _handlerCallback, IntPtr.Zero);

        if (_statusHandle == IntPtr.Zero)
        {
            ServiceLog.Write("RegisterServiceCtrlHandlerEx failed; the service cannot report status.");
            return;
        }

        Report(Native.SERVICE_START_PENDING, waitHint: 5000);

        try
        {
            // Before anything that can throw. The SCM restarts a service that dies, so without a
            // reason written first a crash loop is indistinguishable from a service being stopped
            // and started — and the restart erases the evidence of the previous attempt.
            Core.CrashHandler.Install(ServiceLog.Write);

            ServiceLog.Write($"HERO guardian service starting. pid {Environment.ProcessId}, " +
                             $"identity {Environment.UserName}.");

            // State lives in %ProgramData% so the service and the signed-in user resolve it to
            // the same directory. Creating it here means the service can run on a machine where
            // the interactive app has never been opened.
            Core.HeroPaths.EnsureCreated();

            SelfIntegrity.Begin(Stopping);

            // The guardian itself, running as LocalSystem. This is the point of the whole
            // exercise: detection now lives in the process that user-level malware cannot stop,
            // and it sees the machine with SYSTEM's reach rather than the signed-in user's.
            Guardian.GuardianService.Current.Start();
            ServiceLog.Write("Guardian engine started in the service.");

            _ipc = new Ipc.GuardianPipeServer();
            _ipc.Start();

            Report(Native.SERVICE_RUNNING);
            ServiceLog.Write("Service running.");

            Stopping.Wait();
        }
        catch (Exception ex)
        {
            // A service that dies silently is indistinguishable from one that was killed, and the
            // SCM will keep restarting it. Say why, once, before going down.
            ServiceLog.Write("Service faulted: " + ex);
        }
        finally
        {
            try { _ipc?.Stop(); } catch { }
            ServiceLog.Write("Service stopped.");
            Report(Native.SERVICE_STOPPED);
        }
    }

    private static int Handler(int control, int eventType, IntPtr eventData, IntPtr context)
    {
        switch (control)
        {
            case Native.SERVICE_CONTROL_STOP:
            case Native.SERVICE_CONTROL_SHUTDOWN:
                ServiceLog.Write(control == Native.SERVICE_CONTROL_STOP
                    ? "Stop requested."
                    : "Machine shutting down.");
                Report(Native.SERVICE_STOP_PENDING, waitHint: 5000);
                Stopping.Set();
                return 0;

            default:
                return 0;
        }
    }

    private static void Report(int state, int waitHint = 0)
    {
        var status = new Native.SERVICE_STATUS
        {
            dwServiceType = Native.SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState = state,
            // Accepting shutdown as well as stop is what gives HERO a chance to record a clean
            // exit when the machine reboots, instead of looking like it was killed.
            dwControlsAccepted = state == Native.SERVICE_START_PENDING
                ? 0
                : Native.SERVICE_ACCEPT_STOP | Native.SERVICE_ACCEPT_SHUTDOWN,
            dwWin32ExitCode = 0,
            dwServiceSpecificExitCode = 0,
            dwCheckPoint = state is Native.SERVICE_RUNNING or Native.SERVICE_STOPPED ? 0 : ++_checkPoint,
            dwWaitHint = waitHint,
        };

        Native.SetServiceStatus(_statusHandle, ref status);
    }
}
