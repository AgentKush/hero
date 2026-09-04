using System.Windows;
using Hero.Core;

namespace Hero;

public partial class App : Application
{
    /// <summary>
    /// Single-instance guard. A second HERO would double every poll, fight over the
    /// baseline file and show duplicate toasts, so the second launch simply surfaces
    /// the running instance and exits.
    /// </summary>
    private static Mutex? _instanceMutex;
    private const string MutexName = @"Local\HERO.SingleInstance.v1";

    /// <summary>
    /// Signalled by a second launch to ask the running instance to show its window.
    /// Without this, launching HERO while it sat hidden in the tray did nothing at all: the new
    /// process saw the mutex, exited, and the user was left with no way back to the window.
    /// </summary>
    private const string ShowRequestName = @"Local\HERO.ShowRequest.v1";

    /// <summary>
    /// Passed to an elevated copy so it waits for the outgoing instance to release the mutex.
    /// Without it the elevated copy hit the single-instance guard, exited, and the ordinary
    /// instance then shut itself down — leaving no HERO running at all.
    /// </summary>
    internal const string ReplaceSwitch = Core.Elevation.ReplaceSwitch;

    /// <summary>
    /// Accepts a guardian-service install from a directory a standard user can modify.
    ///
    /// For developers running a build output knowingly. Everyone else gets a refusal, because the
    /// alternative — a SYSTEM service whose binary its own attacker can rewrite — makes the rest of
    /// HERO's self-protection decorative.
    /// </summary>
    internal const string UnsafeInstallDirSwitch = "--allow-unsafe-install-dir";

    /// <summary>Shows the themed installer window. What a downloaded HERO.exe does when run.</summary>
    internal const string SetupSwitch = "--setup";

    /// <summary>The elevated half of an install. Raised by the setup window, never by a person.</summary>
    internal const string SetupInstallSwitch = "--setup-install";

    /// <summary>The elevated half of a removal. Also the QuietUninstallString in Settings > Apps.</summary>
    internal const string SetupUninstallSwitch = "--setup-uninstall";

    /// <summary>Shortcut choices, carried to the elevated install child. Both accompany
    /// <see cref="SetupInstallSwitch"/> and mean nothing on their own.</summary>
    internal const string DesktopShortcutSwitch = "--desktop-shortcut";
    internal const string NoStartMenuShortcutSwitch = "--no-start-menu-shortcut";

    private EventWaitHandle? _showRequest;
    private CancellationTokenSource? _showListener;

    private TrayIcon? _tray;
    private MainWindow? _shell;

    /// <summary>
    /// True once HERO is genuinely exiting, as opposed to the window merely being closed to the
    /// tray. <see cref="MainWindow"/> reads this to decide whether a close request should destroy
    /// the window or just hide it.
    /// </summary>
    internal static bool IsShuttingDown { get; private set; }

    /// <summary>Ends the application, first marking the shutdown so windows stop resisting it.</summary>
    internal static void ExitApplication()
    {
        IsShuttingDown = true;

        // Release the single-instance lock BEFORE shutting down, not during OnExit. An elevated
        // copy is already waiting on this mutex, and making it wait for the whole teardown means
        // it can time out for reasons that have nothing to do with it.
        ReleaseInstanceLock();

        Current?.Shutdown();
    }

    private static int _lockReleased;

    /// <summary>Releases the single-instance mutex. Safe to call more than once.</summary>
    private static void ReleaseInstanceLock()
    {
        if (Interlocked.Exchange(ref _lockReleased, 1) != 0) return;
        try { _instanceMutex?.ReleaseMutex(); } catch { /* not owned, or already released */ }
    }

    /// <summary>
    /// Handles the three headless modes. Returns true when the process has done its job and is
    /// shutting down, in which case the caller must return without starting the shell.
    /// </summary>
    private bool TryRunServiceMode(string[] args)
    {
        bool Has(string flag) => args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));

        if (Has(Service.ServiceControl.ServiceSwitch))
        {
            // Blocks for the lifetime of the service.
            Environment.ExitCode = Service.ServiceHost.Run();
            Shutdown();
            return true;
        }

        if (Has("--install-service") || Has("--uninstall-service"))
        {
            Environment.ExitCode = RunServiceInstaller(
                install: Has("--install-service"),
                allowUnsafeDirectory: Has(UnsafeInstallDirSwitch));
            Shutdown();
            return true;
        }

        // The elevated halves of setup. Windowless: the setup window that raised them is waiting on
        // the exit code, and a second window appearing at high integrity would be both confusing
        // and a thing worth clicking.
        if (Has(SetupInstallSwitch))
        {
            // The tick boxes are in the unelevated setup window; this is the elevated child it
            // launched, so the choices arrive as switches. Expressed as opt-OUT for the Start menu
            // and opt-IN for the Desktop, which matches both the defaults and what a command line
            // with neither switch should do.
            Environment.ExitCode = Core.SetupActions.Install(
                startMenuShortcut: !Has(NoStartMenuShortcutSwitch),
                desktopShortcut: Has(DesktopShortcutSwitch));
            Shutdown();
            return true;
        }

        if (Has(SetupUninstallSwitch))
        {
            Environment.ExitCode = Core.SetupActions.Uninstall();
            Shutdown();
            return true;
        }

        return false;
    }

    /// <summary>
    /// Creates or removes the service. Requires elevation — the caller is the installer, which
    /// has already prompted. Output goes to the service log because a process launched elevated
    /// has no console the user is watching.
    /// </summary>
    private static int RunServiceInstaller(bool install, bool allowUnsafeDirectory = false)
    {
        try
        {
            if (install)
            {
                string exe = Environment.ProcessPath
                             ?? throw new InvalidOperationException("Could not determine HERO's own path.");
                string directory = Path.GetDirectoryName(exe)!;

                // A LocalSystem service is only as trustworthy as the file Windows runs. If a
                // standard user can rewrite that file, they can execute anything they like as
                // SYSTEM at the next start — which outranks every permission this build tightens
                // on %ProgramData%\HERO. Registering the service from a build-output folder does
                // exactly that, and nothing previously stopped it: ServiceControl.Install checked
                // only File.Exists.
                //
                // Refused rather than warned. A warning printed to a log by a windowless elevated
                // child is not a decision anyone makes; it is a decision nobody sees. The refusal
                // costs nothing legitimate, because the supported install copies HERO into
                // %ProgramFiles% first and registers it from there.
                //
                // The override exists because "never" is the wrong answer for someone knowingly
                // testing a development build, and because a check that cannot be bypassed gets
                // deleted by the next person in a hurry. It is explicit, it is recorded, and it
                // does not hide.
                bool allowUnsafe = allowUnsafeDirectory;
                string? unsafeInstallReason = null;
                if (Core.Elevation.DirectoryWritableByNonAdministrators(directory, out string why))
                {
                    if (!allowUnsafe)
                    {
                        Service.ServiceLog.Write(
                            $"REFUSED to install the guardian service from {directory}: {why}. " +
                            "A service running as LocalSystem from a directory a standard user can " +
                            "modify lets that user run code as SYSTEM. Install HERO under " +
                            $"%ProgramFiles% and register it from there, or pass {UnsafeInstallDirSwitch} " +
                            "to accept this knowingly.");
                        return 2;
                    }

                    Service.ServiceLog.Write(
                        $"WARNING: installing the guardian service from {directory}, where {why}. " +
                        $"Accepted only because {UnsafeInstallDirSwitch} was passed. A standard user " +
                        "can replace the service binary and run code as SYSTEM.");

                    unsafeInstallReason = why;
                }

                // Order still matters, but the reason has inverted. It used to be "share the
                // directory before the service starts, or migrated files end up owned by SYSTEM and
                // unwritable by the app that is still the writer". The service IS the writer now,
                // so the directory is CLOSED before the service starts, and every file the service
                // then creates or migrates inherits that closed ACL rather than a loose one which
                // would have to be corrected afterwards.
                //
                // MigrateFromLegacy uses File.Copy, and a copy takes the destination directory's
                // ACL rather than the source file's — so legacy state carries none of its old
                // per-user access across.
                HeroPaths.EnsureCreated();
                HeroPaths.LockDownStateDirectory();

                Service.ServiceControl.Install(exe, autoStart: true);
                Service.SelfIntegrity.Record(directory, unsafeInstallReason);
                Service.ServiceControl.Start();
                Service.ServiceLog.Write("Service installed and started.");
            }
            else
            {
                Service.ServiceControl.Uninstall();
                Service.ServiceLog.Write("Service removed.");
            }

            return 0;
        }
        catch (Exception ex)
        {
            Service.ServiceLog.Write($"Service {(install ? "install" : "uninstall")} failed: {ex.Message}");
            return 1;
        }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        // Service modes run before everything: before the mutex, before elevation parsing, before
        // any window exists. The service control manager gives a service roughly 30 seconds to
        // call StartServiceCtrlDispatcher, and it must happen on this thread.
        //
        // Handled here rather than from a custom entry point because App.xaml is the project's
        // ApplicationDefinition, and demoting it to a Page to get a hand-written Main risks the
        // XAML generator for the sake of a few milliseconds. Blocking inside OnStartup and then
        // shutting down is a pattern this file already relies on for the elevated child below.
        if (TryRunServiceMode(e.Args)) return;

        // The elevated child runs FIRST, before the single-instance mutex and before anything
        // resident starts. An elevated HERO does exactly one job and exits; it must never sit in
        // the tray holding an administrator token, and it must not be turned away by the mutex
        // that the ordinary instance owns.
        if (Core.Elevation.TryParseRequest(e.Args, out var elevatedRequest) && elevatedRequest is not null)
        {
            Environment.ExitCode = Core.ElevatedOperations.Execute(elevatedRequest);
            Shutdown();
            return;
        }

        // Setup, before the single-instance mutex on purpose. It is a different job from running
        // HERO: it must work while an installed copy is already running (that is precisely when
        // someone reinstalls or uninstalls), and it starts no guardian of its own.
        if (e.Args.Any(a => a.Equals(SetupSwitch, StringComparison.OrdinalIgnoreCase)))
        {
            new UI.Views.SetupWindow().Show();
            return;
        }

        bool replacing = e.Args.Any(a => a.Equals(ReplaceSwitch, StringComparison.OrdinalIgnoreCase));

        _instanceMutex = new Mutex(initiallyOwned: true, MutexName, out bool isFirst);

        if (!isFirst && replacing)
        {
            // An elevated copy taking over from the ordinary one. The outgoing instance exits as
            // soon as it has seen this process start, so waiting briefly is expected rather than
            // exceptional. Previously this hit the guard, exited instantly, and the outgoing
            // instance then shut down too — "it restarts and dies".
            try
            {
                isFirst = _instanceMutex.WaitOne(TimeSpan.FromSeconds(20));
            }
            catch (AbandonedMutexException)
            {
                // The outgoing instance died without releasing — killed, or crashed. Windows hands
                // ownership to this waiter anyway and reports it by throwing, so this is SUCCESS,
                // not failure. Treating the exception as an error meant a replacement could never
                // take over from an instance that had crashed, which is exactly when it matters.
                isFirst = true;
            }

            if (!isFirst)
            {
                MessageBox.Show(
                    "The existing copy of HERO did not shut down, so this elevated copy has stopped " +
                    "rather than run a second engine alongside it.",
                    "HERO", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }
        }
        else if (!isFirst)
        {
            // Already running. Ask it to show itself rather than exiting silently, which left the
            // user with no way to reach a window that was hidden in the tray.
            try
            {
                if (EventWaitHandle.TryOpenExisting(ShowRequestName, out var existing))
                {
                    existing.Set();
                    existing.Dispose();
                }
            }
            catch { /* the running instance may be mid-shutdown; nothing useful to do */ }

            Shutdown();
            return;
        }

        StartShowRequestListener();

        base.OnStartup(e);

        HeroPaths.EnsureCreated();

        // The guardian starts here, not from a window. Launching with --tray must monitor
        // exactly as thoroughly as launching with the dashboard open.
        //
        // If the guardian service is answering, this process becomes a VIEW of it rather than a
        // second guardian. Running both would put two engines on one machine, writing two
        // baselines and two writers onto a hash-chained ledger. Falling back to a local engine
        // when the service is absent keeps HERO working on a machine where it was never
        // installed — the dashboard must not require administrator rights to be useful.
        bool serviceAnswering = Service.Ipc.GuardianClient.PingAsync()
                                    .GetAwaiter().GetResult() is not null;

        if (serviceAnswering)
        {
            Guardian.GuardianService.Current.StartRemote();
        }
        else
        {
            // The local fallback is only honest while this process can actually persist what it
            // observes. Since the state directory was closed to the signed-in user, there is a
            // third case that did not exist before: HERO is INSTALLED, so the directory is locked,
            // but the service is not answering — stopped, crashed, or still starting.
            //
            // Starting an in-process guardian there would produce a security tool that watches
            // attentively and records nothing, because every write it makes is swallowed by the
            // catch around it. It would look like it was working. That is the worst of the three
            // possible behaviours, so the engine still runs — live process, connection and
            // persistence views are genuinely useful — but the app says plainly that nothing is
            // being written down, rather than implying a record exists.
            Guardian.GuardianService.Current.PersistenceBlocked = !HeroPaths.CanPersistState();
            Guardian.GuardianService.Current.Start();

            if (Guardian.GuardianService.Current.PersistenceBlocked)
                Log("Guardian started WITHOUT persistence: the state directory is not writable by " +
                    "this user and the guardian service is not answering.");
        }

        _shell = CreateShell();
        _tray = new TrayIcon(
            onOpen: ShowShell,
            onExit: () => { _tray?.Dispose(); ExitApplication(); });

        // Launched with --tray (i.e. from the Windows startup entry), HERO starts silently
        // in the tray. Launched by hand, it shows the dashboard.
        bool silent = e.Args.Any(a => a.Equals("--tray", StringComparison.OrdinalIgnoreCase));
        if (!silent) ShowShell();
    }

    /// <summary>
    /// Builds the shell and, crucially, forgets it again once it is closed.
    ///
    /// WPF throws "Cannot set Visibility or call Show ... after a Window has closed" if Show() is
    /// called on a closed window, and a null-coalescing assignment does not help because the field
    /// is still non-null — it just points at a destroyed window. Clearing the reference in Closed
    /// is what makes the next tray click build a fresh one instead of crashing.
    /// </summary>
    private MainWindow CreateShell()
    {
        var shell = new MainWindow();
        shell.Closed += (_, _) => _shell = null;
        return shell;
    }

    private void ShowShell()
    {
        if (IsShuttingDown) return;

        _shell ??= CreateShell();
        try
        {
            _shell.Show();
        }
        catch (InvalidOperationException)
        {
            // The window was closed between the null check and the call. Rebuild once rather than
            // letting the tray's Open command surface a .NET crash dialog to the user.
            _shell = CreateShell();
            _shell.Show();
        }

        if (_shell.WindowState == WindowState.Minimized) _shell.WindowState = WindowState.Normal;
        _shell.Activate();
        _shell.Topmost = true;
        _shell.Topmost = false;
    }

    /// <summary>
    /// Waits for a second launch to ask this instance to surface its window.
    /// Runs on a background thread and marshals to the dispatcher, because the waiting thread
    /// must not be the UI one.
    /// </summary>
    private void StartShowRequestListener()
    {
        try
        {
            _showRequest = new EventWaitHandle(false, EventResetMode.AutoReset, ShowRequestName);
            _showListener = new CancellationTokenSource();
            var token = _showListener.Token;

            _ = Task.Run(() =>
            {
                while (!token.IsCancellationRequested)
                {
                    if (!_showRequest.WaitOne(TimeSpan.FromSeconds(1))) continue;
                    if (token.IsCancellationRequested) return;
                    Dispatcher.BeginInvoke(ShowShell);
                }
            }, token);
        }
        catch { /* a missing handle only costs the second-launch convenience */ }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        IsShuttingDown = true;

        // First, and unconditionally: nothing below may delay handing over the instance lock.
        ReleaseInstanceLock();

        _showListener?.Cancel();
        _showRequest?.Dispose();
        _tray?.Dispose();

        // Shutting the guardian down must not be able to hang the process.
        //
        // This previously read DisposeAsync().AsTask().GetAwaiter().GetResult() on the UI thread,
        // which DEADLOCKED: the async chain's continuations resume on the dispatcher, and the
        // dispatcher was blocked waiting for them. The visible symptom was HERO staying alive as
        // an invisible process holding the single-instance mutex, so "Restart as administrator"
        // reported that the existing copy had not shut down, and no new copy could start.
        //
        // Run it off the UI thread and bound the wait: an engine that will not stop cleanly is not
        // a reason to leave a process behind.
        try
        {
            var teardown = Task.Run(async () =>
                await Guardian.GuardianService.Current.DisposeAsync().ConfigureAwait(false));

            if (!teardown.Wait(TimeSpan.FromSeconds(5)))
            {
                // The baseline saves itself on its own cadence, so an abandoned teardown costs at
                // most the last few observations.
                Log("Guardian teardown did not finish within 5s; exiting anyway.");
            }
        }
        catch (Exception ex)
        {
            Log($"Guardian teardown failed: {ex.GetType().Name}: {ex.Message}");
        }

        _instanceMutex?.Dispose();
        base.OnExit(e);
    }

    /// <summary>
    /// App-level diagnostics. Per-user, not in the guardian's state directory: this runs as the
    /// signed-in user, and %ProgramData%\HERO is closed to that user. It also no longer calls
    /// EnsureCreated — creating the guardian's directory tree was never this method's job, and
    /// after the lockdown it would be a denied call on every log line.
    /// </summary>
    private static void Log(string message)
        => HeroPaths.WriteUserLog("app.log",
            $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}");
}
