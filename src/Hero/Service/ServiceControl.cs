using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Hero.Service;

/// <summary>
/// Installs, hardens, queries and removes the HERO guardian service.
///
/// WHY A SERVICE AT ALL
///
/// Measured on this machine: HERO as a tray application was terminated by a plain unelevated
/// <c>Stop-Process</c>. Defender's engine, asked the same question, answered "Access is denied"
/// because <c>WinDefend</c> runs at <c>PROTECTION_LEVEL: ANTIMALWARE LIGHT</c> — a Protected
/// Process Light. PPL is not available to us: it requires a binary signed with a Microsoft-issued
/// anti-malware certificate and an ELAM driver, both gated behind Microsoft Virus Initiative
/// membership. So is a kernel driver that strips PROCESS_TERMINATE via ObRegisterCallbacks.
///
/// What IS reachable without any certificate is this: run the guardian as a LocalSystem service.
/// That buys three concrete things, and it is worth being precise about which:
///
///   1. A non-elevated process cannot stop the service. The SCM enforces the service DACL, and
///      the DACL written below grants ordinary users query rights and nothing else.
///   2. A non-elevated process cannot open the LocalSystem process for termination, because it
///      does not hold a token that passes the process's default DACL.
///   3. If something with sufficient privilege DOES kill it, the SCM restarts it — see
///      <see cref="ConfigureRecovery"/>, where the non-crash-failure flag is the whole trick.
///
/// What it does NOT buy: protection from an attacker who already holds Administrator or SYSTEM.
/// Such an attacker can stop the service, rewrite its binary, or delete it. There is no user-mode
/// defence against that on Windows and claiming otherwise would be a lie. Against that adversary
/// HERO's answer is evidence, not resistance: the hash-chained ledger and the self-integrity check
/// make tampering visible after the fact.
/// </summary>
internal static class ServiceControl
{
    /// <summary>
    /// Kept in <see cref="Core.StartupRegistration"/> with the other names HERO answers to, so
    /// that the persistence scanner's self-recognition and the installer cannot drift apart. They
    /// did drift once: HERO shipped a service its own Threats page then reported as a threat,
    /// complete with a button offering to quarantine it.
    /// </summary>
    internal const string ServiceName = Core.StartupRegistration.ServiceName;

    internal const string DisplayName = "HERO Guardian";

    private const string Description =
        "Watches this machine for remote-access tools, unexpected persistence and unusual outbound " +
        "connections. Every action it takes is recorded and reversible. Part of HERO.";

    /// <summary>
    /// The service's own access control list, in SDDL.
    ///
    ///   SY (LocalSystem)     — query, start, stop, pause, interrogate. Not DELETE or WRITE_DAC:
    ///                          the service has no business rewriting its own permissions.
    ///   BA (Administrators)  — everything, including delete. An administrator must be able to
    ///                          uninstall HERO without a fight. A service that cannot be removed
    ///                          by its own machine's administrator is behaving like malware, and
    ///                          locking them out would be theatre anyway: an administrator can
    ///                          take ownership of the object and rewrite this ACL regardless.
    ///   IU (Interactive)     — query and interrogate only. No SERVICE_START, no SERVICE_STOP,
    ///   SU (Service)           no SERVICE_CHANGE_CONFIG.
    ///
    /// Written explicitly rather than left to the SCM default, because the default varies with
    /// how the service was created and can include looser ACEs for Authenticated Users.
    /// </summary>
    private const string HardenedSddl =
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
        "(A;;CCLCSWLOCRRC;;;IU)" +
        "(A;;CCLCSWLOCRRC;;;SU)";

    // ------------------------------------------------------------------ install

    /// <summary>
    /// Creates the service, or brings an existing one back into line. Requires elevation; the
    /// caller is expected to have relaunched itself as administrator already.
    /// </summary>
    /// <param name="exePath">Full path to the installed HERO.exe.</param>
    internal static void Install(string exePath, bool autoStart)
    {
        if (!File.Exists(exePath))
            throw new FileNotFoundException("HERO.exe was not found at the install path.", exePath);

        // The quotes matter: without them a path containing a space is parsed by the SCM as an
        // executable plus arguments, which is the classic unquoted-service-path weakness. HERO
        // flags that pattern on other people's services, so it will not ship it in its own.
        string binPath = $"\"{exePath}\" {ServiceSwitch}";

        using var scm = OpenManager(Native.SC_MANAGER_CONNECT | Native.SC_MANAGER_CREATE_SERVICE);
        using var existing = OpenService(scm, Native.SERVICE_ALL_ACCESS, throwIfMissing: false);

        SafeServiceHandle service;
        if (!existing.IsInvalid)
        {
            // Repoint an existing registration rather than refusing. This is what heals the
            // service after HERO is reinstalled to a different directory.
            if (!Native.ChangeServiceConfigW(
                    existing, Native.SERVICE_WIN32_OWN_PROCESS,
                    autoStart ? Native.SERVICE_AUTO_START : Native.SERVICE_DEMAND_START,
                    Native.SERVICE_ERROR_NORMAL, binPath,
                    null, IntPtr.Zero, null, null, null, DisplayName))
                throw Fail("Could not update the existing HERO service");

            service = existing;
        }
        else
        {
            var created = Native.CreateServiceW(
                scm, ServiceName, DisplayName, Native.SERVICE_ALL_ACCESS,
                Native.SERVICE_WIN32_OWN_PROCESS,
                autoStart ? Native.SERVICE_AUTO_START : Native.SERVICE_DEMAND_START,
                Native.SERVICE_ERROR_NORMAL, binPath,
                null, IntPtr.Zero, null,
                // LocalSystem. Not a virtual service account, because the guardian reads other
                // processes' images and the Security event log, which a lesser account cannot do.
                null, null);

            if (created.IsInvalid) throw Fail("Could not create the HERO service");
            service = created;
        }

        using (service)
        {
            SetDescription(service);
            ConfigureRecovery(service);
            ConfigureSid(service);
            ApplyHardenedAcl(service);
        }
    }

    /// <summary>The argument that tells HERO.exe it has been launched by the SCM.</summary>
    internal const string ServiceSwitch = "--service";

    // ------------------------------------------------------------------ hardening

    /// <summary>
    /// Restart-on-failure, including the case that actually matters.
    ///
    /// By default the SCM treats a process that exits with a non-zero code — which is what
    /// TerminateProcess produces — as an ordinary stop, NOT a failure, so recovery actions never
    /// fire. <c>SERVICE_CONFIG_FAILURE_ACTIONS_FLAG</c> with the flag set is what makes the SCM
    /// treat "the process died without telling me it was stopping" as a failure. Without this one
    /// call the whole restart story is decorative: kill the service and it simply stays dead.
    ///
    /// Three restarts with a short delay, and the failure count resets after a day. The third
    /// action is deliberately another restart rather than a reboot or a command: a guardian that
    /// reboots the machine because it crashed three times is worse than the crash.
    /// </summary>
    private static void ConfigureRecovery(SafeServiceHandle service)
    {
        var actions = new Native.SC_ACTION[]
        {
            new() { Type = Native.SC_ACTION_RESTART, Delay = 1000 },
            new() { Type = Native.SC_ACTION_RESTART, Delay = 5000 },
            new() { Type = Native.SC_ACTION_RESTART, Delay = 15000 },
        };

        int one = Marshal.SizeOf<Native.SC_ACTION>();
        IntPtr buffer = Marshal.AllocHGlobal(one * actions.Length);
        try
        {
            for (int i = 0; i < actions.Length; i++)
                Marshal.StructureToPtr(actions[i], buffer + i * one, false);

            var failure = new Native.SERVICE_FAILURE_ACTIONS
            {
                dwResetPeriod = 86400,          // a day of good behaviour clears the count
                lpRebootMsg = null,
                lpCommand = null,
                cActions = actions.Length,
                lpsaActions = buffer,
            };

            if (!Native.ChangeServiceConfig2W(service, Native.SERVICE_CONFIG_FAILURE_ACTIONS, ref failure))
                throw Fail("Could not set the service recovery actions");
        }
        finally { Marshal.FreeHGlobal(buffer); }

        var flag = new Native.SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures = true };
        if (!Native.ChangeServiceConfig2W(service, Native.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, ref flag))
            throw Fail("Could not enable recovery for non-crash failures");
    }

    /// <summary>
    /// Gives the service its own SID (<c>NT SERVICE\HeroGuardian</c>).
    ///
    /// This is what lets HERO's own files and registry keys be ACL'd to the service specifically
    /// rather than to LocalSystem generally — LocalSystem is shared by most of the operating
    /// system, so an ACE granting it access grants half the machine access.
    /// </summary>
    private static void ConfigureSid(SafeServiceHandle service)
    {
        var sid = new Native.SERVICE_SID_INFO { dwServiceSidType = Native.SERVICE_SID_TYPE_UNRESTRICTED };
        if (!Native.ChangeServiceConfig2W(service, Native.SERVICE_CONFIG_SERVICE_SID_INFO, ref sid))
            throw Fail("Could not set the service SID type");
    }

    private static void SetDescription(SafeServiceHandle service)
    {
        var description = new Native.SERVICE_DESCRIPTION { lpDescription = Description };
        if (!Native.ChangeServiceConfig2W(service, Native.SERVICE_CONFIG_DESCRIPTION, ref description))
            throw Fail("Could not set the service description");
    }

    private static void ApplyHardenedAcl(SafeServiceHandle service)
    {
        if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                HardenedSddl, Native.SDDL_REVISION_1, out IntPtr sd, out _))
            throw Fail("Could not build the service security descriptor");

        try
        {
            if (!Native.SetServiceObjectSecurity(service, Native.DACL_SECURITY_INFORMATION, sd))
                throw Fail("Could not apply the service access control list");
        }
        finally { Native.LocalFree(sd); }
    }

    // ------------------------------------------------------------------ lifecycle

    internal static void Uninstall()
    {
        using var scm = OpenManager(Native.SC_MANAGER_CONNECT);
        using var service = OpenService(scm, Native.SERVICE_ALL_ACCESS, throwIfMissing: false);
        if (service.IsInvalid) return;    // nothing installed; that is a success

        try { Stop(); } catch { /* stopping is best-effort; removal still proceeds */ }

        if (!Native.DeleteService(service)) throw Fail("Could not remove the HERO service");
    }

    internal static void Start()
    {
        using var scm = OpenManager(Native.SC_MANAGER_CONNECT);
        using var service = OpenService(scm, Native.SERVICE_START | Native.SERVICE_QUERY_STATUS);
        if (!Native.StartServiceW(service, 0, IntPtr.Zero))
        {
            int err = Marshal.GetLastWin32Error();
            if (err != Native.ERROR_SERVICE_ALREADY_RUNNING)
                throw new Win32Exception(err, "Could not start the HERO service.");
        }
    }

    internal static void Stop()
    {
        using var scm = OpenManager(Native.SC_MANAGER_CONNECT);
        using var service = OpenService(scm, Native.SERVICE_STOP | Native.SERVICE_QUERY_STATUS);
        var status = new Native.SERVICE_STATUS();
        if (!Native.ControlService(service, Native.SERVICE_CONTROL_STOP, ref status))
        {
            int err = Marshal.GetLastWin32Error();
            if (err != Native.ERROR_SERVICE_NOT_ACTIVE)
                throw new Win32Exception(err, "Could not stop the HERO service.");
        }
    }

    /// <summary>Installed state and current run state, for the Settings page to report honestly.</summary>
    internal static ServiceSnapshot Query()
    {
        try
        {
            using var scm = OpenManager(Native.SC_MANAGER_CONNECT);
            using var service = OpenService(scm, Native.SERVICE_QUERY_STATUS | Native.SERVICE_QUERY_CONFIG,
                                            throwIfMissing: false);
            if (service.IsInvalid) return new ServiceSnapshot(false, false, "Not installed.");

            var status = new Native.SERVICE_STATUS();
            if (!Native.QueryServiceStatus(service, ref status))
                return new ServiceSnapshot(true, false, "Installed, but its state could not be read.");

            bool running = status.dwCurrentState == Native.SERVICE_RUNNING;
            return new ServiceSnapshot(true, running,
                running ? "Running as LocalSystem." : $"Installed but not running (state {status.dwCurrentState}).");
        }
        catch (Exception ex)
        {
            return new ServiceSnapshot(false, false, "Could not reach the service manager: " + ex.Message);
        }
    }

    // ------------------------------------------------------------------ plumbing

    private static SafeServiceHandle OpenManager(int access)
    {
        var scm = Native.OpenSCManagerW(null, null, access);
        if (scm.IsInvalid) throw Fail("Could not open the service control manager");
        return scm;
    }

    private static SafeServiceHandle OpenService(SafeServiceHandle scm, int access, bool throwIfMissing = true)
    {
        var service = Native.OpenServiceW(scm, ServiceName, access);
        if (service.IsInvalid && throwIfMissing) throw Fail("Could not open the HERO service");
        return service;
    }

    private static Win32Exception Fail(string what)
    {
        int err = Marshal.GetLastWin32Error();
        return new Win32Exception(err, $"{what}: {new Win32Exception(err).Message}");
    }
}

internal readonly record struct ServiceSnapshot(bool Installed, bool Running, string Detail);
