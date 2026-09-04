using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Hero.Service;

/// <summary>
/// A handle from OpenSCManager / OpenService / CreateService. All three are closed by
/// CloseServiceHandle, not CloseHandle, which is why they cannot use the usual safe handle types.
/// </summary>
internal sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeServiceHandle() : base(ownsHandle: true) { }

    protected override bool ReleaseHandle() => Native.CloseServiceHandle(handle);
}

/// <summary>
/// Service control manager interop.
///
/// These live here rather than in <c>Hero.Interop.Native</c> because they are the only P/Invokes
/// in the codebase that the guardian never calls at runtime: they run once at install time and
/// once at service start. Keeping them separate keeps the hot interop surface small.
/// </summary>
internal static class Native
{
    private const string Advapi = "advapi32.dll";

    // ---- SCM access rights
    internal const int SC_MANAGER_CONNECT = 0x0001;
    internal const int SC_MANAGER_CREATE_SERVICE = 0x0002;

    // ---- service access rights
    internal const int SERVICE_QUERY_CONFIG = 0x0001;
    internal const int SERVICE_QUERY_STATUS = 0x0004;
    internal const int SERVICE_START = 0x0010;
    internal const int SERVICE_STOP = 0x0020;
    internal const int SERVICE_ALL_ACCESS = 0xF01FF;

    // ---- service type and start type
    internal const int SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    internal const int SERVICE_AUTO_START = 0x00000002;
    internal const int SERVICE_DEMAND_START = 0x00000003;
    internal const int SERVICE_ERROR_NORMAL = 0x00000001;

    // ---- ChangeServiceConfig2 info levels
    internal const int SERVICE_CONFIG_DESCRIPTION = 1;
    internal const int SERVICE_CONFIG_FAILURE_ACTIONS = 2;
    internal const int SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4;
    internal const int SERVICE_CONFIG_SERVICE_SID_INFO = 5;

    internal const int SC_ACTION_RESTART = 1;
    internal const int SERVICE_SID_TYPE_UNRESTRICTED = 1;

    // ---- control codes and states
    internal const int SERVICE_CONTROL_STOP = 0x00000001;
    internal const int SERVICE_CONTROL_SHUTDOWN = 0x00000005;

    internal const int SERVICE_STOPPED = 0x00000001;
    internal const int SERVICE_START_PENDING = 0x00000002;
    internal const int SERVICE_STOP_PENDING = 0x00000003;
    internal const int SERVICE_RUNNING = 0x00000004;

    internal const int SERVICE_ACCEPT_STOP = 0x00000001;
    internal const int SERVICE_ACCEPT_SHUTDOWN = 0x00000004;

    internal const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
    internal const int ERROR_SERVICE_NOT_ACTIVE = 1062;

    internal const int DACL_SECURITY_INFORMATION = 0x00000004;
    internal const int SDDL_REVISION_1 = 1;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS
    {
        internal int dwServiceType;
        internal int dwCurrentState;
        internal int dwControlsAccepted;
        internal int dwWin32ExitCode;
        internal int dwServiceSpecificExitCode;
        internal int dwCheckPoint;
        internal int dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SERVICE_DESCRIPTION
    {
        [MarshalAs(UnmanagedType.LPWStr)] internal string? lpDescription;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SC_ACTION
    {
        internal int Type;
        internal int Delay;      // milliseconds
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SERVICE_FAILURE_ACTIONS
    {
        internal int dwResetPeriod;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? lpRebootMsg;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? lpCommand;
        internal int cActions;
        internal IntPtr lpsaActions;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_FAILURE_ACTIONS_FLAG
    {
        [MarshalAs(UnmanagedType.Bool)] internal bool fFailureActionsOnNonCrashFailures;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_SID_INFO
    {
        internal int dwServiceSidType;
    }

    /// <summary>One row of the dispatch table handed to StartServiceCtrlDispatcher.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SERVICE_TABLE_ENTRY
    {
        [MarshalAs(UnmanagedType.LPWStr)] internal string? lpServiceName;
        internal IntPtr lpServiceProc;
    }

    internal delegate void ServiceMain(int argc, IntPtr argv);
    internal delegate int HandlerEx(int control, int eventType, IntPtr eventData, IntPtr context);

    // ---- manager and service handles

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeServiceHandle OpenSCManagerW(string? machine, string? database, int access);

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeServiceHandle OpenServiceW(SafeServiceHandle scm, string name, int access);

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeServiceHandle CreateServiceW(
        SafeServiceHandle scm, string name, string displayName, int access,
        int serviceType, int startType, int errorControl, string binaryPath,
        string? loadOrderGroup, IntPtr tagId, string? dependencies,
        string? account, string? password);

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ChangeServiceConfigW(
        SafeServiceHandle service, int serviceType, int startType, int errorControl,
        string? binaryPath, string? loadOrderGroup, IntPtr tagId, string? dependencies,
        string? account, string? password, string? displayName);

    [DllImport(Advapi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport(Advapi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteService(SafeServiceHandle service);

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool StartServiceW(SafeServiceHandle service, int argc, IntPtr argv);

    [DllImport(Advapi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ControlService(SafeServiceHandle service, int control, ref SERVICE_STATUS status);

    [DllImport(Advapi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceStatus(SafeServiceHandle service, ref SERVICE_STATUS status);

    // ---- ChangeServiceConfig2 overloads, one per payload shape

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ChangeServiceConfig2W")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ChangeServiceConfig2W(SafeServiceHandle service, int level, ref SERVICE_DESCRIPTION info);

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ChangeServiceConfig2W")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ChangeServiceConfig2W(SafeServiceHandle service, int level, ref SERVICE_FAILURE_ACTIONS info);

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ChangeServiceConfig2W")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ChangeServiceConfig2W(SafeServiceHandle service, int level, ref SERVICE_FAILURE_ACTIONS_FLAG info);

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ChangeServiceConfig2W")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ChangeServiceConfig2W(SafeServiceHandle service, int level, ref SERVICE_SID_INFO info);

    // ---- security descriptor

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl, int revision, out IntPtr securityDescriptor, out int size);

    [DllImport(Advapi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetServiceObjectSecurity(
        SafeServiceHandle service, int securityInformation, IntPtr securityDescriptor);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr LocalFree(IntPtr mem);

    // ---- the service side of the conversation

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool StartServiceCtrlDispatcherW([In] SERVICE_TABLE_ENTRY[] table);

    [DllImport(Advapi, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr RegisterServiceCtrlHandlerExW(string name, HandlerEx handler, IntPtr context);

    [DllImport(Advapi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetServiceStatus(IntPtr statusHandle, ref SERVICE_STATUS status);
}
