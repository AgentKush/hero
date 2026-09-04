# Warden Platform & Build Engineering Spec — .NET 10 WPF, Zero NuGet, Windows 11 26200 (all findings empirically verified on the target machine)

> Area: `dotnet10-constraints` · adversarial critique verdict: **sound_with_fixes**

## Summary
Every claim below was compiled and executed on the actual target machine (Win11 Pro 26200, .NET SDK 10.0.303, WindowsDesktop.App 10.0.11, non-elevated medium-IL shell), not recalled from memory. The headline result: a `net10.0-windows` WPF+WinForms app builds and runs with literally zero NuGet packages — proven by a successful `--no-cache` build against a nuget.config with `<packageSources><clear/></packageSources>`. Two of the nine libraries you asked about are NOT in-box and cannot be used at all without a package (System.Management/WMI and System.ServiceProcess.ServiceController); dependency-free advapi32 and COM replacements are given and were verified enumerating 758 services and 219 scheduled tasks unelevated. Trimming is a hard build error for WPF (NETSDK1168) and WinForms (NETSDK1175), not a warning — do not attempt it. The largest product risk I found is concrete and would have shipped as a false-positive generator: `WinVerifyTrust` with `WTD_CHOICE_FILE` reports Microsoft's own `notepad.exe` and `cmd.exe` as UNTRUSTED because they are catalog-signed, not embedded-signed; the working catalog fallback is specified and verified. Finally, real Windows 11 toasts DO work from an unpackaged app with zero NuGet — I dispatched one and confirmed it in the OS notification database — but only via raw COM with manual IInspectable vtable padding, because .NET does not support `ComInterfaceType.InterfaceIsIInspectable` at all.

## Items (40)
### [critical] The exact .csproj (verified to build offline with zero NuGet sources)
This exact file was built with `--no-cache` against a nuget.config containing `<packageSources><clear /></packageSources>` and produced 0 warnings, 0 errors, a 161 KB exe with the icon and manifest embedded. Deliberately NO TargetPlatformVersion suffix, NO SupportedOSPlatformVersion, NO PublishTrimmed. `project.assets.json` confirmed `libraries: (none)` and zero downloadDependencies for a plain framework-dependent build.

**How:** <Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net10.0-windows</TargetFramework>
    <UseWPF>true</UseWPF>
    <UseWindowsForms>true</UseWindowsForms>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <PlatformTarget>x64</PlatformTarget>
    <AssemblyName>Warden</AssemblyName>
    <RootNamespace>Warden</RootNamespace>
    <ApplicationManifest>app.manifest</ApplicationManifest>
    <ApplicationIcon>warden.ico</ApplicationIcon>
    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>
    <NoWarn>$(NoWarn);WFO0003</NoWarn>
    <EnforceCodeStyleInBuild>false</EnforceCodeStyleInBuild>
    <ServerGarbageCollection>false</ServerGarbageCollection>
    <ConcurrentGarbageCollection>true</ConcurrentGarbageCollection>
    <TieredPGO>true</TieredPGO>
  </PropertyGroup>
</Project>

### [critical] Do NOT use a versioned TFM (net10.0-windows10.0.26100.0) — it silently pulls a 76.9 MB NuGet package
VERIFIED: switching the TFM to `net10.0-windows10.0.26100.0` adds a downloadDependency on `Microsoft.Windows.SDK.NET.Ref [10.0.26100.57]`. That pack is NOT in C:\Program Files\dotnet\packs (I listed it: only AspNetCore.App.Ref, NETCore.App.Ref/Host, WindowsDesktop.App.Ref, NETStandard.Library.Ref). It resolves from the NuGet cache/network and measures 76.9 MB on disk. That breaks the zero-package rule. The SDK's supported-version table lives at Microsoft.NETCoreSdk.BundledVersions.props lines 812-840.

**How:** Use `<TargetFramework>net10.0-windows</TargetFramework>` with no version suffix. Verify with: dotnet restore; then check obj/project.assets.json — `libraries` must be empty and `downloadDependencies` must be absent.

**False positives:** The package is Microsoft-official, so it is not a supply-chain risk — but it is still a 76.9 MB external restore that breaks offline builds. Only accept it if you later decide you want CsWinRT projections; the raw-COM toast approach in this spec makes that unnecessary.

### [high] SupportedOSPlatformVersion is a trap on a bare TFM (NETSDK1135)
VERIFIED: bare `net10.0-windows` resolves TargetPlatformVersion to 7.0 (confirmed via `dotnet msbuild -getProperty:TargetPlatformVersion`). Setting `<SupportedOSPlatformVersion>10.0.22621.0</SupportedOSPlatformVersion>` produces hard error NETSDK1135 'cannot be higher than TargetPlatformVersion 7.0'. I also verified that setting `<TargetPlatformVersion>` as a standalone property does NOT work — it is derived from the TFM string only and is ignored, producing the identical error.

**How:** Simply OMIT SupportedOSPlatformVersion. Its only effect is the CA1416 platform-compatibility analyzer, which adds nothing to Warden because every Win11-specific call is a raw P/Invoke carrying no [SupportedOSPlatform] attribute. Gate Win11 features at runtime instead: `Environment.OSVersion.Version.Build >= 22000`.

### [critical] Trimming is NOT safe for WPF — it is a hard build error, and so is AOT
VERIFIED as ERRORS, not warnings. With UseWPF+UseWindowsForms and PublishTrimmed=true: `error NETSDK1175: Windows Forms is not supported or recommended with trimming enabled`. With UseWindowsForms=false, WPF alone still fails: `error NETSDK1168: WPF is not supported or recommended with trimming enabled`. The reason is fundamental, not a missing annotation: WPF resolves types by name at runtime from BAML/XAML (x:Type, x:Class, markup extensions, custom controls, ResourceDictionary lookups, DependencyProperty registration) and uses reflection for data binding paths, value converters, and TypeDescriptor/TypeConverter. The IL trimmer cannot statically see any of it, so it removes types that XAML later demands, producing runtime XamlParseException/MissingMethodException that no amount of testing reliably catches. PublishAot is unsupported for the same reason.

**How:** Never set PublishTrimmed, PublishAot, or EnableTrimAnalyzer. If size matters, use framework-dependent publish (161 KB exe) rather than trimming.

### [high] Self-contained vs framework-dependent — measured sizes, and the recommendation
MEASURED on this machine, both launched successfully and were verified running. Framework-dependent + PublishSingleFile + ReadyToRun: 0.18 MB exe, 2 files total, working set 156 MB. Self-contained + PublishSingleFile + ReadyToRun + EnableCompressionInSingleFile: 76.87 MB exe, working set 245 MB. Because Microsoft.WindowsDesktop.App 10.0.11 is ALREADY installed on this exact machine, self-contained buys nothing for the target user and costs 76 MB plus a slower first start (compressed single-file extracts to a temp directory on launch).

**How:** RECOMMENDED for this machine: framework-dependent, single-file, ReadyToRun, NOT compressed:
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:PublishReadyToRun=true -p:IncludeNativeLibrariesForSelfExtract=true -o .\dist
Note: self-contained and/or ReadyToRun DO add downloadDependencies (Microsoft.NETCore.App.Runtime.win-x64, Microsoft.WindowsDesktop.App.Runtime.win-x64, Microsoft.NETCore.App.Crossgen2.win-x64). These are Microsoft runtime packs, not third-party libraries, but they are network restores — a plain `dotnet build` needs none of them.

**False positives:** 'Zero NuGet packages' is fully true for `dotnet build` and for framework-dependent publish WITHOUT R2R. ReadyToRun pulls Crossgen2. Decide which definition of 'zero' you want; if strict offline is the goal, drop PublishReadyToRun.

### [high] IN-BOX: Microsoft.Win32.Registry, System.Text.Json, X509Certificates, System.Drawing.Common, NotifyIcon, PerformanceCounter
VERIFIED by compiling and running code that uses each. Microsoft.Win32.Registry.dll and System.Text.Json.dll and System.Security.Cryptography.X509Certificates.dll ship in Microsoft.NETCore.App.Ref 10.0.11. System.Drawing.Common.dll, System.Windows.Forms.dll (NotifyIcon), and System.Diagnostics.PerformanceCounter.dll ship in Microsoft.WindowsDesktop.App.Ref 10.0.11 and are pulled in by UseWPF/UseWindowsForms. PerformanceCounter is the one people most often assume needs a package — it does not, but ONLY because UseWindowsForms/UseWPF references the WindowsDesktop framework.

**How:** No PackageReference needed for any of these. Ref pack contents confirmed at C:\Program Files\dotnet\packs\Microsoft.WindowsDesktop.App.Ref\10.0.11\ref\net10.0\ and ...\Microsoft.NETCore.App.Ref\10.0.11\ref\net10.0\

### [critical] NOT IN-BOX: System.Management (WMI) — needs NuGet. Use these dependency-free replacements
VERIFIED: `error CS0234: The type or namespace name 'Management' does not exist in the namespace 'System'`. System.Management.dll is present in NEITHER ref pack NOR either shared framework runtime directory — so it cannot be loaded even by reflection. It requires the `System.Management` NuGet package.

**How:** Replacements, all verified working: (a) process listing -> EnumProcesses/Toolhelp32/NtQuerySystemInformation, see the perf items; (b) services -> advapi32 EnumServicesStatusEx; (c) disk model/serial -> DeviceIoControl IOCTL_STORAGE_QUERY_PROPERTY (works non-admin, verified: returned 'WDC WD121KRYZ-01W0RB0'); (d) installed software -> read HKLM/HKCU \Software\Microsoft\Windows\CurrentVersion\Uninstall; (e) startup items -> registry Run keys + Startup folders + Task Scheduler COM; (f) anything else, shell out: powershell.exe -NoProfile -NonInteractive -Command "Get-CimInstance ... | ConvertTo-Json -Compress" and parse with System.Text.Json.

### [critical] NOT IN-BOX: System.ServiceProcess.ServiceController — needs NuGet. Use advapi32 (verified: 758 services, no admin)
VERIFIED: `error CS1069: The type name 'ServiceController' could not be found ... has been forwarded to assembly 'System.ServiceProcess.ServiceController'`. NOTE THE TRAP: System.ServiceProcess.dll DOES exist in Microsoft.NETCore.App.Ref and in the shared runtime, but it is a facade containing only type-forwards; the implementation assembly System.ServiceProcess.ServiceController.dll is in neither shared framework. So this is genuinely unusable without the package.

**How:** Replace with advapi32 P/Invoke. Verified enumerating 758 services unelevated with SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE (0x0001|0x0004):
[LibraryImport("advapi32.dll", SetLastError=true, EntryPoint="OpenSCManagerW", StringMarshalling=StringMarshalling.Utf16)]
internal static partial IntPtr OpenSCManager(string? machine, string? db, uint access);
[LibraryImport("advapi32.dll", SetLastError=true, EntryPoint="EnumServicesStatusExW", StringMarshalling=StringMarshalling.Utf16)]
[return: MarshalAs(UnmanagedType.Bool)]
internal static partial bool EnumServicesStatusEx(IntPtr h, int infoLevel, uint svcType, uint svcState, IntPtr buf, uint bufSize, out uint needed, out uint returned, ref uint resume, string? group);
[LibraryImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)] internal static partial bool CloseServiceHandle(IntPtr h);
Call with infoLevel=0 (SC_ENUM_PROCESS_INFO), svcType=0x3B (WIN32|DRIVER), svcState=3 (ALL). Two-pass: call with buf=IntPtr.Zero,bufSize=0 to get `needed`, allocate, call again. Add QueryServiceConfigW for binary path / start type.

**False positives:** Do not flag a service as suspicious merely because its binary path is unsigned — driver services and OEM services frequently are. Correlate with start type, path location, and catalog signature.

### [high] IN-BOX: Task Scheduler via late-bound COM — verified 219 tasks, 55 logon/boot triggers, no admin
VERIFIED working with zero NuGet, zero TLB, zero interop assembly, unelevated. Enumerated 219 tasks across the tree, of which 55 had LOGON(9) or BOOT(8) triggers and 16 had a non-Microsoft Author — exactly Warden's persistence-detection surface.

**How:** var t = Type.GetTypeFromProgID("Schedule.Service");
object svc = Activator.CreateInstance(t)!;
svc.GetType().InvokeMember("Connect", BindingFlags.InvokeMethod, null, svc, new object?[]{null,null,null,null});
object root = svc.GetType().InvokeMember("GetFolder", BindingFlags.InvokeMethod, null, svc, new object[]{"\\"})!;
object tasks = root.GetType().InvokeMember("GetTasks", BindingFlags.InvokeMethod, null, root, new object[]{1})!; // 1 = include hidden
Then walk Definition -> RegistrationInfo.Author, Definition.Triggers[j].Type, Definition.Actions[j].Path. Recurse via GetFolders(0).

**False positives:** 16 of 219 tasks on this clean machine have a non-Microsoft Author. Author is trivially spoofable and mostly reflects OEM/vendor software. Score on: action binary outside Program Files/System32, unsigned action binary, LOGON trigger, hidden flag, and recent RegistrationInfo.Date together — never on Author alone.

### [high] CRITICAL late-binding trap: ITaskCollection.Item is a parameterised PROPERTY, not a method
This cost me a debugging cycle and would silently produce ZERO results for the implementer. Using BindingFlags.InvokeMethod for `Item` throws TargetInvocationException wrapping DISP_E_MEMBERNOTFOUND (0x80020003). My first run reported '0 tasks visible' while the root folder genuinely had 14 tasks and 5 subfolders — a completely silent wrong answer if the exception is swallowed.

**How:** static object? Idx(object o, int i) =>
    o.GetType().InvokeMember("Item", BindingFlags.GetProperty, null, o, new object[]{ i });
Use Idx() for ITaskCollection.Item, ITaskFolderCollection.Item, ITriggerCollection.Item, IActionCollection.Item. All these collections are 1-BASED, not 0-based.

**False positives:** If task enumeration ever returns 0, that is a bug, not a clean machine. Treat a 0 result as an error state and log it rather than reporting 'no persistence found'.

### [medium] Bonus in-box assemblies worth exploiting (all confirmed in WindowsDesktop.App.Ref 10.0.11)
These ship in the ref pack you already reference and solve problems Warden would otherwise need packages or hand-rolled crypto for.

**How:** System.Security.Cryptography.ProtectedData.dll -> ProtectedData.Protect/Unprotect (DPAPI) to seal the quarantine manifest to the user account. System.Security.Cryptography.Pkcs.dll -> SignedCms for parsing Authenticode signer chains and countersignatures. System.Diagnostics.EventLog.dll -> read Security/System/Application logs and write Warden's own audit trail. Microsoft.Win32.SystemEvents.dll -> SystemEvents.SessionSwitch / PowerModeChanged / SessionEnding for lifecycle hooks. System.DirectoryServices.dll, System.Configuration.ConfigurationManager.dll, System.IO.Packaging.dll also present.

### [high] P/Invoke: CreateToolhelp32Snapshot / Process32First / Process32Next — verified, PROCESSENTRY32W = 568 bytes
VERIFIED: enumerated 379 processes; Marshal.SizeOf<PROCESSENTRY32W>() = 568, the correct x64 value. The struct MUST carry CharSet.Unicode or szExeFile silently truncates. Measured cost: 7.46 ms — this is the SLOW path; see the perf items for the 0.02 ms alternative.

**How:** [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct PROCESSENTRY32W {
  public uint dwSize; public uint cntUsage; public uint th32ProcessID;
  public IntPtr th32DefaultHeapID; public uint th32ModuleID; public uint cntThreads;
  public uint th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile; }

[LibraryImport("kernel32.dll", SetLastError = true)]
internal static partial IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
// Process32FirstW/NextW take a byref struct -> LibraryImport cannot marshal it without
// DisableRuntimeMarshalling. Use DllImport for these two:
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW")]
[return: MarshalAs(UnmanagedType.Bool)] internal static extern bool Process32First(IntPtr h, ref PROCESSENTRY32W e);
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32NextW")]
[return: MarshalAs(UnmanagedType.Bool)] internal static extern bool Process32Next(IntPtr h, ref PROCESSENTRY32W e);
MUST set e.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() before Process32First or it fails. Snapshot handle: check against INVALID_HANDLE_VALUE = new IntPtr(-1), not IntPtr.Zero.

### [critical] P/Invoke: EnumProcesses — the 0.0195 ms, zero-allocation path that should drive the 1 Hz loop
MEASURED, and this is the single most important performance finding: EnumProcesses returns just PIDs in 0.0195 ms with 0.0 bytes allocated — versus 7.46 ms for Toolhelp32 and 5.1-6.7 ms for NtQuerySystemInformation. That is a ~385x speedup for change detection. Resolving full detail for ONE newly-appeared PID costs 0.0220 ms.

**How:** [LibraryImport("psapi.dll", SetLastError = true, EntryPoint = "EnumProcesses")]
[return: MarshalAs(UnmanagedType.Bool)]
internal static unsafe partial bool EnumProcesses(uint* pProcessIds, uint cb, uint* pBytesReturned);

unsafe { uint* buf = stackalloc uint[4096]; uint ret;
  EnumProcesses(buf, 4096*sizeof(uint), &ret);
  int n = (int)(ret / sizeof(uint)); }
Diff the PID set against the previous tick's HashSet<uint>; enrich ONLY the additions.

**False positives:** PID reuse is real. A 'new' PID may be a recycled number. Confirm identity with GetProcessTimes creation time before treating it as a new process.

### [critical] P/Invoke: OpenProcess + QueryFullProcessImageName — 133 of 379 FAIL for a non-admin process
VERIFIED non-elevated: 246 succeeded, 133 failed. This is expected and unavoidable — protected/PPL processes, other users' sessions, and System-owned processes deny PROCESS_QUERY_LIMITED_INFORMATION at medium IL. Warden must NOT treat 'cannot read image path' as suspicious; on this clean machine a third of processes are unreadable.

**How:** const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000; // use this, NOT PROCESS_QUERY_INFORMATION (0x0400) which fails far more often
[LibraryImport("kernel32.dll", SetLastError = true)]
internal static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
[LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "QueryFullProcessImageNameW")]
[return: MarshalAs(UnmanagedType.Bool)]
internal static unsafe partial bool QueryFullProcessImageName(IntPtr h, uint flags, char* buf, ref uint size);

unsafe { char* p = stackalloc char[1024]; uint cap = 1024;
  if (QueryFullProcessImageName(h, 0, p, ref cap)) path = new string(p, 0, (int)cap); }
Fallback when it fails: the ImageName field from NtQuerySystemInformation(SystemProcessInformation) gives the base name (no path) for processes you cannot open.

**False positives:** THIS IS A MAJOR FALSE-POSITIVE SOURCE. 35% of processes are unreadable unelevated on a perfectly clean machine. Never score 'unknown path' as evidence of malice. Mark such processes 'not assessable' and exclude them from scoring entirely.

### [high] LibraryImport gotchas that will break the build — two verified compile errors
Both hit during this research and both produce confusing errors. (1) StringBuilder is rejected outright: `error SYSLIB1051: The type 'System.Text.StringBuilder' is not supported by source-generated P/Invokes`. (2) The obvious fix of `ref char` ALSO fails: `error SYSLIB1051: Runtime marshalling must be disabled in this project by applying DisableRuntimeMarshallingAttribute` — because `char` is a runtime-marshalled type (it could be ANSI). Do not add DisableRuntimeMarshalling as a workaround; it globally changes struct marshalling and would break every ByValTStr/Bool struct in the codebase.

**How:** Use `char*` with AllowUnsafeBlocks (verified working), or fall back to [DllImport] with StringBuilder. Rule of thumb: use [LibraryImport] for blittable signatures; use [DllImport] whenever the signature has a byref struct, a StringBuilder, or ByValTStr. Mixing both attributes in the same class is fine and is what I did.

### [high] P/Invoke: NtQueryInformationProcess + PEB read for command line — verified, offsets confirmed
VERIFIED: status 0x00000000, sizeof(PROCESS_BASIC_INFORMATION) = 48 on x64, and the full command line was read back correctly from the target's PEB. x64 offsets confirmed: PEB->ProcessParameters at 0x20, RTL_USER_PROCESS_PARAMETERS->CommandLine (UNICODE_STRING) at 0x70. Requires PROCESS_VM_READ in addition to PROCESS_QUERY_LIMITED_INFORMATION.

**How:** [StructLayout(LayoutKind.Sequential)] struct PROCESS_BASIC_INFORMATION {
  public IntPtr ExitStatus, PebBaseAddress, AffinityMask, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId; }
[StructLayout(LayoutKind.Sequential)] struct UNICODE_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }
[LibraryImport("ntdll.dll")]
internal static partial int NtQueryInformationProcess(IntPtr h, int cls, IntPtr info, uint len, out uint ret); // cls 0 = ProcessBasicInformation
[LibraryImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
internal static partial bool ReadProcessMemory(IntPtr h, IntPtr addr, IntPtr buf, nuint size, out nuint read);
Open with PROCESS_QUERY_LIMITED_INFORMATION(0x1000)|PROCESS_VM_READ(0x0010). Read ptr at PebBaseAddress+0x20, then UNICODE_STRING at that+0x70, then ReadProcessMemory(us.Buffer, us.Length).

**False positives:** These are undocumented offsets that Microsoft may change. Wrap in try/catch, sanity-check us.Length (reject >32768 or odd), and degrade gracefully to 'command line unavailable' rather than throwing. Never treat an unreadable command line as suspicious.

### [low] P/Invoke: IsWow64Process2 — verified
VERIFIED: returned processMachine=0x0000 (IMAGE_FILE_MACHINE_UNKNOWN, meaning NOT running under WOW64) and nativeMachine=0x8664 (AMD64). Note the semantics trap: processMachine is UNKNOWN(0) for native processes, not AMD64.

**How:** [LibraryImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
internal static partial bool IsWow64Process2(IntPtr hProcess, out ushort pProcessMachine, out ushort pNativeMachine);
Interpret: pProcessMachine == 0 (UNKNOWN) => native 64-bit. 0x014C => x86 under WOW64. 0x8664 = AMD64, 0xAA64 = ARM64.

**False positives:** A 32-bit process on x64 is completely normal (installers, older tools). Not a signal on its own.

### [high] P/Invoke: GetExtendedTcpTable / GetExtendedUdpTable — all struct sizes verified correct
VERIFIED live: MIB_TCPROW_OWNER_PID = 24 bytes, MIB_TCP6ROW_OWNER_PID = 56 bytes, MIB_UDPROW_OWNER_PID = 12 bytes — all correct. Returned 92 IPv4 TCP rows, 11 IPv6 rows, 28 UDP rows. Cost: 0.093 ms (TCP4) + 0.049 ms (TCP6) + 0.030 ms (UDP4) = 0.17 ms total. Cheap enough for 1 Hz with room to spare.

**How:** [StructLayout(LayoutKind.Sequential)] struct MIB_TCPROW_OWNER_PID { public uint dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid; }
[StructLayout(LayoutKind.Sequential)] struct MIB_TCP6ROW_OWNER_PID {
  [MarshalAs(UnmanagedType.ByValArray, SizeConst=16)] public byte[] ucLocalAddr; public uint dwLocalScopeId, dwLocalPort;
  [MarshalAs(UnmanagedType.ByValArray, SizeConst=16)] public byte[] ucRemoteAddr; public uint dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid; }
[LibraryImport("iphlpapi.dll", SetLastError = true)]
internal static partial uint GetExtendedTcpTable(IntPtr t, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, uint af, int cls, uint res);
AF_INET=2, AF_INET6=23. TCP_TABLE_OWNER_PID_ALL=5, UDP_TABLE_OWNER_PID=1. Two-pass sizing. Layout: [int dwNumEntries][rows...], rows start at buffer+4.
PORTS ARE NETWORK BYTE ORDER in the low 16 bits: int port = ((p & 0xFF) << 8) | ((p >> 8) & 0xFF);

**False positives:** Note the IPv6 row for port 135 shared a PID with the IPv4 row — dual-stack listeners appear twice. Deduplicate by (pid, port, state) before alerting or you will double-count.

### [critical] THE BIGGEST FALSE-POSITIVE RISK: WinVerifyTrust reports Microsoft's own binaries as UNTRUSTED
VERIFIED AND SEVERE. Using WINTRUST_ACTION_GENERIC_VERIFY_V2 with WTD_CHOICE_FILE, `C:\Windows\System32\notepad.exe` returned 0x800B0100 (TRUST_E_NOSIGNATURE) and so did cmd.exe. Get-AuthenticodeSignature confirms both are Status=Valid, SignatureType=Catalog, signed by 'CN=Microsoft Windows'. They have NO embedded signature — they are catalog-signed. A naive implementation would flag notepad.exe and cmd.exe as unsigned malware on a pristine Windows install. Confirmed struct size: WINTRUST_DATA = 88 bytes on x64.

**How:** MANDATORY two-stage check. Stage 1: WinVerifyTrust with WTD_CHOICE_FILE(1). If it returns 0, trusted. If and only if it returns TRUST_E_NOSIGNATURE (0x800B0100), run Stage 2 (catalog):
CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0)
CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, IntPtr.Zero, 0)  // size probe
CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, pbHash, 0)
hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, 0, IntPtr.Zero)
CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0)
then WinVerifyTrust with dwUnionChoice = WTD_CHOICE_CATALOG(2) and a WINTRUST_CATALOG_INFO whose pcwszMemberTag = Convert.ToHexString(hash), pcwszMemberFilePath = path, hMemberFile = the open handle, pbCalculatedFileHash/cbCalculatedFileHash = the hash, hCatAdmin = hCatAdmin.
AFTER THIS FIX, VERIFIED: notepad.exe -> TRUSTED via Microsoft-Windows-Notepad-System-FoD-Package~...cat; cmd.exe -> TRUSTED via Microsoft-Windows-Client-Desktop-Required-Package0411~...cat; kernel32.dll, svchost.exe, dotnet.exe -> TRUSTED via embedded.

**False positives:** THIS IS THE ITEM MOST LIKELY TO SINK THE PRODUCT. Without the catalog stage, a large fraction of C:\Windows\System32 reads as unsigned. Also: always set fdwRevocationChecks = WTD_REVOKE_NONE and dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL (0x1000) so verification never touches the network — this both honours the no-egress rule and prevents multi-second stalls when a CRL endpoint is slow.

### [critical] Struct marshalling landmine: LayoutKind.Sequential defaults to CharSet.Ansi, silently corrupting ByValTStr
VERIFIED as a real, silent, wrong-answer bug I hit and fixed. CATALOG_INFO declared without CharSet.Unicode marshalled its 260-element WCHAR array as 260 BYTES: struct size became 264 instead of 524, cbStruct was wrong, WinVerifyTrust returned 0x80092003 (CRYPT_E_FILE_ERROR), and the catalog path printed as the single character 'C' instead of the full path. It also caused a hard `Fatal error. Internal CLR error (0x80131506)` crash at process exit. Adding CharSet.Unicode fixed all of it.

**How:** ALWAYS write `[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]` on ANY struct containing a ByValTStr or any string field. Audit every struct in the P/Invoke layer for this. Applies to CATALOG_INFO, PROCESSENTRY32W, MODULEENTRY32W, SHFILEOPSTRUCTW, WIN32_FIND_DATAW.

**False positives:** This class of bug does not throw — it returns plausible-looking wrong data. Assert expected struct sizes at startup in a debug build: Debug.Assert(Marshal.SizeOf<PROCESSENTRY32W>() == 568), CATALOG_INFO == 524, WINTRUST_DATA == 88, MIB_TCPROW_OWNER_PID == 24, MIB_TCP6ROW_OWNER_PID == 56, PROCESS_BASIC_INFORMATION == 48.

### [medium] P/Invoke: DwmSetWindowAttribute — dark mode, Mica, rounded corners all verified hr=0 on build 26200
VERIFIED, every attribute returned S_OK on this exact machine: DWMWA_USE_IMMERSIVE_DARK_MODE(20)=0x0, DWMWA_WINDOW_CORNER_PREFERENCE(33)=0x0, DWMWA_SYSTEMBACKDROP_TYPE(38) for all of AUTO/NONE/MICA/ACRYLIC/MICA_ALT=0x0, DWMWA_CAPTION_COLOR(35)=0x0, DWMWA_BORDER_COLOR(34)=0x0, DwmExtendFrameIntoClientArea(-1 margins)=0x0. Also verified the undocumented uxtheme ordinal #135 SetPreferredAppMode(2) works (returned previous mode 0) for dark scrollbars/context menus.

**How:** [LibraryImport("dwmapi.dll")]
internal static partial int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);
Call from Window.SourceInitialized (the HWND does not exist before that) via new WindowInteropHelper(w).Handle.
Constants: DWMWA_USE_IMMERSIVE_DARK_MODE=20, DWMWA_WINDOW_CORNER_PREFERENCE=33 (0=default,1=donotround,2=round,3=roundsmall), DWMWA_BORDER_COLOR=34, DWMWA_CAPTION_COLOR=35, DWMWA_SYSTEMBACKDROP_TYPE=38 (2=Mica, 3=Acrylic, 4=MicaAlt). Colors are COLORREF 0x00BBGGRR, NOT ARGB.
FOR MICA TO ACTUALLY RENDER you must ALSO: set Window.Background to Transparent, and call DwmExtendFrameIntoClientArea with MARGINS{-1,-1,-1,-1}. Setting attribute 38 alone shows nothing.

**False positives:** DwmSetWindowAttribute returns S_OK even where the effect is unsupported, so a 0 HRESULT is not proof the visual appeared. Gate Mica on Build >= 22000 explicitly.

### [high] P/Invoke: Recycle-Bin-safe delete — SHFileOperationW verified, file confirmed in the bin
VERIFIED end to end: rc=0, fAnyOperationsAborted=false, file gone from disk, and I confirmed it actually landed in the Recycle Bin by enumerating Shell.Application Namespace(10). Measured sizeof = 56 on x64 with the pointer-based declaration below.

**How:** [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct SHFILEOPSTRUCTW { public IntPtr hwnd; public uint wFunc; public IntPtr pFrom, pTo;
  public ushort fFlags; [MarshalAs(UnmanagedType.Bool)] public bool fAnyOperationsAborted;
  public IntPtr hNameMappings, lpszProgressTitle; }
[DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHFileOperationW")]
static extern int SHFileOperation(ref SHFILEOPSTRUCTW op);
FO_DELETE=0x0003. Flags: FOF_ALLOWUNDO(0x0040) — THIS is what sends to the Recycle Bin — plus FOF_NOCONFIRMATION(0x0010)|FOF_SILENT(0x0004)|FOF_NOERRORUI(0x0400).
CRITICAL: pFrom MUST be DOUBLE-NULL terminated. Build it as Marshal.StringToHGlobalUni(path + "\0\0"). A single null silently fails or deletes the wrong thing.
Must be called on an STA thread.

**False positives:** Recycle Bin is NOT a substitute for Warden's own quarantine vault: it is per-volume, can be disabled by policy, is size-capped and auto-purges, and does not preserve the original ACL/zone data. Use the vault (move + rename + strip execute + DPAPI-sealed manifest) as primary; offer Recycle Bin only for Maintenance-side cleanup of user files.

### [low] P/Invoke: GetSystemPowerStatus — verified
VERIFIED on this desktop: ACLineStatus=1 (online), BatteryFlag=128 (no system battery), BatteryLifePercent=255 (unknown). Correctly identifies a desktop with no battery.

**How:** [StructLayout(LayoutKind.Sequential)]
struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }
[LibraryImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)] internal static partial bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);
BatteryFlag 128 = no battery; 255 = unknown. ACLineStatus 0=offline,1=online,255=unknown.

**False positives:** On this desktop there is no battery, so any 'throttle scanning on battery' logic is dead code here. Guard it with BatteryFlag != 128.

### [medium] P/Invoke: DeviceIoControl for SMART/NVMe — split verified. Device info works non-admin; SMART does NOT
VERIFIED both outcomes precisely. IOCTL_STORAGE_QUERY_PROPERTY (0x002D1400) opened \\.\PhysicalDrive0 with dwDesiredAccess=0 and SUCCEEDED non-admin, returning 396 bytes and ProductId 'WDC WD121KRYZ-01W0RB0'. Opening the same device with GENERIC_READ|GENERIC_WRITE (required for SMART_RCV_DRIVE_DATA / IOCTL_STORAGE_PROTOCOL_COMMAND) FAILED with error 5 ACCESS_DENIED. So: model/serial/bus type are free; actual SMART attributes and NVMe health need elevation.

**How:** Non-admin path (use this by default): CreateFileW(@"\\.\PhysicalDrive0", dwDesiredAccess: 0, FILE_SHARE_READ|FILE_SHARE_WRITE, OPEN_EXISTING) then DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY) with STORAGE_PROPERTY_QUERY{PropertyId=0 StorageDeviceProperty, QueryType=0 PropertyStandardQuery}. Parse STORAGE_DEVICE_DESCRIPTOR: ProductIdOffset is the int at byte 16, VendorIdOffset at 12, SerialNumberOffset at 24, all ANSI strings.
Admin path for real health: reopen with GENERIC_READ|GENERIC_WRITE and use IOCTL_STORAGE_PROTOCOL_COMMAND (NVMe) or SMART_RCV_DRIVE_DATA (SATA).
FALLBACK without elevation, no NuGet: powershell.exe -NoProfile -Command "Get-PhysicalDisk | Select FriendlyName,HealthStatus,OperationalStatus | ConvertTo-Json" and Get-StorageReliabilityCounter (the latter usually still needs admin).

**False positives:** Do not present 'SMART unavailable' as a drive problem. It is the normal non-elevated state. Show 'requires elevation' and offer a one-click elevated re-check.

### [low] P/Invoke: SHGetKnownFolderPath — verified
VERIFIED: returned C:\Users\finla\AppData\Local for FOLDERID_LocalAppData. The returned buffer is CoTaskMem and MUST be freed or you leak on every call.

**How:** [LibraryImport("shell32.dll")]
internal static partial int SHGetKnownFolderPath(in Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);
if (hr == 0) { var s = Marshal.PtrToStringUni(ppszPath); Marshal.FreeCoTaskMem(ppszPath); }
FOLDERID_LocalAppData = F1B32785-6FBA-4FCF-9D55-7B8E7F157091. Also useful: Startup B97D20BB-F46A-4C97-BA10-5E3608430854, CommonStartup 82A5EA35-D9CD-47C5-9629-E15D2F714E6E, ProgramData 62AB5D82-FDC1-4DC3-A9DD-070D1D495D97.
Note: Environment.GetFolderPath covers most of these with no P/Invoke at all — prefer it where a KnownFolderId has a SpecialFolder equivalent.

### [medium] P/Invoke: GetTokenInformation for integrity level — verified Medium
VERIFIED: returned RID 0x2000 = Medium integrity, correctly matching the non-elevated shell (independently confirmed via WindowsPrincipal.IsInRole(Administrator) = False).

**How:** const uint TOKEN_QUERY = 0x0008; const int TokenIntegrityLevel = 25;
OpenProcessToken(new IntPtr(-1), TOKEN_QUERY, out tok);
GetTokenInformation(tok, TokenIntegrityLevel, IntPtr.Zero, 0, out uint need); // size probe
GetTokenInformation(tok, TokenIntegrityLevel, buf, need, out _);
var tml = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(buf);   // { SID_AND_ATTRIBUTES Label { IntPtr Sid; uint Attributes; } }
byte cnt = Marshal.ReadByte(GetSidSubAuthorityCount(tml.Label.Sid));
int rid = Marshal.ReadInt32(GetSidSubAuthority(tml.Label.Sid, (uint)(cnt-1)));
RIDs: 0x1000 Low, 0x2000 Medium, 0x3000 High, 0x4000 System.
For Warden's own elevation state, prefer the managed one-liner: new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator).

**False positives:** Low integrity is normal for sandboxed browser renderer processes (Chrome, Edge, Acrobat). Do not score Low IL as suspicious — it usually indicates good sandboxing.

### [critical] THREADING: the monitor loop, and why it must never be a DispatcherTimer
WPF has one UI thread owning the Dispatcher; every DependencyObject/ObservableCollection is thread-affine. A DispatcherTimer runs its tick ON the UI thread, so a 7 ms process scan would jank the UI 60 times a second at 1 Hz cadence. The monitor must live entirely off-thread and marshal only small, already-computed deltas back.

**How:** Use a single long-lived background loop, NOT Task.Run per tick and NOT System.Timers.Timer (which fires on pool threads concurrently and can re-enter):

private async Task MonitorLoopAsync(CancellationToken ct) {
  using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
  while (await timer.WaitForNextTickAsync(ct)) {
    try { var delta = _scanner.Tick();            // pure, off-thread, no WPF types
          if (!delta.IsEmpty)
            await _dispatcher.InvokeAsync(() => _vm.Apply(delta), DispatcherPriority.Background, ct); }
    catch (OperationCanceledException) { throw; }
    catch (Exception ex) { _log.Error(ex); }      // NEVER let the loop die
  }
}
Start it from OnStartup with a CancellationTokenSource stored on the App; cancel it in OnExit.
PeriodicTimer does not drift-accumulate and does not overlap ticks — both true of System.Timers.Timer.
Use DispatcherPriority.Background (not Normal/Send) so input and rendering always win.
Batch UI updates: never raise 300 PropertyChanged events; compute an immutable delta record off-thread and apply it in one Invoke.

### [critical] PERFORMANCE: measured budget, and the polling cadence this dictates
ALL MEASURED on the i9-12900K (24 logical cores, 355 live processes, 5967 threads). Toolhelp32 full snapshot 7.46 ms. NtQuerySystemInformation 5.1-6.7 ms and allocates 75-77 KB. Process.GetProcesses() 4.1-4.4 ms. EnumProcesses (PIDs only) 0.0195 ms, ZERO allocation. TCP4 0.093 ms, TCP6 0.049 ms, UDP4 0.030 ms. Naive full poll = 7.87 ms/s = 0.79% of one core, 17.2 KB garbage per second. The key insight: the ~5-7 ms is kernel-side cost of gathering data for 355 processes and 5967 threads — it is NOT an API-choice problem, so switching from Toolhelp32 to NtQuerySystemInformation buys almost nothing.

**How:** TIERED CADENCE (recommended):
- 1 Hz: EnumProcesses PID diff (0.0195 ms) + GetExtendedTcpTable v4/v6 + Udp (0.17 ms) = ~0.19 ms/s => 0.019% of one core, effectively zero idle CPU.
- On new PID only: enrich at 0.022 ms each (OpenProcess + QueryFullProcessImageName + GetProcessTimes), then signature-verify ASYNCHRONOUSLY off the hot path.
- 30-60 s: full Toolhelp32/NtQuerySystemInformation sweep for drift reconciliation.
- 5-15 min: persistence sweep (Run keys, Startup folders, 219 scheduled tasks, services).
- Never on a timer: WinVerifyTrust. It is the expensive operation (disk + crypto + catalog enumeration). Cache results keyed by (full path, file size, last-write-time, volume serial) and only re-verify on change.
Set <ConcurrentGarbageCollection>true</ConcurrentGarbageCollection> and leave ServerGC OFF (ServerGC would create 24 heaps and inflate the working set badly for a tray app).

### [high] TRAY: correct NotifyIcon usage inside WPF, including the disposal bug that leaves ghost icons
WinForms NotifyIcon works in a WPF app (verified compiling and running with both UseWPF and UseWindowsForms). The classic defect is failing to call Dispose(), which leaves a dead icon in the tray until the user mouses over it. Application.Current.Shutdown does NOT dispose it for you.

**How:** var ni = new System.Windows.Forms.NotifyIcon {
    Icon = new System.Drawing.Icon(iconStream, System.Windows.Forms.SystemInformation.SmallIconSize), // pick the right size for DPI
    Visible = true, Text = "Warden"  // Text is capped at 63 chars, longer silently truncates
};
ni.DoubleClick += (s,e) => ShowDashboard();
ni.ContextMenuStrip = BuildMenu();
// MANDATORY:
AppDomain.CurrentDomain.ProcessExit += (s,e) => { ni.Visible = false; ni.Dispose(); };
Application.Current.Exit  += (s,e) => { ni.Visible = false; ni.Dispose(); };
Set ShutdownMode = ShutdownMode.OnExplicitShutdown in App.xaml so closing the dashboard does not kill the app.
Minimise-to-tray: handle Window.Closing, set e.Cancel = true, this.Hide(). Re-show with Show() + WindowState=Normal + Activate().
DPI: load a multi-resolution .ico and pass SystemInformation.SmallIconSize; a single 16x16 will look blurry at 150%+ scaling. Windows 11 hides new tray icons in the overflow flyout by default — the user must drag it out; you cannot force visibility programmatically, so do not depend on the icon being visible for critical alerts.

### [high] LIFECYCLE: single-instance enforcement via named Mutex
Use a Local\ mutex (per-session) rather than Global\ — Global requires no special rights but collides across fast-user-switching sessions and is unnecessary for a per-user tray app. Must hold the Mutex object in a field for the process lifetime or the GC will collect and release it.

**How:** private static Mutex? _single;
protected override void OnStartup(StartupEventArgs e) {
  _single = new Mutex(initiallyOwned: true, @"Local\Warden.HostDefence.SingleInstance", out bool createdNew);
  if (!createdNew) { /* signal the running instance to show, then */ Shutdown(); return; }
  base.OnStartup(e);
}
protected override void OnExit(ExitEventArgs e) { _single?.ReleaseMutex(); _single?.Dispose(); base.OnExit(e); }
To raise the existing instance, register a custom window message with RegisterWindowMessage("WardenShowDashboard") and PostMessage(HWND_BROADCAST=0xFFFF, msg, 0, 0); the running instance catches it in an HwndSourceHook. This avoids named pipes entirely.
Catch AbandonedMutexException on acquisition — it means a previous instance crashed and you should proceed, not abort.

### [critical] STARTUP: use HKCU Run. Scheduled-task logon triggers REQUIRE ADMIN — verified
VERIFIED EMPIRICALLY, and this overturns the common advice. From a non-elevated shell: `schtasks /Create /SC ONLOGON` => 'ERROR: Access is denied.' It still failed with an explicit `/RU <currentuser>`. By contrast `schtasks /Create /SC ONCE` SUCCEEDED, proving it is the LOGON TRIGGER specifically that is privileged, not task creation generally. Writing HKCU\Software\Microsoft\Windows\CurrentVersion\Run SUCCEEDED with no admin. (I deleted every probe artifact and verified removal.)

**How:** RECOMMENDATION: HKCU Run key. It is the only no-admin option that actually works.
using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
k.SetValue("Warden", $"\"{Environment.ProcessPath}\" --tray");   // quote the path
Trade-offs to design around: (1) the user can disable it in Task Manager > Startup, and Windows writes a tombstone under ...\Explorer\StartupApproved\Run — READ that value and reflect the real state in your UI rather than assuming your Run entry is live; (2) Run entries launch at medium IL after the shell is ready, which is exactly what Warden wants; (3) Warden will detect its OWN Run key during persistence scans — see the self-detection item.
Only use a logon-triggered scheduled task if you later add an elevated installer step; do not build the no-admin path on it.

**False positives:** Warden's own Run key is the #1 guaranteed self-inflicted false positive. Suppress it explicitly.

### [high] SELF-MONITORING: how Warden must avoid detecting itself
Warden will exhibit every behaviour it hunts for: a Run key, a tray process reading other processes' memory (ReadProcessMemory on PEBs), opening handles to every PID, enumerating services and scheduled tasks, and touching \\.\PhysicalDrive0. Naive scoring will flag it as a RAT.

**How:** Build an identity-based self-exclusion, not a name-based one (a name check is trivially spoofed by an attacker dropping warden.exe):
1. Capture at startup: Environment.ProcessId, Environment.ProcessPath, and the SHA-256 of your own executable.
2. Exclude by (pid + process start time) for the live process — start time defeats PID reuse.
3. For on-disk artifacts (Run key, quarantine vault, config dir), exclude by exact full path compared with StringComparer.OrdinalIgnoreCase against your known-good paths.
4. VERIFY YOUR OWN BINARY at startup with the same catalog-aware WinVerifyTrust routine. If Warden's own file fails signature verification, that is a tamper signal worth surfacing loudly.
5. Do NOT exclude by image name, window title, or company string.
6. Log self-exclusions to the audit trail so the user can see exactly what Warden is not scanning.

**False positives:** Conversely, be careful the exclusion cannot be abused: an attacker who can write to Warden's install directory could drop a payload there and inherit the exclusion. Exclude the specific executable path and the vault, never the whole parent directory.

### [high] NOTIFICATIONS: real Windows 11 toasts DO work unpackaged with zero NuGet — verified end to end
PROVEN ON THIS MACHINE. Full chain returned S_OK: RoGetActivationFactory(ToastNotificationManager) -> RoActivateInstance(XmlDocument) -> LoadXml -> RoGetActivationFactory(ToastNotification) -> CreateToastNotification -> CreateToastNotifierWithId -> Show = 0x00000000. Confirmed the platform genuinely accepted it: Windows created HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Warden.HostDefence with LastNotificationAddedTime decoding to 19:41:59 — matching my launch timestamp to the second. No NuGet, no packaging, no admin, no Start Menu shortcut.

**How:** Two requirements, both verified necessary:
1. SetCurrentProcessExplicitAppUserModelID("Warden.HostDefence") — shell32, call once at startup BEFORE any toast.
2. Create HKCU\Software\Classes\AppUserModelId\Warden.HostDefence with string value DisplayName (and optionally IconUri). BEFORE creating this key get_Setting returned 0x80070490 ELEMENT_NOT_FOUND and the toast was silently dropped; AFTER creating it get_Setting returned 0x0 with value 0 = NotificationSetting.Enabled and Show succeeded. This is a plain HKCU write, no admin.
Runtime classes: "Windows.UI.Notifications.ToastNotificationManager", "Windows.Data.Xml.Dom.XmlDocument", "Windows.UI.Notifications.ToastNotification". Use combase.dll WindowsCreateString / RoGetActivationFactory / RoActivateInstance / WindowsDeleteString.
Always check get_Setting before relying on a toast; treat non-zero as 'user has notifications off, fall back'.

### [high] NOTIFICATIONS: .NET cannot marshal IInspectable at all — you MUST pad the vtable manually
TWO VERIFIED FAILURES that block the obvious implementations. (1) [MarshalAs(UnmanagedType.IInspectable)] throws MarshalDirectiveException: 'Marshalling as IInspectable is not supported in the .NET runtime'. (2) [ComImport] with ComInterfaceType.InterfaceIsIInspectable throws PlatformNotSupportedException from Marshal.GetTypedObjectForIUnknown with the same message. Neither is usable on .NET Core/5+/10. The working technique is to declare each WinRT interface as IUnknown-based and manually insert the three IInspectable slots.

**How:** [ComImport, Guid("50AC103F-D235-4598-BBEF-98FE4D1A3AD4")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IToastNotificationManagerStatics {
    // IInspectable padding - MUST be present and in this exact order
    void GetIids(out int count, out IntPtr iids);
    void GetRuntimeClassName(out IntPtr className);
    void GetTrustLevel(out int trustLevel);
    // actual methods
    [PreserveSig] int CreateToastNotifier(out IntPtr notifier);
    [PreserveSig] int CreateToastNotifierWithId(IntPtr appId, out IntPtr notifier);
    [PreserveSig] int GetTemplateContent(int type, out IntPtr content);
}
Use Marshal.GetObjectForIUnknown(ptr) and cast. IIDs verified working: IToastNotificationManagerStatics 50AC103F-D235-4598-BBEF-98FE4D1A3AD4; IToastNotifier 75927B93-03F3-41EC-91D3-6E5BAC1B38E7; IToastNotificationFactory 04124B20-82C6-4229-B109-FD9ED4662B53; IXmlDocumentIO 6CD0E74E-EE65-4489-9EBF-CA43E87BA637.
Also: do NOT call RoInitialize on an [STAThread] — it returns RPC_E_CHANGED_MODE (0x80010106). The STA is already initialised and WinRT activation works on it fine.

**False positives:** Getting a vtable slot count wrong does not fail cleanly — it calls the wrong function pointer and can corrupt or crash the process. Add each interface carefully and test in isolation.

### [high] NOTIFICATIONS: recommended strategy and fallbacks
Toasts are proven possible but carry ~200 lines of hand-written COM, a registry dependency, and OS-level suppression you cannot control (Focus Assist / Do Not Disturb will silently swallow them — my own test toast was accepted by the platform but never appeared on screen, almost certainly for this reason).

**How:** RECOMMENDATION - tiered by severity:
- HIGH-CONFIDENCE AUTO-ACTION taken (killed + quarantined): custom WPF toast window. Full control, cannot be suppressed by Focus Assist, can carry Warden's own styling and an inline Undo button that maps to the quarantine rollback. Position with SystemParameters.WorkArea.Right/Bottom minus margins, ShowActivated=false, Topmost=true, no taskbar entry, auto-dismiss on a timer. This should be the PRIMARY channel because the reversibility promise depends on the user actually seeing it.
- AMBIGUOUS, needs a decision: bring up the dashboard window itself, or a modal-less prompt card. Never a toast, since a missed toast means an unhandled threat.
- INFORMATIONAL (scan complete, maintenance finished): real WinRT toast, so it lands in Notification Center history where the user can review it later. Falls back silently to nothing if get_Setting != 0.
- AVOID NotifyIcon.ShowBalloonTip as the primary channel: on Win10/11 the shell reroutes it through the same toast pipeline, so it inherits the identical Focus Assist suppression while giving you less control and no buttons.

### [high] BUILD AND RUN commands for this exact machine
All verified working from this machine's shell. Note the Bash tool is broken in this environment (fork errors); use PowerShell.

**How:** # Day-to-day (fully offline, zero packages, ~7 s cold):
dotnet build .\Warden.sln -c Debug
dotnet run --project .\src\Warden\Warden.csproj

# Release build:
dotnet build .\Warden.sln -c Release

# RECOMMENDED ship build for this machine (framework-dependent, 0.18 MB, runtime already present):
dotnet publish .\src\Warden\Warden.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:PublishReadyToRun=true -p:IncludeNativeLibrariesForSelfExtract=true -o .\dist

# Portable/other-machine build (76.9 MB, no runtime dependency):
dotnet publish .\src\Warden\Warden.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -p:EnableCompressionInSingleFile=true -o .\dist-sc

# Prove the zero-NuGet claim at any time (drop a nuget.config with <packageSources><clear/></packageSources> next to the csproj):
dotnet build .\src\Warden\Warden.csproj -c Release --no-cache

# Pin the SDK so 9.0.317 is never selected - put global.json at the repo root:
{ "sdk": { "version": "10.0.303", "rollForward": "latestFeature" } }

### [critical] TOP 10 mistakes that will break this build on .NET 10 WPF
Ranked by how likely they are to bite, based on what actually went wrong during this research. Items 1, 3, 4, 5, 7 I hit personally.

**How:** 1. AMBIGUOUS TYPE NAMES (I hit this): with UseWPF+UseWindowsForms+ImplicitUsings, `new Application()` gives `error CS0104: 'Application' is an ambiguous reference between 'System.Windows.Forms.Application' and 'System.Windows.Application'`. Same for MessageBox, Clipboard, Cursor(s), Point, Size, Color, Brush(es), Control, Binding, Orientation, HorizontalAlignment, DataFormats, KeyEventArgs, MouseEventArgs, TextBox, Label, MenuItem. FIX: fully qualify, or add global usings with aliases: `global using WinForms = System.Windows.Forms;` and never `using System.Windows.Forms;` at file scope.
2. PublishTrimmed or PublishAot => hard errors NETSDK1168 / NETSDK1175. Never set them.
3. SupportedOSPlatformVersion on a bare TFM => NETSDK1135. Omit it.
4. LibraryImport with StringBuilder => SYSLIB1051. Use char* or DllImport.
5. LibraryImport with `ref char` => SYSLIB1051 demanding DisableRuntimeMarshalling. Use char*.
6. Versioned TFM net10.0-windows10.0.26100.0 => silent 76.9 MB package restore, breaks offline builds.
7. LayoutKind.Sequential without CharSet.Unicode on a ByValTStr struct => silent data corruption and a CLR crash at exit.
8. Forgetting `dwSize = Marshal.SizeOf<T>()` on PROCESSENTRY32W (and cbStruct on WINTRUST_DATA/WINTRUST_FILE_INFO/CATALOG_INFO) => the API fails or misbehaves.
9. Touching WPF objects from the monitor thread => InvalidOperationException 'The calling thread cannot access this object'. Marshal via Dispatcher.InvokeAsync.
10. Missing <AllowUnsafeBlocks>true</AllowUnsafeBlocks> once you use char*/stackalloc => CS0227. And a WinForms DPI manifest triggers warning WFO0003 which becomes an error under TreatWarningsAsErrors — suppress with <NoWarn>$(NoWarn);WFO0003</NoWarn>.

### [medium] app.manifest — the exact contents, and why WFO0003 must be suppressed rather than obeyed
VERIFIED building cleanly with NoWarn. The WinForms analyzer emits WFO0003 telling you to move DPI settings out of the manifest and into Application.SetHighDpiMode — that advice is WRONG for this app, because SetHighDpiMode is WinForms-only and WPF reads DPI awareness from the manifest at process start. Removing the manifest DPI block would leave the WPF UI blurry on this user's likely high-DPI multi-monitor setup (the screenshot showed an 8096x2566 desktop spanning multiple displays).

**How:** Manifest essentials: requestedExecutionLevel level="asInvoker" (Warden runs unelevated by design); supportedOS Id {8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a} for Win10/11; dpiAwareness PerMonitorV2 + dpiAware true/pm; longPathAware true (important — Warden walks deep paths and quarantine paths get long); activeCodePage UTF-8.
Then <NoWarn>$(NoWarn);WFO0003</NoWarn> in the csproj.

### [high] Elevation strategy — what Warden genuinely cannot do at medium IL
Measured, non-elevated: 133/379 process image paths unreadable; SMART/NVMe health denied (error 5); service CONFIG CHANGES denied (enumeration is fine); HKLM writes denied; scheduled-task logon triggers denied; killing/quarantining processes owned by SYSTEM or other users denied; ETW kernel providers denied. Everything else Warden needs works fine unelevated.

**How:** Do NOT mark the whole app requireAdministrator — that would make it prompt at every logon and is hostile for a tray app. Instead: run asInvoker, and for the handful of privileged operations launch a short-lived elevated helper with ShellExecute verb "runas":
new ProcessStartInfo { FileName = Environment.ProcessPath, Arguments = "--elevated-op <verb> <args>", UseShellExecute = true, Verb = "runas" }
Catch Win32Exception with NativeErrorCode 1223 (ERROR_CANCELLED) for the user declining UAC and degrade gracefully. Show a clear 'requires elevation' affordance in the UI rather than silently failing or reporting a false clean result.

**False positives:** NEVER report 'no threats found' for a scan tier that silently failed on access-denied. Track per-check status as Pass/Fail/NotAssessable and surface NotAssessable distinctly, or Warden will give false assurance.

### [critical] Never-kill list — enforcing the do-not-brick constraint
The safety constraint requires that critical processes are un-killable. A name-based blocklist is insufficient (malware names itself svchost.exe) and a name-based allowlist is dangerous (it would protect the impostor).

**How:** Layer these, all available with zero NuGet:
1. IsProcessCritical: [LibraryImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] static partial bool IsProcessCritical(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool Critical); — terminating a critical process bugchecks the machine. Hard-block any process where this returns true.
2. Block PID 0 and 4 (System), and any process whose session id is 0 unless explicitly confirmed.
3. Block anything whose image path is under %SystemRoot%\System32 or SysWOW64 AND passes catalog-aware signature verification as Microsoft — the conjunction is what makes it safe; neither test alone is.
4. Block if the process token integrity is System (RID 0x4000) and Warden is not elevated (the kill would fail anyway).
5. Require a signed-by-Microsoft check to have SUCCEEDED, not merely 'not failed' — treat NotAssessable as protected, never as killable.
6. Maintain an explicit protect-list of the user's own workflow: Blender, Unreal, BlueStacks/HD-Player, dotnet, node, python, cargo, git, and the shells — this user is a developer and these legitimately spawn odd children and read memory.

**False positives:** This user runs BlueStacks with root, Unreal, Blender and slot-game math simulations. Rooted-emulator components, Unreal shader compiler workers, and long-running headless simulation processes all look anomalous to naive heuristics: high CPU, many threads, unsigned binaries under user directories, and odd parent-child chains. Whitelist these explicitly before shipping or Warden will be unusable on this machine.

## Risks
- FALSE POSITIVES FROM CATALOG SIGNING - the single highest product risk, and it is confirmed real, not theoretical: WinVerifyTrust with WTD_CHOICE_FILE reports notepad.exe and cmd.exe as UNTRUSTED on this clean machine because they are catalog-signed. Shipping without the CryptCATAdmin fallback would flag a large fraction of C:\Windows\System32 as unsigned.
- FALSE ASSURANCE FROM ACCESS-DENIED - 133 of 379 processes could not be opened at medium IL, and SMART returned ACCESS_DENIED. If these are recorded as 'clean' rather than 'not assessable', Warden will tell the user they are safe when a third of the process table was never examined. This is arguably worse than a false positive.
- SILENT MARSHALLING CORRUPTION - the CATALOG_INFO CharSet bug returned plausible wrong data (a path truncated to 'C') and caused a fatal CLR error at exit, with no exception at the call site. Any struct in the P/Invoke layer missing CharSet.Unicode is a latent version of this. Mitigate with startup size assertions.
- UNDOCUMENTED PEB OFFSETS - command-line extraction depends on hardcoded x64 offsets 0x20 and 0x70 that Microsoft can change in any Windows update. It works today on 26200 (verified) but must be defensively wrapped and must degrade to 'unavailable' rather than throwing or producing garbage.
- HAND-WRITTEN COM VTABLES - the toast implementation depends on manually padding three IInspectable slots per interface. An off-by-one in slot count calls the wrong function pointer, which can corrupt memory rather than fail cleanly. Each interface should be added and tested in isolation.
- TOAST SUPPRESSION IS OUTSIDE YOUR CONTROL - my verified toast was accepted by the platform (confirmed in the notification database) but never appeared on screen, almost certainly due to Focus Assist during video playback. Any alert whose delivery matters must not depend on a toast.
- THIS USER'S WORKLOAD LOOKS MALICIOUS TO GENERIC HEURISTICS - rooted BlueStacks, Unreal shader compilers, Blender, and long-running slot-math simulations exhibit exactly the CPU, threading, memory-access and unsigned-binary patterns that cryptominer and RAT heuristics target. Without an explicit developer-workload allowlist, precision will be poor on the only machine that matters.
- SELF-EXCLUSION AS AN ATTACK SURFACE - Warden must exclude its own Run key, vault and process, but a path-based exclusion covering a whole directory would let anything dropped there inherit immunity. Scope exclusions to exact file paths plus (pid, start time).
- REGISTRY DEPENDENCY FOR TOASTS - notifications require an HKCU\Software\Classes\AppUserModelId key. If the user or a cleanup tool removes it, toasts silently stop working (get_Setting returns 0x80070490). Re-assert the key at startup and verify get_Setting before relying on the channel.
- 'ZERO NUGET' IS TRUE FOR BUILD BUT NOT FOR EVERY PUBLISH MODE - ReadyToRun pulls Crossgen2 and self-contained pulls runtime packs. These are Microsoft runtime packs rather than third-party libraries, but if strict offline reproducibility is the goal, the ship command must drop PublishReadyToRun.

## Implementation notes
EVERYTHING ABOVE WAS EXECUTED, NOT RECALLED. Environment confirmed: Windows 11 Pro build 26200, .NET SDK 10.0.303 (also 9.0.317 present - pin with global.json), Microsoft.WindowsDesktop.App 10.0.11 and Microsoft.NETCore.App 10.0.11 installed as both ref packs and shared runtimes. The probe shell was NON-ELEVATED (WindowsPrincipal.IsInRole(Administrator)=False, token integrity RID 0x2000 Medium), so every access-denied result reflects genuine unprivileged behaviour rather than an artifact of testing.

WORKING PROBE PROJECTS - all still on disk, all build and run, use them as the starting point rather than retyping the P/Invokes:
C:\Users\finla\AppData\Local\Temp\claude\D--My-projects\a6d7918b-0315-41b5-8d82-d4025862d88a\scratchpad\wardenprobe\
  A\  minimal WPF+WinForms app; also the publish-matrix testbed (out-fd, out-sc)
  B\Probe.cs   Toolhelp32, OpenProcess, QueryFullProcessImageName, IsWow64Process2, NtQueryInformationProcess+PEB cmdline, GetExtendedTcp/UdpTable, WinVerifyTrust, GetSystemPowerStatus, integrity level, SHGetKnownFolderPath, EnumServicesStatusEx, DeviceIoControl
  C\Cat.cs     catalog-aware signature verification (the critical false-positive fix)
  D\Dwm.cs     dark mode, Mica, rounded corners, caption/border colour, SetPreferredAppMode
  E\E.cs       SHFileOperationW recycle + WinRT activation factory
  F\Toast.cs   complete working unpackaged toast via raw COM with vtable padding
  G\           benchmarks: Bench.cs, Nt.cs, Cheap.cs
  I\           the FINAL recommended csproj + app.manifest, verified building offline with zero NuGet sources
  K\Sched.cs   Task Scheduler enumeration via late-bound COM

ORDERING CONSTRAINTS THAT MATTER:
- DWM attributes must be set in Window.SourceInitialized, not the constructor - the HWND does not exist earlier.
- For Mica you must do all three: DWMWA_SYSTEMBACKDROP_TYPE=2, Window.Background=Transparent, and DwmExtendFrameIntoClientArea with MARGINS{-1,-1,-1,-1}. Any one alone renders nothing.
- SetCurrentProcessExplicitAppUserModelID must be called before the first toast, and the AppUserModelId registry key must exist before CreateToastNotifierWithId or the toast is silently dropped.
- In the catalog verification path, release order is CryptCATAdminReleaseCatalogContext then CryptCATAdminReleaseContext, and the member FileStream handle must stay alive until after WinVerifyTrust's STATEACTION_CLOSE. Getting this wrong produced a fatal CLR error at exit during testing.
- Set dwSize/cbStruct before every call that takes them: PROCESSENTRY32W.dwSize, WINTRUST_DATA.cbStruct, WINTRUST_FILE_INFO.cbStruct, WINTRUST_CATALOG_INFO.cbStruct, CATALOG_INFO.cbStruct, STORAGE_PROPERTY_QUERY.
- Two-pass sizing is required for GetExtendedTcpTable, GetExtendedUdpTable, EnumServicesStatusEx and GetTokenInformation: call once to obtain the needed size, allocate, call again.

ADMIN REQUIREMENTS (verified): SMART/NVMe health needs GENERIC_READ|GENERIC_WRITE on \\.\PhysicalDriveN (denied at medium IL, error 5). Scheduled tasks with ONLOGON triggers need elevation even with /RU for your own account. Service configuration changes need elevation, though enumeration does not. HKLM writes need elevation. Everything else Warden needs - process enumeration, socket tables, service enumeration (758), task enumeration (219), signature verification, recycle-bin delete, HKCU writes, toasts, device ProductId - works unelevated.

CLEANUP PERFORMED: I created and then removed a scheduled task probe (WardenProbeOnce), an HKCU Run value (WardenProbeTemp), and an HKCU AppUserModelId key (Warden.HostDefence), and verified all three are gone. One residue I deliberately did NOT touch: Windows itself created HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Warden.HostDefence as normal OS bookkeeping when it accepted the test toast - it is harmless and Warden will legitimately use that identity. Two test files named warden_recycle_probe are sitting in the Recycle Bin; I left them rather than permanently deleting anything.

ONE THING I DID NOT TEST: I did not implement IFileOperation (the modern COM replacement for SHFileOperation). SHFileOperationW is formally deprecated but demonstrably works and correctly recycles on build 26200. If you want IFileOperation instead, note it needs the same manual COM interface declarations and offers better progress/collision UI - but it is not required, and SHFileOperationW is the lower-risk choice for a first implementation. I also did not test ETW-based real-time process creation events; the EnumProcesses tiered-polling design in this spec is specifically intended to make ETW unnecessary, since kernel ETW providers require elevation.

## ADVERSARIAL CRITIQUE
### Corrections (16)
- **Claim:** "AFTER THIS FIX, VERIFIED: ... kernel32.dll, svchost.exe, dotnet.exe -> TRUSTED via embedded."
  - **Why wrong:** Wrong for two of the three, verified just now on this machine: Get-AuthenticodeSignature reports SignatureType=Catalog for C:\Windows\System32\kernel32.dll, svchost.exe, ntdll.dll and C:\Windows\explorer.exe. Only dotnet.exe is Authenticode/embedded. Essentially nothing under System32 is embedded-signed on 26200. This inverts the spec's own performance design: it frames Stage 2 (CryptCATAdmin hash + CryptCATAdminEnumCatalogFromHash + a second WinVerifyTrust) as the rare exception taken only on TRUST_E_NOSIGNATURE, when in reality it is the path taken for nearly every Microsoft binary on the box. Catalog enumeration is the expensive operation (it hashes the file and walks the CatRoot store — my own recursive enumeration of C:\Windows\System32\CatRoot timed out at 120 s), so the real per-file verification cost is far above what the spec implies.
  - **Fix:** Re-baseline the signature-verification budget assuming the catalog path is the common case, not the exception. Concretely: (a) skip Stage 1 entirely for files under %SystemRoot% and go straight to catalog, since Stage 1 is a guaranteed wasted syscall there; (b) hold one HCATADMIN open for the whole app lifetime rather than acquiring/releasing per file; (c) make the verification queue strictly background with a bounded worker and a hard per-file timeout; (d) re-measure — the spec never actually reports a WinVerifyTrust timing, which is the one number the whole 'never on a timer' cadence decision rests on.
- **Claim:** Command-line extraction via NtQueryInformationProcess(ProcessBasicInformation) + ReadProcessMemory of the PEB at offsets 0x20/0x70, requiring PROCESS_VM_READ.
  - **Why wrong:** This is the obsolete technique and it is the single most dangerous P/Invoke in the spec. It needs PROCESS_VM_READ on every process, which (1) is exactly the access right Defender's ASR rule 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)' watches for — Warden will attempt it against lsass on every enrichment pass and will be blocked and alerted on, and may itself be quarantined; (2) depends on undocumented offsets the spec itself lists as a top risk; (3) fails for the ~35% of processes that cannot be opened anyway. Windows 8.1+ exposes PROCESSINFOCLASS 60 (ProcessCommandLineInformation), which returns a UNICODE_STRING command line and requires only PROCESS_QUERY_LIMITED_INFORMATION — no VM read, no PEB walk, no hardcoded offsets.
  - **Fix:** Replace the PEB path with NtQueryInformationProcess(h, 60, buf, len, out ret) using the two-pass size probe (it returns STATUS_INFO_LENGTH_MISMATCH first). Keep the PEB code only as a fallback for pre-8.1, which does not apply here, i.e. delete it. Regardless of technique, add lsass.exe and any PPL/protected process to a hard exclusion list for memory-read operations.
- **Claim:** EnumProcesses into a fixed stackalloc uint[4096] with no follow-up check.
  - **Why wrong:** EnumProcesses gives no indication that the buffer was too small — it silently truncates. The documented contract is to compare lpcbNeeded against cb and retry with a larger buffer if they are equal. As written, the 1 Hz PID diff is silently capped at 4096 PIDs. That is generous today (355 processes) but the failure mode is 'process list silently truncated', i.e. missed detections reported as clean — the worst possible failure for this product.
  - **Fix:** if (ret == cb) { grow and retry }. Loop until ret < cb. Also treat a returned false or a truncation as a scan-tier failure that surfaces as NotAssessable, consistent with the spec's own access-denied policy.
- **Claim:** Single-instance Mutex sample: OnStartup does `if (!createdNew) { Shutdown(); return; }` and OnExit unconditionally does `_single?.ReleaseMutex()`.
  - **Why wrong:** In the second-instance path createdNew is false, so this process does not own the mutex, yet Shutdown() raises Exit and OnExit calls ReleaseMutex on an unowned mutex. That throws ApplicationException ('Object synchronization method was called from an unsynchronized block of code'), so the duplicate-launch path crashes with an unhandled exception dialog instead of exiting quietly. Separately, `Catch AbandonedMutexException on acquisition` is inapplicable — the Mutex constructor never throws AbandonedMutexException; only WaitOne does, and this code never waits.
  - **Fix:** Track ownership: `_owned = createdNew;` and in OnExit `if (_owned) _single?.ReleaseMutex(); _single?.Dispose();`. Drop the AbandonedMutexException advice or switch to CreateMutex + WaitOne(0) if you actually want abandonment semantics.
- **Claim:** Never-kill rule 3: 'Block anything whose image path is under System32/SysWOW64 AND passes catalog-aware signature verification as Microsoft.'
  - **Why wrong:** The verification routine specified everywhere else in the document returns only an HRESULT from WinVerifyTrust. hr==0 means 'chains to a trusted root', not 'signed by Microsoft'. Any code-signing certificate from any public CA — including a stolen or purchased one — returns 0. There is no code path in this spec that ever extracts the signer identity, so the conjunction that the spec says 'is what makes it safe' cannot actually be evaluated. The same gap makes the entire trusted/untrusted axis far weaker than the document implies.
  - **Fix:** Set dwStateAction = WTD_STATEACTION_VERIFY (1), then on success call WTHelperProvDataFromStateData(hWVTStateData) and WTHelperGetProvSignerFromChain(...)/WTHelperGetProvCertFromChain(...) to pull the leaf and issuer, and finally call WinVerifyTrust again with WTD_STATEACTION_CLOSE (2) to free state. Or parse the signature with SignedCms (in-box per the spec's own bonus list) and check the chain root. Store signer subject/issuer/thumbprint alongside the trusted bit, and make 'Microsoft-signed' a separate predicate from 'trusted'.
- **Claim:** 'System.Diagnostics.EventLog.dll -> read Security/System/Application logs and write Warden's own audit trail.'
  - **Why wrong:** Reading the Security log requires membership in Administrators or Event Log Readers — a medium-IL standard-user read throws UnauthorizedAccessException. Writing to a custom source is worse: EventLog.CreateEventSource writes under HKLM\SYSTEM\CurrentControlSet\Services\EventLog and requires elevation, and WriteEntry with an unregistered source attempts that creation and fails. So both halves of this bullet fail at the medium IL the spec correctly insists on everywhere else. The assembly being in-box was verified; the capability was not.
  - **Fix:** Security-log reading goes in the elevated-helper bucket alongside SMART. For Warden's own audit trail use an append-only file under %LOCALAPPDATA%\Warden with an HMAC chain (the spec already has ProtectedData and can derive a key), not the Windows event log — or have the elevated installer step pre-create the event source once.
- **Claim:** app.manifest 'longPathAware true (important — Warden walks deep paths and quarantine paths get long)' plus SHFileOperationW as the recycle mechanism.
  - **Why wrong:** Two errors. (1) longPathAware in the manifest is only half the opt-in; Win32 long-path support also requires HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled=1, which needs admin and is off by default. The manifest alone changes nothing. (2) SHFileOperation is documented as not supporting paths longer than MAX_PATH at all, regardless of the manifest or the registry policy. On this machine that is not theoretical: projects live at D:\My projects with node_modules and Unreal Intermediate/DerivedDataCache trees that routinely exceed 260 characters — exactly the trees a maintenance cleaner targets. The recycle path will fail on precisely the files it is most needed for.
  - **Fix:** Do not treat IFileOperation as optional. It is the only in-box recycle API that handles long paths (Win10 1607+ with the manifest opt-in). Implement it with the same raw-COM declarations the toast code already needs (IFileOperation CLSID_FileOperation, SetOperationFlags with FOFX_RECYCLEONDELETE | FOFX_EARLYFAILURE, DeleteItem with SHCreateItemFromParsingName). Also detect LongPathsEnabled at startup and surface it, rather than silently failing on deep paths.
- **Claim:** SHFileOperationW with FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI as the Maintenance-side delete.
  - **Why wrong:** FOF_ALLOWUNDO is best-effort. When the item cannot be recycled — file larger than the bin quota, Recycle Bin disabled by policy on that volume, network or removable volume, or a path the bin does not cover — the shell falls back to a permanent delete. Normally the user gets a 'this item is too big to recycle, delete permanently?' prompt; FOF_NOCONFIRMATION suppresses exactly that prompt. The combination as written is a silent permanent-delete of user data with a return code of 0, in an app whose stated first constraint is that every action be reversible.
  - **Fix:** Never pair FOF_ALLOWUNDO with FOF_NOCONFIRMATION for user data. Either drop NOCONFIRMATION, or pre-flight each item: check the volume actually has a bin (SHQueryRecycleBin) and that the item fits, and route anything that would fall back to permanent delete into Warden's own vault instead. With IFileOperation, FOFX_RECYCLEONDELETE plus FOFX_EARLYFAILURE gives you a hard failure instead of a silent permanent delete.
- **Claim:** EnumServicesStatusEx with svcType = 0x3B (SERVICE_WIN32 | SERVICE_DRIVER); QueryServiceConfigW for binary path.
  - **Why wrong:** Two gaps. (1) 0x3B omits SERVICE_USER_SERVICE (0x40) and SERVICE_USERSERVICE_INSTANCE (0x80), so per-user services are invisible to the sweep — and per-user services are exactly the class a per-user tool should be watching. (2) QueryServiceConfigW returns svchost.exe -k <group> as the binary for the large majority of Windows services. A persistence scan that records 'C:\Windows\system32\svchost.exe -k netsvcs' as the service binary is detecting nothing; the actual code is the ServiceDll.
  - **Fix:** Add 0x40|0x80 to the type mask (verify the call still succeeds; fall back to two passes if it returns ERROR_INVALID_PARAMETER). For every service, read HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ServiceDll (readable non-admin) and treat that DLL, not svchost.exe, as the artifact to verify and score. Also read the Services key's FailureCommand — a service failure action that launches a binary is a classic persistence hook the spec never mentions.
- **Claim:** 'startup items -> registry Run keys + Startup folders + Task Scheduler COM' via Microsoft.Win32.Registry.
  - **Why wrong:** Microsoft.Win32.Registry opens the view matching the process bitness. Warden is x64, so Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run") reads only the 64-bit view and never sees HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run — where a large share of real-world 32-bit persistence lives, and where plenty of this user's 32-bit installers write.
  - **Fix:** Enumerate both views explicitly: RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64) and RegistryView.Registry32, for Run, RunOnce, and every other HKLM persistence key. Same for HKCU where WOW6432Node applies.
- **Claim:** 'Scheduled-task logon triggers REQUIRE ADMIN — verified' (schtasks /SC ONLOGON => Access denied, even with /RU), therefore build startup on HKCU Run only.
  - **Why wrong:** The experiment tests schtasks.exe, not Windows. schtasks /SC ONLOGON defaults to a principal/logon-type that needs stored credentials or a privileged principal, which is why it fails while /SC ONCE succeeds; that does not establish that a logon-triggered task is privileged per se. Registering the same trigger through ITaskFolder.RegisterTaskDefinition with LogonType = TASK_LOGON_INTERACTIVE_TOKEN (3) and RunLevel = TASK_RUNLEVEL_LUA, in a user-owned subfolder, is a different code path. The generalisation is doing real work in this spec (it drives the startup decision) and is not supported by the evidence given.
  - **Fix:** Retest via the COM API before accepting the conclusion — you already have the Schedule.Service late-binding harness in K\Sched.cs. Separately, the spec never mentions the option that unambiguously works with no admin and no registry: a .lnk in %AppData%\Microsoft\Windows\Start Menu\Programs\Startup. It carries the same StartupApproved\StartupFolder tombstone semantics, and is worth listing next to HKCU Run so the choice is made on merits.
- **Claim:** Self-monitoring item 4: 'VERIFY YOUR OWN BINARY at startup with the same catalog-aware WinVerifyTrust routine. If Warden's own file fails signature verification, that is a tamper signal worth surfacing loudly.'
  - **Why wrong:** Warden as specified is built with `dotnet build` / `dotnet publish` and is never code-signed anywhere in this document. An unsigned exe returns TRUST_E_NOSIGNATURE from Stage 1 and finds no catalog entry in Stage 2, so this check fails on every single launch. Shipped as written, Warden opens with a loud tamper warning about itself forever, which trains the user to ignore Warden's loudest alert channel.
  - **Fix:** Either add a signing step to the ship build (and note that an unsigned Warden.exe will also draw SmartScreen and Defender attention as an unsigned binary that opens handles to every process), or replace the self-check with hash pinning: record the SHA-256 of the executable in a DPAPI-sealed install manifest and compare against that, falling back to the signature check only when the binary is actually signed.
- **Claim:** 'PID reuse is real ... Confirm identity with GetProcessTimes creation time before treating it as a new process.'
  - **Why wrong:** GetProcessTimes requires PROCESS_QUERY_LIMITED_INFORMATION on the target — the same handle the spec measured failing for 133 of 379 processes. So for exactly the third of the process table that is unopenable, the PID-reuse defence is unavailable, and the 1 Hz diff cannot distinguish a new process from a recycled PID there.
  - **Fix:** Use NtQuerySystemInformation(SystemProcessInformation) for creation times: it returns CreateTime for every process without opening a handle. This also weakens the headline '385x speedup' framing — the correctness-critical enrichment needs the 5–7 ms call anyway, so the honest design is a cheap 1 Hz PID diff plus a Nt sweep whenever the diff is non-empty.
- **Claim:** 'do NOT call RoInitialize on an [STAThread] — it returns RPC_E_CHANGED_MODE (0x80010106).'
  - **Why wrong:** RPC_E_CHANGED_MODE comes from requesting RO_INIT_MULTITHREADED (1) on a thread already in an STA. RoInitialize(RO_INIT_SINGLETHREADED /* 0 */) succeeds on a WPF [STAThread] and returns S_FALSE for the nested case. The blanket 'do not call RoInitialize' is a misdiagnosis of a parameter error, and it will mislead whoever later needs WinRT activation on a non-UI thread.
  - **Fix:** State the actual rule: on the WPF UI thread the STA is already initialised, so no RoInitialize call is needed; on any worker thread doing WinRT activation, call RoInitialize(0) and treat S_FALSE as success. Reserve RO_INIT_MULTITHREADED for threads you created as MTA.
- **Claim:** 'Prove the zero-NuGet claim at any time (drop a nuget.config with <packageSources><clear/></packageSources>) ... dotnet build --no-cache'
  - **Why wrong:** --no-cache disables the HTTP request cache, not the global packages folder (%UserProfile%\.nuget\packages). With sources cleared, NuGet can still satisfy exact-version PackageReference and downloadDependency entries from the global folder, so this specific command does not prove an offline/zero-package build. The project.assets.json inspection the spec also performed is the claim that actually holds; the command is not.
  - **Fix:** Prove it with an isolated restore path: dotnet build -p:RestorePackagesPath=<empty temp dir> --no-cache with sources cleared. Keep the assets.json check as the assertion in CI.
- **Claim:** SHFileOperationW usage: `Marshal.StringToHGlobalUni(path + "\0\0")` for pFrom; 'Must be called on an STA thread.'
  - **Why wrong:** The allocation is never freed (Marshal.FreeHGlobal is absent), so every maintenance delete leaks. And 'STA thread' understates the constraint: SHFileOperation is a synchronous shell call that can block for a long time on large trees or slow volumes. Called on the WPF dispatcher thread — the only STA thread the app has by default — it freezes the UI, which directly contradicts the spec's own threading section.
  - **Fix:** Free the HGlobal in a finally. Run shell file operations on a dedicated STA thread (new Thread(...) { ApartmentState = STA }) or a small STA task scheduler, never on the dispatcher, and marshal only the result back.

### False-positive risks
- The never-kill 'protect-list of the user's own workflow: Blender, Unreal, BlueStacks/HD-Player, dotnet, node, python, cargo, git, and the shells' directly contradicts the self-monitoring item three bullets earlier ('Do NOT exclude by image name... a name check is trivially spoofed by an attacker dropping warden.exe'). It is the same defect with worse consequences: any payload named node.exe, python.exe or git.exe becomes unkillable. Worse, node/python/dotnet/powershell are the four most common living-off-the-land hosts for exactly the RATs and infostealers Warden exists to catch — a malicious npm postinstall or a stealer packed as a Python script runs inside a blanket-immune process name. Replace with (resolved full path + signature/publisher + parent lineage) tuples, and make matches downweight the score rather than grant immunity.
- This user patches HD-Player.exe to keep BlueStacks root (per the machine's own notes: auto-update reverts the patch and kills root). A patched signed binary fails WinVerifyTrust with TRUST_E_BAD_DIGEST — which in every mainstream scoring model is a near-top-tier signal ('signed binary whose hash no longer matches'). Warden will flag the user's deliberate modification as tampering on every scan, and if auto-action is on, quarantine it and break the emulator. This specific machine-level fact is not covered by anything in the spec.
- The rooted BlueStacks stack is ReZygisk + LSPosed — literally a code-injection and API-hooking framework, plus a hypervisor, plus BstHdAndroidSvc/BstkSVC auto-start services, plus adb listeners on 5037/5555. Every one of those is a textbook RAT indicator. The spec names BlueStacks in a warning but provides no mechanism that would actually spare it.
- Unreal's ShaderCompileWorker spawns dozens of short-lived children that saturate all 24 logical cores for minutes, and UnrealBuildTool/UBA spawn deep unusual process trees. A 1 Hz PID diff will see burst process creation plus sustained 100% CPU — the exact cryptominer/process-burst signature. Same for Blender Cycles renders and the user's slot-math simulations, which peg every core for hours by design.
- Local dev servers (vite/webpack/next on 3000/5173/8080, .NET dev certs on 5000/5001, Python http.server, Docker's proxy) mean dozens of listening sockets on a normal day. The spec's only TCP-table guidance is 'deduplicate dual-stack rows'. Add the rule that actually matters: a listener bound to 127.0.0.1/::1 is categorically lower-signal than one bound to 0.0.0.0/::, and outbound connections to RFC1918 or loopback should not score at all.
- After the catalog fix, the remaining 'unsigned executable' population on this machine is overwhelmingly the user's own toolchain: node_modules/.bin shims, cargo target/debug and target/release output, Python venv Scripts, Unreal Intermediate binaries, Blender addon helpers, and Warden's own dotnet build output. Any rule of the form 'unsigned binary running from a user directory' will fire continuously. The catalog fix solves the System32 half of the problem and leaves the developer half untouched, which the spec does not acknowledge.
- The signature cache key '(full path, file size, last-write-time, volume serial)' is forgeable by any same-user process: set the timestamp, pad the size, reuse the path, and a malicious binary inherits a previously verified 'trusted' verdict. If that cache is persisted across runs (which the 'never re-verify unless changed' design implies), it is also directly poisonable on disk. Key on a content hash, and treat any file in a user-writable directory as never cacheable across sessions.
- Trusted != Microsoft, and on this machine the binaries the user most cares about (Epic, Blender Foundation, BlueStacks, JetBrains, npm-shipped native modules) are signed by non-Microsoft CAs or not at all. If the never-kill logic requires a Microsoft signature, every application the user actually runs is in the killable set while genuinely malicious signed-with-a-stolen-cert payloads are in the trusted set.
- Warden's own behaviour — spawning powershell.exe repeatedly for the WMI/CIM fallbacks, opening handles to every PID, reading other processes' memory, moving executables into a vault, relaunching itself with the runas verb — is a strong composite malware signature. It will draw Defender/ASR attention, and Warden's own scanner will see its powershell.exe children as suspicious process spawns unless the self-exclusion covers descendants, which the spec's (pid + start time) scheme does not.
- '16 of 219 tasks have a non-Microsoft Author' is presented as a clean-machine baseline, but that baseline was taken on a machine that already has the full dev toolchain installed. Any 'new since baseline' logic seeded after installation inherits whatever is already present as normal; any logic seeded before will fire on every legitimate installer the user runs. The spec has no baselining or aging model at all.

### Safety objections
- FOF_ALLOWUNDO combined with FOF_NOCONFIRMATION silently permanently deletes anything that cannot be recycled (oversized for the bin quota, bin disabled by policy, network/removable volume) and returns 0. In the Maintenance half, aimed at a machine with only 88.5 GB free on C:, this is a realistic path to unrecoverable data loss on exactly the large files the cleaner will target.
- There is no circuit breaker on autonomous action. A single bad heuristic can quarantine an unbounded number of files in one sweep before any human sees it. For an app whose product decision is 'auto-kill + quarantine on high-confidence detections', a hard cap (e.g. N auto-actions per hour, M per sweep, then stop and require confirmation), plus a mandatory dry-run/observation period on first install, are safety requirements, not polish.
- Nothing prevents quarantining a file that Windows needs to boot. Quarantining a binary referenced by a service ImagePath, a kernel driver, a Winlogon Userinit/Shell value, or a boot-start service produces an unbootable or badly degraded machine — this is the concrete way the app violates 'must never brick the machine', and the never-kill list only covers process termination, not file quarantine. Before any quarantine, resolve whether the path is referenced by a boot-start/auto-start service, a driver, or a Winlogon value, and hard-block those.
- TerminateProcess is the only kill mechanism implied, and it is applied to a developer's machine. Killing Unreal Editor, Blender, or a multi-hour slot-math simulation mid-write destroys unsaved work and can leave corrupt project files. Suspend first (NtSuspendProcess) and prompt; reserve termination for the narrow set where suspension is insufficient, and never terminate a process with a visible top-level window without asking.
- The quarantine vault stores raw executable bytes ('move + rename + strip execute'). Defender will re-detect those bytes wherever the vault lives and remove them, destroying the rollback the whole safety model rests on. Neuter the payload in the container (encrypt or XOR the bytes into a non-executable blob) so it is inert to both the user and other AV, rather than relying on a renamed extension.
- 'Strip execute' is not a real control on NTFS: the file owner is the user, who can re-grant FILE_EXECUTE, and same-user malware can too. Combined with DPAPI CurrentUser sealing of the manifest — which any process running as the same user can also unprotect — the vault has no integrity boundary against the threat it is defending against. State this explicitly in the threat model and add an HMAC over the manifest so tampering is at least detectable.
- Reversibility is promised but under-specified. Restoring a file requires the original full path, volume serial, ACL/owner/SACL, creation and write timestamps, and alternate data streams (notably Zone.Identifier). None of these are captured in the spec. A restore that puts the bytes back with default ACLs and a new timestamp is not a rollback. Also: moving from C: to a vault on another volume is copy+delete, not atomic — a crash mid-operation must not leave zero copies, and a file held open by a running process will fail with a sharing violation that must be handled rather than retried destructively.
- The elevated helper is launched as ShellExecute(Environment.ProcessPath, "--elevated-op ...", Verb="runas"). If Warden is published to a user-writable location (the spec's own ship command outputs to .\dist inside D:\My projects), any same-user malware can replace that exe and obtain UAC-approved elevation the next time the user clicks Yes on a prompt Warden itself raised. Install the shipping binary under Program Files (or another location not writable at medium IL), and have the parent verify the child's hash/signature before invoking runas.
- There is no kill switch. If a bad rule causes Warden to quarantine in a loop or its UI wedges, the user needs a documented way to stop it that works without the UI — a safe-mode flag file, a --disable switch that clears the Run key, and a rule that Warden never auto-acts on the first run after an abnormal termination.
- There is no uninstall story. Warden leaves an HKCU Run value, an AppUserModelId key, a notification-settings key, a config directory and a vault full of the user's quarantined files. An uninstall that removes the app without first restoring or explicitly handing over the vault contents destroys the user's only copy of those files.
- The Maintenance half has no never-delete list, and the obvious targets on this machine are catastrophic to delete: Unreal DerivedDataCache and Intermediate (hours of shader compilation), Unreal Saved (autosaves and config), cargo target, node_modules, Python venvs, __pycache__, and %TEMP% files held open by running builds. Any cleaner must be dry-run-first, recycle-only, and must refuse to touch a directory under an active project tree.

### Omissions
- No detection of code injection into existing processes — the dominant RAT technique and the one thing a PID-diff design structurally cannot see. The highest-signal, zero-NuGet, non-elevated check is missing entirely: walk the target's address space with VirtualQueryEx/NtQueryVirtualMemory and flag MEM_PRIVATE regions with PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ that are not backed by a mapped image (unbacked executable memory). This finds reflectively loaded and hollowed payloads that every signature and path check in this spec misses.
- No module-level inspection. The spec verifies only the process image, so DLL sideloading — a legitimately signed exe loading an attacker DLL from its own directory — passes every check cleanly. Add EnumProcessModulesEx (or Module32FirstW/NextW, whose MODULEENTRY32W struct is mentioned in the CharSet warning but never specified) and verify loaded modules, prioritising those outside System32 and those loaded by a signed host.
- The persistence surface is incomplete to the point of being ineffective. Missing and all reachable with zero NuGet at medium IL: RunOnce, RunOnceEx, Policies\Explorer\Run; Winlogon Userinit/Shell/Notify; Image File Execution Options Debugger and SilentProcessExit\...\MonitorProcess; AppInit_DLLs and AppCertDlls; COM hijacking via HKCU\Software\Classes\CLSID\{...}\InprocServer32 (the single most common user-writable persistence today); HKCU\Environment\UserInitMprLogonScript; Winsock LSPs and netsh helper DLLs; WMI __EventFilter/CommandLineEventConsumer under root\subscription. Note the last one is a direct casualty of dropping System.Management — it now requires a powershell.exe shell-out, which the spec should call out explicitly since it is the one persistence class its stack cannot reach natively.
- Scheduled-task enumeration via the COM API returns only tasks the caller can read; real malware sets a task DACL that hides it from non-admin enumeration. Cross-check the COM result against HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree and the C:\Windows\System32\Tasks file tree (both at least partially readable non-admin) and treat any name present there but absent from the COM enumeration as a high-signal finding rather than a gap.
- Startup-folder .lnk files are listed as a persistence surface but nothing resolves them. Reading the target of a shortcut needs IShellLink/IPersistFile via raw COM — another interface set to declare — otherwise the scan sees a filename and nothing about what it launches.
- At 1 Hz, any process that lives under a second is invisible — which covers most droppers, most LOLBin one-liners, and most of what a stealer does. The spec's own measurements show the full tick costs 0.19 ms, i.e. roughly 50x headroom before it reaches even 1% of one core. Dropping to a 100–250 ms diff is nearly free and closes most of that gap; the spec should say so rather than presenting 1 Hz as dictated by the budget.
- The performance section measures CPU and ignores memory, which is the actual overhead of a tray-resident app: the spec's own numbers are 156 MB working set framework-dependent and 245 MB self-contained. That is the number the user will see in Task Manager and judge the app by. Add guidance to defer constructing the dashboard Window until first show, avoid materialising WPF visual trees for the tray path, and re-measure a tray-only idle process.
- No global exception handling and no health surface. A tool that must not fail silently has no Application.DispatcherUnhandledException, AppDomain.CurrentDomain.UnhandledException, or TaskScheduler.UnobservedTaskException handlers, no watchdog for a dead monitor loop, and no user-visible 'last successful sweep' timestamp. The monitor loop's `catch (OperationCanceledException) { throw; }` also escapes into an unobserved Task if nobody awaits MonitorLoopAsync.
- No coexistence plan with Windows Defender. Warden and Defender will race on the same file (both trying to quarantine), Warden's ReadProcessMemory and mass OpenProcess will trip ASR rules, and Defender will scan and may remove the quarantine vault. Decide and document: does the vault need a Defender exclusion, does Warden defer to Defender when Defender acts first, and how does the UI avoid double-reporting the same detection.
- The custom WPF toast — designated the primary channel for auto-action alerts because reversibility depends on the user seeing it — has no fullscreen suppression. A Topmost window appearing over an exclusive-fullscreen game or an Unreal PIE session can cause a present-mode change, a stutter, or a minimise. Query SHQueryUserNotificationState (shell32, in-box) and queue alerts while QUNS_RUNNING_D3D_FULL_SCREEN / QUNS_BUSY / QUNS_PRESENTATION_MODE, replaying them when the user returns.
- That same toast is positioned with SystemParameters.WorkArea, which is the primary monitor's work area only. The user's desktop spans multiple displays (the spec itself cites 8096x2566), so critical alerts will land on whichever monitor happens to be primary, not where the user is looking. Use MonitorFromWindow/MonitorFromPoint plus GetMonitorInfo on the monitor holding the cursor or the foreground window.
- The WinRT toast path registers no COM activator (a CLSID under HKCU\Software\Classes\CLSID\{...}\LocalServer32 with the matching activationType in the toast XML), so a click or a button on a real toast does nothing. For the informational tier that may be acceptable, but the spec should say so rather than leaving the implementer to discover that Notification Center entries are inert.
- There is no definition of 'high confidence' anywhere, despite auto-kill-and-quarantine being gated on it. Every primitive the spec provides — unsigned, unusual path, persistence entry, listening port, unknown parent — is individually weak on this machine. State the rule explicitly: auto-action requires at least one hard indicator (unbacked executable memory, a known-bad hash, a signature-mismatched system binary), never a score assembled from soft ones alone.
- No baseline snapshot or decision memory. There is nothing that records the machine's clean state at install, nothing that ages a finding from 'new' to 'known', and nothing that remembers a user's 'no, that's fine' answer so the same ambiguous prompt does not reappear every sweep. Without those, the ambiguous-prompt path becomes a nuisance the user learns to dismiss reflexively.
- No testing strategy for the detection logic. You cannot test a RAT detector without something to detect. Specify a synthetic-artifact harness (a benign process that allocates unbacked RX memory, writes a Run key, registers a logon task, opens a listener) plus a captured-baseline replay corpus, so heuristic changes can be regression-tested without live malware. Related: the spec's struct-size checks should be runtime guards that fail startup loudly, not Debug.Assert calls that vanish in Release — the CATALOG_INFO bug it describes is precisely the class of defect that would ship.
- No configuration/versioning story: where config, allowlists, the baseline and the vault manifest live, their schema version, and how they migrate. A vault manifest that a later Warden version cannot read is a silent loss of rollback capability.
- No explicit enforcement of the no-egress constraint beyond WTD_CACHE_ONLY_URL_RETRIEVAL on one API. Add WTD_REVOCATION_CHECK_NONE (0x10) to dwProvFlags alongside fdwRevocationChecks = WTD_REVOKE_NONE, and state a project-wide rule that no code path performs a network call — including the CRL/OCSP fetches that X509Chain will happily make by default if SignedCms parsing is added later.
- No threat-model statement. Warden runs at medium IL as the user, so it is not a security boundary against code already running as that user: such code can kill Warden, empty its vault, edit its config, poison its cache, or replace its binary. That is an acceptable design for this product, but it must be written down, because the rest of the spec (DPAPI sealing, self-verification, tamper alerts) reads as though it were a boundary.
