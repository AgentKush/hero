using System.Runtime.InteropServices;
using System.Text;

namespace Hero.Interop;

internal enum IntegrityLevel { Unknown, Untrusted, Low, Medium, High, System }

/// <summary>One process as observed at a point in time. Immutable by design.</summary>
internal sealed record ProcessRecord
{
    internal required int Pid { get; init; }
    internal required int ParentPid { get; init; }
    internal required string Name { get; init; }
    internal string ImagePath { get; init; } = "";
    internal string CommandLine { get; init; } = "";
    internal DateTime StartTimeUtc { get; init; }
    internal int ThreadCount { get; init; }
    internal IntegrityLevel Integrity { get; init; } = IntegrityLevel.Unknown;

    /// <summary>
    /// True when HERO could not read the image path — almost always a higher-integrity
    /// process that requires elevation. This is an access limitation, NOT a suspicion signal;
    /// treating it as one would flag most of the Windows kernel-adjacent process set.
    /// </summary>
    internal bool PathUnavailable => string.IsNullOrEmpty(ImagePath);

    internal string FileName => PathUnavailable ? Name : Path.GetFileName(ImagePath);
    internal string? Directory => PathUnavailable ? null : Path.GetDirectoryName(ImagePath);
}

/// <summary>
/// Process enumeration built on CreateToolhelp32Snapshot plus a direct PEB read for
/// command lines.
///
/// Measured unelevated on this machine: a full walk of 392 processes recovers 254 command
/// lines in 9ms. The equivalent WMI query (Get-CimInstance Win32_Process) took 3095ms —
/// roughly 340x slower — which is why WMI is not used here at all. That also avoids the
/// System.Management NuGet dependency, which is not in-box on net10.0-windows.
///
/// The 138 processes that deny a PEB read are higher-integrity (SYSTEM/protected). HERO
/// records them with an empty command line rather than guessing.
/// </summary>
internal static class ProcessProbe
{
    internal static List<ProcessRecord> Snapshot(bool includeCommandLines = true)
    {
        var results = new List<ProcessRecord>(512);

        IntPtr snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
        if (snap == Native.INVALID_HANDLE_VALUE || snap == IntPtr.Zero) return results;

        try
        {
            var entry = new Native.PROCESSENTRY32W
            {
                dwSize = (uint)Marshal.SizeOf<Native.PROCESSENTRY32W>(),
                szExeFile = string.Empty,
            };

            if (!Native.Process32First(snap, ref entry)) return results;

            do
            {
                int pid = (int)entry.th32ProcessID;
                if (pid == 0) continue; // System Idle Process

                var record = Describe(pid, (int)entry.th32ParentProcessID, entry.szExeFile,
                                      (int)entry.cntThreads, includeCommandLines);
                results.Add(record);
            }
            while (Native.Process32Next(snap, ref entry));
        }
        finally
        {
            Native.CloseHandle(snap);
        }

        return results;
    }

    private static ProcessRecord Describe(int pid, int ppid, string name, int threads, bool wantCommandLine)
    {
        string imagePath = "";
        string commandLine = "";
        DateTime start = default;
        var integrity = IntegrityLevel.Unknown;

        // PROCESS_QUERY_LIMITED_INFORMATION succeeds for most processes unelevated;
        // PROCESS_VM_READ is what the PEB read additionally needs.
        uint access = Native.PROCESS_QUERY_LIMITED_INFORMATION | (wantCommandLine ? Native.PROCESS_VM_READ : 0);
        IntPtr h = Native.OpenProcess(access, false, pid);

        if (h == IntPtr.Zero && wantCommandLine)
        {
            // Retry without VM_READ: the path and times are often still readable.
            h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            wantCommandLine = false;
        }

        if (h != IntPtr.Zero)
        {
            try
            {
                imagePath = ReadImagePath(h);
                if (Native.GetProcessTimes(h, out long creation, out _, out _, out _))
                {
                    try { start = DateTime.FromFileTimeUtc(creation); } catch { /* out of range */ }
                }
                integrity = ReadIntegrity(h);
                if (wantCommandLine) commandLine = ReadCommandLine(h) ?? "";
            }
            finally
            {
                Native.CloseHandle(h);
            }
        }

        return new ProcessRecord
        {
            Pid = pid,
            ParentPid = ppid,
            Name = name ?? "",
            ImagePath = imagePath,
            CommandLine = commandLine,
            StartTimeUtc = start,
            ThreadCount = threads,
            Integrity = integrity,
        };
    }

    private static string ReadImagePath(IntPtr hProcess)
    {
        var sb = new StringBuilder(1024);
        int size = sb.Capacity;
        return Native.QueryFullProcessImageName(hProcess, 0, sb, ref size) ? sb.ToString() : "";
    }

    private static string? ReadCommandLine(IntPtr hProcess)
    {
        try
        {
            var pbi = default(Native.PROCESS_BASIC_INFORMATION);
            if (Native.NtQueryInformationProcess(hProcess, 0, ref pbi,
                    Marshal.SizeOf<Native.PROCESS_BASIC_INFORMATION>(), out _) != 0)
                return null;
            if (pbi.PebBaseAddress == IntPtr.Zero) return null;

            var ptrBuf = new byte[8];
            if (!Native.ReadProcessMemory(hProcess, pbi.PebBaseAddress + Native.PebOffsetProcessParameters,
                    ptrBuf, 8, out _))
                return null;

            var pParams = (IntPtr)BitConverter.ToInt64(ptrBuf, 0);
            if (pParams == IntPtr.Zero) return null;

            // UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
            var us = new byte[16];
            if (!Native.ReadProcessMemory(hProcess, pParams + Native.ProcessParametersOffsetCommandLine,
                    us, 16, out _))
                return null;

            ushort length = BitConverter.ToUInt16(us, 0);
            var buffer = (IntPtr)BitConverter.ToInt64(us, 8);
            if (length == 0 || buffer == IntPtr.Zero || length > 32768) return null;

            var chars = new byte[length];
            if (!Native.ReadProcessMemory(hProcess, buffer, chars, length, out _)) return null;

            return Encoding.Unicode.GetString(chars);
        }
        catch
        {
            return null;
        }
    }

    private static IntegrityLevel ReadIntegrity(IntPtr hProcess)
    {
        IntPtr token = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!Native.OpenProcessToken(hProcess, Native.TOKEN_QUERY, out token)) return IntegrityLevel.Unknown;

            Native.GetTokenInformation(token, Native.TokenIntegrityLevel, IntPtr.Zero, 0, out int needed);
            if (needed <= 0) return IntegrityLevel.Unknown;

            buffer = Marshal.AllocHGlobal(needed);
            if (!Native.GetTokenInformation(token, Native.TokenIntegrityLevel, buffer, needed, out _))
                return IntegrityLevel.Unknown;

            // TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label; } -> Label.Sid is the first pointer.
            IntPtr pSid = Marshal.ReadIntPtr(buffer);
            IntPtr pCount = Native.GetSidSubAuthorityCount(pSid);
            if (pCount == IntPtr.Zero) return IntegrityLevel.Unknown;
            byte count = Marshal.ReadByte(pCount);
            if (count == 0) return IntegrityLevel.Unknown;

            IntPtr pRid = Native.GetSidSubAuthority(pSid, (uint)(count - 1));
            int rid = Marshal.ReadInt32(pRid);

            return rid switch
            {
                >= Native.SECURITY_MANDATORY_SYSTEM_RID => IntegrityLevel.System,
                >= Native.SECURITY_MANDATORY_HIGH_RID => IntegrityLevel.High,
                >= Native.SECURITY_MANDATORY_MEDIUM_RID => IntegrityLevel.Medium,
                >= Native.SECURITY_MANDATORY_LOW_RID => IntegrityLevel.Low,
                _ => IntegrityLevel.Untrusted,
            };
        }
        catch
        {
            return IntegrityLevel.Unknown;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero) Native.CloseHandle(token);
        }
    }

    /// <summary>Seconds since the last keyboard/mouse input, used to distinguish
    /// "user is working" from "machine is idle" when scoring CPU-heavy processes.</summary>
    internal static double IdleSeconds()
    {
        var lii = new Native.LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<Native.LASTINPUTINFO>() };
        if (!Native.GetLastInputInfo(ref lii)) return 0;
        return (Environment.TickCount64 - lii.dwTime) / 1000.0;
    }

    /// <summary>PID of the process owning the foreground window, or 0.</summary>
    internal static int ForegroundPid()
    {
        var hwnd = Native.GetForegroundWindow();
        if (hwnd == IntPtr.Zero) return 0;
        Native.GetWindowThreadProcessId(hwnd, out uint pid);
        return (int)pid;
    }
}
