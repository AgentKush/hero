using System.Net;
using System.Runtime.InteropServices;

namespace Hero.Interop;

internal enum TcpState
{
    Closed = 1, Listen = 2, SynSent = 3, SynReceived = 4, Established = 5,
    FinWait1 = 6, FinWait2 = 7, CloseWait = 8, Closing = 9, LastAck = 10,
    TimeWait = 11, DeleteTcb = 12,
}

internal sealed record Connection
{
    internal required int Pid { get; init; }
    internal required string Protocol { get; init; }   // "TCP" | "UDP"
    internal required IPAddress LocalAddress { get; init; }
    internal required int LocalPort { get; init; }
    internal IPAddress? RemoteAddress { get; init; }
    internal int RemotePort { get; init; }
    internal TcpState State { get; init; }

    internal bool IsListening => State == TcpState.Listen;

    /// <summary>
    /// True when the peer is outside this machine and outside the RFC1918/link-local
    /// ranges — i.e. genuinely off-network. Beaconing analysis only considers these,
    /// because a developer machine chatters constantly to localhost and the LAN.
    /// </summary>
    internal bool IsExternal
    {
        get
        {
            if (RemoteAddress is null) return false;
            if (IPAddress.IsLoopback(RemoteAddress)) return false;

            // A listener has no peer. Windows reports its remote endpoint as the unspecified
            // address (0.0.0.0 or ::) with port 0, and treating that as a real destination made
            // lsass, services and spoolsv appear to be talking to something external — with the
            // reason "port 0 is an unusual privileged port", which is doubly wrong: port 0 is not
            // a port at all.
            if (RemotePort == 0) return false;
            if (RemoteAddress.Equals(IPAddress.Any) || RemoteAddress.Equals(IPAddress.IPv6Any)) return false;

            var b = RemoteAddress.GetAddressBytes();
            if (RemoteAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (b[0] == 0 || b[0] == 10 || b[0] == 127) return false;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
                if (b[0] == 192 && b[1] == 168) return false;
                if (b[0] == 169 && b[1] == 254) return false;   // link-local
                if (b[0] >= 224) return false;                   // multicast / reserved
                return true;
            }
            if (RemoteAddress.IsIPv6LinkLocal || RemoteAddress.IsIPv6SiteLocal) return false;
            if (b[0] == 0xfd || b[0] == 0xfc) return false;      // unique local
            if (b[0] == 0xff) return false;                       // multicast
            return true;
        }
    }

    /// <summary>Stable identity of the peer, used as the key for beacon interval tracking.</summary>
    internal string PeerKey => RemoteAddress is null ? "" : $"{RemoteAddress}:{RemotePort}";
}

/// <summary>
/// Per-process socket tables via GetExtendedTcpTable / GetExtendedUdpTable.
/// Verified unelevated: returns all 177 TCP rows on this machine including owning PIDs,
/// with no administrator rights required.
/// </summary>
internal static class NetworkProbe
{
    internal static List<Connection> Snapshot()
    {
        var list = new List<Connection>(256);
        ReadTcp4(list);
        ReadTcp6(list);
        ReadUdp4(list);
        ReadUdp6(list);
        return list;
    }

    private static void ReadTcp4(List<Connection> into)
    {
        int size = 0;
        Native.GetExtendedTcpTable(IntPtr.Zero, ref size, true, Native.AF_INET, Native.TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (Native.GetExtendedTcpTable(buf, ref size, true, Native.AF_INET, Native.TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            int stride = Marshal.SizeOf<Native.MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++, row += stride)
            {
                var r = Marshal.PtrToStructure<Native.MIB_TCPROW_OWNER_PID>(row);
                into.Add(new Connection
                {
                    Pid = (int)r.dwOwningPid,
                    Protocol = "TCP",
                    LocalAddress = new IPAddress(r.dwLocalAddr),
                    LocalPort = NetworkPort(r.dwLocalPort),
                    RemoteAddress = new IPAddress(r.dwRemoteAddr),
                    RemotePort = NetworkPort(r.dwRemotePort),
                    State = (TcpState)r.dwState,
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void ReadTcp6(List<Connection> into)
    {
        int size = 0;
        Native.GetExtendedTcpTable(IntPtr.Zero, ref size, true, Native.AF_INET6, Native.TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (Native.GetExtendedTcpTable(buf, ref size, true, Native.AF_INET6, Native.TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            int stride = Marshal.SizeOf<Native.MIB_TCP6ROW_OWNER_PID>();
            for (int i = 0; i < count; i++, row += stride)
            {
                var r = Marshal.PtrToStructure<Native.MIB_TCP6ROW_OWNER_PID>(row);
                into.Add(new Connection
                {
                    Pid = (int)r.dwOwningPid,
                    Protocol = "TCP",
                    LocalAddress = new IPAddress(r.ucLocalAddr, r.dwLocalScopeId),
                    LocalPort = NetworkPort(r.dwLocalPort),
                    RemoteAddress = new IPAddress(r.ucRemoteAddr, r.dwRemoteScopeId),
                    RemotePort = NetworkPort(r.dwRemotePort),
                    State = (TcpState)r.dwState,
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void ReadUdp4(List<Connection> into)
    {
        int size = 0;
        Native.GetExtendedUdpTable(IntPtr.Zero, ref size, true, Native.AF_INET, Native.UDP_TABLE_OWNER_PID, 0);
        if (size <= 0) return;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (Native.GetExtendedUdpTable(buf, ref size, true, Native.AF_INET, Native.UDP_TABLE_OWNER_PID, 0) != 0) return;
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            int stride = Marshal.SizeOf<Native.MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < count; i++, row += stride)
            {
                var r = Marshal.PtrToStructure<Native.MIB_UDPROW_OWNER_PID>(row);
                into.Add(new Connection
                {
                    Pid = (int)r.dwOwningPid,
                    Protocol = "UDP",
                    LocalAddress = new IPAddress(r.dwLocalAddr),
                    LocalPort = NetworkPort(r.dwLocalPort),
                    RemoteAddress = null,
                    RemotePort = 0,
                    State = 0,
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void ReadUdp6(List<Connection> into)
    {
        int size = 0;
        Native.GetExtendedUdpTable(IntPtr.Zero, ref size, true, Native.AF_INET6, Native.UDP_TABLE_OWNER_PID, 0);
        if (size <= 0) return;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (Native.GetExtendedUdpTable(buf, ref size, true, Native.AF_INET6, Native.UDP_TABLE_OWNER_PID, 0) != 0) return;
            int count = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            int stride = Marshal.SizeOf<Native.MIB_UDP6ROW_OWNER_PID>();
            for (int i = 0; i < count; i++, row += stride)
            {
                var r = Marshal.PtrToStructure<Native.MIB_UDP6ROW_OWNER_PID>(row);
                into.Add(new Connection
                {
                    Pid = (int)r.dwOwningPid,
                    Protocol = "UDP",
                    LocalAddress = new IPAddress(r.ucLocalAddr, r.dwLocalScopeId),
                    LocalPort = NetworkPort(r.dwLocalPort),
                    RemoteAddress = null,
                    RemotePort = 0,
                    State = 0,
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    /// <summary>
    /// The table stores ports as a DWORD holding the port in network byte order in the
    /// low two bytes. Getting this wrong yields nonsense port numbers such as 20480 for 80.
    /// </summary>
    private static int NetworkPort(uint raw) => ((int)(raw & 0xFF) << 8) | (int)((raw >> 8) & 0xFF);
}
