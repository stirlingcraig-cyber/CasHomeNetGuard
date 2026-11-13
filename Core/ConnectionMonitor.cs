using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace CasHomeNetGuard.Core;

/// <summary>Lists this PC's TCP connections with owning process, using GetExtendedTcpTable.</summary>
public static class ConnectionMonitor
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved = 0);

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state, localAddr; public uint localPort; public uint remoteAddr; public uint remotePort; public uint owningPid;
    }

    private static readonly string[] States =
        { "?", "Closed", "Listen", "SynSent", "SynReceived", "Established", "FinWait1", "FinWait2", "CloseWait", "Closing", "LastAck", "TimeWait", "DeleteTcb" };

    // Ports commonly used by remote-access trojans / backdoors when seen on an outbound connection
    private static readonly HashSet<int> SuspiciousRemotePorts = new() { 4444, 1337, 31337, 6667, 6697, 5552, 1604, 3460, 9001, 9030 };

    public static List<ConnectionInfo> Snapshot(ThreatIntel intel)
    {
        var list = new List<ConnectionInfo>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        IntPtr buf = IntPtr.Zero;
        try
        {
            uint rc;
            do
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                size += 4096; // table may grow between calls
                buf = Marshal.AllocHGlobal(size);
                rc = GetExtendedTcpTable(buf, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
            } while (rc == ERROR_INSUFFICIENT_BUFFER);
            if (rc != 0) return list;

            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            IntPtr row = buf + 4;
            var procCache = new Dictionary<int, (string name, string path)>();

            for (int i = 0; i < count; i++, row += rowSize)
            {
                var r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(row);
                var c = new ConnectionInfo
                {
                    LocalAddress = new IPAddress(r.localAddr).ToString(),
                    LocalPort = Port(r.localPort),
                    RemoteAddress = new IPAddress(r.remoteAddr).ToString(),
                    RemotePort = Port(r.remotePort),
                    State = r.state < States.Length ? States[r.state] : r.state.ToString(),
                    Pid = (int)r.owningPid,
                };
                if (!procCache.TryGetValue(c.Pid, out var pi)) procCache[c.Pid] = pi = ProcessInfo(c.Pid);
                (c.ProcessName, c.ProcessPath) = pi;

                if (c.State != "Listen" && !IpUtil.IsLocalOrSpecial(c.RemoteAddress))
                {
                    if (intel.IsMalicious(c.RemoteAddress)) { c.Flagged = true; c.FlagReason = "Remote IP is on a threat list"; }
                    else if (SuspiciousRemotePorts.Contains(c.RemotePort)) { c.Flagged = true; c.FlagReason = $"Port {c.RemotePort} is commonly used by backdoors"; }
                    else if (c.ProcessPath.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
                    { c.Flagged = true; c.FlagReason = "Program running from a Temp folder"; }
                }
                list.Add(c);
            }
        }
        finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return list;
    }

    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    private static (string, string) ProcessInfo(int pid)
    {
        if (pid == 0) return ("System Idle", "");
        if (pid == 4) return ("System", "");
        try
        {
            using var p = Process.GetProcessById(pid);
            string path = "";
            try { path = p.MainModule?.FileName ?? ""; } catch { }
            return (p.ProcessName, path);
        }
        catch { return ($"PID {pid}", ""); }
    }
}
