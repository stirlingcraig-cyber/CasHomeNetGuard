using System.Net;
using System.Net.Sockets;

namespace CasHomeNetGuard.Core;

public static class IpUtil
{
    public static bool TryToUInt(string s, out uint value)
    {
        value = 0;
        if (!IPAddress.TryParse(s.Trim(), out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) return false;
        value = ToUInt(ip);
        return true;
    }

    public static uint ToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static IPAddress FromUInt(uint v) =>
        new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    public static uint MaskFor(int prefix) => prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);

    /// <summary>RFC1918, loopback, link-local, CGNAT, multicast and broadcast – never auto-blocked.</summary>
    public static bool IsLocalOrSpecial(string ip)
    {
        if (!TryToUInt(ip, out var v)) return true; // IPv6 / unparseable: treat as special
        return InRange(v, "10.0.0.0", 8) || InRange(v, "172.16.0.0", 12) || InRange(v, "192.168.0.0", 16)
            || InRange(v, "127.0.0.0", 8) || InRange(v, "169.254.0.0", 16) || InRange(v, "100.64.0.0", 10)
            || InRange(v, "224.0.0.0", 4) || InRange(v, "0.0.0.0", 8) || v == uint.MaxValue;
    }

    public static bool IsPrivateLan(string ip)
    {
        if (!TryToUInt(ip, out var v)) return false;
        return InRange(v, "10.0.0.0", 8) || InRange(v, "172.16.0.0", 12) || InRange(v, "192.168.0.0", 16);
    }

    private static bool InRange(uint v, string net, int prefix)
    {
        TryToUInt(net, out var n);
        var m = MaskFor(prefix);
        return (v & m) == (n & m);
    }
}
