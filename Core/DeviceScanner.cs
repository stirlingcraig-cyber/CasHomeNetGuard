using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace CasHomeNetGuard.Core;

public sealed record NetworkContext(string LocalIp, string SubnetMask, string Gateway, string InterfaceName, uint NetworkBase, int HostCount);

/// <summary>
/// Discovers every device on the home LAN (ping sweep + ARP table + SSDP/UPnP),
/// identifies vendor/category, probes ports that IoT malware exploits and rates each device's risk.
/// Only probes the local private subnet – never external hosts.
/// </summary>
public sealed class DeviceScanner
{
    [DllImport("iphlpapi.dll")] private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPNETROW
    {
        public int dwIndex; public int dwPhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] bPhysAddr;
        public uint dwAddr; public int dwType;
    }

    public sealed record PortRisk(int Port, string Service, DeviceRisk Risk, string Advice);

    public static readonly IReadOnlyList<PortRisk> RiskyPorts = new List<PortRisk>
    {
        new(23,    "Telnet",              DeviceRisk.High,   "Telnet is the #1 way Mirai-type botnets take over IoT devices. Disable it or replace the device."),
        new(2323,  "Telnet (alt)",        DeviceRisk.High,   "Alternate Telnet port targeted by IoT botnets. Disable it."),
        new(5555,  "Android Debug (ADB)", DeviceRisk.High,   "Open ADB gives anyone on the network full control (common on cheap TV boxes). Turn off developer/network debugging."),
        new(5900,  "VNC",                 DeviceRisk.High,   "Remote desktop without strong auth. Disable or set a strong password."),
        new(37777, "Dahua DVR service",   DeviceRisk.High,   "Dahua NVR/DVR port with a history of auth-bypass flaws. Update firmware; never port-forward it."),
        new(34567, "Xiongmai DVR service",DeviceRisk.High,   "XMEye/Xiongmai DVR port with known backdoors. Update or replace; never expose to the internet."),
        new(9527,  "Xiongmai debug shell",DeviceRisk.High,   "Debug console on Xiongmai devices allows command execution. Replace or isolate the device."),
        new(21,    "FTP",                 DeviceRisk.Medium, "Passwords travel in clear text. Disable FTP or use SFTP."),
        new(554,   "RTSP camera stream",  DeviceRisk.Medium, "Camera video stream. Make sure it requires a password and isn't port-forwarded."),
        new(1883,  "MQTT (unencrypted)",  DeviceRisk.Medium, "Smart-home message bus without TLS. Require authentication."),
        new(7547,  "TR-069 management",   DeviceRisk.Medium, "ISP remote management port, exploited by Mirai in 2016. Should not be reachable from the internet."),
        new(3389,  "Remote Desktop",      DeviceRisk.Medium, "Ensure Network Level Authentication and a strong password; never port-forward RDP."),
        new(445,   "Windows file sharing",DeviceRisk.Low,    "Normal for PCs/NAS. Make sure SMBv1 is disabled."),
        new(22,    "SSH",                 DeviceRisk.Low,    "Fine if the password is strong or keys are used. Change any default password."),
        new(80,    "Web admin (HTTP)",    DeviceRisk.Low,    "Device admin page over plain HTTP. Change default credentials."),
        new(8080,  "Web admin (HTTP alt)",DeviceRisk.Low,    "Secondary admin page. Change default credentials."),
        new(443,   "Web (HTTPS)",         DeviceRisk.Low,    "Encrypted web interface."),
        new(8443,  "Web (HTTPS alt)",     DeviceRisk.Low,    "Encrypted admin interface."),
        new(5000,  "UPnP / NAS admin",    DeviceRisk.Low,    "Often a NAS or UPnP service."),
        new(6668,  "Tuya local control",  DeviceRisk.Low,    "Tuya/Smart Life device local API."),
        new(8009,  "Google Cast",         DeviceRisk.Low,    "Chromecast / Google speaker control port."),
    };

    // Best-effort OUI → vendor map for common home & IoT brands.
    private static readonly Dictionary<string, string> Oui = BuildOui();

    public event Action<string>? Progress;
    public string? LastUpnpGateway { get; private set; }

    public static NetworkContext? DetectNetwork()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                     .OrderByDescending(n => n.GetIPProperties().GatewayAddresses.Any()))
        {
            var props = nic.GetIPProperties();
            var gw = props.GatewayAddresses.Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            var uni = props.UnicastAddresses.FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);
            if (gw == null || uni == null || !IpUtil.IsPrivateLan(uni.Address.ToString())) continue;

            int prefix = Math.Max(uni.PrefixLength, 22); // cap sweep at 1022 hosts
            uint ip = IpUtil.ToUInt(uni.Address), mask = IpUtil.MaskFor(prefix);
            return new NetworkContext(uni.Address.ToString(), IpUtil.FromUInt(mask).ToString(), gw.ToString(),
                nic.Name, ip & mask, (int)(~mask) - 1);
        }
        return null;
    }

    public async Task<List<DeviceInfo>> ScanAsync(IDictionary<string, DeviceInfo> known, CancellationToken ct)
    {
        var net = DetectNetwork() ?? throw new InvalidOperationException("No active private network connection found.");
        Progress?.Invoke($"Sweeping {net.HostCount} addresses on {IpUtil.FromUInt(net.NetworkBase)} ({net.InterfaceName})…");

        // 1. Ping sweep (also populates the ARP cache for devices that ignore ping)
        var alive = new ConcurrentDictionary<string, bool>();
        using (var sem = new SemaphoreSlim(64))
        {
            var tasks = Enumerable.Range(1, net.HostCount).Select(async i =>
            {
                await sem.WaitAsync(ct);
                try
                {
                    var ip = IpUtil.FromUInt(net.NetworkBase + (uint)i).ToString();
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(ip, 700);
                    if (reply.Status == IPStatus.Success) alive[ip] = true;
                }
                catch { }
                finally { sem.Release(); }
            });
            await Task.WhenAll(tasks);
        }

        // 2. SSDP / UPnP discovery
        Progress?.Invoke("Listening for UPnP / smart-home announcements…");
        var upnp = await SsdpDiscoverAsync(TimeSpan.FromSeconds(3), ct);

        // 3. Merge with ARP table
        var arp = ReadArpTable();
        var ips = alive.Keys.Union(arp.Keys).Union(upnp.Keys)
            .Where(ip => SameSubnet(ip, net))
            .Append(net.LocalIp)
            .Distinct().ToList();

        // 4. Fingerprint each device
        var results = new ConcurrentBag<DeviceInfo>();
        int done = 0;
        using (var sem = new SemaphoreSlim(16))
        {
            await Task.WhenAll(ips.Select(async ip =>
            {
                await sem.WaitAsync(ct);
                try
                {
                    known.TryGetValue(ip, out var prev);
                    var d = new DeviceInfo
                    {
                        Ip = ip,
                        Mac = arp.GetValueOrDefault(ip) ?? prev?.Mac ?? "",
                        IsGateway = ip == net.Gateway,
                        IsThisPc = ip == net.LocalIp,
                        FirstSeenUtc = prev?.FirstSeenUtc ?? DateTime.UtcNow,
                        Trusted = prev?.Trusted ?? false,
                        Nickname = prev?.Nickname ?? "",
                    };
                    if (d.IsThisPc) d.Mac = LocalMac(net.InterfaceName);
                    d.Vendor = VendorFor(d.Mac);
                    d.HostName = await ReverseDnsAsync(ip);
                    d.OpenPorts = await ProbePortsAsync(ip, ct);
                    if (upnp.TryGetValue(ip, out var server)) d.Findings.Add("UPnP: " + server);
                    Assess(d, upnp.ContainsKey(ip));
                    results.Add(d);
                }
                finally
                {
                    sem.Release();
                    Progress?.Invoke($"Fingerprinted {Interlocked.Increment(ref done)}/{ips.Count} devices…");
                }
            }));
        }
        return results.OrderBy(d => IpUtil.TryToUInt(d.Ip, out var v) ? v : 0).ToList();
    }

    private static bool SameSubnet(string ip, NetworkContext net)
    {
        if (!IpUtil.TryToUInt(ip, out var v) || !IpUtil.TryToUInt(net.SubnetMask, out var m)) return false;
        return (v & m) == net.NetworkBase && v != net.NetworkBase && v != (net.NetworkBase | ~m);
    }

    internal static void Assess(DeviceInfo d, bool advertisesUpnp)
    {
        var risk = DeviceRisk.Low;
        foreach (var p in d.OpenPorts)
        {
            var pr = RiskyPorts.FirstOrDefault(r => r.Port == p);
            if (pr == null) continue;
            if (pr.Risk > DeviceRisk.Low || d.Findings.Count < 12) d.Findings.Add($"Port {p} ({pr.Service}): {pr.Advice}");
            if (pr.Risk > risk) risk = pr.Risk;
        }
        if (d.IsGateway && advertisesUpnp)
        {
            d.Findings.Add("Router advertises UPnP: any infected device can silently open ports to the internet. Consider disabling UPnP in router settings.");
            if (risk < DeviceRisk.Medium) risk = DeviceRisk.Medium;
        }
        if (IsRandomisedMac(d.Mac)) d.Findings.Add("Uses a private (randomised) MAC – typical of modern phones, tablets and laptops.");

        d.Category = Categorise(d);
        // Admin pages on PCs/phones are normal; on cameras/DVRs plain HTTP admin is more concerning
        if (d.Category == "Camera / DVR" && d.OpenPorts.Contains(80) && risk < DeviceRisk.Medium) risk = DeviceRisk.Medium;
        d.Risk = risk;
        d.LastSeenUtc = DateTime.UtcNow;
    }

    private static string Categorise(DeviceInfo d)
    {
        var v = d.Vendor.ToLowerInvariant(); var ports = d.OpenPorts; var host = d.HostName.ToLowerInvariant();
        if (d.IsThisPc) return "This PC";
        if (d.IsGateway) return "Router / Gateway";
        if (ports.Contains(554) || ports.Contains(37777) || ports.Contains(34567) || v.Contains("hikvision") || v.Contains("dahua") || v.Contains("wyze") || host.Contains("cam"))
            return "Camera / DVR";
        if (v.Contains("synology") || v.Contains("qnap") || host.Contains("nas")) return "NAS / Storage";
        if (v.Contains("sonos") || ports.Contains(8009) || v.Contains("google")) return "Speaker / Cast";
        if (v.Contains("roku") || v.Contains("lg ") || host.Contains("tv")) return "TV / Streaming";
        if (v.Contains("amazon")) return "Echo / Ring / Fire";
        if (v.Contains("philips hue") || v.Contains("espressif") || ports.Contains(6668) || ports.Contains(1883) || v.Contains("xiaomi") || v.Contains("tuya"))
            return "Smart-home / IoT";
        if (v.Contains("raspberry")) return "Raspberry Pi";
        if (v.Contains("apple") || IsRandomisedMac(d.Mac)) return "Phone / Tablet / Laptop";
        if (ports.Contains(3389) || ports.Contains(445)) return "Windows PC";
        if (v.Contains("tp-link") || v.Contains("ubiquiti") || v.Contains("netgear")) return "Network equipment";
        return "Unknown";
    }

    private static async Task<List<int>> ProbePortsAsync(string ip, CancellationToken ct)
    {
        var open = new ConcurrentBag<int>();
        await Task.WhenAll(RiskyPorts.Select(async pr =>
        {
            try
            {
                using var client = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(450);
                await client.ConnectAsync(ip, pr.Port, cts.Token);
                if (client.Connected) open.Add(pr.Port);
            }
            catch { }
        }));
        return open.OrderBy(p => p).ToList();
    }

    private static async Task<string> ReverseDnsAsync(string ip)
    {
        try
        {
            var t = Dns.GetHostEntryAsync(ip);
            if (await Task.WhenAny(t, Task.Delay(1200)) == t && t.Result.HostName != ip) return t.Result.HostName;
        }
        catch { }
        return "";
    }

    private static async Task<Dictionary<string, string>> SsdpDiscoverAsync(TimeSpan listen, CancellationToken ct)
    {
        var found = new Dictionary<string, string>();
        try
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
            var msg = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n");
            var ep = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
            await udp.SendAsync(msg, msg.Length, ep);
            await udp.SendAsync(msg, msg.Length, ep);

            var until = DateTime.UtcNow + listen;
            while (DateTime.UtcNow < until && !ct.IsCancellationRequested)
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(until - DateTime.UtcNow);
                try
                {
                    var res = await udp.ReceiveAsync(cts.Token);
                    var text = Encoding.ASCII.GetString(res.Buffer);
                    var server = text.Split("\r\n").FirstOrDefault(l => l.StartsWith("SERVER:", StringComparison.OrdinalIgnoreCase))?[7..].Trim() ?? "UPnP device";
                    found.TryAdd(res.RemoteEndPoint.Address.ToString(), server.Length > 80 ? server[..80] : server);
                }
                catch (OperationCanceledException) { break; }
            }
        }
        catch (Exception ex) { EngineLog.Write("SCAN", "SSDP discovery failed: " + ex.Message); }
        return found;
    }

    private static Dictionary<string, string> ReadArpTable()
    {
        var map = new Dictionary<string, string>();
        int size = 0;
        GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size <= 0) return map;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buf, ref size, false) != 0) return map;
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_IPNETROW>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(buf + 4 + i * rowSize);
                if (row.dwType == 2 || row.dwPhysAddrLen != 6) continue; // invalid entry
                var mac = string.Join(":", row.bPhysAddr.Take(6).Select(b => b.ToString("X2")));
                if (mac is "00:00:00:00:00:00" or "FF:FF:FF:FF:FF:FF") continue;
                map[new IPAddress(row.dwAddr).ToString()] = mac;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return map;
    }

    private static string LocalMac(string nicName)
    {
        var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name == nicName);
        var b = nic?.GetPhysicalAddress().GetAddressBytes();
        return b is { Length: 6 } ? string.Join(":", b.Select(x => x.ToString("X2"))) : "";
    }

    public static bool IsRandomisedMac(string mac) =>
        mac.Length >= 2 && "26AE".Contains(char.ToUpperInvariant(mac[1]));

    public static string VendorFor(string mac)
    {
        if (string.IsNullOrEmpty(mac) || mac.Length < 8) return "Unknown";
        if (IsRandomisedMac(mac)) return "Private MAC";
        return Oui.TryGetValue(mac[..8].ToUpperInvariant(), out var v) ? v : "Unknown";
    }

    private static Dictionary<string, string> BuildOui()
    {
        var d = new Dictionary<string, string>();
        void Add(string vendor, params string[] prefixes) { foreach (var p in prefixes) d[p] = vendor; }
        Add("Raspberry Pi", "B8:27:EB", "DC:A6:32", "E4:5F:01", "28:CD:C1", "D8:3A:DD", "2C:CF:67");
        Add("Espressif (ESP IoT module)", "24:0A:C4", "30:AE:A4", "84:F3:EB", "A4:CF:12", "24:62:AB", "BC:DD:C2", "CC:50:E3",
            "3C:71:BF", "8C:AA:B5", "EC:FA:BC", "60:01:94", "5C:CF:7F", "18:FE:34", "2C:3A:E8", "48:3F:DA", "C4:4F:33", "7C:9E:BD");
        Add("Philips Hue (Signify)", "00:17:88", "EC:B5:FA");
        Add("Sonos", "00:0E:58", "5C:AA:FD", "94:9F:3E", "48:A6:B8", "B8:E9:37", "78:28:CA");
        Add("Synology", "00:11:32");
        Add("QNAP", "24:5E:BE", "00:08:9B");
        Add("Hikvision", "44:19:B6", "BC:AD:28", "C0:56:E3", "4C:BD:8F", "28:57:BE", "54:C4:15");
        Add("Dahua", "3C:EF:8C", "90:02:A9", "E0:50:8B", "38:AF:29");
        Add("Amazon", "44:65:0D", "F0:27:2D", "74:C2:46", "68:54:FD", "FC:65:DE", "0C:47:C9", "84:D6:D0", "A0:02:DC", "40:B4:CD");
        Add("Google", "F4:F5:D8", "F4:F5:E8", "54:60:09", "1C:F2:9A", "20:DF:B9", "3C:5A:B4", "48:D6:D5");
        Add("Ubiquiti", "24:A4:3C", "80:2A:A8", "F0:9F:C2", "78:8A:20", "FC:EC:DA", "74:83:C2");
        Add("Roku", "B0:A7:37", "DC:3A:5E", "08:05:81", "CC:6D:A0");
        Add("Xiaomi", "28:6C:07", "64:09:80", "78:11:DC", "50:EC:50", "7C:49:EB");
        Add("Wyze", "2C:AA:8E", "D0:3F:27");
        Add("TP-Link", "50:C7:BF", "98:DA:C4", "1C:3B:F3", "B0:4E:26", "54:AF:97", "60:32:B1", "14:EB:B6", "AC:84:C6");
        Add("Netgear", "A0:40:A0", "9C:3D:CF", "28:C6:8E", "C0:3F:0E");
        Add("Apple", "F0:18:98", "3C:22:FB", "A4:83:E7", "AC:BC:32", "BC:D0:74", "F4:0F:24");
        Add("Samsung", "8C:77:12", "F8:04:2E", "CC:6E:A4");
        Add("LG Electronics", "A8:23:FE", "78:5D:C8");
        Add("Sony", "FC:F1:52", "AC:9B:0A");
        Add("Intel (PC/laptop Wi-Fi)", "A4:34:D9", "8C:8D:28", "3C:A9:F4", "48:51:B7");
        return d;
    }

    public static void SaveInventory(IEnumerable<DeviceInfo> devices)
    {
        AppPaths.Ensure();
        File.WriteAllText(AppPaths.DevicesFile, JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true }));
    }

    public static List<DeviceInfo> LoadInventory()
    {
        try { return File.Exists(AppPaths.DevicesFile) ? JsonSerializer.Deserialize<List<DeviceInfo>>(File.ReadAllText(AppPaths.DevicesFile)) ?? new() : new(); }
        catch { return new(); }
    }
}
