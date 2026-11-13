namespace CasHomeNetGuard.Core;

public readonly record struct PacketMeta(
    string Src, string Dst, int SrcPort, int DstPort, bool IsTcp, bool Syn, bool Ack, int Length, DateTime TimeUtc);

/// <summary>
/// Unsupervised behavioural engine. Learns each local device's normal outbound volume
/// (exponentially-weighted mean/variance per 10-second window) and flags:
///  • data-exfiltration bursts (volume far above the device's own baseline)
///  • port scans (one source probing many ports on one target)
///  • worm-style sweeps (one local device contacting many hosts on the same port)
///  • C2 beaconing (connections to one server at machine-regular intervals)
/// Memory is bounded; state for idle hosts is evicted.
/// </summary>
public sealed class AnomalyEngine
{
    private const int WindowSeconds = 10;
    private const int WarmupWindows = 30;           // ~5 minutes per device before volume alerts
    private const double Alpha = 0.05;               // EWMA smoothing
    private const long MinBurstBytes = 8_000_000;    // ignore "anomalies" under 8 MB / 10 s
    private const int PortScanThreshold = 60;
    private const int SweepThreshold = 40;
    private const int MaxHosts = 2048;

    private sealed class HostBaseline
    {
        public double Mean, Var; public int Windows; public DateTime LastActive;
    }

    private sealed class Beacon
    {
        public readonly List<DateTime> Starts = new(); public DateTime LastAlert = DateTime.MinValue;
    }

    private readonly Dictionary<string, HostBaseline> _baselines = new();
    private readonly Dictionary<string, long> _windowBytesOut = new();
    private readonly Dictionary<(string src, string dst), HashSet<int>> _portsProbed = new();
    private readonly Dictionary<(string src, int port), HashSet<string>> _sweeps = new();
    private readonly Dictionary<(string local, string remote), Beacon> _beacons = new();
    private DateTime _windowStart = DateTime.MinValue;

    public double Sensitivity { get; set; } = 4.0;
    public Action<Alert>? Raise { get; set; }
    public int TrackedHosts => _baselines.Count;

    public void Observe(in PacketMeta p)
    {
        // First packet, or system clock moved backwards: restart the window
        if (_windowStart == DateTime.MinValue || p.TimeUtc < _windowStart - TimeSpan.FromMinutes(1)) _windowStart = p.TimeUtc;
        if (p.TimeUtc - _windowStart >= TimeSpan.FromSeconds(WindowSeconds)) CloseWindow(p.TimeUtc);

        bool srcLocal = IpUtil.IsPrivateLan(p.Src), dstLocal = IpUtil.IsPrivateLan(p.Dst);

        // Volume: bytes leaving a LAN device for the internet
        if (srcLocal && !IpUtil.IsLocalOrSpecial(p.Dst))
            _windowBytesOut[p.Src] = _windowBytesOut.GetValueOrDefault(p.Src) + p.Length;

        if (p.IsTcp && p.Syn && !p.Ack)
        {
            // Port scan: many distinct destination ports from one source to one target
            if (_portsProbed.Count < 20_000)
            {
                var key = (p.Src, p.Dst);
                if (!_portsProbed.TryGetValue(key, out var ports)) _portsProbed[key] = ports = new HashSet<int>();
                if (ports.Count <= PortScanThreshold) ports.Add(p.DstPort);
            }

            // Sweep: a LAN device opening connections to many hosts on one port (worm propagation)
            if (srcLocal && _sweeps.Count < 20_000)
            {
                var key = (p.Src, p.DstPort);
                if (!_sweeps.TryGetValue(key, out var hosts)) _sweeps[key] = hosts = new HashSet<string>();
                if (hosts.Count <= SweepThreshold) hosts.Add(p.Dst);
            }

            // Beaconing: regular new connections from a LAN device to the same internet host
            if (srcLocal && !dstLocal && !IpUtil.IsLocalOrSpecial(p.Dst) && _beacons.Count < 20_000)
                TrackBeacon(p.Src, p.Dst, p.DstPort, p.TimeUtc);
        }
    }

    private void TrackBeacon(string local, string remote, int port, DateTime t)
    {
        var key = (local, remote);
        if (!_beacons.TryGetValue(key, out var b)) _beacons[key] = b = new Beacon();
        if (b.Starts.Count > 0 && (t - b.Starts[^1]).TotalSeconds < 2) return; // collapse retries
        b.Starts.Add(t);
        if (b.Starts.Count > 24) b.Starts.RemoveAt(0);
        if (b.Starts.Count < 10 || (t - b.LastAlert).TotalHours < 6) return;

        var gaps = b.Starts.Zip(b.Starts.Skip(1), (a, c) => (c - a).TotalSeconds).ToArray();
        double mean = gaps.Average();
        if (mean < 10 || mean > 3600) return;
        double sd = Math.Sqrt(gaps.Sum(g => (g - mean) * (g - mean)) / gaps.Length);
        if (sd / mean < 0.08) // jitter under 8% – far more regular than human browsing
        {
            b.LastAlert = t;
            Raise?.Invoke(new Alert
            {
                Severity = Severity.Medium, Source = AlertSource.Anomaly,
                Title = "Possible command-and-control beaconing",
                Detail = $"{local} connects to {remote}:{port} every {mean:F0}s (±{sd:F1}s) – machine-regular timing.",
                LocalIp = local, RemoteIp = remote, RemotePort = port,
                Recommendation = "Many apps poll legitimately (updates, smart-home hubs). Look up the remote IP; if the device or owner is unknown, block it."
            });
        }
    }

    private void CloseWindow(DateTime now)
    {
        foreach (var (host, bytes) in _windowBytesOut) UpdateBaseline(host, bytes, now);
        // Hosts that sent nothing this window still contribute a zero sample
        foreach (var (host, bl) in _baselines)
            if (!_windowBytesOut.ContainsKey(host) && (now - bl.LastActive).TotalMinutes < 30) Learn(bl, 0);

        foreach (var ((src, dst), ports) in _portsProbed)
            if (ports.Count >= PortScanThreshold)
                Raise?.Invoke(new Alert
                {
                    Severity = IpUtil.IsPrivateLan(src) ? Severity.High : Severity.Medium,
                    Source = AlertSource.Anomaly, Title = "Port scan detected",
                    Detail = $"{src} probed {ports.Count}+ ports on {dst} within {WindowSeconds}s.",
                    LocalIp = IpUtil.IsPrivateLan(dst) ? dst : src, RemoteIp = src,
                    HighConfidence = !IpUtil.IsLocalOrSpecial(src),
                    Recommendation = IpUtil.IsPrivateLan(src)
                        ? "A device inside your network is scanning – it may be compromised. Identify and isolate it."
                        : "An internet host is scanning you. Blocking it is safe."
                });

        foreach (var ((src, port), hosts) in _sweeps)
            if (hosts.Count >= SweepThreshold)
                Raise?.Invoke(new Alert
                {
                    Severity = port is 23 or 2323 or 22 or 5555 or 7547 ? Severity.Critical : Severity.High,
                    Source = AlertSource.Anomaly, Title = "Worm-like scanning from a home device",
                    Detail = $"{src} opened connections to {hosts.Count}+ different hosts on port {port} within {WindowSeconds}s.",
                    LocalIp = src,
                    Recommendation = "Classic sign of an infected IoT device spreading malware. Unplug or isolate this device, then factory-reset it."
                });

        _windowBytesOut.Clear(); _portsProbed.Clear(); _sweeps.Clear();
        _windowStart = now;
        Evict(now);
    }

    private void UpdateBaseline(string host, long bytes, DateTime now)
    {
        if (!_baselines.TryGetValue(host, out var bl))
        {
            if (_baselines.Count >= MaxHosts) return;
            _baselines[host] = bl = new HostBaseline();
        }
        bl.LastActive = now;

        if (bl.Windows >= WarmupWindows && bytes >= MinBurstBytes)
        {
            double sd = Math.Sqrt(Math.Max(bl.Var, 1));
            double z = (bytes - bl.Mean) / sd;
            if (z >= Sensitivity)
            {
                Raise?.Invoke(new Alert
                {
                    Severity = z > Sensitivity * 2 ? Severity.High : Severity.Medium,
                    Source = AlertSource.Anomaly, Title = "Unusual upload volume",
                    Detail = $"{host} sent {bytes / 1_048_576.0:F1} MB in {WindowSeconds}s – {z:F1}σ above its normal " +
                             $"{bl.Mean / 1_048_576.0:F2} MB.",
                    LocalIp = host,
                    Recommendation = "Could be a cloud backup or video upload. If the device shouldn't be uploading (camera, plug, TV), investigate it."
                });
                return; // don't learn from the outlier itself
            }
        }
        Learn(bl, bytes);
    }

    private static void Learn(HostBaseline bl, double x)
    {
        if (bl.Windows == 0) { bl.Mean = x; bl.Var = 0; }
        else
        {
            double diff = x - bl.Mean;
            double incr = Alpha * diff;
            bl.Mean += incr;
            bl.Var = (1 - Alpha) * (bl.Var + diff * incr);
        }
        bl.Windows++;
    }

    private void Evict(DateTime now)
    {
        foreach (var k in _baselines.Where(kv => (now - kv.Value.LastActive).TotalHours > 24).Select(kv => kv.Key).ToList())
            _baselines.Remove(k);
        foreach (var k in _beacons.Where(kv => kv.Value.Starts.Count > 0 && (now - kv.Value.Starts[^1]).TotalHours > 2).Select(kv => kv.Key).ToList())
            _beacons.Remove(k);
    }
}
