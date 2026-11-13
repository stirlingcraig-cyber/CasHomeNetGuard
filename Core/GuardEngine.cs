using System.Collections.Concurrent;
using System.Threading.Channels;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace CasHomeNetGuard.Core;

public sealed record AdapterChoice(string Name, string Description);

/// <summary>
/// Orchestrates every protection layer: packet capture (Npcap), threat intelligence,
/// signature DPI, behavioural anomaly detection, connection monitoring, scheduled
/// device audits, and the automatic-response policy.
/// </summary>
public sealed class GuardEngine : IDisposable
{
    public Settings Settings { get; }
    public ThreatIntel Intel { get; } = new();
    public AlertStore Alerts { get; } = new();
    public FirewallManager Firewall { get; } = new();
    public DeviceScanner Scanner { get; } = new();
    private readonly AnomalyEngine _anomaly = new();

    private ILiveDevice? _device;
    private readonly Channel<RawCapture> _queue = Channel.CreateBounded<RawCapture>(
        new BoundedChannelOptions(50_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
    private CancellationTokenSource _cts = new();
    private System.Threading.Timer? _secondTimer, _connTimer, _feedTimer, _scanTimer;

    // Live statistics
    private long _bytes, _packets, _totalPackets, _droppedParse;
    private readonly ConcurrentQueue<TrafficSample> _history = new();
    private readonly ConcurrentDictionary<string, long> _hostBytes = new();
    private readonly ConcurrentDictionary<string, DeviceInfo> _devices = new();

    public bool CaptureAvailable { get; private set; }
    public string CaptureStatus { get; private set; } = "Not started";
    public string? ActiveAdapter => _device?.Description;
    public long TotalPackets => Interlocked.Read(ref _totalPackets);
    public DateTime StartedUtc { get; } = DateTime.UtcNow;
    public bool ScanInProgress { get; private set; }
    public DateTime? LastScanUtc { get; private set; }
    public int AnomalyHostsTracked => _anomaly.TrackedHosts;

    public event Action<Alert>? AlertRaised;
    public event Action? StatsTick;
    public event Action? DevicesUpdated;
    public event Action<string>? StatusMessage;

    public GuardEngine(Settings settings)
    {
        Settings = settings;
        _anomaly.Raise = a => Raise(a);
        _anomaly.Sensitivity = settings.AnomalySensitivity;
        foreach (var d in DeviceScanner.LoadInventory()) _devices[d.Ip] = d;
    }

    public IReadOnlyList<TrafficSample> History => _history.ToArray();
    public IReadOnlyList<DeviceInfo> Devices => _devices.Values.OrderBy(d => IpUtil.TryToUInt(d.Ip, out var v) ? v : 0).ToList();
    public IReadOnlyList<KeyValuePair<string, long>> TopTalkers(int n) =>
        _hostBytes.Where(kv => IpUtil.IsPrivateLan(kv.Key)).OrderByDescending(kv => kv.Value).Take(n).ToList();

    // ───────────────────────────── Lifecycle ─────────────────────────────

    public void Start()
    {
        AppPaths.Ensure();
        Alerts.Load();
        Intel.LoadLocal();
        EngineLog.Write("SYSTEM", $"Engine starting – {Intel.EntryCount:N0} threat-intel entries loaded.");

        var restored = Firewall.Reconcile();
        if (restored > 0) EngineLog.Write("FIREWALL", $"Re-applied {restored} block rule(s) missing from Windows Firewall.");

        _ = Task.Run(() => ProcessQueueAsync(_cts.Token));
        StartCapture();

        _secondTimer = new System.Threading.Timer(_ => SampleStats(), null, 1000, 1000);
        _connTimer = new System.Threading.Timer(_ => SafeRun(CheckConnections), null, 3000, 5000);
        _feedTimer = new System.Threading.Timer(async _ => { if (Settings.AutoUpdateThreatFeeds) await UpdateFeedsAsync(); },
            null, TimeSpan.FromSeconds(20), TimeSpan.FromHours(Math.Max(1, Settings.FeedUpdateHours)));
        _scanTimer = new System.Threading.Timer(async _ => await ScanDevicesAsync(),
            null, TimeSpan.FromSeconds(45), TimeSpan.FromMinutes(Math.Max(5, Settings.DeviceScanMinutes)));
    }

    public static List<AdapterChoice> ListAdapters()
    {
        try
        {
            return CaptureDeviceList.Instance.Select(d => new AdapterChoice(d.Name, AdapterLabel(d))).ToList();
        }
        catch { return new(); }
    }

    private static string AdapterLabel(ILiveDevice d)
    {
        var friendly = (d as LibPcapLiveDevice)?.Interface?.FriendlyName;
        return string.IsNullOrWhiteSpace(friendly) ? d.Description ?? d.Name : $"{friendly} – {d.Description}";
    }

    public void StartCapture()
    {
        StopCapture();
        try
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0) throw new InvalidOperationException("no capture adapters");

            var net = DeviceScanner.DetectNetwork();
            ILiveDevice? pick = null;
            if (!string.IsNullOrEmpty(Settings.CaptureAdapterName))
                pick = devices.FirstOrDefault(d => d.Name == Settings.CaptureAdapterName);
            // Prefer the adapter that owns our LAN address, then Ethernet/Wi-Fi by name
            pick ??= devices.OfType<LibPcapLiveDevice>().FirstOrDefault(d => net != null &&
                       d.Addresses.Any(a => a.Addr?.ipAddress?.ToString() == net.LocalIp));
            pick ??= devices.FirstOrDefault(d => (d.Description ?? "").Contains("Ethernet") || (d.Description ?? "").Contains("Wi-Fi"))
                     ?? devices[0];

            pick.OnPacketArrival += OnPacketArrival;
            pick.Open(new DeviceConfiguration
            {
                Mode = Settings.PromiscuousMode ? DeviceModes.Promiscuous : DeviceModes.None,
                ReadTimeout = 1000,
                Snaplen = 4096
            });
            try { pick.Filter = "ip"; } catch { }
            pick.StartCapture();
            _device = pick;
            CaptureAvailable = true;
            CaptureStatus = "Monitoring " + AdapterLabel(pick);
            EngineLog.Write("CAPTURE", CaptureStatus);
        }
        catch (Exception ex) when (ex is DllNotFoundException or TypeInitializationException or PcapException or InvalidOperationException)
        {
            CaptureAvailable = false;
            CaptureStatus = "Packet inspection off – install Npcap to enable it. Connection monitoring and device audits still run.";
            EngineLog.Write("CAPTURE", "Capture unavailable: " + ex.Message);
        }
        StatusMessage?.Invoke(CaptureStatus);
    }

    public void StopCapture()
    {
        if (_device == null) return;
        try { _device.OnPacketArrival -= OnPacketArrival; _device.StopCapture(); _device.Close(); } catch { }
        _device = null;
    }

    public void SetProtection(bool on)
    {
        Settings.ProtectionEnabled = on;
        Settings.Save();
        EngineLog.Write("SYSTEM", on ? "Protection enabled by user." : "Protection PAUSED by user.");
        StatusMessage?.Invoke(on ? "Protection enabled" : "Protection paused");
    }

    public void ApplySettings()
    {
        _anomaly.Sensitivity = Settings.AnomalySensitivity;
        _feedTimer?.Change(TimeSpan.FromSeconds(5), TimeSpan.FromHours(Math.Max(1, Settings.FeedUpdateHours)));
        _scanTimer?.Change(TimeSpan.FromMinutes(Math.Max(5, Settings.DeviceScanMinutes)), TimeSpan.FromMinutes(Math.Max(5, Settings.DeviceScanMinutes)));
        Settings.Save();
    }

    public void Dispose()
    {
        _cts.Cancel();
        _secondTimer?.Dispose(); _connTimer?.Dispose(); _feedTimer?.Dispose(); _scanTimer?.Dispose();
        StopCapture();
        EngineLog.Write("SYSTEM", "Engine stopped.");
    }

    // ───────────────────────────── Packet pipeline ─────────────────────────────

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        var raw = e.GetPacket();
        Interlocked.Add(ref _bytes, raw.Data.Length);
        Interlocked.Increment(ref _packets);
        Interlocked.Increment(ref _totalPackets);
        if (Settings.ProtectionEnabled) _queue.Writer.TryWrite(raw);
    }

    private async Task ProcessQueueAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var raw in _queue.Reader.ReadAllAsync(ct))
            {
                try { Inspect(raw); }
                catch { Interlocked.Increment(ref _droppedParse); }
            }
        }
        catch (OperationCanceledException) { }
    }

    private void Inspect(RawCapture raw)
    {
        var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
        var ip = packet.Extract<IPv4Packet>();
        if (ip == null) return;

        string src = ip.SourceAddress.ToString(), dst = ip.DestinationAddress.ToString();
        _hostBytes.AddOrUpdate(IpUtil.IsPrivateLan(src) ? src : dst, raw.Data.Length, (_, v) => v + raw.Data.Length);

        // 1. Threat intelligence
        bool srcBad = !IpUtil.IsLocalOrSpecial(src) && Intel.IsMalicious(src);
        bool dstBad = !IpUtil.IsLocalOrSpecial(dst) && Intel.IsMalicious(dst);
        if (srcBad || dstBad)
        {
            var bad = dstBad ? dst : src; var local = dstBad ? src : dst;
            Raise(new Alert
            {
                Severity = Severity.Critical, Source = AlertSource.ThreatIntel, HighConfidence = true,
                Title = dstBad ? "Device contacted a known malicious server" : "Traffic from a known malicious server",
                Detail = $"{local} ↔ {bad} – this address is on a botnet / malware threat list.",
                LocalIp = local, RemoteIp = bad,
                Recommendation = dstBad
                    ? $"Block {bad}. Something on {local} reached out to it on its own – scan that device for malware or factory-reset it if it's an IoT gadget."
                    : $"Block {bad}. Inbound probes from threat-listed hosts are common; blocking is safe."
            });
        }

        var tcp = packet.Extract<TcpPacket>();
        var udp = tcp == null ? packet.Extract<UdpPacket>() : null;
        _anomaly.Observe(new PacketMeta(src, dst,
            tcp?.SourcePort ?? udp?.SourcePort ?? 0, tcp?.DestinationPort ?? udp?.DestinationPort ?? 0,
            tcp != null, tcp?.Synchronize ?? false, tcp?.Acknowledgment ?? false, raw.Data.Length,
            raw.Timeval.Date.ToUniversalTime()));

        // 2. Signature DPI (clear-text TCP only)
        if (tcp?.PayloadData is { Length: > 0 } payload)
        {
            var rule = Signatures.Inspect(payload);
            if (rule != null)
            {
                bool inbound = !IpUtil.IsLocalOrSpecial(src);
                var remote = inbound ? src : dst;
                var local = inbound ? dst : src;
                Raise(new Alert
                {
                    Severity = rule.Severity, Source = AlertSource.Signature,
                    Title = $"{rule.Name} [{rule.Id}]",
                    Detail = $"{src}:{tcp.SourcePort} → {dst}:{tcp.DestinationPort}. {(inbound ? "Inbound attack attempt." : "Outbound – a home device may be infected or attacking.")}",
                    LocalIp = local, RemoteIp = remote, RemotePort = inbound ? tcp.SourcePort : tcp.DestinationPort,
                    HighConfidence = !IpUtil.IsLocalOrSpecial(remote),
                    Recommendation = rule.Advice
                });
            }
        }
    }

    // ───────────────────────────── Connection monitor (works without Npcap) ─────────────────────────────

    private void CheckConnections()
    {
        if (!Settings.ProtectionEnabled) return;
        foreach (var c in ConnectionMonitor.Snapshot(Intel).Where(c => c.Flagged))
        {
            bool intel = c.FlagReason.Contains("threat list");
            Raise(new Alert
            {
                Severity = intel ? Severity.Critical : Severity.Medium,
                Source = intel ? AlertSource.ThreatIntel : AlertSource.Anomaly,
                HighConfidence = intel,
                Title = intel ? "Program connected to a known malicious server" : "Suspicious program connection",
                Detail = $"{c.ProcessName} (PID {c.Pid}) → {c.RemoteAddress}:{c.RemotePort}. {c.FlagReason}." +
                         (string.IsNullOrEmpty(c.ProcessPath) ? "" : $" Path: {c.ProcessPath}"),
                LocalIp = c.LocalAddress, RemoteIp = c.RemoteAddress, RemotePort = c.RemotePort,
                Recommendation = "Block the remote address, then check the program on the Connections page. If you don't recognise it, end it and run a full Microsoft Defender scan."
            });
        }
    }

    public List<ConnectionInfo> SnapshotConnections() => ConnectionMonitor.Snapshot(Intel);

    // ───────────────────────────── Alerts & response policy ─────────────────────────────

    public void Raise(Alert a)
    {
        if (a.RemoteIp != null && Settings.WhitelistIps.Contains(a.RemoteIp)) return;
        if (!Alerts.TryAdd(a)) return;

        EngineLog.Write("ALERT", $"[{a.Severity}] {a.Title} – {a.Detail}");

        bool remoteBlockable = a.RemoteIp != null && !IpUtil.IsLocalOrSpecial(a.RemoteIp);
        bool auto = Settings.ProtectionEnabled && remoteBlockable && Settings.AutoResponse switch
        {
            AutoResponseMode.HighConfidenceOnly => a.HighConfidence && a.Severity >= Severity.High,
            AutoResponseMode.Aggressive => a.Severity >= Severity.High,
            _ => false
        };
        if (auto)
        {
            var (ok, msg) = Firewall.Block(a.RemoteIp!, a.Title, automatic: true);
            if (ok) Alerts.SetStatus(a, AlertStatus.Blocked);
            else EngineLog.Write("FIREWALL", "Auto-block failed: " + msg);
        }
        AlertRaised?.Invoke(a);
    }

    public (bool ok, string message) BlockFromAlert(Alert a)
    {
        if (a.RemoteIp == null) return (false, "This alert has no remote address to block.");
        var r = Firewall.Block(a.RemoteIp, a.Title, automatic: false);
        if (r.ok) Alerts.SetStatus(a, AlertStatus.Blocked);
        return r;
    }

    public void TrustIp(string ip)
    {
        if (!Settings.WhitelistIps.Contains(ip)) Settings.WhitelistIps.Add(ip);
        Settings.Save();
        if (Firewall.IsBlocked(ip)) Firewall.Unblock(ip);
    }

    // ───────────────────────────── Threat feeds & device audits ─────────────────────────────

    public async Task<(bool ok, string message)> UpdateFeedsAsync()
    {
        var r = await Intel.UpdateFeedsAsync(Settings.FeedUrls, _cts.Token);
        StatusMessage?.Invoke(r.message);
        return r;
    }

    public async Task<string> ScanDevicesAsync()
    {
        if (ScanInProgress) return "A scan is already running.";
        ScanInProgress = true;
        try
        {
            bool firstEver = _devices.IsEmpty;
            var previousMacs = _devices.Values.Select(d => d.Mac).Where(m => m.Length > 0).ToHashSet();
            var found = await Scanner.ScanAsync(new Dictionary<string, DeviceInfo>(_devices), _cts.Token);

            foreach (var d in found)
            {
                _devices[d.Ip] = d;
                if (!firstEver && Settings.AlertOnNewDevice && d.Mac.Length > 0 && !previousMacs.Contains(d.Mac) && !d.IsThisPc)
                    Raise(new Alert
                    {
                        Severity = Severity.Medium, Source = AlertSource.DeviceAudit,
                        Title = "New device joined your network",
                        Detail = $"{d.DisplayName} ({d.Ip}, {d.Mac}, {d.Vendor}) appeared for the first time. Category: {d.Category}.",
                        LocalIp = d.Ip,
                        Recommendation = "If you don't recognise it, change your Wi-Fi password and check your router's connected-device list."
                    });
                if (d.Risk == DeviceRisk.High && !d.Trusted)
                    Raise(new Alert
                    {
                        Severity = Severity.High, Source = AlertSource.DeviceAudit,
                        Title = "High-risk service exposed on a device",
                        Detail = $"{d.DisplayName} ({d.Ip}, {d.Vendor}): " + string.Join(" ", d.Findings.Where(f => f.StartsWith("Port")).Take(3)),
                        LocalIp = d.Ip,
                        Recommendation = "Open the Devices page for fix-it steps. Botnets break into IoT gadgets through exactly these services."
                    });
            }
            // Devices not seen this scan are kept (they may be asleep) but not refreshed
            DeviceScanner.SaveInventory(_devices.Values);
            LastScanUtc = DateTime.UtcNow;
            var msg = $"Device audit complete – {found.Count} device(s) online, {found.Count(d => d.Risk == DeviceRisk.High)} high-risk.";
            EngineLog.Write("SCAN", msg);
            DevicesUpdated?.Invoke();
            return msg;
        }
        catch (Exception ex)
        {
            EngineLog.Write("SCAN", "Scan failed: " + ex.Message);
            return "Scan failed: " + ex.Message;
        }
        finally { ScanInProgress = false; }
    }

    public void UpdateDevice(DeviceInfo d)
    {
        _devices[d.Ip] = d;
        DeviceScanner.SaveInventory(_devices.Values);
        DevicesUpdated?.Invoke();
    }

    public void ForgetDevice(string ip)
    {
        _devices.TryRemove(ip, out _);
        DeviceScanner.SaveInventory(_devices.Values);
        DevicesUpdated?.Invoke();
    }

    // ───────────────────────────── Stats ─────────────────────────────

    private void SampleStats()
    {
        var b = Interlocked.Exchange(ref _bytes, 0);
        var p = Interlocked.Exchange(ref _packets, 0);
        _history.Enqueue(new TrafficSample { TimeUtc = DateTime.UtcNow, BytesPerSec = b, PacketsPerSec = p });
        while (_history.Count > 180) _history.TryDequeue(out _);
        if (_hostBytes.Count > 5000) _hostBytes.Clear();
        StatsTick?.Invoke();
    }

    private static void SafeRun(Action a)
    {
        try { a(); } catch (Exception ex) { EngineLog.Write("ENGINE", ex.Message); }
    }
}
