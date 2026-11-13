using System.Text.Json.Serialization;

namespace CasHomeNetGuard.Core;

public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

public enum AlertStatus { Open, Blocked, Ignored, Resolved }

public enum AlertSource { ThreatIntel, Signature, Anomaly, DeviceAudit, System }

public sealed class Alert
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime TimeUtc { get; set; } = DateTime.UtcNow;
    public Severity Severity { get; set; }
    public AlertSource Source { get; set; }
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public string? LocalIp { get; set; }
    public string? RemoteIp { get; set; }
    public int? RemotePort { get; set; }
    public string? Recommendation { get; set; }
    public AlertStatus Status { get; set; } = AlertStatus.Open;
    /// <summary>True when this detector is confident enough for automatic blocking.</summary>
    public bool HighConfidence { get; set; }
    /// <summary>Key used to suppress duplicate alerts within a cool-down window.</summary>
    [JsonIgnore] public string DedupKey => $"{Source}|{Title}|{LocalIp}|{RemoteIp}";
}

public enum DeviceRisk { Unknown, Low, Medium, High }

public sealed class DeviceInfo
{
    public string Ip { get; set; } = "";
    public string Mac { get; set; } = "";
    public string Vendor { get; set; } = "Unknown";
    public string HostName { get; set; } = "";
    public string Category { get; set; } = "Unknown";
    public List<int> OpenPorts { get; set; } = new();
    public DeviceRisk Risk { get; set; } = DeviceRisk.Unknown;
    public List<string> Findings { get; set; } = new();
    public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    public bool Trusted { get; set; }
    public string Nickname { get; set; } = "";
    public bool IsGateway { get; set; }
    public bool IsThisPc { get; set; }

    public string DisplayName =>
        !string.IsNullOrWhiteSpace(Nickname) ? Nickname :
        !string.IsNullOrWhiteSpace(HostName) ? HostName : Ip;
}

public sealed class ConnectionInfo
{
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public bool Flagged { get; set; }
    public string FlagReason { get; set; } = "";
}

public sealed class TrafficSample
{
    public DateTime TimeUtc { get; init; }
    public double BytesPerSec { get; init; }
    public double PacketsPerSec { get; init; }
}
