using System.Text.Json;

namespace CasHomeNetGuard.Core;

public enum AutoResponseMode
{
    /// <summary>Alert only. Nothing is blocked without the user clicking Block.</summary>
    AlertOnly,
    /// <summary>Automatically block only high-confidence detections (threat-intel matches). Default.</summary>
    HighConfidenceOnly,
    /// <summary>Automatically block every High/Critical internet detection.</summary>
    Aggressive
}

public sealed class Settings
{
    public bool ProtectionEnabled { get; set; } = true;
    public AutoResponseMode AutoResponse { get; set; } = AutoResponseMode.HighConfidenceOnly;
    public string? CaptureAdapterName { get; set; }
    public bool PromiscuousMode { get; set; } = false;
    public bool StartWithWindows { get; set; } = false;
    public bool StartMinimised { get; set; } = true;
    public bool MinimiseToTray { get; set; } = true;
    public bool DesktopNotifications { get; set; } = true;
    public bool AutoUpdateThreatFeeds { get; set; } = true;
    public int FeedUpdateHours { get; set; } = 6;
    public int DeviceScanMinutes { get; set; } = 30;
    public double AnomalySensitivity { get; set; } = 4.0;   // z-score threshold
    public bool AlertOnNewDevice { get; set; } = true;
    public List<string> WhitelistIps { get; set; } = new();
    public List<string> FeedUrls { get; set; } = new()
    {
        // abuse.ch Feodo Tracker – botnet C2 servers (plain IP list, free, no key)
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        // Spamhaus DROP – hijacked netblocks (CIDR)
        "https://www.spamhaus.org/drop/drop.txt",
    };

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static Settings Load()
    {
        try
        {
            if (File.Exists(AppPaths.SettingsFile))
                return JsonSerializer.Deserialize<Settings>(File.ReadAllText(AppPaths.SettingsFile)) ?? new Settings();
        }
        catch (Exception ex) { EngineLog.Write("SETTINGS", "Could not read settings, using defaults: " + ex.Message); }
        return new Settings();
    }

    public void Save()
    {
        AppPaths.Ensure();
        var tmp = AppPaths.SettingsFile + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, AppPaths.SettingsFile, overwrite: true);
    }
}
