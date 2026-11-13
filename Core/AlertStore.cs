using System.Text.Json;
using System.Text.Json.Serialization;

namespace CasHomeNetGuard.Core;

public sealed class AlertStore
{
    private const int MaxAlerts = 5000;
    private readonly object _gate = new();
    private readonly List<Alert> _alerts = new();
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };

    public event Action<Alert>? Added;
    public event Action<Alert>? Changed;

    public void Load()
    {
        if (!File.Exists(AppPaths.AlertsFile)) return;
        lock (_gate)
        {
            foreach (var line in File.ReadLines(AppPaths.AlertsFile))
            {
                try { if (JsonSerializer.Deserialize<Alert>(line, Json) is { } a) _alerts.Add(a); } catch { }
            }
            if (_alerts.Count > MaxAlerts) _alerts.RemoveRange(0, _alerts.Count - MaxAlerts);
        }
    }

    public IReadOnlyList<Alert> All { get { lock (_gate) return _alerts.ToList(); } }

    /// <summary>Returns false if an equivalent alert was raised recently or the user chose to ignore it.</summary>
    public bool TryAdd(Alert a)
    {
        var cooldown = a.Source == AlertSource.DeviceAudit ? TimeSpan.FromDays(7) : TimeSpan.FromMinutes(15);
        lock (_gate)
        {
            if (_alerts.Any(x => x.DedupKey == a.DedupKey &&
                                 (x.Status == AlertStatus.Ignored || a.TimeUtc - x.TimeUtc < cooldown)))
                return false;
            _alerts.Add(a);
            if (_alerts.Count > MaxAlerts) { _alerts.RemoveRange(0, 500); Rewrite(); }
            else Append(a);
        }
        Added?.Invoke(a);
        return true;
    }

    public void SetStatus(Alert a, AlertStatus status)
    {
        lock (_gate) { a.Status = status; Rewrite(); }
        Changed?.Invoke(a);
    }

    public void Clear()
    {
        lock (_gate) { _alerts.Clear(); Rewrite(); }
    }

    public int OpenCount(Severity min = Severity.Low)
    {
        lock (_gate) return _alerts.Count(a => a.Status == AlertStatus.Open && a.Severity >= min);
    }

    private void Append(Alert a)
    {
        try { AppPaths.Ensure(); File.AppendAllText(AppPaths.AlertsFile, JsonSerializer.Serialize(a, Json) + Environment.NewLine); }
        catch (Exception ex) { EngineLog.Write("ALERTS", "Persist failed: " + ex.Message); }
    }

    private void Rewrite()
    {
        try
        {
            AppPaths.Ensure();
            var tmp = AppPaths.AlertsFile + ".tmp";
            File.WriteAllLines(tmp, _alerts.Select(x => JsonSerializer.Serialize(x, Json)));
            File.Move(tmp, AppPaths.AlertsFile, overwrite: true);
        }
        catch (Exception ex) { EngineLog.Write("ALERTS", "Persist failed: " + ex.Message); }
    }
}
