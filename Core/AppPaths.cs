namespace CasHomeNetGuard.Core;

public static class AppPaths
{
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CAS Solutions", "HomeNetGuard");

    public static string SettingsFile => Path.Combine(Root, "settings.json");
    public static string AlertsFile => Path.Combine(Root, "alerts.jsonl");
    public static string DevicesFile => Path.Combine(Root, "devices.json");
    public static string BlocklistFile => Path.Combine(Root, "blocklist.txt");
    public static string FeedCacheFile => Path.Combine(Root, "feed-cache.txt");
    public static string LogFile => Path.Combine(Root, "engine.log");

    public static void Ensure() => Directory.CreateDirectory(Root);
}

public static class EngineLog
{
    private static readonly object Gate = new();
    public static event Action<string>? LineWritten;

    public static void Write(string category, string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{category}] {message}";
        lock (Gate)
        {
            try
            {
                AppPaths.Ensure();
                var fi = new FileInfo(AppPaths.LogFile);
                if (fi.Exists && fi.Length > 5_000_000)
                    File.Move(AppPaths.LogFile, AppPaths.LogFile + ".old", overwrite: true);
                File.AppendAllText(AppPaths.LogFile, line + Environment.NewLine);
            }
            catch { /* logging must never crash the engine */ }
        }
        LineWritten?.Invoke(line);
    }
}
