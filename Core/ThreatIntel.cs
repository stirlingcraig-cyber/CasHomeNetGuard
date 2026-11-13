using System.Net.Http;
using System.Text.RegularExpressions;

namespace CasHomeNetGuard.Core;

/// <summary>
/// IP reputation store. Combines the user's own blocklist with public threat feeds
/// (single IPs and CIDR ranges). Lookups are O(prefix count), safe to call per packet.
/// </summary>
public sealed class ThreatIntel
{
    private static readonly Regex IpOrCidr = new(@"\b(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?\b", RegexOptions.Compiled);

    private volatile Dictionary<int, HashSet<uint>> _byPrefix = new();
    private volatile HashSet<string> _userList = new();
    public int EntryCount { get; private set; }
    public DateTime? LastFeedUpdateUtc { get; private set; }
    public event Action? Updated;

    // Seed entries from the original HomeNetGuard brief – kept so behaviour is familiar.
    private static readonly string[] Seed = { "185.220.101.5", "45.142.120.11", "103.224.182.23" };

    public void LoadLocal()
    {
        AppPaths.Ensure();
        if (!File.Exists(AppPaths.BlocklistFile))
            File.WriteAllLines(AppPaths.BlocklistFile, new[]
            {
                "# CAS HomeNet Guard – personal blocklist",
                "# One IPv4 address or CIDR range per line. Lines starting with # are ignored.",
            }.Concat(Seed));

        var user = ParseList(File.ReadAllText(AppPaths.BlocklistFile)).ToList();
        var feed = File.Exists(AppPaths.FeedCacheFile) ? ParseList(File.ReadAllText(AppPaths.FeedCacheFile)).ToList() : new();
        if (File.Exists(AppPaths.FeedCacheFile)) LastFeedUpdateUtc = File.GetLastWriteTimeUtc(AppPaths.FeedCacheFile);
        _userList = user.Select(e => e.text).ToHashSet();
        Rebuild(user.Concat(feed));
    }

    public async Task<(bool ok, string message)> UpdateFeedsAsync(IEnumerable<string> urls, CancellationToken ct = default)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("CAS-HomeNetGuard/1.0");
        var combined = new System.Text.StringBuilder();
        int okCount = 0; var errors = new List<string>();
        foreach (var url in urls)
        {
            try
            {
                var text = await http.GetStringAsync(url, ct);
                combined.AppendLine("# source: " + url).AppendLine(text);
                okCount++;
            }
            catch (Exception ex) { errors.Add($"{new Uri(url).Host}: {ex.Message}"); }
        }
        if (okCount == 0) return (false, "No feeds could be downloaded. " + string.Join("; ", errors));

        File.WriteAllText(AppPaths.FeedCacheFile, combined.ToString());
        LoadLocal();
        var msg = $"Threat feeds updated ({okCount} source(s), {EntryCount:N0} entries).";
        if (errors.Count > 0) msg += " Failed: " + string.Join("; ", errors);
        EngineLog.Write("INTEL", msg);
        return (true, msg);
    }

    public bool AddToUserBlocklist(string ip)
    {
        if (!IpUtil.TryToUInt(ip, out _) || _userList.Contains(ip)) return false;
        File.AppendAllText(AppPaths.BlocklistFile, ip + Environment.NewLine);
        LoadLocal();
        return true;
    }

    public bool IsMalicious(string ip)
    {
        if (!IpUtil.TryToUInt(ip, out var v)) return false;
        foreach (var (prefix, set) in _byPrefix)
            if (set.Contains(v & IpUtil.MaskFor(prefix))) return true;
        return false;
    }

    private void Rebuild(IEnumerable<(uint net, int prefix, string text)> entries)
    {
        var map = new Dictionary<int, HashSet<uint>>();
        int count = 0;
        foreach (var (net, prefix, _) in entries)
        {
            if (prefix < 8) continue; // refuse absurdly broad ranges from a bad feed
            if (!map.TryGetValue(prefix, out var set)) map[prefix] = set = new HashSet<uint>();
            if (set.Add(net & IpUtil.MaskFor(prefix))) count++;
        }
        _byPrefix = map;
        EntryCount = count;
        Updated?.Invoke();
    }

    internal static IEnumerable<(uint net, int prefix, string text)> ParseList(string text)
    {
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            var m = IpOrCidr.Match(line);
            if (!m.Success || !IpUtil.TryToUInt(m.Groups[1].Value, out var v)) continue;
            var prefix = m.Groups[2].Success ? int.Parse(m.Groups[2].Value) : 32;
            if (prefix is < 0 or > 32) continue;
            yield return (v, prefix, m.Value);
        }
    }
}
