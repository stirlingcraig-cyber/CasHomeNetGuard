using System.Diagnostics;
using System.Text.Json;

namespace CasHomeNetGuard.Core;

public sealed class BlockEntry
{
    public string Ip { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTime BlockedUtc { get; set; } = DateTime.UtcNow;
    public bool Automatic { get; set; }
}

/// <summary>
/// Manages Windows Defender Firewall rules created by this app (prefixed "CAS-HNG").
/// Keeps its own register so rules can be listed and removed cleanly.
/// </summary>
public sealed class FirewallManager
{
    public const string RulePrefix = "CAS-HNG Block";
    private static string RegisterFile => Path.Combine(AppPaths.Root, "blocked.json");
    private readonly object _gate = new();
    private List<BlockEntry> _entries;

    public event Action? Changed;

    public FirewallManager()
    {
        try { _entries = File.Exists(RegisterFile) ? JsonSerializer.Deserialize<List<BlockEntry>>(File.ReadAllText(RegisterFile)) ?? new() : new(); }
        catch { _entries = new(); }
    }

    public IReadOnlyList<BlockEntry> Entries { get { lock (_gate) return _entries.ToList(); } }

    public bool IsBlocked(string ip) { lock (_gate) return _entries.Any(e => e.Ip == ip); }

    public (bool ok, string message) Block(string ip, string reason, bool automatic)
    {
        if (!IpUtil.TryToUInt(ip, out _)) return (false, $"'{ip}' is not a valid IPv4 address.");
        if (IsBlocked(ip)) return (true, $"{ip} is already blocked.");

        var name = $"{RulePrefix} {ip}";
        var r1 = Netsh($"advfirewall firewall add rule name=\"{name} (in)\" dir=in action=block remoteip={ip} enable=yes profile=any");
        var r2 = Netsh($"advfirewall firewall add rule name=\"{name} (out)\" dir=out action=block remoteip={ip} enable=yes profile=any");
        if (!r1.ok || !r2.ok)
            return (false, $"Windows Firewall refused the rule: {r1.output} {r2.output}".Trim());

        lock (_gate)
        {
            _entries.Add(new BlockEntry { Ip = ip, Reason = reason, Automatic = automatic });
            Persist();
        }
        EngineLog.Write("FIREWALL", $"Blocked {ip} ({(automatic ? "auto" : "manual")}): {reason}");
        Changed?.Invoke();
        return (true, $"{ip} is now blocked in both directions.");
    }

    public (bool ok, string message) Unblock(string ip)
    {
        var name = $"{RulePrefix} {ip}";
        Netsh($"advfirewall firewall delete rule name=\"{name} (in)\"");
        Netsh($"advfirewall firewall delete rule name=\"{name} (out)\"");
        lock (_gate) { _entries.RemoveAll(e => e.Ip == ip); Persist(); }
        EngineLog.Write("FIREWALL", $"Unblocked {ip}");
        Changed?.Invoke();
        return (true, $"{ip} unblocked.");
    }

    public int UnblockAll()
    {
        var ips = Entries.Select(e => e.Ip).ToList();
        foreach (var ip in ips) Unblock(ip);
        return ips.Count;
    }

    /// <summary>Re-creates any registered rules that were removed outside the app (e.g. firewall reset).</summary>
    public int Reconcile()
    {
        int restored = 0;
        foreach (var e in Entries)
        {
            var (ok, _) = Netsh($"advfirewall firewall show rule name=\"{RulePrefix} {e.Ip} (out)\"");
            if (ok) continue;
            lock (_gate) _entries.RemoveAll(x => x.Ip == e.Ip);
            if (Block(e.Ip, e.Reason, e.Automatic).ok) restored++;
        }
        return restored;
    }

    private void Persist()
    {
        AppPaths.Ensure();
        File.WriteAllText(RegisterFile, JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true }));
    }

    internal static (bool ok, string output) Netsh(string args) => Run("netsh", args);

    internal static (bool ok, string output) Run(string file, string args, int timeoutMs = 15000)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args)
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true
            })!;
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } return (false, "timed out"); }
            return (p.ExitCode == 0, (stdout.Result + stderr.Result).Trim());
        }
        catch (Exception ex) { return (false, ex.Message); }
    }
}
