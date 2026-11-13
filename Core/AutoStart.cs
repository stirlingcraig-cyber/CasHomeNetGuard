namespace CasHomeNetGuard.Core;

/// <summary>
/// Starts the app at logon via a Scheduled Task with highest privileges
/// (a Run-key entry can't launch an admin app without a UAC prompt every boot).
/// </summary>
public static class AutoStart
{
    private const string TaskName = "CAS HomeNet Guard";

    public static (bool ok, string message) Set(bool enable)
    {
        if (!enable)
        {
            var (ok, output) = FirewallManager.Run("schtasks", $"/delete /tn \"{TaskName}\" /f");
            return (ok || output.Contains("cannot find", StringComparison.OrdinalIgnoreCase), ok ? "Start-up task removed." : output);
        }
        var exe = Environment.ProcessPath ?? Application.ExecutablePath;
        var args = $"/create /tn \"{TaskName}\" /tr \"\\\"{exe}\\\" --tray\" /sc onlogon /rl highest /f /delay 0000:30";
        var r = FirewallManager.Run("schtasks", args);
        return (r.ok, r.ok ? "CAS HomeNet Guard will start protected at every sign-in." : r.output);
    }

    public static bool IsEnabled() => FirewallManager.Run("schtasks", $"/query /tn \"{TaskName}\"").ok;
}
