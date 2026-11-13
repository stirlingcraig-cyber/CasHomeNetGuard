using System.Text;

namespace CasHomeNetGuard.Core;

/// <summary>
/// Deep-packet-inspection rules for clear-text TCP payloads. Each rule targets a specific,
/// well-documented IoT malware or exploit artefact. Deliberately avoids generic words
/// ("exec", "mips") that appear in normal traffic and would cause false blocks.
/// </summary>
public sealed record SignatureRule(string Id, string Name, Severity Severity, string Advice, Func<string, bool> Match);

public static class Signatures
{
    private static bool Has(string p, string s) => p.Contains(s, StringComparison.OrdinalIgnoreCase);

    public static readonly IReadOnlyList<SignatureRule> Rules = new List<SignatureRule>
    {
        new("IOT-001", "Mirai/Gafgyt BusyBox infection command", Severity.Critical,
            "A device received shell commands typical of Mirai-family botnets. Isolate it, factory-reset it and change its password.",
            p => Has(p, "/bin/busybox") && (Has(p, "MIRAI") || Has(p, "ECCHI") || Has(p, "tftp") || Has(p, "wget") || Has(p, "chmod"))),

        new("IOT-002", "Remote downloader (wget/curl piped to shell)", Severity.Critical,
            "Something tried to download and execute a script on a device. Identify the target device and isolate it.",
            p => (Has(p, "wget http") || Has(p, "curl http") || Has(p, "curl -O")) &&
                 (Has(p, "|sh") || Has(p, "| sh") || Has(p, ";sh") || Has(p, "; sh") || Has(p, "chmod 777") || Has(p, "chmod +x"))),

        new("IOT-003", "TFTP payload fetch command", Severity.High,
            "TFTP 'get' commands are used by IoT malware to pull binaries. Check the device it targeted.",
            p => Has(p, "tftp -g") || Has(p, "tftp -r")),

        new("IOT-004", "Mozi botnet artefact", Severity.Critical,
            "Mozi peer-to-peer botnet traffic detected. Isolate the device and reflash or replace it.",
            p => Has(p, "Mozi.m") || Has(p, "Mozi.a") || Has(p, "Mozi.7")),

        new("IOT-005", "Botnet binary download (/bins/<arch>)", Severity.High,
            "A request for CPU-specific malware binaries (arm7/mips/mpsl) was seen.",
            p => Has(p, "GET /bins/") || (Has(p, "GET /") && (Has(p, ".arm7 HTTP") || Has(p, ".mips HTTP") || Has(p, ".mpsl HTTP")))),

        new("EXP-001", "GPON router remote-code exploit", Severity.Critical,
            "Exploit attempt against GPON fibre routers (CVE-2018-10561/10562). Update router firmware.",
            p => Has(p, "GponForm/diag_Form")),

        new("EXP-002", "Router shell-injection URL (/shell?cd+/tmp)", Severity.Critical,
            "Command-injection attempt used by Hajime/Mozi. Update router/DVR firmware and disable remote admin.",
            p => Has(p, "/shell?cd") || Has(p, "/shell?cd+/tmp")),

        new("EXP-003", "Log4Shell JNDI injection", Severity.Critical,
            "Log4j exploit string detected (CVE-2021-44228). Patch any Java-based NAS/media servers.",
            p => Has(p, "${jndi:")),

        new("EXP-004", "Shellshock injection", Severity.Critical,
            "Bash Shellshock payload (CVE-2014-6271). Older NAS/camera firmware is often vulnerable.",
            p => p.Contains("() { :; };") || p.Contains("() { :;};")),

        new("EXP-005", "Realtek SDK UPnP exploit", Severity.High,
            "Exploit against Realtek SDK miniigd (CVE-2014-8361) common in cheap routers/cameras.",
            p => Has(p, "/picsdesc.xml") && Has(p, "AddPortMapping") && (Has(p, "`") || Has(p, "$("))),

        new("EXP-006", "Netgear setup.cgi command injection", Severity.Critical,
            "Netgear router RCE attempt. Update firmware and disable remote management.",
            p => Has(p, "setup.cgi?next_file=netgear.cfg") && Has(p, "todo=syscmd")),

        new("EXP-007", "D-Link HNAP command injection", Severity.High,
            "HNAP exploit attempt against D-Link devices. Update firmware.",
            p => Has(p, "/HNAP1/") && (Has(p, "`") || Has(p, "$(") || Has(p, ";wget"))),

        new("EXP-008", "Path traversal to system files", Severity.High,
            "Attempt to read system password files via path traversal.",
            p => Has(p, "../../etc/passwd") || Has(p, "..%2f..%2fetc%2fpasswd") || Has(p, "..\\..\\windows\\win.ini")),
    };

    /// <summary>Returns the first matching rule, or null. Only the first 4 KB of payload is inspected.</summary>
    public static SignatureRule? Inspect(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 6) return null;
        var text = Encoding.Latin1.GetString(payload[..Math.Min(payload.Length, 4096)]);
        foreach (var r in Rules)
            if (r.Match(text)) return r;
        return null;
    }
}
