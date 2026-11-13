using System.Diagnostics;
using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

public sealed class FirewallPage : PageBase
{
    private readonly DataGridView _grid = Kit.Grid();
    private readonly TextBox _ip = Kit.TextBox();
    private readonly Label _feed = Kit.Label("", Theme.Body, Theme.Muted);

    public FirewallPage(GuardEngine engine) : base(engine)
    {
        var bar = Kit.Toolbar();
        _ip.Width = 170; _ip.Margin = new Padding(0, 6, 8, 0); _ip.PlaceholderText = "IP address to block";
        bar.Controls.Add(_ip);
        bar.Controls.Add(Kit.Button("Block", (_, _) => AddManual(), danger: true));
        bar.Controls.Add(Kit.Button("Unblock selected", (_, _) => Unblock()));
        bar.Controls.Add(Kit.Button("Unblock all", (_, _) =>
        {
            if (!Kit.Confirm(FindForm()!, "Remove every block rule created by CAS HomeNet Guard?")) return;
            Kit.Info(FindForm()!, $"{Engine.Firewall.UnblockAll()} rule(s) removed."); Reload();
        }));

        _grid.Columns.AddRange(Kit.Col("Blocked address", 70), Kit.Col("Reason", 200), Kit.Col("How", 45), Kit.Col("When", 60));

        var intelCard = new Card { Dock = DockStyle.Bottom, Height = 132, Padding = new Padding(18, 14, 18, 12) };
        var t = Kit.Label("THREAT INTELLIGENCE FEEDS", Theme.Small, Theme.Muted); t.Location = new Point(18, 14);
        _feed.Location = new Point(18, 38); _feed.MaximumSize = new Size(1100, 0);
        var actions = new FlowLayoutPanel { Location = new Point(14, 80), AutoSize = true, BackColor = Theme.Card };
        actions.Controls.Add(Kit.Button("Update feeds now", async (s, _) =>
        {
            var b = (Button)s!; b.Enabled = false; b.Text = "Updating…";
            var (_, msg) = await Engine.UpdateFeedsAsync();
            b.Enabled = true; b.Text = "Update feeds now"; Reload(); Kit.Info(FindForm()!, msg);
        }, primary: true));
        actions.Controls.Add(Kit.Button("Edit my personal blocklist", (_, _) =>
        {
            Process.Start(new ProcessStartInfo("notepad.exe", $"\"{AppPaths.BlocklistFile}\"") { UseShellExecute = true })?.WaitForExitAsync()
                .ContinueWith(_ => { Engine.Intel.LoadLocal(); BeginInvoke(Reload); });
        }));
        actions.Controls.Add(Kit.Button("Open Windows Firewall", (_, _) => Process.Start(new ProcessStartInfo("wf.msc") { UseShellExecute = true })));
        intelCard.Controls.AddRange(new Control[] { t, _feed, actions });

        var gridCard = new Card { Dock = DockStyle.Fill, Padding = new Padding(1) };
        gridCard.Controls.Add(_grid);
        Controls.Add(gridCard);
        Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 14, BackColor = Theme.Bg });
        Controls.Add(intelCard);
        Controls.Add(bar);
        Controls.Add(Kit.PageHeader("Firewall", "Addresses blocked by CAS HomeNet Guard through Windows Defender Firewall"));
        Engine.Firewall.Changed += () => { if (IsHandleCreated) BeginInvoke(Reload); };
    }

    public override void OnActivated() => Reload();

    public void Reload()
    {
        _grid.Rows.Clear();
        foreach (var e in Engine.Firewall.Entries.OrderByDescending(e => e.BlockedUtc))
        {
            int i = _grid.Rows.Add(e.Ip, e.Reason, e.Automatic ? "Automatic" : "Manual", e.BlockedUtc.ToLocalTime().ToString("dd MMM yyyy HH:mm"));
            _grid.Rows[i].Tag = e;
        }
        var s = Engine.Settings;
        _feed.Text = $"{Engine.Intel.EntryCount:N0} malicious addresses and ranges loaded from {s.FeedUrls.Count} public feed(s) plus your personal list.  " +
                     (Engine.Intel.LastFeedUpdateUtc is { } u ? $"Last updated {Kit.Ago(u)}." : "Feeds not downloaded yet.") +
                     (s.AutoUpdateThreatFeeds ? $"  Auto-update every {s.FeedUpdateHours} h." : "  Auto-update is off.") +
                     "\nAny device that talks to one of these addresses raises a Critical alert" +
                     (s.AutoResponse == AutoResponseMode.AlertOnly ? "." : " and the address is blocked automatically.");
    }

    private void AddManual()
    {
        var ip = _ip.Text.Trim();
        if (IpUtil.IsPrivateLan(ip) && !Kit.Confirm(FindForm()!, $"{ip} is on your home network. Block it from this PC anyway?")) return;
        var (ok, msg) = Engine.Firewall.Block(ip, "Added manually", false);
        if (ok) _ip.Clear();
        Kit.Info(FindForm()!, msg);
    }

    private void Unblock()
    {
        if (_grid.CurrentRow?.Tag is not BlockEntry e) return;
        Engine.Firewall.Unblock(e.Ip);
    }
}
