using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

public abstract class PageBase : UserControl
{
    protected readonly GuardEngine Engine;
    protected PageBase(GuardEngine engine)
    {
        Engine = engine; Dock = DockStyle.Fill; BackColor = Theme.Bg; ForeColor = Theme.Text;
        Padding = new Padding(28, 22, 28, 22); DoubleBuffered = true;
    }
    public virtual void OnActivated() { }
    public virtual void OnStatsTick() { }
    public MainForm Main => (MainForm)FindForm()!;
}

public sealed class DashboardPage : PageBase
{
    private readonly StatusBanner _banner = new() { Dock = DockStyle.Top };
    private readonly StatCard _devices = new("Devices on network");
    private readonly StatCard _alerts = new("Open alerts");
    private readonly StatCard _blocked = new("Blocked addresses");
    private readonly StatCard _intel = new("Threat intelligence");
    private readonly TrafficChart _chart = new() { Dock = DockStyle.Fill };
    private readonly ListBox _recent;
    private readonly Label _engineLine = Kit.Label("", Theme.Small, Theme.Muted);
    private readonly Button _toggle, _scan;

    public DashboardPage(GuardEngine engine) : base(engine)
    {
        _toggle = Kit.Button("Pause protection", (_, _) => { Engine.SetProtection(!Engine.Settings.ProtectionEnabled); Reload(); Main.RefreshChrome(); });
        _scan = Kit.Button("Scan network now", async (_, _) => await Main.RunScanAsync(), primary: true);
        _banner.Actions.Controls.Add(_toggle);
        _banner.Actions.Controls.Add(_scan);

        var stats = new TableLayoutPanel { Dock = DockStyle.Top, Height = 128, ColumnCount = 4, BackColor = Theme.Bg, Padding = new Padding(0, 16, 0, 0) };
        for (int i = 0; i < 4; i++) stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        foreach (var (c, i) in new[] { _devices, _alerts, _blocked, _intel }.Select((c, i) => (c, i)))
        {
            c.Dock = DockStyle.Fill; c.Margin = new Padding(i == 0 ? 0 : 8, 0, i == 3 ? 0 : 8, 0);
            stats.Controls.Add(c, i, 0);
        }
        _devices.Cursor = _alerts.Cursor = _blocked.Cursor = Cursors.Hand;
        _devices.Click += (_, _) => Main.Navigate("Devices");
        _alerts.Click += (_, _) => Main.Navigate("Alerts");
        _blocked.Click += (_, _) => Main.Navigate("Firewall");

        var lower = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Theme.Bg, Padding = new Padding(0, 16, 0, 0) };
        lower.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
        lower.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
        _chart.Margin = new Padding(0, 0, 8, 0);
        lower.Controls.Add(_chart, 0, 0);

        var recentCard = new Card { Dock = DockStyle.Fill, Margin = new Padding(8, 0, 0, 0), Padding = new Padding(16, 40, 16, 12) };
        var rTitle = Kit.Label("RECENT ACTIVITY", Theme.Small, Theme.Muted); rTitle.Location = new Point(18, 14);
        recentCard.Controls.Add(rTitle);
        _recent = new ListBox
        {
            Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, BackColor = Theme.Card, ForeColor = Theme.Text,
            DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = 44, IntegralHeight = false
        };
        _recent.DrawItem += DrawRecent;
        _recent.DoubleClick += (_, _) => Main.Navigate("Alerts");
        recentCard.Controls.Add(_recent);
        lower.Controls.Add(recentCard, 1, 0);

        var footer = new Panel { Dock = DockStyle.Bottom, Height = 26, BackColor = Theme.Bg };
        _engineLine.Location = new Point(2, 8); footer.Controls.Add(_engineLine);

        Controls.Add(lower);
        Controls.Add(footer);
        Controls.Add(stats);
        Controls.Add(_banner);
        Controls.Add(Kit.PageHeader("Overview", "Real-time protection for every device on your home network"));
    }

    private void DrawRecent(object? sender, DrawItemEventArgs e)
    {
        if (e.Index < 0) return;
        var a = (Alert)_recent.Items[e.Index];
        var g = e.Graphics;
        using (var bg = new SolidBrush(Theme.Card)) g.FillRectangle(bg, e.Bounds);
        using (var dot = new SolidBrush(Theme.For(a.Severity))) g.FillEllipse(dot, e.Bounds.X + 2, e.Bounds.Y + 10, 10, 10);
        TextRenderer.DrawText(g, a.Title, Theme.BodyBold, new Rectangle(e.Bounds.X + 20, e.Bounds.Y + 3, e.Bounds.Width - 110, 20), Theme.Text, TextFormatFlags.EndEllipsis);
        var sub = a.Status == AlertStatus.Blocked ? "Blocked automatically · " + (a.RemoteIp ?? "") : (a.LocalIp ?? a.RemoteIp ?? "");
        TextRenderer.DrawText(g, sub, Theme.Small, new Rectangle(e.Bounds.X + 20, e.Bounds.Y + 22, e.Bounds.Width - 110, 18),
            a.Status == AlertStatus.Blocked ? Theme.Accent : Theme.Muted, TextFormatFlags.EndEllipsis);
        TextRenderer.DrawText(g, Kit.Ago(a.TimeUtc), Theme.Small, new Rectangle(e.Bounds.Right - 90, e.Bounds.Y + 4, 88, 18), Theme.Muted, TextFormatFlags.Right);
    }

    public override void OnActivated() => Reload();

    public void Reload()
    {
        var s = Engine.Settings;
        int critical = Engine.Alerts.OpenCount(Severity.High);
        int open = Engine.Alerts.OpenCount(Severity.Low);
        if (!s.ProtectionEnabled)
            _banner.Set("Protection is paused", "Threats are not being inspected or blocked. Resume protection as soon as possible.", Theme.Muted);
        else if (critical > 0)
            _banner.Set($"{critical} serious issue{(critical == 1 ? "" : "s")} need attention", "Review the alerts and choose Block or Ignore for each one.", Theme.Danger);
        else if (open > 0)
            _banner.Set("Protected – minor items to review", $"{open} lower-priority alert{(open == 1 ? "" : "s")} to review when convenient.", Theme.Warning);
        else
            _banner.Set("Your network is protected", Engine.CaptureAvailable
                ? "All protection layers active: threat intelligence, packet inspection, behavioural AI and device audits."
                : "Connection monitoring and device audits active. Install Npcap to enable full packet inspection.", Theme.Accent);
        _toggle.Text = s.ProtectionEnabled ? "Pause protection" : "Resume protection";
        _toggle.BackColor = s.ProtectionEnabled ? Theme.CardAlt : Theme.Accent;

        var devs = Engine.Devices;
        int risky = devs.Count(d => d.Risk == DeviceRisk.High && !d.Trusted);
        _devices.Set(devs.Count.ToString(), Engine.ScanInProgress ? "Scanning…" :
            risky > 0 ? $"{risky} high-risk – click to review" :
            Engine.LastScanUtc is { } t ? $"Last scan {Kit.Ago(t)}" : devs.Count == 0 ? "Scan pending" : "From last session",
            risky > 0 ? Theme.Danger : null);
        _alerts.Set(open.ToString(), critical > 0 ? $"{critical} high / critical" : "None serious", critical > 0 ? Theme.Danger : open > 0 ? Theme.Warning : Theme.Accent);
        var blocked = Engine.Firewall.Entries;
        _blocked.Set(blocked.Count.ToString(), $"{blocked.Count(b => b.Automatic)} blocked automatically");
        _intel.Set(Engine.Intel.EntryCount.ToString("N0"), Engine.Intel.LastFeedUpdateUtc is { } f ? $"Feeds updated {Kit.Ago(f)}" : "Local list only");

        var recent = Engine.Alerts.All.OrderByDescending(a => a.TimeUtc).Take(20).Cast<object>().ToArray();
        _recent.BeginUpdate(); _recent.Items.Clear(); _recent.Items.AddRange(recent); _recent.EndUpdate();
        OnStatsTick();
    }

    public override void OnStatsTick()
    {
        _chart.SetData(Engine.History);
        var up = DateTime.UtcNow - Engine.StartedUtc;
        _engineLine.Text = $"{Engine.CaptureStatus}   ·   {Engine.TotalPackets:N0} packets inspected   ·   " +
                           $"{Engine.AnomalyHostsTracked} device baselines learned   ·   up {(int)up.TotalHours}h {up.Minutes}m";
    }
}
