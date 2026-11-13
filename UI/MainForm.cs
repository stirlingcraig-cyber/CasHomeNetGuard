using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

public sealed class MainForm : Form
{
    private readonly GuardEngine _engine;
    private readonly Panel _content = new() { Dock = DockStyle.Fill, BackColor = Theme.Bg };
    private readonly Dictionary<string, (NavButton nav, PageBase page)> _pages = new();
    private readonly NotifyIcon _tray;
    private readonly ToolStripMenuItem _trayToggle;
    private readonly Label _sideStatus = Kit.Label("", Theme.Small, Theme.Muted, autoSize: false);
    private readonly Panel _sideDot = new() { Size = new Size(10, 10) };
    private string _current = "";
    private bool _reallyExit;
    private readonly bool _startHidden;

    public MainForm(GuardEngine engine, bool startHidden)
    {
        _engine = engine; _startHidden = startHidden;
        Text = "CAS HomeNet Guard";
        Icon = Theme.AppIcon();
        MinimumSize = new Size(1100, 720);
        Size = new Size(1320, 840);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Theme.Bg; ForeColor = Theme.Text; Font = Theme.Body;
        DoubleBuffered = true;

        // ── Sidebar
        var side = new Panel { Dock = DockStyle.Left, Width = 236, BackColor = Theme.Sidebar };
        var brand = new Panel { Dock = DockStyle.Top, Height = 92, BackColor = Theme.Sidebar };
        var logo = new PictureBox { Image = Theme.AppIcon().ToBitmap(), SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(38, 38), Location = new Point(22, 26) };
        var name = Kit.Label("HomeNet Guard", Theme.H2); name.Location = new Point(68, 24);
        var by = Kit.Label("CAS Solutions", Theme.Small, Theme.Accent); by.Location = new Point(70, 50);
        brand.Controls.AddRange(new Control[] { logo, name, by });

        var nav = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Sidebar, Padding = new Padding(0, 8, 0, 0) };
        var foot = new Panel { Dock = DockStyle.Bottom, Height = 70, BackColor = Theme.Sidebar };
        _sideDot.Location = new Point(24, 18);
        _sideDot.Paint += (_, e) =>
        {
            e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            e.Graphics.Clear(Theme.Sidebar);
            using var b = new SolidBrush(_engine.Settings.ProtectionEnabled ? Theme.Accent : Theme.Danger);
            e.Graphics.FillEllipse(b, 0, 0, 9, 9);
        };
        _sideStatus.SetBounds(42, 12, 180, 48);
        foot.Controls.Add(_sideDot); foot.Controls.Add(_sideStatus);

        side.Controls.Add(nav); side.Controls.Add(foot); side.Controls.Add(brand);
        Controls.Add(_content);
        Controls.Add(side);

        // ── Pages (added in reverse because of Dock=Top stacking)
        var defs = new (string key, string glyph, PageBase page)[]
        {
            ("Overview", "", new DashboardPage(engine)),
            ("Devices", "", new DevicesPage(engine)),
            ("Alerts", "", new AlertsPage(engine)),
            ("Connections", "", new ConnectionsPage(engine)),
            ("Firewall", "", new FirewallPage(engine)),
            ("Activity", "", new ActivityPage(engine)),
            ("Settings", "", new SettingsPage(engine)),
        };
        foreach (var (key, glyph, page) in defs.Reverse())
        {
            var b = new NavButton(key, glyph);
            b.Click += (_, _) => Navigate(key);
            nav.Controls.Add(b);
            _pages[key] = (b, page);
        }

        // ── Tray
        _trayToggle = new ToolStripMenuItem("Pause protection", null, (_, _) => { _engine.SetProtection(!_engine.Settings.ProtectionEnabled); RefreshChrome(); });
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open HomeNet Guard", null, (_, _) => ShowFromTray());
        menu.Items.Add("Scan network now", null, async (_, _) => await RunScanAsync());
        menu.Items.Add(_trayToggle);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit (stops protection)", null, (_, _) => ExitApp());
        _tray = new NotifyIcon { Icon = Icon, Text = "CAS HomeNet Guard – protected", Visible = true, ContextMenuStrip = menu };
        _tray.DoubleClick += (_, _) => ShowFromTray();
        _tray.BalloonTipClicked += (_, _) => { ShowFromTray(); Navigate("Alerts"); };

        // ── Engine events (raised on background threads)
        _engine.AlertRaised += a => Ui(() => OnAlert(a));
        _engine.Alerts.Changed += _ => Ui(RefreshChrome);
        _engine.StatsTick += () => Ui(() => { if (_pages.TryGetValue(_current, out var p)) p.page.OnStatsTick(); });
        _engine.DevicesUpdated += () => Ui(() => { RefreshChrome(); if (_current == "Devices") ((DevicesPage)_pages["Devices"].page).Reload(); });
        _engine.StatusMessage += m => Ui(RefreshChrome);
        _engine.Scanner.Progress += m => Ui(() => ((DevicesPage)_pages["Devices"].page).SetScanProgress(m));

        Navigate("Overview");
        RefreshChrome();
    }

    protected override void SetVisibleCore(bool value)
    {
        // Honour "start hidden in tray" without flashing the window
        if (_startHidden && !IsHandleCreated) { CreateHandle(); value = false; }
        base.SetVisibleCore(value);
    }

    public void Navigate(string key)
    {
        if (!_pages.TryGetValue(key, out var target)) return;
        foreach (var (k, (n, _)) in _pages) n.Selected = k == key;
        _content.SuspendLayout();
        _content.Controls.Clear();
        _content.Controls.Add(target.page);
        _content.ResumeLayout();
        _current = key;
        target.page.OnActivated();
    }

    public void RefreshChrome()
    {
        int open = _engine.Alerts.OpenCount(Severity.Medium);
        _pages["Alerts"].nav.Badge = open;
        bool on = _engine.Settings.ProtectionEnabled;
        _sideStatus.Text = (on ? "Protection active" : "Protection PAUSED") + "\n" +
                           (_engine.CaptureAvailable ? "Packet inspection on" : "Packet inspection off (no Npcap)");
        _sideStatus.ForeColor = on ? Theme.Muted : Theme.Danger;
        _sideDot.Invalidate();
        _trayToggle.Text = on ? "Pause protection" : "Resume protection";
        var trayText = on ? (open > 0 ? $"CAS HomeNet Guard – {open} alert(s)" : "CAS HomeNet Guard – protected") : "CAS HomeNet Guard – PAUSED";
        _tray.Text = trayText.Length > 63 ? trayText[..63] : trayText;
        if (_current == "Overview") ((DashboardPage)_pages["Overview"].page).Reload();
    }

    private void OnAlert(Alert a)
    {
        RefreshChrome();
        if (_current == "Alerts") ((AlertsPage)_pages["Alerts"].page).Reload();
        if (_engine.Settings.DesktopNotifications && a.Severity >= Severity.High)
        {
            var blocked = a.Status == AlertStatus.Blocked;
            _tray.ShowBalloonTip(6000, blocked ? "Threat blocked" : $"{a.Severity} alert", $"{a.Title}\n{(blocked ? $"{a.RemoteIp} was blocked automatically." : a.Detail)}",
                blocked ? ToolTipIcon.Info : ToolTipIcon.Warning);
        }
    }

    public async Task RunScanAsync()
    {
        if (_engine.ScanInProgress) return;
        ((DevicesPage)_pages["Devices"].page).SetScanProgress("Starting network scan…");
        RefreshChrome();
        var msg = await _engine.ScanDevicesAsync();
        RefreshChrome();
        if (_current == "Devices") ((DevicesPage)_pages["Devices"].page).Reload();
        if (Visible && _current is "Devices" or "Overview") _tray.ShowBalloonTip(3000, "Network scan", msg, ToolTipIcon.Info);
    }

    private void ShowFromTray()
    {
        Show(); WindowState = FormWindowState.Normal; Activate();
        if (_pages.TryGetValue(_current, out var p)) p.page.OnActivated();
    }

    private void ExitApp()
    {
        if (!Kit.Confirm(this, "Exit CAS HomeNet Guard? Your network will not be monitored until you start it again.\n\n(Firewall blocks already in place remain active.)")) return;
        _reallyExit = true;
        Close();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_reallyExit && _engine.Settings.MinimiseToTray && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            _tray.ShowBalloonTip(2500, "Still protecting you", "CAS HomeNet Guard keeps running in the system tray.", ToolTipIcon.Info);
            return;
        }
        _tray.Visible = false;
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _tray.Dispose();
        base.Dispose(disposing);
    }

    private void Ui(Action a)
    {
        if (IsDisposed || !IsHandleCreated) return;
        try { BeginInvoke(a); } catch (ObjectDisposedException) { } catch (InvalidOperationException) { }
    }
}
