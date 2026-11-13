using System.Diagnostics;
using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

public sealed class SettingsPage : PageBase
{
    private readonly RadioButton _alertOnly, _highConf, _aggressive;
    private readonly ComboBox _adapter = Kit.Combo();
    private readonly CheckBox _promisc, _startup, _startMin, _tray, _notify, _newDevice, _autoFeeds;
    private readonly NumericUpDown _feedHours, _scanMins;
    private readonly TrackBar _sensitivity;
    private readonly Label _sensLabel = Kit.Label("", Theme.Small, Theme.Muted);
    private readonly TextBox _whitelist = Kit.TextBox(true), _feeds = Kit.TextBox(true);
    private List<AdapterChoice> _adapters = new();

    public SettingsPage(GuardEngine engine) : base(engine)
    {
        var s = engine.Settings;
        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = Theme.Bg };
        var col = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, BackColor = Theme.Bg, Location = new Point(0, 0) };
        scroll.Controls.Add(col);

        // ── Automatic response
        _alertOnly = Radio("Alert only – I'll decide what to block", s.AutoResponse == AutoResponseMode.AlertOnly);
        _highConf = Radio("Recommended – automatically block confirmed threats (threat-list matches and inbound exploits)", s.AutoResponse == AutoResponseMode.HighConfidenceOnly);
        _aggressive = Radio("Strict – automatically block every High or Critical internet detection", s.AutoResponse == AutoResponseMode.Aggressive);
        col.Controls.Add(Section("Automatic response",
            "Home-network devices and your router are never blocked automatically – that could cut you off. Internet addresses can be.",
            _highConf, _alertOnly, _aggressive));

        // ── Detection
        _sensitivity = new TrackBar { Minimum = 2, Maximum = 8, Value = (int)Math.Clamp(s.AnomalySensitivity, 2, 8), Width = 320, TickStyle = TickStyle.None, BackColor = Theme.Card };
        _sensitivity.ValueChanged += (_, _) => UpdateSensLabel();
        _newDevice = Kit.Check("Alert me when a new device joins the network", s.AlertOnNewDevice);
        _scanMins = Num(s.DeviceScanMinutes, 5, 1440);
        col.Controls.Add(Section("Detection",
            "Behavioural AI sensitivity – lower values catch more but may flag big downloads or backups.",
            Row(Kit.Label("More alerts", Theme.Small, Theme.Muted), _sensitivity, Kit.Label("Fewer alerts", Theme.Small, Theme.Muted)),
            _sensLabel, _newDevice, Row(Kit.Label("Audit devices every"), _scanMins, Kit.Label("minutes"))));
        UpdateSensLabel();

        // ── Packet capture
        _promisc = Kit.Check("Promiscuous mode (see other devices' traffic on wired/mirrored networks)", s.PromiscuousMode);
        _adapter.Width = 520;
        col.Controls.Add(Section("Packet inspection",
            "Requires the free Npcap driver. On Wi-Fi, Windows only sees this PC's traffic; to inspect every IoT device, connect this PC by cable to a switch port that mirrors the router port.",
            _adapter, _promisc,
            Row(Kit.Button("Apply & restart capture", (_, _) => { Save(); Engine.StartCapture(); Kit.Info(FindForm()!, Engine.CaptureStatus); }),
                Kit.Button("Download Npcap", (_, _) => Open("https://npcap.com/#download")))));

        // ── Threat feeds
        _autoFeeds = Kit.Check("Update threat feeds automatically", s.AutoUpdateThreatFeeds);
        _feedHours = Num(s.FeedUpdateHours, 1, 168);
        _feeds.Text = string.Join(Environment.NewLine, s.FeedUrls); _feeds.Size = new Size(620, 70);
        col.Controls.Add(Section("Threat intelligence", "Plain-text IP or CIDR lists, one URL per line.",
            _autoFeeds, Row(Kit.Label("Every"), _feedHours, Kit.Label("hours")), _feeds));

        // ── Trusted addresses
        _whitelist.Text = string.Join(Environment.NewLine, s.WhitelistIps); _whitelist.Size = new Size(620, 70);
        col.Controls.Add(Section("Trusted addresses", "Never alert on or block these IPs (one per line).", _whitelist));

        // ── Application
        _startup = Kit.Check("Start protection automatically when I sign in to Windows", s.StartWithWindows);
        _startMin = Kit.Check("Start hidden in the system tray", s.StartMinimised);
        _tray = Kit.Check("Closing the window keeps protection running in the tray", s.MinimiseToTray);
        _notify = Kit.Check("Show desktop notifications for High and Critical alerts", s.DesktopNotifications);
        col.Controls.Add(Section("Application", $"Data folder: {AppPaths.Root}", _startup, _startMin, _tray, _notify,
            Row(Kit.Button("Open data folder", (_, _) => Open(AppPaths.Root)))));

        var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 52, BackColor = Theme.Bg, Padding = new Padding(0, 10, 0, 0) };
        bar.Controls.Add(Kit.Button("Save settings", (_, _) => { Save(); Kit.Info(FindForm()!, "Settings saved."); }, primary: true));
        bar.Controls.Add(Kit.Button("Restore defaults", (_, _) => RestoreDefaults()));

        Controls.Add(scroll);
        Controls.Add(bar);
        Controls.Add(Kit.PageHeader("Settings", "Tune how CAS HomeNet Guard protects your network"));
    }

    public override void OnActivated()
    {
        _adapters = GuardEngine.ListAdapters();
        _adapter.Items.Clear();
        _adapter.Items.Add("Automatic (adapter with my home network address)");
        foreach (var a in _adapters) _adapter.Items.Add(a.Description);
        if (_adapters.Count == 0) _adapter.Items[0] = "Npcap not installed – packet inspection unavailable";
        var idx = _adapters.FindIndex(a => a.Name == Engine.Settings.CaptureAdapterName);
        _adapter.SelectedIndex = idx < 0 ? 0 : idx + 1;
        _startup.Checked = AutoStart.IsEnabled();
    }

    private void UpdateSensLabel() =>
        _sensLabel.Text = $"Flag uploads more than {_sensitivity.Value} standard deviations above a device's learned normal.";

    private void Save()
    {
        var s = Engine.Settings;
        s.AutoResponse = _alertOnly.Checked ? AutoResponseMode.AlertOnly : _aggressive.Checked ? AutoResponseMode.Aggressive : AutoResponseMode.HighConfidenceOnly;
        s.AnomalySensitivity = _sensitivity.Value;
        s.AlertOnNewDevice = _newDevice.Checked;
        s.DeviceScanMinutes = (int)_scanMins.Value;
        s.PromiscuousMode = _promisc.Checked;
        s.CaptureAdapterName = _adapter.SelectedIndex > 0 ? _adapters[_adapter.SelectedIndex - 1].Name : null;
        s.AutoUpdateThreatFeeds = _autoFeeds.Checked;
        s.FeedUpdateHours = (int)_feedHours.Value;
        s.FeedUrls = Lines(_feeds.Text).Where(u => Uri.TryCreate(u, UriKind.Absolute, out var x) && x.Scheme == "https").ToList();
        s.WhitelistIps = Lines(_whitelist.Text).Where(ip => IpUtil.TryToUInt(ip, out _)).ToList();
        s.StartMinimised = _startMin.Checked;
        s.MinimiseToTray = _tray.Checked;
        s.DesktopNotifications = _notify.Checked;
        if (_startup.Checked != s.StartWithWindows || _startup.Checked != AutoStart.IsEnabled())
        {
            var (ok, msg) = AutoStart.Set(_startup.Checked);
            if (!ok) Kit.Info(FindForm()!, "Couldn't change start-up setting: " + msg);
            s.StartWithWindows = ok ? _startup.Checked : s.StartWithWindows;
        }
        Engine.ApplySettings();
    }

    private void RestoreDefaults()
    {
        if (!Kit.Confirm(FindForm()!, "Restore default settings? Your device names, alerts and blocks are kept.")) return;
        var d = new Settings();
        _highConf.Checked = true; _sensitivity.Value = (int)d.AnomalySensitivity; _newDevice.Checked = d.AlertOnNewDevice;
        _scanMins.Value = d.DeviceScanMinutes; _promisc.Checked = d.PromiscuousMode; _adapter.SelectedIndex = 0;
        _autoFeeds.Checked = d.AutoUpdateThreatFeeds; _feedHours.Value = d.FeedUpdateHours;
        _feeds.Text = string.Join(Environment.NewLine, d.FeedUrls); _startMin.Checked = d.StartMinimised;
        _tray.Checked = d.MinimiseToTray; _notify.Checked = d.DesktopNotifications;
        Save();
    }

    // ── layout helpers
    private static IEnumerable<string> Lines(string t) => t.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#'));

    private static RadioButton Radio(string text, bool on) => new()
    {
        Text = text, Checked = on, AutoSize = true, ForeColor = Theme.Text, Font = Theme.Body, Margin = new Padding(0, 4, 0, 4)
    };

    private static NumericUpDown Num(int v, int min, int max) => new()
    {
        Minimum = min, Maximum = max, Value = Math.Clamp(v, min, max), Width = 70,
        BackColor = Theme.CardAlt, ForeColor = Theme.Text, BorderStyle = BorderStyle.FixedSingle
    };

    private static FlowLayoutPanel Row(params Control[] items)
    {
        var f = new FlowLayoutPanel { AutoSize = true, WrapContents = false, BackColor = Theme.Card, Margin = new Padding(0, 4, 0, 4) };
        foreach (var c in items) { c.Margin = new Padding(0, 3, 8, 0); f.Controls.Add(c); }
        return f;
    }

    private static Card Section(string title, string help, params Control[] items)
    {
        var card = new Card { Width = 760, AutoSize = false, Margin = new Padding(0, 0, 0, 14), Padding = new Padding(20, 14, 20, 14) };
        var inner = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Location = new Point(20, 14), BackColor = Theme.Card };
        var h = Kit.Label(title, Theme.H2); h.Margin = new Padding(0, 0, 0, 2);
        var hp = Kit.Label(help, Theme.Small, Theme.Muted); hp.MaximumSize = new Size(700, 0); hp.Margin = new Padding(0, 0, 0, 8);
        inner.Controls.Add(h); inner.Controls.Add(hp);
        foreach (var c in items) { if (c is not FlowLayoutPanel) c.BackColor = c is TextBox or ComboBox or NumericUpDown ? Theme.CardAlt : Theme.Card; inner.Controls.Add(c); }
        card.Controls.Add(inner);
        card.Height = inner.PreferredSize.Height + 30;
        inner.SizeChanged += (_, _) => card.Height = inner.Height + 30;
        return card;
    }

    private static void Open(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); } catch { }
    }
}

public sealed class ActivityPage : PageBase
{
    private readonly TextBox _log;

    public ActivityPage(GuardEngine engine) : base(engine)
    {
        _log = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, WordWrap = false,
            BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None, Font = Theme.Mono
        };
        var card = new Card { Dock = DockStyle.Fill, Padding = new Padding(14) };
        card.Controls.Add(_log);
        var bar = Kit.Toolbar();
        bar.Controls.Add(Kit.Button("Open full log", (_, _) =>
            Process.Start(new ProcessStartInfo("notepad.exe", $"\"{AppPaths.LogFile}\"") { UseShellExecute = true })));
        Controls.Add(card);
        Controls.Add(bar);
        Controls.Add(Kit.PageHeader("Activity log", "Everything the protection engine has done, in order"));
        EngineLog.LineWritten += line => { if (IsHandleCreated) BeginInvoke(() => Append(line)); };
    }

    public override void OnActivated()
    {
        try
        {
            if (!File.Exists(AppPaths.LogFile)) return;
            using var fs = new FileStream(AppPaths.LogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var lines = sr.ReadToEnd().Split('\n');
            _log.Text = string.Join(Environment.NewLine, lines.TakeLast(500).Select(l => l.TrimEnd('\r')));
            _log.SelectionStart = _log.TextLength; _log.ScrollToCaret();
        }
        catch { }
    }

    private void Append(string line)
    {
        if (_log.TextLength > 200_000) _log.Text = _log.Text[^100_000..];
        _log.AppendText(Environment.NewLine + line);
    }
}
