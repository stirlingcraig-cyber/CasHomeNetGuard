using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

public sealed class DevicesPage : PageBase
{
    private readonly DataGridView _grid = Kit.Grid();
    private readonly Label _status = Kit.Label("", Theme.Body, Theme.Muted);
    private readonly RichTextBox _detail;
    private readonly Label _detailTitle = Kit.Label("Select a device", Theme.H2);
    private readonly FlowLayoutPanel _detailActions;
    private DeviceInfo? _selected;

    public DevicesPage(GuardEngine engine) : base(engine)
    {
        var bar = Kit.Toolbar();
        bar.Controls.Add(Kit.Button("Scan network now", async (_, _) => await Main.RunScanAsync(), primary: true));
        bar.Controls.Add(Kit.Button("Export inventory", (_, _) => Export()));
        _status.Margin = new Padding(8, 9, 0, 0);
        bar.Controls.Add(_status);

        _grid.Columns.AddRange(
            Kit.Col("Risk", 45, 60), Kit.Col("Name", 120), Kit.Col("IP address", 80), Kit.Col("Category", 95),
            Kit.Col("Vendor", 100), Kit.Col("MAC address", 90), Kit.Col("Open services", 110), Kit.Col("Last seen", 60));
        _grid.CellFormatting += (_, e) =>
        {
            if (e.RowIndex < 0 || _grid.Rows[e.RowIndex].Tag is not DeviceInfo d) return;
            if (e.ColumnIndex == 0) { e.CellStyle!.ForeColor = Theme.For(d.Risk); e.CellStyle.Font = Theme.BodyBold; }
        };
        _grid.SelectionChanged += (_, _) => ShowDetail(_grid.CurrentRow?.Tag as DeviceInfo);

        // Detail pane
        var detailCard = new Card { Dock = DockStyle.Bottom, Height = 250, Padding = new Padding(18, 14, 18, 14) };
        var head = new Panel { Dock = DockStyle.Top, Height = 34, BackColor = Theme.Card };
        _detailTitle.Location = new Point(0, 2); head.Controls.Add(_detailTitle);
        _detailActions = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 42, BackColor = Theme.Card, Padding = new Padding(0, 6, 0, 0) };
        _detailActions.Controls.Add(Kit.Button("Rename", (_, _) => Rename()));
        _detailActions.Controls.Add(Kit.Button("Mark as trusted", (_, _) => ToggleTrust()));
        _detailActions.Controls.Add(Kit.Button("Block from this PC", (_, _) => BlockLocal(), danger: true));
        _detailActions.Controls.Add(Kit.Button("How to isolate this device", (_, _) => IsolationHelp()));
        _detailActions.Controls.Add(Kit.Button("Forget", (_, _) => Forget()));
        _detail = new RichTextBox
        {
            Dock = DockStyle.Fill, BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None,
            ReadOnly = true, Font = Theme.Body, DetectUrls = false
        };
        detailCard.Controls.Add(_detail);
        detailCard.Controls.Add(_detailActions);
        detailCard.Controls.Add(head);

        var gridCard = new Card { Dock = DockStyle.Fill, Padding = new Padding(1) };
        gridCard.Controls.Add(_grid);

        var spacer = new Panel { Dock = DockStyle.Bottom, Height = 14, BackColor = Theme.Bg };
        Controls.Add(gridCard);
        Controls.Add(spacer);
        Controls.Add(detailCard);
        Controls.Add(bar);
        Controls.Add(Kit.PageHeader("Devices", "Everything connected to your home network – including smart-home and IoT gadgets"));
        ShowDetail(null);
    }

    public override void OnActivated() => Reload();

    public void Reload()
    {
        var keep = _selected?.Ip;
        var devices = Engine.Devices.OrderByDescending(d => d.Risk).ThenBy(d => IpUtil.TryToUInt(d.Ip, out var v) ? v : 0).ToList();
        _grid.Rows.Clear();
        foreach (var d in devices)
        {
            var ports = d.OpenPorts.Count == 0 ? "–" : string.Join(", ", d.OpenPorts.Select(p =>
                DeviceScanner.RiskyPorts.FirstOrDefault(r => r.Port == p)?.Service ?? p.ToString()));
            var name = d.DisplayName + (d.Trusted ? "  ✓" : "") + (d.IsGateway ? "  (router)" : d.IsThisPc ? "  (this PC)" : "");
            int i = _grid.Rows.Add(d.Trusted && d.Risk > DeviceRisk.Low ? "Trusted" : d.Risk.ToString(), name, d.Ip, d.Category, d.Vendor,
                d.Mac, ports, Kit.Ago(d.LastSeenUtc));
            _grid.Rows[i].Tag = d;
            if (d.Ip == keep) { _grid.ClearSelection(); _grid.Rows[i].Selected = true; _grid.CurrentCell = _grid.Rows[i].Cells[0]; }
        }
        int high = devices.Count(d => d.Risk == DeviceRisk.High && !d.Trusted);
        _status.Text = Engine.ScanInProgress ? "Scanning your network…" :
            $"{devices.Count} devices  ·  {high} high-risk  ·  " +
            (Engine.LastScanUtc is { } t ? $"last scanned {Kit.Ago(t)}" : "not yet scanned this session") +
            $"  ·  auto-scan every {Engine.Settings.DeviceScanMinutes} min";
        if (_grid.Rows.Count == 0) ShowDetail(null);
    }

    public void SetScanProgress(string text) => _status.Text = text;

    private void ShowDetail(DeviceInfo? d)
    {
        _selected = d;
        foreach (Control c in _detailActions.Controls) c.Enabled = d != null;
        _detail.Clear();
        if (d == null)
        {
            _detailTitle.Text = "Select a device";
            _detail.SelectionColor = Theme.Muted;
            _detail.AppendText("Choose a device above to see its security findings and how to fix them.\n\n" +
                               "Tip: name your devices and mark the ones you recognise as trusted – you'll then be alerted only when something new appears.");
            return;
        }
        _detailTitle.Text = $"{d.DisplayName}  –  {d.Category}";
        _detailActions.Controls[1].Text = d.Trusted ? "Remove trust" : "Mark as trusted";

        void Line(string label, string value, Color? c = null)
        {
            _detail.SelectionColor = Theme.Muted; _detail.SelectionFont = Theme.Body; _detail.AppendText(label.PadRight(14));
            _detail.SelectionColor = c ?? Theme.Text; _detail.SelectionFont = Theme.BodyBold; _detail.AppendText(value + "\n");
        }
        Line("Risk", d.Risk + (d.Trusted ? " (you marked this device as trusted)" : ""), Theme.For(d.Risk));
        Line("Address", $"{d.Ip}   MAC {d.Mac}   Vendor {d.Vendor}");
        if (!string.IsNullOrEmpty(d.HostName)) Line("Host name", d.HostName);
        Line("First seen", d.FirstSeenUtc.ToLocalTime().ToString("dd MMM yyyy HH:mm"));
        _detail.AppendText("\n");
        if (d.Findings.Count == 0)
        {
            _detail.SelectionColor = Theme.Accent; _detail.AppendText("✓ No risky services found on this device.\n");
        }
        foreach (var f in d.Findings)
        {
            var bad = f.Contains("Telnet") || f.Contains("ADB") || f.Contains("backdoor") || f.Contains("VNC") || f.Contains("DVR");
            _detail.SelectionColor = bad ? Theme.Danger : f.StartsWith("Port") ? Theme.Warning : Theme.Muted;
            _detail.SelectionFont = Theme.Body;
            _detail.AppendText("•  " + f + "\n");
        }
    }

    private void Rename()
    {
        if (_selected == null) return;
        var name = Prompt.Show(FindForm()!, "Rename device", $"Friendly name for {_selected.Ip}:", _selected.Nickname);
        if (name == null) return;
        _selected.Nickname = name.Trim();
        Engine.UpdateDevice(_selected);
        Reload();
    }

    private void ToggleTrust()
    {
        if (_selected == null) return;
        _selected.Trusted = !_selected.Trusted;
        Engine.UpdateDevice(_selected);
        Reload();
    }

    private void BlockLocal()
    {
        if (_selected == null) return;
        if (_selected.IsGateway) { Kit.Info(FindForm()!, "Blocking your router would disconnect this PC from the internet, so it isn't allowed."); return; }
        if (_selected.IsThisPc) return;
        if (!Kit.Confirm(FindForm()!, $"Block all traffic between this PC and {_selected.DisplayName} ({_selected.Ip})?\n\n" +
                                      "Note: this protects this PC only. To cut the device off from the internet, use 'How to isolate this device'.")) return;
        var (_, msg) = Engine.Firewall.Block(_selected.Ip, $"Manual device block: {_selected.DisplayName}", false);
        Kit.Info(FindForm()!, msg);
    }

    private void IsolationHelp() => Kit.Info(FindForm()!,
        "A Windows PC can't stop another device talking to the internet – that has to be done on your router.\n\n" +
        $"To isolate {_selected?.DisplayName} ({_selected?.Ip}, MAC {_selected?.Mac}):\n\n" +
        "1.  Quickest: unplug it, or remove it from your Wi-Fi.\n" +
        "2.  In your router admin page (usually http://" + (Engine.Devices.FirstOrDefault(d => d.IsGateway)?.Ip ?? "192.168.1.1") + "), find 'Connected devices' or 'Access control' and block this MAC address.\n" +
        "3.  Better long-term: put smart-home gadgets on a separate Guest / IoT Wi-Fi network so they can't reach your PCs and phones.\n" +
        "4.  Factory-reset an infected gadget, update its firmware, and set a new unique password before reconnecting it.\n" +
        "5.  Change your Wi-Fi password if the device is unknown to you.",
        "Isolating a device");

    private void Forget()
    {
        if (_selected == null) return;
        Engine.ForgetDevice(_selected.Ip);
        Reload();
    }

    private void Export()
    {
        using var dlg = new SaveFileDialog { Filter = "CSV file|*.csv", FileName = $"home-devices-{DateTime.Now:yyyyMMdd}.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var lines = new List<string> { "Name,IP,MAC,Vendor,Category,Risk,Trusted,OpenPorts,FirstSeen,LastSeen" };
        lines.AddRange(Engine.Devices.Select(d => string.Join(",", new[]
        {
            d.DisplayName, d.Ip, d.Mac, d.Vendor, d.Category, d.Risk.ToString(), d.Trusted.ToString(),
            string.Join(" ", d.OpenPorts), d.FirstSeenUtc.ToLocalTime().ToString("s"), d.LastSeenUtc.ToLocalTime().ToString("s")
        }.Select(Csv))));
        File.WriteAllLines(dlg.FileName, lines);
    }

    internal static string Csv(string s) => s.Contains(',') || s.Contains('"') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
}

/// <summary>Minimal themed input dialog.</summary>
public static class Prompt
{
    public static string? Show(IWin32Window owner, string title, string label, string value = "")
    {
        using var f = new Form
        {
            Text = title, Width = 420, Height = 180, FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent, MaximizeBox = false, MinimizeBox = false,
            BackColor = Theme.Card, ForeColor = Theme.Text, Font = Theme.Body, ShowInTaskbar = false
        };
        var l = Kit.Label(label); l.Location = new Point(16, 16);
        var t = Kit.TextBox(); t.Text = value; t.SetBounds(16, 42, 372, 26);
        var ok = Kit.Button("OK", (_, _) => f.DialogResult = DialogResult.OK, primary: true); ok.Location = new Point(240, 86);
        var cancel = Kit.Button("Cancel", (_, _) => f.DialogResult = DialogResult.Cancel); cancel.Location = new Point(316, 86);
        f.Controls.AddRange(new Control[] { l, t, ok, cancel });
        f.AcceptButton = ok; f.CancelButton = cancel;
        return f.ShowDialog(owner) == DialogResult.OK ? t.Text : null;
    }
}
