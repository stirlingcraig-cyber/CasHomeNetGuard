using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

public sealed class AlertsPage : PageBase
{
    private readonly DataGridView _grid = Kit.Grid();
    private readonly ComboBox _statusFilter = Kit.Combo();
    private readonly ComboBox _sevFilter = Kit.Combo();
    private readonly Label _title = Kit.Label("Select an alert", Theme.H2);
    private readonly RichTextBox _body;
    private readonly FlowLayoutPanel _actions;
    private Alert? _selected;

    public AlertsPage(GuardEngine engine) : base(engine)
    {
        var bar = Kit.Toolbar();
        _statusFilter.Items.AddRange(new object[] { "Needs action", "All alerts", "Blocked", "Ignored", "Resolved" });
        _statusFilter.SelectedIndex = 0; _statusFilter.Width = 150; _statusFilter.Margin = new Padding(0, 5, 8, 0);
        _sevFilter.Items.AddRange(new object[] { "All severities", "Critical only", "High and above", "Medium and above" });
        _sevFilter.SelectedIndex = 0; _sevFilter.Width = 160; _sevFilter.Margin = new Padding(0, 5, 16, 0);
        _statusFilter.SelectedIndexChanged += (_, _) => Reload();
        _sevFilter.SelectedIndexChanged += (_, _) => Reload();
        bar.Controls.Add(_statusFilter);
        bar.Controls.Add(_sevFilter);
        bar.Controls.Add(Kit.Button("Mark all reviewed", (_, _) => ResolveAll()));
        bar.Controls.Add(Kit.Button("Export CSV", (_, _) => Export()));
        bar.Controls.Add(Kit.Button("Clear history", (_, _) =>
        {
            if (!Kit.Confirm(FindForm()!, "Delete all alert history? Blocked addresses stay blocked.")) return;
            Engine.Alerts.Clear(); Reload(); Main.RefreshChrome();
        }));

        _grid.Columns.AddRange(Kit.Col("Severity", 50, 70), Kit.Col("Time", 60, 90), Kit.Col("Alert", 190),
            Kit.Col("Device", 70), Kit.Col("Remote", 70), Kit.Col("Detector", 60), Kit.Col("Status", 55));
        _grid.CellFormatting += (_, e) =>
        {
            if (e.RowIndex < 0 || _grid.Rows[e.RowIndex].Tag is not Alert a) return;
            if (e.ColumnIndex == 0) { e.CellStyle!.ForeColor = Theme.For(a.Severity); e.CellStyle.Font = Theme.BodyBold; }
            if (e.ColumnIndex == 6) e.CellStyle!.ForeColor = a.Status switch
            {
                AlertStatus.Blocked => Theme.Accent, AlertStatus.Open => Theme.Warning, _ => Theme.Muted
            };
        };
        _grid.SelectionChanged += (_, _) => Show(_grid.CurrentRow?.Tag as Alert);

        var detail = new Card { Dock = DockStyle.Bottom, Height = 230, Padding = new Padding(18, 14, 18, 14) };
        var head = new Panel { Dock = DockStyle.Top, Height = 34, BackColor = Theme.Card };
        _title.Location = new Point(0, 2); head.Controls.Add(_title);
        _body = new RichTextBox { Dock = DockStyle.Fill, BackColor = Theme.Card, ForeColor = Theme.Text, BorderStyle = BorderStyle.None, ReadOnly = true, Font = Theme.Body };
        _actions = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 42, BackColor = Theme.Card, Padding = new Padding(0, 6, 0, 0) };
        _actions.Controls.Add(Kit.Button("Block remote address", (_, _) => Block(), danger: true));
        _actions.Controls.Add(Kit.Button("Mark resolved", (_, _) => SetStatus(AlertStatus.Resolved)));
        _actions.Controls.Add(Kit.Button("Ignore – don't alert again", (_, _) => SetStatus(AlertStatus.Ignored)));
        _actions.Controls.Add(Kit.Button("Trust this address", (_, _) => Trust()));
        _actions.Controls.Add(Kit.Button("Look up address", (_, _) => Lookup()));
        _actions.Controls.Add(Kit.Button("Copy details", (_, _) => { if (_selected != null) Clipboard.SetText(Describe(_selected)); }));
        detail.Controls.Add(_body); detail.Controls.Add(_actions); detail.Controls.Add(head);

        var gridCard = new Card { Dock = DockStyle.Fill, Padding = new Padding(1) };
        gridCard.Controls.Add(_grid);
        Controls.Add(gridCard);
        Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 14, BackColor = Theme.Bg });
        Controls.Add(detail);
        Controls.Add(bar);
        Controls.Add(Kit.PageHeader("Alerts", "What the guard has detected – and what you should do about it"));
        Show(null);
    }

    public override void OnActivated() => Reload();

    public void Reload()
    {
        var keep = _selected?.Id;
        IEnumerable<Alert> q = Engine.Alerts.All.OrderByDescending(a => a.TimeUtc);
        q = _statusFilter.SelectedIndex switch
        {
            0 => q.Where(a => a.Status == AlertStatus.Open),
            2 => q.Where(a => a.Status == AlertStatus.Blocked),
            3 => q.Where(a => a.Status == AlertStatus.Ignored),
            4 => q.Where(a => a.Status == AlertStatus.Resolved),
            _ => q
        };
        q = _sevFilter.SelectedIndex switch
        {
            1 => q.Where(a => a.Severity == Severity.Critical),
            2 => q.Where(a => a.Severity >= Severity.High),
            3 => q.Where(a => a.Severity >= Severity.Medium),
            _ => q
        };
        _grid.Rows.Clear();
        foreach (var a in q.Take(1000))
        {
            int i = _grid.Rows.Add(a.Severity.ToString(), a.TimeUtc.ToLocalTime().ToString("dd MMM HH:mm:ss"), a.Title,
                DeviceName(a.LocalIp), a.RemoteIp ?? "–", a.Source switch
                {
                    AlertSource.ThreatIntel => "Threat intel", AlertSource.Signature => "Packet inspection",
                    AlertSource.Anomaly => "Behavioural AI", AlertSource.DeviceAudit => "Device audit", _ => "System"
                }, a.Status.ToString());
            _grid.Rows[i].Tag = a;
            if (a.Id == keep) { _grid.ClearSelection(); _grid.Rows[i].Selected = true; _grid.CurrentCell = _grid.Rows[i].Cells[0]; }
        }
        if (_grid.Rows.Count == 0) Show(null);
    }

    private string DeviceName(string? ip)
    {
        if (ip == null) return "–";
        var d = Engine.Devices.FirstOrDefault(x => x.Ip == ip);
        return d == null ? ip : d.DisplayName == ip ? ip : $"{d.DisplayName} ({ip})";
    }

    private void Show(Alert? a)
    {
        _selected = a;
        foreach (Control c in _actions.Controls) c.Enabled = a != null;
        _body.Clear();
        if (a == null)
        {
            _title.Text = _grid.Rows.Count == 0 ? "Nothing needs your attention" : "Select an alert";
            _title.ForeColor = Theme.Text;
            _body.SelectionColor = Theme.Muted;
            _body.AppendText(_grid.Rows.Count == 0 ? "✓ No alerts match this filter." : "Choose an alert above to see what happened and the recommended action.");
            return;
        }
        bool blockable = a.RemoteIp != null && !IpUtil.IsLocalOrSpecial(a.RemoteIp) && a.Status != AlertStatus.Blocked;
        _actions.Controls[0].Enabled = blockable;
        _actions.Controls[3].Enabled = _actions.Controls[4].Enabled = a.RemoteIp != null && !IpUtil.IsLocalOrSpecial(a.RemoteIp);
        _title.Text = a.Title;
        _title.ForeColor = Theme.For(a.Severity);
        _body.SelectionColor = Theme.Muted; _body.AppendText($"{a.Severity} · {a.TimeUtc.ToLocalTime():dddd dd MMM yyyy HH:mm:ss} · status {a.Status}\n\n");
        _body.SelectionColor = Theme.Text; _body.SelectionFont = Theme.Body; _body.AppendText(a.Detail + "\n\n");
        if (!string.IsNullOrEmpty(a.Recommendation))
        {
            _body.SelectionColor = Theme.Accent; _body.SelectionFont = Theme.BodyBold; _body.AppendText("What to do:  ");
            _body.SelectionColor = Theme.Text; _body.SelectionFont = Theme.Body; _body.AppendText(a.Recommendation + "\n");
        }
        if (a.Status == AlertStatus.Blocked)
        {
            _body.SelectionColor = Theme.Accent; _body.AppendText($"\n✓ {a.RemoteIp} is blocked by Windows Firewall. Undo this on the Firewall page if needed.");
        }
    }

    private void Block()
    {
        if (_selected == null) return;
        var (ok, msg) = Engine.BlockFromAlert(_selected);
        if (!ok) Kit.Info(FindForm()!, msg);
        Reload(); Main.RefreshChrome();
    }

    private void SetStatus(AlertStatus s)
    {
        if (_selected == null) return;
        Engine.Alerts.SetStatus(_selected, s);
        Reload(); Main.RefreshChrome();
    }

    private void Trust()
    {
        if (_selected?.RemoteIp is not { } ip) return;
        if (!Kit.Confirm(FindForm()!, $"Trust {ip}? It will be unblocked and future alerts for it will be suppressed.")) return;
        Engine.TrustIp(ip);
        Engine.Alerts.SetStatus(_selected, AlertStatus.Ignored);
        Reload(); Main.RefreshChrome();
    }

    private void Lookup()
    {
        if (_selected?.RemoteIp is not { } ip) return;
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo($"https://www.abuseipdb.com/check/{ip}") { UseShellExecute = true }); }
        catch { }
    }

    private void ResolveAll()
    {
        var open = Engine.Alerts.All.Where(a => a.Status == AlertStatus.Open).ToList();
        if (open.Count == 0 || !Kit.Confirm(FindForm()!, $"Mark {open.Count} open alert(s) as reviewed?")) return;
        foreach (var a in open) Engine.Alerts.SetStatus(a, AlertStatus.Resolved);
        Reload(); Main.RefreshChrome();
    }

    private static string Describe(Alert a) =>
        $"[{a.Severity}] {a.Title}\n{a.TimeUtc.ToLocalTime():u}\n{a.Detail}\nRecommendation: {a.Recommendation}\nStatus: {a.Status}";

    private void Export()
    {
        using var dlg = new SaveFileDialog { Filter = "CSV file|*.csv", FileName = $"homenet-alerts-{DateTime.Now:yyyyMMdd}.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var lines = new List<string> { "Time,Severity,Detector,Title,Detail,LocalIp,RemoteIp,Status" };
        lines.AddRange(Engine.Alerts.All.Select(a => string.Join(",", new[]
        {
            a.TimeUtc.ToLocalTime().ToString("s"), a.Severity.ToString(), a.Source.ToString(), a.Title, a.Detail,
            a.LocalIp ?? "", a.RemoteIp ?? "", a.Status.ToString()
        }.Select(DevicesPage.Csv))));
        File.WriteAllLines(dlg.FileName, lines);
    }
}
