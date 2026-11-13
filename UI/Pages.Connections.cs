using System.Diagnostics;
using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

public sealed class ConnectionsPage : PageBase
{
    private readonly DataGridView _grid = Kit.Grid();
    private readonly CheckBox _externalOnly = Kit.Check("Internet connections only", true);
    private readonly CheckBox _auto = Kit.Check("Auto-refresh", true);
    private readonly Label _summary = Kit.Label("", Theme.Body, Theme.Muted);
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 5000 };
    private bool _busy;

    public ConnectionsPage(GuardEngine engine) : base(engine)
    {
        var bar = Kit.Toolbar();
        bar.Controls.Add(Kit.Button("Refresh", async (_, _) => await LoadAsync(), primary: true));
        bar.Controls.Add(Kit.Button("Block remote address", (_, _) => BlockSelected(), danger: true));
        bar.Controls.Add(Kit.Button("End program", (_, _) => KillSelected()));
        bar.Controls.Add(Kit.Button("Open file location", (_, _) => OpenLocation()));
        _externalOnly.Margin = new Padding(8, 9, 12, 0); _auto.Margin = new Padding(0, 9, 12, 0);
        _externalOnly.CheckedChanged += async (_, _) => await LoadAsync();
        bar.Controls.Add(_externalOnly); bar.Controls.Add(_auto);

        _grid.Columns.AddRange(Kit.Col("Program", 90), Kit.Col("PID", 30, 50), Kit.Col("Local", 70), Kit.Col("Remote address", 80),
            Kit.Col("Port", 30, 50), Kit.Col("State", 50), Kit.Col("Notes", 130));
        _grid.CellFormatting += (_, e) =>
        {
            if (e.RowIndex >= 0 && _grid.Rows[e.RowIndex].Tag is ConnectionInfo { Flagged: true })
            { e.CellStyle!.ForeColor = Theme.Danger; e.CellStyle.Font = Theme.BodyBold; }
        };

        var gridCard = new Card { Dock = DockStyle.Fill, Padding = new Padding(1) };
        gridCard.Controls.Add(_grid);
        var foot = new Panel { Dock = DockStyle.Bottom, Height = 30, BackColor = Theme.Bg };
        _summary.Location = new Point(2, 10); foot.Controls.Add(_summary);

        Controls.Add(gridCard);
        Controls.Add(foot);
        Controls.Add(bar);
        Controls.Add(Kit.PageHeader("Connections", "Live view of which programs on this PC are talking to the internet"));

        _timer.Tick += async (_, _) => { if (_auto.Checked && Visible) await LoadAsync(); };
        _timer.Start();
    }

    public override void OnActivated() => _ = LoadAsync();

    private async Task LoadAsync()
    {
        if (_busy) return; _busy = true;
        try
        {
            var conns = await Task.Run(Engine.SnapshotConnections);
            var keep = (_grid.CurrentRow?.Tag as ConnectionInfo) is { } k ? $"{k.Pid}|{k.RemoteAddress}|{k.RemotePort}" : null;
            var shown = conns.Where(c => !_externalOnly.Checked || (c.State != "Listen" && !IpUtil.IsLocalOrSpecial(c.RemoteAddress)))
                             .OrderByDescending(c => c.Flagged).ThenBy(c => c.ProcessName).ToList();
            int firstRow = _grid.FirstDisplayedScrollingRowIndex;
            _grid.Rows.Clear();
            foreach (var c in shown)
            {
                var note = c.Flagged ? "⚠ " + c.FlagReason : Engine.Firewall.IsBlocked(c.RemoteAddress) ? "Blocked" : "";
                int i = _grid.Rows.Add(c.ProcessName, c.Pid, $"{c.LocalAddress}:{c.LocalPort}", c.RemoteAddress, c.RemotePort, c.State, note);
                _grid.Rows[i].Tag = c;
                if ($"{c.Pid}|{c.RemoteAddress}|{c.RemotePort}" == keep) { _grid.ClearSelection(); _grid.Rows[i].Selected = true; _grid.CurrentCell = _grid.Rows[i].Cells[0]; }
            }
            if (firstRow >= 0 && firstRow < _grid.Rows.Count) _grid.FirstDisplayedScrollingRowIndex = firstRow;
            int ext = conns.Count(c => c.State == "Established" && !IpUtil.IsLocalOrSpecial(c.RemoteAddress));
            _summary.Text = $"{ext} active internet connections from {conns.Where(c => c.State == "Established").Select(c => c.Pid).Distinct().Count()} programs  ·  " +
                            $"{conns.Count(c => c.Flagged)} flagged  ·  {conns.Count(c => c.State == "Listen")} listening ports";
        }
        catch (Exception ex) { _summary.Text = "Could not read connection table: " + ex.Message; }
        finally { _busy = false; }
    }

    private ConnectionInfo? Selected => _grid.CurrentRow?.Tag as ConnectionInfo;

    private void BlockSelected()
    {
        if (Selected is not { } c) return;
        if (IpUtil.IsLocalOrSpecial(c.RemoteAddress)) { Kit.Info(FindForm()!, "Local and special addresses can't be blocked from here."); return; }
        if (!Kit.Confirm(FindForm()!, $"Block {c.RemoteAddress} (used by {c.ProcessName}) in both directions?")) return;
        var (_, msg) = Engine.Firewall.Block(c.RemoteAddress, $"Manual block from Connections ({c.ProcessName})", false);
        Kit.Info(FindForm()!, msg);
        _ = LoadAsync();
    }

    private void KillSelected()
    {
        if (Selected is not { } c || c.Pid <= 4) return;
        if (!Kit.Confirm(FindForm()!, $"End '{c.ProcessName}' (PID {c.Pid})?\n\n{c.ProcessPath}\n\nUnsaved work in that program will be lost. " +
                                      "If this is malware, also run a full Microsoft Defender scan afterwards.")) return;
        try
        {
            using var p = Process.GetProcessById(c.Pid);
            p.Kill(entireProcessTree: true);
            EngineLog.Write("PROCESS", $"User ended {c.ProcessName} (PID {c.Pid}) {c.ProcessPath}");
        }
        catch (Exception ex) { Kit.Info(FindForm()!, "Could not end the program: " + ex.Message); }
        _ = LoadAsync();
    }

    private void OpenLocation()
    {
        if (Selected is not { } c || string.IsNullOrEmpty(c.ProcessPath)) return;
        Process.Start("explorer.exe", $"/select,\"{c.ProcessPath}\"");
    }
}
