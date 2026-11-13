using System.Drawing.Drawing2D;
using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

public static class Theme
{
    public static readonly Color Bg = Color.FromArgb(11, 18, 32);
    public static readonly Color Sidebar = Color.FromArgb(15, 23, 42);
    public static readonly Color Card = Color.FromArgb(20, 30, 51);
    public static readonly Color CardAlt = Color.FromArgb(26, 38, 64);
    public static readonly Color Border = Color.FromArgb(40, 54, 84);
    public static readonly Color Text = Color.FromArgb(229, 231, 235);
    public static readonly Color Muted = Color.FromArgb(148, 163, 184);
    public static readonly Color Accent = Color.FromArgb(16, 185, 129);
    public static readonly Color AccentDim = Color.FromArgb(6, 78, 59);
    public static readonly Color Danger = Color.FromArgb(239, 68, 68);
    public static readonly Color Warning = Color.FromArgb(245, 158, 11);
    public static readonly Color Info = Color.FromArgb(59, 130, 246);

    public static readonly Font Body = new("Segoe UI", 9.75f);
    public static readonly Font BodyBold = new("Segoe UI Semibold", 9.75f);
    public static readonly Font Small = new("Segoe UI", 8.5f);
    public static readonly Font H1 = new("Segoe UI Semibold", 18f);
    public static readonly Font H2 = new("Segoe UI Semibold", 12.5f);
    public static readonly Font Stat = new("Segoe UI Light", 24f);
    public static readonly Font Mono = new("Cascadia Mono", 9f);

    public static Color For(Severity s) => s switch
    {
        Severity.Critical => Danger,
        Severity.High => Color.FromArgb(249, 115, 22),
        Severity.Medium => Warning,
        Severity.Low => Info,
        _ => Muted
    };

    public static Color For(DeviceRisk r) => r switch
    {
        DeviceRisk.High => Danger,
        DeviceRisk.Medium => Warning,
        DeviceRisk.Low => Accent,
        _ => Muted
    };

    public static GraphicsPath RoundRect(Rectangle r, int radius)
    {
        var p = new GraphicsPath();
        int d = radius * 2;
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    public static Icon AppIcon()
    {
        try
        {
            using var s = typeof(Theme).Assembly.GetManifestResourceStream("CasHomeNetGuard.Assets.app.ico");
            if (s != null) return new Icon(s);
        }
        catch { }
        return SystemIcons.Shield;
    }
}

/// <summary>Factory helpers so every page looks consistent.</summary>
public static class Kit
{
    public static Button Button(string text, EventHandler onClick, bool primary = false, bool danger = false)
    {
        var b = new Button
        {
            Text = text, AutoSize = true, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand,
            Font = Theme.BodyBold, ForeColor = primary || danger ? Color.White : Theme.Text,
            BackColor = primary ? Theme.Accent : danger ? Theme.Danger : Theme.CardAlt,
            Padding = new Padding(10, 4, 10, 4), Margin = new Padding(0, 0, 8, 0), Height = 34,
        };
        b.FlatAppearance.BorderColor = primary ? Theme.Accent : danger ? Theme.Danger : Theme.Border;
        b.FlatAppearance.MouseOverBackColor = ControlPaint.Light(b.BackColor, 0.15f);
        b.Click += onClick;
        return b;
    }

    public static Label Label(string text, Font? font = null, Color? color = null, bool autoSize = true) => new()
    {
        Text = text, Font = font ?? Theme.Body, ForeColor = color ?? Theme.Text,
        AutoSize = autoSize, BackColor = Color.Transparent
    };

    public static FlowLayoutPanel Toolbar() => new()
    {
        Dock = DockStyle.Top, Height = 48, Padding = new Padding(0, 6, 0, 6),
        BackColor = Color.Transparent, WrapContents = false, AutoScroll = false
    };

    public static Panel PageHeader(string title, string subtitle)
    {
        var p = new Panel { Dock = DockStyle.Top, Height = 70, BackColor = Color.Transparent };
        var t = Label(title, Theme.H1); t.Location = new Point(0, 4);
        var s = Label(subtitle, Theme.Body, Theme.Muted); s.Location = new Point(2, 42);
        p.Controls.Add(t); p.Controls.Add(s);
        return p;
    }

    public static DataGridView Grid()
    {
        var g = new DataGridView
        {
            Dock = DockStyle.Fill, BackgroundColor = Theme.Card, BorderStyle = BorderStyle.None,
            GridColor = Theme.Border, RowHeadersVisible = false, AllowUserToAddRows = false,
            AllowUserToDeleteRows = false, AllowUserToResizeRows = false, ReadOnly = true,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
            ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None,
            ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
            ColumnHeadersHeight = 36, EnableHeadersVisualStyles = false, Font = Theme.Body,
        };
        g.RowTemplate.Height = 32;
        g.DefaultCellStyle.BackColor = Theme.Card;
        g.DefaultCellStyle.ForeColor = Theme.Text;
        g.DefaultCellStyle.SelectionBackColor = Theme.AccentDim;
        g.DefaultCellStyle.SelectionForeColor = Color.White;
        g.DefaultCellStyle.Padding = new Padding(6, 0, 6, 0);
        g.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(23, 34, 57);
        g.ColumnHeadersDefaultCellStyle.BackColor = Theme.Sidebar;
        g.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Muted;
        g.ColumnHeadersDefaultCellStyle.Font = Theme.BodyBold;
        g.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Sidebar;
        g.ColumnHeadersDefaultCellStyle.Padding = new Padding(6, 0, 6, 0);
        typeof(DataGridView).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.SetValue(g, true);
        return g;
    }

    public static DataGridViewTextBoxColumn Col(string header, int fillWeight = 100, int minWidth = 60) => new()
    {
        HeaderText = header, FillWeight = fillWeight, MinimumWidth = minWidth, SortMode = DataGridViewColumnSortMode.Automatic
    };

    public static TextBox TextBox(bool multiline = false) => new()
    {
        BackColor = Theme.CardAlt, ForeColor = Theme.Text, BorderStyle = BorderStyle.FixedSingle,
        Font = Theme.Body, Multiline = multiline, ScrollBars = multiline ? ScrollBars.Vertical : ScrollBars.None
    };

    public static ComboBox Combo() => new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Theme.CardAlt, ForeColor = Theme.Text,
        FlatStyle = FlatStyle.Flat, Font = Theme.Body
    };

    public static CheckBox Check(string text, bool value) => new()
    {
        Text = text, Checked = value, AutoSize = true, ForeColor = Theme.Text, Font = Theme.Body,
        Margin = new Padding(0, 4, 0, 4), BackColor = Color.Transparent
    };

    public static string Ago(DateTime utc)
    {
        var s = DateTime.UtcNow - utc;
        if (s.TotalSeconds < 60) return "just now";
        if (s.TotalMinutes < 60) return $"{(int)s.TotalMinutes} min ago";
        if (s.TotalHours < 24) return $"{(int)s.TotalHours} h ago";
        return utc.ToLocalTime().ToString("dd MMM HH:mm");
    }

    public static string Bytes(double b) =>
        b >= 1_073_741_824 ? $"{b / 1_073_741_824:F1} GB" :
        b >= 1_048_576 ? $"{b / 1_048_576:F1} MB" :
        b >= 1024 ? $"{b / 1024:F0} KB" : $"{b:F0} B";

    public static void Info(IWin32Window owner, string msg, string title = "CAS HomeNet Guard") =>
        MessageBox.Show(owner, msg, title, MessageBoxButtons.OK, MessageBoxIcon.Information);

    public static bool Confirm(IWin32Window owner, string msg, string title = "Please confirm") =>
        MessageBox.Show(owner, msg, title, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes;
}
