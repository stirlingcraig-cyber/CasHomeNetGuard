using System.Drawing.Drawing2D;
using CasHomeNetGuard.Core;

namespace CasHomeNetGuard.UI;

/// <summary>Rounded card panel.</summary>
public class Card : Panel
{
    public Color Fill { get; set; } = Theme.Card;
    public Color? Stripe { get; set; }

    public Card()
    {
        DoubleBuffered = true; BackColor = Theme.Bg; Padding = new Padding(16);
        SetStyle(ControlStyles.ResizeRedraw | ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var r = new Rectangle(0, 0, Width - 1, Height - 1);
        using var path = Theme.RoundRect(r, 10);
        using var br = new SolidBrush(Fill);
        e.Graphics.FillPath(br, path);
        using var pen = new Pen(Theme.Border);
        e.Graphics.DrawPath(pen, path);
        if (Stripe is { } s)
        {
            using var sb = new SolidBrush(s);
            e.Graphics.SetClip(path);
            e.Graphics.FillRectangle(sb, 0, 0, 5, Height);
            e.Graphics.ResetClip();
        }
    }

    protected override void OnControlAdded(ControlEventArgs e)
    {
        base.OnControlAdded(e);
        if (e.Control is Label or CheckBox or FlowLayoutPanel or TableLayoutPanel) e.Control.BackColor = Fill;
    }
}

/// <summary>KPI tile: caption, big number, sub-text.</summary>
public sealed class StatCard : Card
{
    private readonly Label _caption, _value, _sub;
    public StatCard(string caption)
    {
        Height = 112; Padding = new Padding(18, 14, 14, 10);
        _caption = Kit.Label(caption.ToUpperInvariant(), Theme.Small, Theme.Muted);
        _value = Kit.Label("–", Theme.Stat);
        _sub = Kit.Label("", Theme.Small, Theme.Muted);
        _caption.Location = new Point(18, 14); _value.Location = new Point(14, 32); _sub.Location = new Point(18, 80);
        Controls.AddRange(new Control[] { _caption, _value, _sub });
    }
    public void Set(string value, string sub, Color? valueColor = null)
    {
        _value.Text = value; _sub.Text = sub; _value.ForeColor = valueColor ?? Theme.Text;
    }
}

/// <summary>Live traffic area chart (bytes/sec).</summary>
public sealed class TrafficChart : Card
{
    private IReadOnlyList<TrafficSample> _data = Array.Empty<TrafficSample>();
    public TrafficChart() { Height = 220; }

    public void SetData(IReadOnlyList<TrafficSample> data) { _data = data; Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
        TextRenderer.DrawText(g, "LIVE TRAFFIC", Theme.Small, new Point(18, 14), Theme.Muted);
        var plot = new Rectangle(18, 42, Width - 36, Height - 64);
        double max = Math.Max(1024, _data.Count == 0 ? 0 : _data.Max(d => d.BytesPerSec));
        var latest = _data.Count == 0 ? 0 : _data[^1].BytesPerSec;
        var label = $"{Kit.Bytes(latest)}/s  ·  peak {Kit.Bytes(max)}/s";
        var sz = TextRenderer.MeasureText(label, Theme.Small);
        TextRenderer.DrawText(g, label, Theme.Small, new Point(Width - sz.Width - 18, 14), Theme.Text);

        using (var grid = new Pen(Color.FromArgb(40, Theme.Muted)) { DashStyle = DashStyle.Dot })
            for (int i = 0; i <= 3; i++) { int y = plot.Top + plot.Height * i / 3; g.DrawLine(grid, plot.Left, y, plot.Right, y); }

        if (_data.Count < 2)
        {
            TextRenderer.DrawText(g, "Waiting for traffic… (requires Npcap)", Theme.Body, plot, Theme.Muted,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            return;
        }
        const int slots = 180;
        var pts = new List<PointF>();
        for (int i = 0; i < _data.Count; i++)
        {
            float x = plot.Left + plot.Width * (slots - _data.Count + i) / (float)(slots - 1);
            float y = plot.Bottom - (float)(_data[i].BytesPerSec / max) * plot.Height;
            pts.Add(new PointF(x, y));
        }
        using var area = new GraphicsPath();
        area.AddLines(pts.ToArray());
        area.AddLine(pts[^1], new PointF(pts[^1].X, plot.Bottom));
        area.AddLine(new PointF(pts[^1].X, plot.Bottom), new PointF(pts[0].X, plot.Bottom));
        area.CloseFigure();
        using var fill = new LinearGradientBrush(plot, Color.FromArgb(110, Theme.Accent), Color.FromArgb(5, Theme.Accent), LinearGradientMode.Vertical);
        g.FillPath(fill, area);
        using var line = new Pen(Theme.Accent, 2f);
        g.DrawLines(line, pts.ToArray());
    }
}

/// <summary>Sidebar navigation button with optional badge.</summary>
public sealed class NavButton : Control
{
    public bool Selected { get => _sel; set { _sel = value; Invalidate(); } }
    public int Badge { get => _badge; set { _badge = value; Invalidate(); } }
    public string Glyph { get; }
    private bool _sel, _hover; private int _badge;

    public NavButton(string text, string glyph)
    {
        Text = text; Glyph = glyph; Height = 44; Dock = DockStyle.Top; Cursor = Cursors.Hand;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Sidebar;
    }

    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Theme.Sidebar);
        if (_sel || _hover)
        {
            using var path = Theme.RoundRect(new Rectangle(10, 3, Width - 20, Height - 6), 8);
            using var b = new SolidBrush(_sel ? Theme.CardAlt : Color.FromArgb(22, 32, 54));
            g.FillPath(b, path);
        }
        if (_sel) using (var a = new SolidBrush(Theme.Accent)) g.FillRectangle(a, 10, 12, 3, Height - 24);
        var col = _sel ? Color.White : Theme.Muted;
        TextRenderer.DrawText(g, Glyph, new Font("Segoe MDL2 Assets", 12f), new Rectangle(24, 0, 24, Height), _sel ? Theme.Accent : col,
            TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter);
        TextRenderer.DrawText(g, Text, _sel ? Theme.BodyBold : Theme.Body, new Rectangle(56, 0, Width - 100, Height), col,
            TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
        if (_badge > 0)
        {
            var t = _badge > 99 ? "99+" : _badge.ToString();
            var sz = TextRenderer.MeasureText(t, Theme.Small);
            var r = new Rectangle(Width - sz.Width - 32, (Height - 20) / 2, sz.Width + 12, 20);
            using var path = Theme.RoundRect(r, 9);
            using var b = new SolidBrush(Theme.Danger);
            g.FillPath(b, path);
            TextRenderer.DrawText(g, t, Theme.Small, r, Color.White, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
    }
}

/// <summary>Large status banner on the dashboard.</summary>
public sealed class StatusBanner : Card
{
    private string _title = "", _detail = ""; private Color _tone = Theme.Accent;
    public FlowLayoutPanel Actions { get; }

    public StatusBanner()
    {
        Height = 132;
        Actions = new FlowLayoutPanel { AutoSize = true, BackColor = Fill, WrapContents = false, Anchor = AnchorStyles.Right | AnchorStyles.Top };
        Controls.Add(Actions);
        Resize += (_, _) => Actions.Location = new Point(Width - Actions.Width - 20, (Height - Actions.Height) / 2);
        Actions.SizeChanged += (_, _) => Actions.Location = new Point(Width - Actions.Width - 20, (Height - Actions.Height) / 2);
    }

    public void Set(string title, string detail, Color tone)
    {
        _title = title; _detail = detail; _tone = tone; Stripe = tone; Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
        // Shield glyph
        var c = new Rectangle(28, (Height - 76) / 2, 64, 76);
        PointF[] shield =
        {
            new(c.X + c.Width / 2f, c.Y), new(c.Right, c.Y + 12), new(c.Right - 3, c.Y + 42),
            new(c.X + c.Width / 2f, c.Bottom), new(c.X + 3, c.Y + 42), new(c.X, c.Y + 12)
        };
        using (var b = new SolidBrush(Color.FromArgb(50, _tone))) g.FillPolygon(b, shield);
        using (var p = new Pen(_tone, 2.5f)) g.DrawPolygon(p, shield);
        var mark = _tone == Theme.Accent ? "" : _tone == Theme.Muted ? "" : "";
        TextRenderer.DrawText(g, mark, new Font("Segoe MDL2 Assets", 20f), c, _tone, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

        int textW = Math.Max(100, Width - 140 - Actions.Width - 30);
        TextRenderer.DrawText(g, _title, Theme.H1, new Rectangle(116, 30, textW, 36), Theme.Text, TextFormatFlags.EndEllipsis);
        TextRenderer.DrawText(g, _detail, Theme.Body, new Rectangle(118, 70, textW, 40), Theme.Muted, TextFormatFlags.WordBreak | TextFormatFlags.EndEllipsis);
    }
}
