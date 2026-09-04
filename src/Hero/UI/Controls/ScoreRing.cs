using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Hero.Guardian;

namespace Hero.UI.Controls;

/// <summary>
/// The posture score gauge — the one visual the user reads before anything else.
///
/// Design rules this encodes, in priority order:
///
/// 1. A degraded machine gets a SHORTER arc, not a bigger redder one. Less arc reads as
///    "less protection earned"; a full red ring would read as "lots of something", which is
///    backwards and is how security software teaches people to ignore it.
/// 2. There is an explicit no-data state. A ring that keeps showing a confident green 96 while
///    the engine is dead, paused, or still building a baseline is the most dangerous pixel in
///    the product, so <see cref="HasData"/> switches it to a dashed track, "--" and "UNKNOWN".
/// 3. Everything is drawn, not templated. One element, no ControlTemplate, no converters — so
///    the digits and the arc read the same animated value in the same render pass and cannot
///    desynchronise, and the control renders identically whether or not any dictionary beyond
///    Theme.xaml has been merged.
///
/// All geometry is proportional to the rendered size, so it is correct at 176 DIP on a 1080p
/// panel and at 300 DIP on this machine's 4096x2160 display, and crisp at any DPI because
/// nothing is rasterised.
/// </summary>
internal sealed class ScoreRing : FrameworkElement
{
    /// <summary>Diameter used when the ring is given an unconstrained slot (e.g. a StackPanel).</summary>
    private const double DefaultDiameter = 176d;

    // Stroke is 6.8% of the diameter — the 12/176 ratio of the reference design, expressed as a
    // ratio so the ring keeps its proportions when a screen sizes it larger.
    private const double StrokeRatio = 0.068d;
    private const double NumeralRatio = 0.227d;   // 40/176
    private const double BandWordRatio = 0.068d;  // 12/176

    private readonly SolidColorBrush _arcBrush = new(Colors.Transparent);
    private Pen? _arcPen;
    private Pen? _trackPen;
    private Pen? _dashedPen;
    private Pen? _guidePen;

    private Typeface? _numeralFace;
    private Typeface? _wordFace;
    private double _digitAdvance;
    private double _digitAdvanceFor = -1;

    internal ScoreRing()
    {
        // The ring is decorative by position but load-bearing by meaning: name it so a screen
        // reader announces something other than "custom".
        System.Windows.Automation.AutomationProperties.SetName(this, "Posture score");
    }

    // ---------------------------------------------------------------- dependency properties

    /// <summary>
    /// The posture score the view-model publishes, 0-100. Setting it animates the ring; the
    /// caller never has to write a Storyboard.
    /// </summary>
    internal static readonly DependencyProperty ScoreProperty = DependencyProperty.Register(
        nameof(Score), typeof(double), typeof(ScoreRing),
        new FrameworkPropertyMetadata(0d, OnScoreChanged, CoerceScore));

    internal double Score
    {
        get => (double)GetValue(ScoreProperty);
        set => SetValue(ScoreProperty, value);
    }

    /// <summary>
    /// The value actually drawn. This is the animation target; bind <see cref="Score"/> instead.
    /// Registered AffectsRender and NOT AffectsMeasure: AffectsMeasure appears to work and runs a
    /// full layout pass on all ~42 frames of the sweep, which stutters the whole window.
    /// </summary>
    internal static readonly DependencyProperty ArcValueProperty = DependencyProperty.Register(
        nameof(ArcValue), typeof(double), typeof(ScoreRing),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

    internal double ArcValue
    {
        get => (double)GetValue(ArcValueProperty);
        set => SetValue(ArcValueProperty, value);
    }

    /// <summary>
    /// False when the engine has not produced a fresh reading — paused, stopped, or still
    /// building its baseline. Renders a dashed track with no arc and no number.
    /// </summary>
    internal static readonly DependencyProperty HasDataProperty = DependencyProperty.Register(
        nameof(HasData), typeof(bool), typeof(ScoreRing),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender, OnHasDataChanged));

    internal bool HasData
    {
        get => (bool)GetValue(HasDataProperty);
        set => SetValue(HasDataProperty, value);
    }

    /// <summary>Word drawn under the numeral. Null uses the score band's own short word.</summary>
    internal static readonly DependencyProperty CaptionProperty = DependencyProperty.Register(
        nameof(Caption), typeof(string), typeof(ScoreRing),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    internal string? Caption
    {
        get => (string?)GetValue(CaptionProperty);
        set => SetValue(CaptionProperty, value);
    }

    /// <summary>Arc colour. Animated by a 400ms crossfade whenever the band changes.</summary>
    internal static readonly DependencyProperty ArcColorProperty = DependencyProperty.Register(
        nameof(ArcColor), typeof(Color), typeof(ScoreRing),
        new FrameworkPropertyMetadata(Color.FromRgb(0x3F, 0xB9, 0x84),
            FrameworkPropertyMetadataOptions.AffectsRender));

    internal Color ArcColor
    {
        get => (Color)GetValue(ArcColorProperty);
        set => SetValue(ArcColorProperty, value);
    }

    /// <summary>Unfilled portion of the ring.</summary>
    internal static readonly DependencyProperty TrackBrushProperty = DependencyProperty.Register(
        nameof(TrackBrush), typeof(Brush), typeof(ScoreRing),
        new FrameworkPropertyMetadata(Freeze(new SolidColorBrush(Color.FromRgb(0x24, 0x2D, 0x38))),
            FrameworkPropertyMetadataOptions.AffectsRender, OnTrackBrushChanged));

    internal Brush TrackBrush
    {
        get => (Brush)GetValue(TrackBrushProperty);
        set => SetValue(TrackBrushProperty, value);
    }

    internal static readonly DependencyProperty NumeralBrushProperty = DependencyProperty.Register(
        nameof(NumeralBrush), typeof(Brush), typeof(ScoreRing),
        new FrameworkPropertyMetadata(Freeze(new SolidColorBrush(Color.FromRgb(0xED, 0xF1, 0xF7))),
            FrameworkPropertyMetadataOptions.AffectsRender));

    internal Brush NumeralBrush
    {
        get => (Brush)GetValue(NumeralBrushProperty);
        set => SetValue(NumeralBrushProperty, value);
    }

    internal static readonly DependencyProperty MutedBrushProperty = DependencyProperty.Register(
        nameof(MutedBrush), typeof(Brush), typeof(ScoreRing),
        new FrameworkPropertyMetadata(Freeze(new SolidColorBrush(Color.FromRgb(0x78, 0x84, 0x9A))),
            FrameworkPropertyMetadataOptions.AffectsRender));

    internal Brush MutedBrush
    {
        get => (Brush)GetValue(MutedBrushProperty);
        set => SetValue(MutedBrushProperty, value);
    }

    /// <summary>Set false to honour a "reduce motion" preference. Also gated by the OS setting.</summary>
    internal static readonly DependencyProperty AnimationsEnabledProperty = DependencyProperty.Register(
        nameof(AnimationsEnabled), typeof(bool), typeof(ScoreRing), new PropertyMetadata(true));

    internal bool AnimationsEnabled
    {
        get => (bool)GetValue(AnimationsEnabledProperty);
        set => SetValue(AnimationsEnabledProperty, value);
    }

    // Read-only surface for the headline that sits beside or beneath the ring. "Needs attention"
    // will not fit inside a 176px ring, so the long band word is published rather than drawn.
    private static readonly DependencyPropertyKey BandLabelKey = DependencyProperty.RegisterReadOnly(
        nameof(BandLabel), typeof(string), typeof(ScoreRing), new PropertyMetadata("Protected"));

    internal static readonly DependencyProperty BandLabelProperty = BandLabelKey.DependencyProperty;

    internal string BandLabel => (string)GetValue(BandLabelProperty);

    private static readonly DependencyPropertyKey BandBrushKey = DependencyProperty.RegisterReadOnly(
        nameof(BandBrush), typeof(Brush), typeof(ScoreRing), new PropertyMetadata(Brushes.Transparent));

    internal static readonly DependencyProperty BandBrushProperty = BandBrushKey.DependencyProperty;

    internal Brush BandBrush => (Brush)GetValue(BandBrushProperty);

    private static readonly DependencyPropertyKey BandKey = DependencyProperty.RegisterReadOnly(
        nameof(Band), typeof(Severity), typeof(ScoreRing), new PropertyMetadata(Severity.Safe));

    internal static readonly DependencyProperty BandProperty = BandKey.DependencyProperty;

    /// <summary>Severity the current score falls into, for callers that mirror the ring's colour.</summary>
    internal Severity Band => (Severity)GetValue(BandProperty);

    // ---------------------------------------------------------------------------- behaviour

    private static object CoerceScore(DependencyObject d, object baseValue)
    {
        var v = (double)baseValue;
        return double.IsNaN(v) ? 0d : Math.Clamp(v, 0d, 100d);
    }

    private static void OnScoreChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((ScoreRing)d).Apply((double)e.NewValue, animate: true);

    private static void OnHasDataChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((ScoreRing)d).Apply(((ScoreRing)d).Score, animate: false);

    private static void OnTrackBrushChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var ring = (ScoreRing)d;
        ring._trackPen = null;
        ring._dashedPen = null;
    }

    protected override void OnInitialized(EventArgs e)
    {
        base.OnInitialized(e);

        // Theme tokens win over the compiled-in defaults, but an unresolved key simply falls back
        // to the default value, so the ring is never blank if a dictionary is missing.
        SeverityPalette.BindToken(this, TrackBrushProperty, "Surface3");
        SeverityPalette.BindToken(this, NumeralBrushProperty, "TextPrimary");
        SeverityPalette.BindToken(this, MutedBrushProperty, "TextTertiary");

        // Seed the colour without a crossfade so a cold start does not fade in from the default.
        Apply(Score, animate: false);
    }

    private void Apply(double score, bool animate)
    {
        var band = BandFor(score);
        SetValue(BandKey, band);
        SetValue(BandLabelKey, HasData ? LongWord(band) : "Unknown");

        var target = HasData
            ? SeverityPalette.Base(this, band)
            : MutedBrush is SolidColorBrush muted ? muted.Color : Color.FromRgb(0x78, 0x84, 0x9A);
        SetValue(BandBrushKey, SeverityPalette.Brush(target));

        if (!MotionAllowed || !animate)
        {
            BeginAnimation(ArcColorProperty, null);
            BeginAnimation(ArcValueProperty, null);
            ArcColor = target;
            ArcValue = score;
            return;
        }

        if (ArcColor != target)
        {
            // 400ms is long enough to read as a state change and short enough not to lag the arc.
            BeginAnimation(ArcColorProperty, new ColorAnimation(target, new Duration(TimeSpan.FromMilliseconds(400)))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
                FillBehavior = FillBehavior.HoldEnd,
            });
        }

        // No From: the animation starts at the currently held value, so repeat updates ease from
        // wherever the arc actually is. Only the very first update sweeps from zero, because
        // ArcValue's default is zero.
        BeginAnimation(ArcValueProperty, new DoubleAnimation(score, new Duration(TimeSpan.FromMilliseconds(700)))
        {
            EasingFunction = new QuinticEase { EasingMode = EasingMode.EaseOut },
            FillBehavior = FillBehavior.HoldEnd,
        });
    }

    // Motion.Active is the app's single gate: the Settings toggle AND the OS "Animation effects"
    // preference. Reading SystemParameters directly here would honour the OS but ignore the user's
    // own switch, which is the half people actually turn off.
    private bool MotionAllowed => AnimationsEnabled && Motion.Active;

    /// <summary>Score bands. Deliberately four, matching the four status words the UI speaks.</summary>
    internal static Severity BandFor(double score) => score switch
    {
        >= 90 => Severity.Safe,
        >= 75 => Severity.Medium,
        >= 50 => Severity.High,
        _ => Severity.Critical,
    };

    private static string LongWord(Severity band) => band switch
    {
        Severity.Safe => "Protected",
        Severity.Medium => "Watchful",
        Severity.High => "Needs attention",
        _ => "At risk",
    };

    private static string ShortWord(Severity band) => band switch
    {
        Severity.Safe => "PROTECTED",
        Severity.Medium => "WATCHFUL",
        Severity.High => "ATTENTION",
        _ => "AT RISK",
    };

    /// <summary>Drops cached typefaces after a theme or font change.</summary>
    internal void RefreshTheme()
    {
        _numeralFace = null;
        _wordFace = null;
        _digitAdvanceFor = -1;
        InvalidateVisual();
    }

    protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi)
    {
        base.OnDpiChanged(oldDpi, newDpi);
        _digitAdvanceFor = -1;   // digit metrics are measured in device pixels
        InvalidateVisual();
    }

    // ------------------------------------------------------------------------------- layout

    protected override Size MeasureOverride(Size availableSize)
    {
        // Square, and never larger than the slot it was given. An unconstrained axis falls back
        // to the reference diameter rather than to infinity.
        double w = double.IsInfinity(availableSize.Width) ? DefaultDiameter : availableSize.Width;
        double h = double.IsInfinity(availableSize.Height) ? DefaultDiameter : availableSize.Height;
        double d = Math.Min(w, h);
        if (double.IsNaN(d) || d <= 0) d = DefaultDiameter;
        return new Size(d, d);
    }

    // ------------------------------------------------------------------------------- render

    protected override void OnRender(DrawingContext dc)
    {
        double w = RenderSize.Width, h = RenderSize.Height;
        double d = Math.Min(w, h);

        // The measure pass can hand a Shape-derived gauge a zero size and a negative radius; that
        // is a documented crash in the naive implementation (Size(-6,-6) throws). Bail instead.
        if (d < 16) return;

        double ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var centre = new Point(w / 2, h / 2);
        double half = d / 2;
        double thickness = Math.Max(3, d * StrokeRatio);
        double gap = Math.Max(3, d * 0.045);           // room for the faint outer guide circle
        double r = half - gap - thickness / 2;
        if (r <= 1) { r = Math.Max(1, half - thickness / 2); gap = 0; }

        // Transparent ground so tooltips and hit-testing work over the whole square.
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));

        // Faint guide circle: a single hairline that gives the gauge physical depth for free.
        if (gap > 2)
        {
            _guidePen ??= FreezePen(new Pen(new SolidColorBrush(Color.FromArgb(0x66, 0x24, 0x2D, 0x38)), 1));
            dc.DrawEllipse(null, _guidePen, centre, half - 0.5, half - 0.5);
        }

        if (HasData)
        {
            _trackPen ??= FreezePen(new Pen(TrackBrush, thickness));
            if (Math.Abs(_trackPen.Thickness - thickness) > 0.01) _trackPen = FreezePen(new Pen(TrackBrush, thickness));
            dc.DrawEllipse(null, _trackPen, centre, r, r);
            DrawArc(dc, centre, r, thickness);
        }
        else
        {
            // Dashed track, no arc: "not measured" must not be able to look like "measured, fine".
            if (_dashedPen is null || Math.Abs(_dashedPen.Thickness - thickness) > 0.01)
            {
                _dashedPen = FreezePen(new Pen(TrackBrush, thickness)
                {
                    DashStyle = new DashStyle(new double[] { 0.6, 0.9 }, 0),
                    DashCap = PenLineCap.Round,
                });
            }
            dc.DrawEllipse(null, _dashedPen, centre, r, r);
        }

        DrawCentreStack(dc, centre, d, ppd);
    }

    private void DrawArc(DrawingContext dc, Point centre, double r, double thickness)
    {
        double sweep = Math.Clamp(ArcValue, 0d, 100d) / 100d * 360d;

        // A 360-degree ArcSegment is degenerate — start and end coincide and WPF draws nothing, so
        // a perfect 100 would render an empty ring. Clamp just short of a full turn.
        sweep = Math.Clamp(sweep, 0.01d, 359.99d);

        var start = new Point(centre.X, centre.Y - r);
        double rad = (sweep - 90d) * Math.PI / 180d;
        var end = new Point(centre.X + r * Math.Cos(rad), centre.Y + r * Math.Sin(rad));

        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(start, false, false);
            ctx.ArcTo(end, new Size(r, r), 0, sweep > 180d, SweepDirection.Clockwise, true, false);
        }
        geo.Freeze();

        // The brush is mutated rather than replaced so an animating colour costs no allocation
        // per frame, and because it is private to this element it cannot bleed into other
        // controls the way an animated ResourceDictionary brush does.
        _arcBrush.Color = ArcColor;
        if (_arcPen is null || Math.Abs(_arcPen.Thickness - thickness) > 0.01)
        {
            _arcPen = new Pen(_arcBrush, thickness)
            {
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round,
            };
        }
        dc.DrawGeometry(null, _arcPen, geo);
    }

    private void DrawCentreStack(DrawingContext dc, Point centre, double d, double ppd)
    {
        double numeralSize = d * NumeralRatio;
        double wordSize = Math.Max(9, d * BandWordRatio);

        _numeralFace ??= Face("DisplayFont", "Segoe UI Variable Display, Segoe UI", FontWeights.Bold);
        _wordFace ??= Face("UIFont", "Segoe UI Variable Text, Segoe UI", FontWeights.SemiBold);

        if (_digitAdvanceFor != numeralSize)
        {
            _digitAdvance = GlyphText.DigitAdvance(_numeralFace, numeralSize, ppd);
            _digitAdvanceFor = numeralSize;
        }

        string numeral = HasData
            ? ((int)Math.Round(Math.Clamp(ArcValue, 0d, 100d))).ToString(CultureInfo.InvariantCulture)
            : "--";
        string word = Caption ?? (HasData ? ShortWord(Band) : "UNKNOWN");

        var numeralBrush = HasData ? NumeralBrush : MutedBrush;
        var wordBrush = HasData ? BandBrush : MutedBrush;

        double tracking = wordSize * 0.06;   // +0.6px at 11px, the overline treatment
        double numeralWidth = GlyphText.TabularWidth(numeral, _numeralFace, numeralSize, ppd, _digitAdvance);
        double numeralHeight = GlyphText.Height(numeral, _numeralFace, numeralSize, ppd);
        double wordWidth = GlyphText.TrackedWidth(word, _wordFace, wordSize, ppd, tracking);
        double wordHeight = GlyphText.Height(word, _wordFace, wordSize, ppd);

        double spacing = d * 0.012;
        double total = numeralHeight + spacing + wordHeight;

        // Optical rather than metric centring: text boxes carry more space below the baseline than
        // above, so a mathematically centred stack sits visibly low inside a circle.
        double top = centre.Y - total / 2 - numeralHeight * 0.06;

        GlyphText.DrawTabular(dc, numeral, _numeralFace, numeralSize, numeralBrush, ppd, _digitAdvance,
            new Point(centre.X - numeralWidth / 2, top));

        GlyphText.DrawTracked(dc, word, _wordFace, wordSize, wordBrush, ppd, tracking,
            new Point(centre.X - wordWidth / 2, top + numeralHeight + spacing));
    }

    private Typeface Face(string resourceKey, string fallback, FontWeight weight)
    {
        var family = TryFindResource(resourceKey) as FontFamily ?? new FontFamily(fallback);
        return new Typeface(family, FontStyles.Normal, weight, FontStretches.Normal);
    }

    private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

    private static Pen FreezePen(Pen p) { if (p.CanFreeze) p.Freeze(); return p; }
}

/// <summary>
/// Text drawing shared by every hand-rendered HERO control.
///
/// These controls paint text with <see cref="FormattedText"/> rather than hosting TextBlocks,
/// which is what keeps a 400-row table at one visual element per row. That means the niceties a
/// TextBlock gives for free — tabular figures, letter spacing, middle truncation — have to be
/// done here.
/// </summary>
internal static class GlyphText
{
    /// <summary>
    /// Hard ceiling on a rendered run. Command lines and registry values can be megabytes; laying
    /// out one of those on the UI thread would stall the window, and no cell can show it anyway.
    /// </summary>
    private const int MaxRenderedChars = 512;

    internal static FormattedText Make(string text, Typeface face, double size, Brush brush, double pixelsPerDip)
    {
        // Display mode snaps stems to the pixel grid and is what keeps 11-15px UI text sharp.
        // Above 20px it distorts Segoe UI Variable's outlines, so large runs use Ideal.
        var mode = size >= 20 ? TextFormattingMode.Ideal : TextFormattingMode.Display;
        return new FormattedText(text, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
                                 face, size, brush, null, mode, pixelsPerDip);
    }

    internal static double Width(string text, Typeface face, double size, double ppd)
        => Make(text, face, size, Brushes.Black, ppd).WidthIncludingTrailingWhitespace;

    // Per-character layouts, reused across every row of every table. Measuring and drawing text a
    // character at a time is what buys tabular figures and letter spacing, and without this cache
    // it would allocate a FormattedText per character per cell per tick — measured at roughly
    // 15ms per 1 Hz repaint of a screenful, which is a whole frame budget spent on text metrics.
    // Keyed by typeface identity (instances are cached per control), size and DPI. UI thread only.
    private static readonly Dictionary<(Typeface, double, double, char), FormattedText> GlyphCache = new();
    private static readonly Dictionary<(Typeface, double, double), double> LineHeights = new();

    /// <summary>A cached single-character layout, recoloured for this draw.</summary>
    internal static FormattedText Glyph(char ch, Typeface face, double size, double ppd, Brush brush)
    {
        var key = (face, size, ppd, ch);
        if (!GlyphCache.TryGetValue(key, out var ft))
        {
            if (GlyphCache.Count > 4096) GlyphCache.Clear();
            ft = Make(ch.ToString(), face, size, Brushes.Black, ppd);
            GlyphCache[key] = ft;
        }
        ft.SetForegroundBrush(brush);
        return ft;
    }

    internal static double CharWidth(char ch, Typeface face, double size, double ppd)
        => Glyph(ch, face, size, ppd, Brushes.Black).WidthIncludingTrailingWhitespace;

    /// <summary>
    /// Line box height for a face and size. Every run HERO draws is single-line, so this depends
    /// only on the font, not on the string — which makes it cacheable.
    /// </summary>
    internal static double Height(string text, Typeface face, double size, double ppd)
    {
        var key = (face, size, ppd);
        if (LineHeights.TryGetValue(key, out var h)) return h;
        if (LineHeights.Count > 512) LineHeights.Clear();
        h = Make("0", face, size, Brushes.Black, ppd).Height;
        LineHeights[key] = h;
        return h;
    }

    /// <summary>Widest digit in the face, so numerals can be laid out on a fixed advance.</summary>
    internal static double DigitAdvance(Typeface face, double size, double ppd)
    {
        double w = 0;
        for (char c = '0'; c <= '9'; c++) w = Math.Max(w, CharWidth(c, face, size, ppd));
        return w;
    }

    internal static double TabularWidth(string text, Typeface face, double size, double ppd, double digitAdvance)
    {
        double w = 0;
        foreach (var ch in text) w += IsDigit(ch) ? digitAdvance : CharWidth(ch, face, size, ppd);
        return w;
    }

    /// <summary>
    /// Draws digits on a fixed advance. Without this, a value that ticks 87 -> 88 shifts sideways
    /// on every update, which is the single most visible "cheap" tell in a live dashboard.
    /// </summary>
    internal static void DrawTabular(DrawingContext dc, string text, Typeface face, double size,
                                     Brush brush, double ppd, double digitAdvance, Point origin)
    {
        double x = origin.X;
        foreach (var ch in text)
        {
            var ft = Glyph(ch, face, size, ppd, brush);
            if (IsDigit(ch))
            {
                dc.DrawText(ft, new Point(x + (digitAdvance - ft.Width) / 2, origin.Y));
                x += digitAdvance;
            }
            else
            {
                dc.DrawText(ft, new Point(x, origin.Y));
                x += ft.WidthIncludingTrailingWhitespace;
            }
        }
    }

    internal static double TrackedWidth(string text, Typeface face, double size, double ppd, double tracking)
    {
        if (text.Length == 0) return 0;
        double w = 0;
        foreach (var ch in text) w += CharWidth(ch, face, size, ppd) + tracking;
        return w - tracking;
    }

    /// <summary>Letter-spaced run, for uppercase overlines and severity pills.</summary>
    internal static void DrawTracked(DrawingContext dc, string text, Typeface face, double size,
                                     Brush brush, double ppd, double tracking, Point origin)
    {
        if (tracking <= 0)
        {
            dc.DrawText(Make(text, face, size, brush, ppd), origin);
            return;
        }

        double x = origin.X;
        foreach (var ch in text)
        {
            var ft = Glyph(ch, face, size, ppd, brush);
            dc.DrawText(ft, new Point(x, origin.Y));
            x += ft.WidthIncludingTrailingWhitespace + tracking;
        }
    }

    /// <summary>
    /// Fits a string to a pixel budget, truncating in the MIDDLE when asked.
    ///
    /// Paths truncate in the middle because the filename is the load-bearing part:
    /// "C:\Users\...\Temp\svchost32.exe" is useful, "C:\Users\finla\AppData\Local\Mic..." is not.
    /// WPF's TextTrimming has no middle mode, which is one of the reasons these cells are drawn
    /// rather than templated.
    /// </summary>
    internal static string Fit(string text, Typeface face, double size, double ppd, double maxWidth, bool middle)
    {
        if (maxWidth <= 0 || text.Length == 0) return string.Empty;
        if (Width(text, face, size, ppd) <= maxWidth) return text;

        const string Ellipsis = "\u2026";

        // Binary search on how many source characters survive: O(log n) text measurements rather
        // than the O(n) walk the obvious implementation does. A 260-character path costs 8 measures.
        int lo = 0, hi = text.Length - 1;
        string best = Ellipsis;
        while (lo <= hi)
        {
            int keep = (lo + hi) / 2;
            string candidate;
            if (middle)
            {
                // Two thirds of the budget goes to the tail: the filename is the load-bearing end.
                // Below ~24 surviving characters the head is dropped altogether — "C:\Us…\uv.exe"
                // spends a third of a narrow column on three characters that say nothing, whereas
                // "…\astral-sh.uv_…\uv.exe" at least reaches the meaningful part of the path.
                int tail = keep >= 24 ? Math.Clamp(keep * 2 / 3, 0, keep) : keep;
                int head = keep - tail;
                candidate = (head > 0 ? text[..head] : string.Empty) + Ellipsis
                          + (tail > 0 ? text[^tail..] : string.Empty);
            }
            else
            {
                candidate = text[..keep] + Ellipsis;
            }

            if (Width(candidate, face, size, ppd) <= maxWidth) { best = candidate; lo = keep + 1; }
            else hi = keep - 1;
        }
        return best;
    }

    /// <summary>
    /// Neutralises display attacks in attacker-controlled strings before they reach a glyph run.
    ///
    /// The real filename attack is not homoglyphs — monospace does not defend against those,
    /// since a Cyrillic U+043E is an identical round 'o' in Cascadia Mono. It is U+202E
    /// RIGHT-TO-LEFT OVERRIDE, which makes "invoice{RLO}fdp.exe" render as "invoicexe.pdf" in any
    /// WPF text run. Every path, command line and incident title in HERO is written by whatever
    /// it is watching, so bidi and other format controls are escaped to visible \uXXXX, control
    /// characters likewise, and trailing whitespace is made visible with a middle dot.
    /// </summary>
    internal static string Sanitise(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return string.Empty;

        string s = raw;
        if (s.Length > MaxRenderedChars)
        {
            // Never cut between a surrogate pair. A lone surrogate draws as a replacement box, so
            // truncation would manufacture exactly the corrupted-looking glyph this method exists
            // to make legible and attributable.
            int cut = char.IsHighSurrogate(s[MaxRenderedChars - 1]) ? MaxRenderedChars - 1 : MaxRenderedChars;
            s = s[..cut] + "\u2026";
        }

        bool needsWork = char.IsWhiteSpace(s[^1]);
        if (!needsWork)
        {
            foreach (var ch in s)
            {
                if (IsHostile(ch)) { needsWork = true; break; }
            }
        }
        if (!needsWork) return s;

        string escaped = Escape(s);
        return escaped.Length > 0 && char.IsWhiteSpace(escaped[^1]) ? escaped + '\u00B7' : escaped;
    }

    /// <summary>
    /// Escapes the same hostile characters as <see cref="Sanitise"/> but changes nothing else \u2014
    /// no length cap, no trailing-whitespace marker \u2014 so the result still round-trips as a path,
    /// hash or command line.
    ///
    /// This is the clipboard path. A watched process controls its own command line and can put a
    /// carriage return in it; text after a CR pasted into a shell is not text, it is a submitted
    /// line, and HERO would be the courier. Escaping is cheap insurance against being the delivery
    /// mechanism for the thing it is meant to catch.
    /// </summary>
    internal static string Neutralise(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return string.Empty;
        foreach (var ch in raw)
        {
            if (IsHostile(ch)) return Escape(raw);
        }
        return raw;
    }

    private static string Escape(string s)
    {
        var sb = new StringBuilder(s.Length + 8);
        foreach (var ch in s)
        {
            if (IsHostile(ch)) sb.Append("\\u").Append(((int)ch).ToString("X4", CultureInfo.InvariantCulture));
            else sb.Append(ch);
        }
        return sb.ToString();
    }

    private static bool IsHostile(char ch)
        => ch < 0x20
           || ch == 0x7F
           || (ch >= '\u202A' && ch <= '\u202E')    // LRE RLE PDF LRO RLO
           || (ch >= '\u2066' && ch <= '\u2069')    // LRI RLI FSI PDI
           || ch == '\u200E' || ch == '\u200F'      // LRM RLM
           || char.GetUnicodeCategory(ch) == UnicodeCategory.Format;

    private static bool IsDigit(char ch) => ch is >= '0' and <= '9';
}
