using System.Windows;
using System.Windows.Media;
using Hero.Guardian;

namespace Hero.UI.Controls;

/// <summary>
/// A compact severity label: rounded fill, optional leading dot, uppercase word.
///
/// Severity is always encoded twice — colour AND the word — because a bare coloured dot is
/// unreadable to a colour-blind user and unlabelled colour is exactly where a security UI
/// stops being auditable. The word is never dropped, at any size.
///
/// Drawn rather than templated, so it costs one visual element and can sit inside a
/// virtualised table row without pushing the row over its element budget.
/// </summary>
internal sealed class SeverityPill : FrameworkElement
{
    private Typeface? _face;

    internal SeverityPill()
    {
        SnapsToDevicePixels = true;
        UseLayoutRounding = true;
    }

    internal static readonly DependencyProperty SeverityProperty = DependencyProperty.Register(
        nameof(Severity), typeof(Severity), typeof(SeverityPill),
        new FrameworkPropertyMetadata(Guardian.Severity.Safe,
            FrameworkPropertyMetadataOptions.AffectsMeasure | FrameworkPropertyMetadataOptions.AffectsRender,
            OnSeverityChanged));

    internal Severity Severity
    {
        get => (Severity)GetValue(SeverityProperty);
        set => SetValue(SeverityProperty, value);
    }

    /// <summary>Overrides the severity word — used for counts ("3 NEW") and status words.</summary>
    internal static readonly DependencyProperty LabelProperty = DependencyProperty.Register(
        nameof(Label), typeof(string), typeof(SeverityPill),
        new FrameworkPropertyMetadata(null,
            FrameworkPropertyMetadataOptions.AffectsMeasure | FrameworkPropertyMetadataOptions.AffectsRender,
            OnSeverityChanged));

    internal string? Label
    {
        get => (string?)GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    internal static readonly DependencyProperty ShowDotProperty = DependencyProperty.Register(
        nameof(ShowDot), typeof(bool), typeof(SeverityPill),
        new FrameworkPropertyMetadata(true,
            FrameworkPropertyMetadataOptions.AffectsMeasure | FrameworkPropertyMetadataOptions.AffectsRender));

    internal bool ShowDot
    {
        get => (bool)GetValue(ShowDotProperty);
        set => SetValue(ShowDotProperty, value);
    }

    /// <summary>Label size. Defaults to the theme's FsMicro so it tracks the app's type scale.</summary>
    internal static readonly DependencyProperty PillFontSizeProperty = DependencyProperty.Register(
        nameof(PillFontSize), typeof(double), typeof(SeverityPill),
        new FrameworkPropertyMetadata(11.5d,
            FrameworkPropertyMetadataOptions.AffectsMeasure | FrameworkPropertyMetadataOptions.AffectsRender));

    internal double PillFontSize
    {
        get => (double)GetValue(PillFontSizeProperty);
        set => SetValue(PillFontSizeProperty, value);
    }

    /// <summary>
    /// The surface the pill sits on. The fill is mixed from the severity colour into this ground,
    /// so the pill stays opaque (ClearType survives) and its contrast is predictable.
    /// </summary>
    internal static readonly DependencyProperty GroundBrushProperty = DependencyProperty.Register(
        nameof(GroundBrush), typeof(Brush), typeof(SeverityPill),
        new FrameworkPropertyMetadata(SeverityPalette.Brush(Color.FromRgb(0x1C, 0x23, 0x2C)),
            FrameworkPropertyMetadataOptions.AffectsRender));

    internal Brush GroundBrush
    {
        get => (Brush)GetValue(GroundBrushProperty);
        set => SetValue(GroundBrushProperty, value);
    }

    private static void OnSeverityChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var pill = (SeverityPill)d;
        System.Windows.Automation.AutomationProperties.SetName(pill, pill.Text());
    }

    protected override void OnInitialized(EventArgs e)
    {
        base.OnInitialized(e);
        SeverityPalette.BindToken(this, PillFontSizeProperty, "FsMicro");
        SeverityPalette.BindToken(this, GroundBrushProperty, "Surface2");
        System.Windows.Automation.AutomationProperties.SetName(this, Text());
    }

    protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi)
    {
        base.OnDpiChanged(oldDpi, newDpi);
        InvalidateMeasure();
    }

    private string Text() => GlyphText.Sanitise(Label ?? SeverityPalette.Word(Severity)).ToUpperInvariant();

    /// <summary>Pill height. Named to avoid shadowing FrameworkElement.Height.</summary>
    internal double PillHeight => Math.Round(PillFontSize * 1.9);

    protected override Size MeasureOverride(Size availableSize)
    {
        double h = PillHeight;
        double ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        _face ??= Face();

        double tracking = PillFontSize * 0.035;          // ~+0.4px at 11.5px
        double text = GlyphText.TrackedWidth(Text(), _face, PillFontSize, ppd, tracking);
        double pad = h * 0.42;
        double dot = ShowDot ? h * 0.27 + h * 0.27 : 0;  // dot plus its gap

        double wanted = Math.Ceiling(pad * 2 + dot + text);
        double cap = double.IsInfinity(availableSize.Width) ? wanted : availableSize.Width;
        return new Size(Math.Min(wanted, cap), h);
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = RenderSize.Width, h = RenderSize.Height;
        if (w <= 2 || h <= 2) return;

        double ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        _face ??= Face();

        var ground = GroundBrush is SolidColorBrush g ? g.Color : Color.FromRgb(0x1C, 0x23, 0x2C);
        var basis = SeverityPalette.Base(this, Severity);
        var fill = SeverityPalette.Brush(SeverityPalette.PillBackground(basis, ground));
        var ink = SeverityPalette.Brush(SeverityPalette.PillForeground(basis));

        double r = h / 2;
        dc.DrawRoundedRectangle(fill, null, new Rect(0, 0, w, h), r, r);

        double pad = h * 0.42;
        double x = pad;

        if (ShowDot)
        {
            double dotR = h * 0.135;
            dc.DrawEllipse(SeverityPalette.Brush(basis), null, new Point(x + dotR, h / 2), dotR, dotR);
            x += dotR * 2 + h * 0.27;
        }

        string text = Text();
        double tracking = PillFontSize * 0.035;
        double th = GlyphText.Height(text, _face, PillFontSize, ppd);
        GlyphText.DrawTracked(dc, text, _face, PillFontSize, ink, ppd, tracking, new Point(x, (h - th) / 2));
    }

    private Typeface Face()
    {
        var family = TryFindResource("UIFont") as FontFamily ?? new FontFamily("Segoe UI Variable Text, Segoe UI");
        // 600 (SemiBold), never 500: the shipped Segoe UI Variable exposes 300/350/400/600/700 only
        // and a Medium request silently snaps to a neighbouring face.
        return new Typeface(family, FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
    }
}

/// <summary>
/// Severity colour resolution shared by every HERO control.
///
/// Theme.xaml declares one brush per severity. The pill's background and foreground are DERIVED
/// from that single value rather than being separate tokens, so retuning a severity in Theme.xaml
/// keeps every pill in the app consistent and cannot silently break contrast.
///
/// The derivation is fixed at 18% of the severity colour mixed into the surface for the fill, and
/// 35% toward white for the ink. Measured against the shipped tokens on Surface2 (#1C232C) with
/// the WCAG 2.x relative-luminance formula:
///
///   Critical #E5484D -> ink #EE888B on #402A32 = 5.35:1
///   High     #E8743B -> ink #F0A580 on #41312F = 6.11:1
///   Medium   #E0A54B -> ink #EBC48A on #3F3A32 = 6.88:1
///   Low      #7E93AC -> ink #ABB9C9 on #2E3743 = 6.02:1
///   Safe     #3FB984 -> ink #82D2AF on #223E3C = 6.48:1
///
/// All clear AA (4.5:1) for normal text with margin. If the severity tokens are ever retuned,
/// re-run those five numbers rather than eyeballing the result.
/// </summary>
internal static class SeverityPalette
{
    // Fallbacks are byte-identical to Theme.xaml, so the controls render correctly even if a
    // dictionary has not been merged yet (during a designer load, for instance).
    private static readonly Color SafeFallback = Color.FromRgb(0x3F, 0xB9, 0x84);
    private static readonly Color LowFallback = Color.FromRgb(0x7E, 0x93, 0xAC);
    private static readonly Color MediumFallback = Color.FromRgb(0xE0, 0xA5, 0x4B);
    private static readonly Color HighFallback = Color.FromRgb(0xE8, 0x74, 0x3B);
    private static readonly Color CriticalFallback = Color.FromRgb(0xE5, 0x48, 0x4D);

    // Frozen brushes are cheaper to render and are shared across every row of every table, which
    // matters when a 400-row list repaints. Access is UI-thread-only by construction: the only
    // callers are OnRender and measure passes.
    private static readonly Dictionary<uint, SolidColorBrush> BrushCache = new();

    internal static string Word(Severity severity) => severity switch
    {
        Severity.Safe => "Safe",
        Severity.Low => "Low",
        Severity.Medium => "Medium",
        Severity.High => "High",
        _ => "Critical",
    };

    /// <summary>Resolves a severity's base colour from the merged theme, or its shipped default.</summary>
    internal static Color Base(FrameworkElement context, Severity severity)
    {
        var (key, fallback) = severity switch
        {
            Severity.Safe => ("SevSafe", SafeFallback),
            Severity.Low => ("SevLow", LowFallback),
            Severity.Medium => ("SevMedium", MediumFallback),
            Severity.High => ("SevHigh", HighFallback),
            _ => ("SevCritical", CriticalFallback),
        };
        return Resolve(context, key, fallback);
    }

    internal static Color Resolve(FrameworkElement context, string key, Color fallback)
    {
        var found = context.TryFindResource(key);
        return found switch
        {
            SolidColorBrush b => b.Color,
            Color c => c,
            _ => fallback,
        };
    }

    internal static Brush ResolveBrush(FrameworkElement context, string key, Color fallback)
    {
        var found = context.TryFindResource(key);
        return found as Brush ?? Brush(found is Color c ? c : fallback);
    }

    internal static double ResolveDouble(FrameworkElement context, string key, double fallback)
        => context.TryFindResource(key) is double d ? d : fallback;

    /// <summary>
    /// Points a property at a theme token, but never over a value the caller set explicitly.
    ///
    /// The controls bind their tokens from OnInitialized, which for a code-created element runs
    /// when it is first parented — i.e. AFTER an object initialiser has run. An unguarded
    /// SetResourceReference there silently discards `new SeverityPill { PillFontSize = 16 }`,
    /// because both are local values and the later write wins.
    /// </summary>
    internal static void BindToken(FrameworkElement element, DependencyProperty property, string key)
    {
        if (element.ReadLocalValue(property) == DependencyProperty.UnsetValue)
            element.SetResourceReference(property, key);
    }

    internal static Color Mix(Color from, Color to, double amount)
    {
        amount = Math.Clamp(amount, 0d, 1d);
        return Color.FromRgb(
            (byte)Math.Round(from.R + (to.R - from.R) * amount),
            (byte)Math.Round(from.G + (to.G - from.G) * amount),
            (byte)Math.Round(from.B + (to.B - from.B) * amount));
    }

    internal static Color PillBackground(Color basis, Color ground) => Mix(ground, basis, 0.18d);

    internal static Color PillForeground(Color basis) => Mix(basis, Colors.White, 0.35d);

    internal static SolidColorBrush Brush(Color colour)
    {
        uint key = ((uint)colour.A << 24) | ((uint)colour.R << 16) | ((uint)colour.G << 8) | colour.B;
        if (BrushCache.TryGetValue(key, out var brush)) return brush;

        // A colour crossfade produces a new colour per frame; without a ceiling the cache would
        // grow for the life of the process. Severity colours are few, so a reset is free.
        if (BrushCache.Count > 256) BrushCache.Clear();

        brush = new SolidColorBrush(colour);
        brush.Freeze();
        BrushCache[key] = brush;
        return brush;
    }
}
