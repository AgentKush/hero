using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Hero.Guardian;

namespace Hero.UI.Controls;

/// <summary>
/// A 60-second ambient trend line for CPU, network or disk.
///
/// Cost discipline, because these run at 1 Hz forever while the app sits in the tray:
///
/// * Samples live in a fixed-length ring buffer allocated once. <see cref="Push"/> never grows,
///   never copies and never allocates.
/// * The geometry is a frozen <see cref="StreamGeometry"/> rebuilt only when the data or the
///   size actually changes — never per render pass. Frozen is what makes it cheap.
/// * The stroke pen and the area gradient are created once and MUTATED, so even a severity
///   colour crossfade allocates nothing per frame.
/// * There is no timer in here. One shared 1 Hz tick in the view-model must drive every
///   sparkline on screen, or three charts become three independent redraw storms.
///
/// The trace is never interpolated between ticks. A smoothed network chart hides the
/// single-sample burst that is exactly the shape of an exfiltration attempt, so the raw 1 Hz
/// steps are what get drawn.
/// </summary>
internal sealed class Sparkline : FrameworkElement
{
    private const double DefaultHeight = 44d;
    private const double DefaultWidth = 240d;

    private double[] _samples = new double[60];
    private int _count;
    private int _head;                     // next write position

    private StreamGeometry? _area;
    private StreamGeometry? _line;
    private bool _dirty = true;
    private Size _builtFor;

    private readonly SolidColorBrush _strokeBrush = new(Color.FromRgb(0x4C, 0x8D, 0xFF));
    private readonly LinearGradientBrush _areaBrush;
    private Pen? _strokePen;
    private Pen? _basePen;
    private Color _areaColour;

    private Typeface? _monoFace;
    private double _peakValue;
    private int _peakIndex = -1;
    private double _mean;

    // ---- continuous scroll
    //
    // Samples arrive once a second, but redrawing only on arrival makes the whole line jump left
    // by a full step once a second, which reads as stuttering however smooth the curve is. The
    // fix is to decouple the two: geometry is rebuilt on arrival, and every rendered frame slides
    // it left by the fraction of the interval that has elapsed. The line then glides continuously
    // and the newest point eases in from the right edge.
    private double _easedScale;
    private long _lastEaseTicks;
    private long _lastPushTicks;
    private double _intervalMs = 1000;
    private bool _renderingHooked;

    /// <summary>Set false for a static chart that should not glide (e.g. a historical view).</summary>
    internal bool Live { get; set; } = true;

    internal Sparkline()
    {
        SnapsToDevicePixels = true;

        Loaded += (_, _) => HookRendering(true);
        Unloaded += (_, _) => HookRendering(false);

        // Vertical fade under the curve. Left unfrozen deliberately: the stops are recoloured in
        // place when the stroke colour changes, which costs nothing and avoids a per-tick brush.
        _areaBrush = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(0, 1),
            GradientStops =
            {
                new GradientStop(Color.FromArgb(0x2E, 0x4C, 0x8D, 0xFF), 0d),
                new GradientStop(Color.FromArgb(0x00, 0x4C, 0x8D, 0xFF), 1d),
            },
        };
        _areaColour = _strokeBrush.Color;
    }

    // ---------------------------------------------------------------- dependency properties

    /// <summary>Number of samples in the rolling window. 60 at 1 Hz is a one-minute view.</summary>
    internal static readonly DependencyProperty CapacityProperty = DependencyProperty.Register(
        nameof(Capacity), typeof(int), typeof(Sparkline),
        new FrameworkPropertyMetadata(60, FrameworkPropertyMetadataOptions.AffectsRender, OnCapacityChanged));

    internal int Capacity
    {
        get => (int)GetValue(CapacityProperty);
        set => SetValue(CapacityProperty, value);
    }

    /// <summary>
    /// Fixed y-axis maximum. NaN (the default) auto-scales to the window maximum rounded up to a
    /// readable number. Set 100 for a CPU percentage so the trace is comparable between cards.
    /// </summary>
    internal static readonly DependencyProperty MaximumProperty = DependencyProperty.Register(
        nameof(Maximum), typeof(double), typeof(Sparkline),
        new FrameworkPropertyMetadata(double.NaN, FrameworkPropertyMetadataOptions.AffectsRender, OnShapeChanged));

    internal double Maximum
    {
        get => (double)GetValue(MaximumProperty);
        set => SetValue(MaximumProperty, value);
    }

    /// <summary>Floor for the auto-scale, so an idle trace does not amplify rounding noise.</summary>
    internal static readonly DependencyProperty MinimumScaleProperty = DependencyProperty.Register(
        nameof(MinimumScale), typeof(double), typeof(Sparkline),
        new FrameworkPropertyMetadata(1d, FrameworkPropertyMetadataOptions.AffectsRender, OnShapeChanged));

    internal double MinimumScale
    {
        get => (double)GetValue(MinimumScaleProperty);
        set => SetValue(MinimumScaleProperty, value);
    }

    /// <summary>Mirrors the trace vertically, for the "down" half of a network up/down pair.</summary>
    internal static readonly DependencyProperty InvertedProperty = DependencyProperty.Register(
        nameof(Inverted), typeof(bool), typeof(Sparkline),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender, OnShapeChanged));

    internal bool Inverted
    {
        get => (bool)GetValue(InvertedProperty);
        set => SetValue(InvertedProperty, value);
    }

    /// <summary>Trace colour. Animate this (not a shared theme brush) for a severity crossfade.</summary>
    internal static readonly DependencyProperty StrokeColorProperty = DependencyProperty.Register(
        nameof(StrokeColor), typeof(Color), typeof(Sparkline),
        new FrameworkPropertyMetadata(Color.FromRgb(0x4C, 0x8D, 0xFF),
            FrameworkPropertyMetadataOptions.AffectsRender));

    internal Color StrokeColor
    {
        get => (Color)GetValue(StrokeColorProperty);
        set => SetValue(StrokeColorProperty, value);
    }

    internal static readonly DependencyProperty StrokeThicknessProperty = DependencyProperty.Register(
        nameof(StrokeThickness), typeof(double), typeof(Sparkline),
        new FrameworkPropertyMetadata(1.5d, FrameworkPropertyMetadataOptions.AffectsRender, OnPenChanged));

    internal double StrokeThickness
    {
        get => (double)GetValue(StrokeThicknessProperty);
        set => SetValue(StrokeThicknessProperty, value);
    }

    internal static readonly DependencyProperty ShowAreaProperty = DependencyProperty.Register(
        nameof(ShowArea), typeof(bool), typeof(Sparkline),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));

    internal bool ShowArea
    {
        get => (bool)GetValue(ShowAreaProperty);
        set => SetValue(ShowAreaProperty, value);
    }

    internal static readonly DependencyProperty ShowBaselineProperty = DependencyProperty.Register(
        nameof(ShowBaseline), typeof(bool), typeof(Sparkline),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));

    internal bool ShowBaseline
    {
        get => (bool)GetValue(ShowBaselineProperty);
        set => SetValue(ShowBaselineProperty, value);
    }

    /// <summary>Marks the window maximum, but only when it is genuinely a spike (see OnRender).</summary>
    internal static readonly DependencyProperty ShowPeakProperty = DependencyProperty.Register(
        nameof(ShowPeak), typeof(bool), typeof(Sparkline),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));

    internal bool ShowPeak
    {
        get => (bool)GetValue(ShowPeakProperty);
        set => SetValue(ShowPeakProperty, value);
    }

    /// <summary>Formats the peak label. Defaults to a plain integer.</summary>
    internal Func<double, string>? PeakFormatter { get; set; }

    internal static readonly DependencyProperty TrackBrushProperty = DependencyProperty.Register(
        nameof(TrackBrush), typeof(Brush), typeof(Sparkline),
        new FrameworkPropertyMetadata(SeverityPalette.Brush(Color.FromRgb(0x24, 0x2D, 0x38)),
            FrameworkPropertyMetadataOptions.AffectsRender, OnPenChanged));

    internal Brush TrackBrush
    {
        get => (Brush)GetValue(TrackBrushProperty);
        set => SetValue(TrackBrushProperty, value);
    }

    internal static readonly DependencyProperty LabelBrushProperty = DependencyProperty.Register(
        nameof(LabelBrush), typeof(Brush), typeof(Sparkline),
        new FrameworkPropertyMetadata(SeverityPalette.Brush(Color.FromRgb(0x78, 0x84, 0x9A)),
            FrameworkPropertyMetadataOptions.AffectsRender));

    internal Brush LabelBrush
    {
        get => (Brush)GetValue(LabelBrushProperty);
        set => SetValue(LabelBrushProperty, value);
    }

    private static void OnCapacityChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((Sparkline)d).Resize(Math.Max(2, (int)e.NewValue));

    private static void OnShapeChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((Sparkline)d)._dirty = true;

    private static void OnPenChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var s = (Sparkline)d;
        s._strokePen = null;
        s._basePen = null;
    }

    protected override void OnInitialized(EventArgs e)
    {
        base.OnInitialized(e);
        SeverityPalette.BindToken(this, TrackBrushProperty, "Surface3");
        SeverityPalette.BindToken(this, LabelBrushProperty, "TextTertiary");

        // Take the theme accent unless a colour was set explicitly on this instance.
        if (ReadLocalValue(StrokeColorProperty) == DependencyProperty.UnsetValue)
            StrokeColor = SeverityPalette.Resolve(this, "Accent", StrokeColor);
    }

    // ---------------------------------------------------------------------------- data feed

    /// <summary>Appends one sample. Allocation-free; call this from a single shared 1 Hz tick.</summary>
    internal void Push(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value)) value = 0;

        // Learn the real arrival interval rather than assuming 1 Hz. The engine backs off to a
        // slower cadence when the machine is idle, and a glide tuned to the wrong interval either
        // finishes early and stalls, or never finishes and jumps.
        long now = Environment.TickCount64;
        if (_lastPushTicks != 0)
        {
            double observed = now - _lastPushTicks;
            if (observed is > 50 and < 30000)
                _intervalMs = _intervalMs * 0.7 + observed * 0.3;   // smoothed, ignores outliers
        }
        _lastPushTicks = now;

        _samples[_head] = value;
        _head = (_head + 1) % _samples.Length;
        if (_count < _samples.Length) _count++;
        _dirty = true;
        InvalidateVisual();
    }

    /// <summary>
    /// Drives the glide. One handler per visible sparkline, detached on unload so a hidden chart
    /// costs nothing — this fires at the compositor's frame rate and would otherwise keep the
    /// render thread busy for a control nobody can see.
    /// </summary>
    private void HookRendering(bool hook)
    {
        if (hook == _renderingHooked) return;
        _renderingHooked = hook;

        if (hook) CompositionTarget.Rendering += OnFrame;
        else CompositionTarget.Rendering -= OnFrame;
    }

    private void OnFrame(object? sender, EventArgs e)
    {
        if (!Live || _count < 2) return;
        if (!Motion.Active) return;     // honour the animation setting, in-app and system-wide

        // The vertical scale eases towards its target, so the geometry has to be rebuilt while it
        // is moving. Sixty points is a trivial rebuild; the alternative — a render-time transform —
        // would also have to correct the inset and is easier to get subtly wrong.
        if (EaseScale()) _dirty = true;

        InvalidateVisual();
    }

    /// <summary>How far through the current sample interval we are, 0..1.</summary>
    private double Phase()
    {
        if (!Live || !Motion.Active || _lastPushTicks == 0) return 1;
        double elapsed = Environment.TickCount64 - _lastPushTicks;
        return Math.Clamp(elapsed / Math.Max(1, _intervalMs), 0, 1);
    }

    /// <summary>Seeds the window from history, oldest first.</summary>
    internal void Seed(IEnumerable<double> values)
    {
        _count = 0;
        _head = 0;
        foreach (var v in values)
        {
            _samples[_head] = double.IsNaN(v) || double.IsInfinity(v) ? 0 : v;
            _head = (_head + 1) % _samples.Length;
            if (_count < _samples.Length) _count++;
        }
        _dirty = true;
        InvalidateVisual();
    }

    internal void Clear()
    {
        _count = 0;
        _head = 0;
        _dirty = true;
        InvalidateVisual();
    }

    /// <summary>Most recent sample, or 0 when the window is empty.</summary>
    internal double Latest => _count == 0 ? 0 : _samples[(_head - 1 + _samples.Length) % _samples.Length];

    private void Resize(int capacity)
    {
        _samples = new double[capacity];
        _count = 0;
        _head = 0;
        _dirty = true;
        InvalidateVisual();
    }

    private double At(int i) => _samples[(_head - _count + i + _samples.Length * 2) % _samples.Length];

    // --------------------------------------------------------------------------- colouring

    /// <summary>
    /// Crossfades the trace to a severity colour over 400ms. Resource brushes are frozen and
    /// shared, so animating one would either throw or recolour every control using that token —
    /// this animates a private Color dependency property instead.
    /// </summary>
    internal void AnimateStrokeTo(Color target, int milliseconds = 400)
    {
        // Motion.Active, not SystemParameters: the Settings toggle has to switch this off too.
        if (!Motion.Active)
        {
            BeginAnimation(StrokeColorProperty, null);
            StrokeColor = target;
            return;
        }

        BeginAnimation(StrokeColorProperty, new ColorAnimation(target, new Duration(TimeSpan.FromMilliseconds(milliseconds)))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
            FillBehavior = FillBehavior.HoldEnd,
        });
    }

    /// <summary>
    /// Convenience for the severity variant. Note the product rule this must respect: resource
    /// metrics are ambient telemetry. A sustained 100% CPU on this machine is a Blender render or
    /// a 24-thread build, so recolouring a sparkline must never be treated as, or promoted to, a
    /// detection signal — it is a reading, not an accusation.
    /// </summary>
    internal void AnimateStrokeTo(Severity severity, int milliseconds = 400)
        => AnimateStrokeTo(SeverityPalette.Base(this, severity), milliseconds);

    // ------------------------------------------------------------------------------- layout

    protected override Size MeasureOverride(Size availableSize)
    {
        double w = double.IsInfinity(availableSize.Width) ? DefaultWidth : availableSize.Width;
        double h = double.IsInfinity(availableSize.Height) ? DefaultHeight : availableSize.Height;
        return new Size(w, h);
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo info)
    {
        base.OnRenderSizeChanged(info);
        _dirty = true;   // sample spacing is derived from ActualWidth
    }

    protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi)
    {
        base.OnDpiChanged(oldDpi, newDpi);
        _dirty = true;
        InvalidateVisual();
    }

    // ------------------------------------------------------------------------------- render

    protected override void OnRender(DrawingContext dc)
    {
        double w = RenderSize.Width, h = RenderSize.Height;
        if (w <= 2 || h <= 2) return;

        // Transparent ground keeps the whole card hit-testable for tooltips.
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));

        var colour = StrokeColor;
        _strokeBrush.Color = colour;
        if (_areaColour != colour)
        {
            _areaBrush.GradientStops[0].Color = Color.FromArgb(0x2E, colour.R, colour.G, colour.B);
            _areaBrush.GradientStops[1].Color = Color.FromArgb(0x00, colour.R, colour.G, colour.B);
            _areaColour = colour;
        }

        _strokePen ??= new Pen(_strokeBrush, StrokeThickness)
        {
            LineJoin = PenLineJoin.Round,
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
        };
        _basePen ??= FreezePen(new Pen(TrackBrush, 1));

        double baseY = Inverted ? 0.5 : h - 0.5;
        if (ShowBaseline) dc.DrawLine(_basePen, new Point(0, baseY), new Point(w, baseY));

        if (_count < 2) return;

        if (_dirty || _builtFor != RenderSize) Rebuild(w, h);

        // Glide. The geometry extends one step past the right edge; sliding it left by the
        // elapsed fraction of the sample interval turns a once-a-second jump into continuous
        // motion. Clipping hides the incoming point until it has arrived and the outgoing one
        // after it has left.
        double step = _count > 2 ? w / (_count - 2) : 0;
        double shift = -Phase() * step;

        dc.PushClip(new RectangleGeometry(new Rect(0, 0, w, h)));
        dc.PushTransform(new TranslateTransform(shift, 0));

        if (ShowArea && _area is not null) dc.DrawGeometry(_areaBrush, null, _area);
        if (_line is not null) dc.DrawGeometry(null, _strokePen, _line);

        dc.Pop();   // transform
        dc.Pop();   // clip

        // The peak is only worth marking when it is genuinely a spike; on a flat trace a marker on
        // the highest of sixty near-identical samples is noise dressed as information.
        if (ShowPeak && _peakIndex >= 0 && _mean > 0 && _peakValue > _mean * 1.5)
        {
            // The marker rides with the curve, so it uses the same step and shift.
            double dx = step > 0 ? step : w / Math.Max(1, _count - 1);
            double px = _peakIndex * dx + shift;

            // Fade the marker out as it approaches either edge.
            //
            // Previously the dot kept sliding while its label was clamped into view, so the two
            // separated and then both vanished at once — the "jump when it hits the wall". A
            // marker that cannot be drawn where it belongs should fade rather than be dragged
            // somewhere it does not belong.
            // The label is wider than the dot, so the fade has to start far enough in that the
            // TEXT never reaches the edge. Sized off the label, not an arbitrary percentage.
            double margin = Math.Max(46, w * 0.09);
            double edge = Math.Min(px, w - px);
            if (edge <= 0) return;

            double fade = Math.Clamp(edge / margin, 0, 1);
            // Ease it so the last few pixels do not fade linearly and appear to snap.
            fade = fade * fade * (3 - 2 * fade);
            if (fade <= 0.02) return;

            dc.PushOpacity(fade);
            double py = MapY(_peakValue, h);
            dc.DrawEllipse(_strokeBrush, null, new Point(px, py), 3, 3);

            _monoFace ??= MonoFace();
            double ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip;
            double size = Math.Max(9, SeverityPalette.ResolveDouble(this, "FsMicro", 11.5));
            string label = (PeakFormatter ?? DefaultPeakFormat)(_peakValue);
            var ft = GlyphText.Make(label, _monoFace, size, LabelBrush, ppd);

            // The label tracks the dot exactly. It is NOT clamped into view: clamping is what made
            // the label stop while the dot carried on, which is the separation the fade replaces.
            double lx = px - ft.Width / 2;
            double ly = Inverted ? py + 5 : py - ft.Height - 3;
            dc.DrawText(ft, new Point(lx, Math.Clamp(ly, 0, Math.Max(0, h - ft.Height))));

            dc.Pop();   // opacity
        }
    }

    /// <summary>
    /// Emits a Catmull-Rom spline through the points as cubic Beziers.
    ///
    /// Straight segments between one-second samples looked like a saw. A spline reads as a
    /// measurement rather than a bar chart joined up.
    ///
    /// The control-point Y values are clamped to the span of the segment they belong to. Plain
    /// Catmull-Rom overshoots after a sharp change, which on a latency graph would draw dips below
    /// zero that never happened — a chart that invents data to look smoother is worse than a jagged
    /// one.
    /// </summary>
    private static void AppendSmooth(StreamGeometryContext ctx, Point[] p)
    {
        const double tension = 1.0 / 6.0;

        for (int i = 0; i < p.Length - 1; i++)
        {
            var p0 = i == 0 ? p[0] : p[i - 1];
            var p1 = p[i];
            var p2 = p[i + 1];
            var p3 = i + 2 < p.Length ? p[i + 2] : p[^1];

            double lo = Math.Min(p1.Y, p2.Y), hi = Math.Max(p1.Y, p2.Y);

            var c1 = new Point(
                p1.X + (p2.X - p0.X) * tension,
                Math.Clamp(p1.Y + (p2.Y - p0.Y) * tension, lo, hi));

            var c2 = new Point(
                p2.X - (p3.X - p1.X) * tension,
                Math.Clamp(p2.Y - (p3.Y - p1.Y) * tension, lo, hi));

            ctx.BezierTo(c1, c2, p2, true, false);
        }
    }

    private void Rebuild(double w, double h)
    {
        // One extra step of width so the newest sample starts just beyond the right edge and
        // slides in as the phase advances. With w/(count-1) the newest point would already be at
        // the edge and there would be nothing to glide.
        double dx = _count > 2 ? w / (_count - 2) : w / Math.Max(1, _count - 1);

        _peakValue = double.MinValue;
        _peakIndex = -1;
        double sum = 0;
        for (int i = 0; i < _count; i++)
        {
            double v = At(i);
            sum += v;
            if (v > _peakValue) { _peakValue = v; _peakIndex = i; }
        }
        _mean = sum / _count;

        // Points are precomputed once and shared by both geometries.
        var pts = new Point[_count];
        for (int i = 0; i < _count; i++) pts[i] = new Point(i * dx, MapY(At(i), h));

        var area = new StreamGeometry { FillRule = FillRule.Nonzero };
        using (var ctx = area.Open())
        {
            double baseY = Inverted ? 0 : h;
            ctx.BeginFigure(new Point(pts[0].X, baseY), true, true);
            ctx.LineTo(pts[0], true, false);
            AppendSmooth(ctx, pts);
            ctx.LineTo(new Point(pts[^1].X, baseY), true, false);
        }
        area.Freeze();

        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            ctx.BeginFigure(pts[0], false, false);
            AppendSmooth(ctx, pts);
        }
        line.Freeze();

        _area = area;
        _line = line;
        _builtFor = RenderSize;
        _dirty = false;
    }

    private double MapY(double value, double h)
    {
        double max = Scale();
        double t = Math.Clamp(value / max, 0d, 1d);
        double inset = Math.Min(2, h / 4);
        return Inverted ? inset + t * (h - inset * 2) : h - inset - t * (h - inset * 2);
    }

    /// <summary>
    /// Auto-scale ceiling. It is derived from the window maximum, so it rises the moment a spike
    /// arrives and only falls once that spike has rolled out of the window — which stops the whole
    /// trace jumping vertically the instant a burst ages out.
    /// </summary>
    private double Scale()
    {
        if (!double.IsNaN(Maximum) && Maximum > 0) return Maximum;
        return _easedScale > 0 ? _easedScale : TargetScale();
    }

    /// <summary>
    /// The ceiling the trace is heading towards. Continuous, deliberately.
    ///
    /// This used to be NiceCeiling(windowMax), which snaps to 1, 2, 2.5, 5 or 10 times a power of
    /// ten. That quantisation is exactly what made the graph bounce: when the tallest sample rolled
    /// out of the window and the maximum crossed a boundary, the ceiling could halve, and halving
    /// the ceiling doubles every point's height in a single frame. Rounded ceilings make sense for
    /// an axis with printed gridlines; this has neither.
    ///
    /// The 1.15 headroom keeps the peak just below the top edge instead of touching it.
    /// </summary>
    private double TargetScale()
    {
        double max = MinimumScale;
        for (int i = 0; i < _count; i++) max = Math.Max(max, At(i));
        return Math.Max(MinimumScale, max * 1.15);
    }

    /// <summary>
    /// Moves the working scale towards the target a little each frame.
    ///
    /// Framerate-independent exponential easing: the same visual speed whether the compositor is
    /// running at 60Hz or 165Hz. Returns true when the scale moved enough to be worth redrawing.
    /// </summary>
    private bool EaseScale()
    {
        double target = TargetScale();
        if (_easedScale <= 0) { _easedScale = target; return false; }

        long now = Environment.TickCount64;
        double dt = _lastEaseTicks == 0 ? 16 : Math.Clamp(now - _lastEaseTicks, 1, 250);
        _lastEaseTicks = now;

        // ~300ms time constant: fast enough not to feel laggy, slow enough that a spike ageing
        // out of the window reads as the view zooming rather than the trace jumping.
        double k = 1 - Math.Exp(-dt / 300.0);
        double next = _easedScale + (target - _easedScale) * k;

        bool moved = Math.Abs(next - _easedScale) / Math.Max(1e-6, _easedScale) > 0.0015;
        _easedScale = next;
        return moved;
    }

    private static double NiceCeiling(double v)
    {
        if (v <= 0) return 1;
        double exp = Math.Floor(Math.Log10(v));
        double pow = Math.Pow(10, exp);
        double f = v / pow;
        double nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
        return nice * pow;
    }

    private static string DefaultPeakFormat(double v)
        => v >= 100 ? v.ToString("F0", System.Globalization.CultureInfo.CurrentCulture)
                    : v.ToString("0.#", System.Globalization.CultureInfo.CurrentCulture);

    private Typeface MonoFace()
    {
        var family = TryFindResource("MonoFont") as FontFamily ?? new FontFamily("Cascadia Mono, Consolas");
        return new Typeface(family, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    }

    private static Pen FreezePen(Pen p) { if (p.CanFreeze) p.Freeze(); return p; }
}
