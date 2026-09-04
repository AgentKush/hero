using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Hero.UI.Controls;

/// <summary>
/// A liquid progress indicator: a vessel that fills, with a moving surface.
///
/// It exists because the scans it reports on are LONG. Walking a drive or hashing a candidate set
/// runs for tens of seconds with nothing to show for most of it, and a bar that sits still is
/// indistinguishable from a bar that has hung — the complaint that started this was a page that
/// "starts blank then randomly populates after not showing itself doing anything". Motion that
/// continues while the number is unchanged is the part that communicates "still working"; the
/// number alone cannot.
///
/// The surface is two sine waves of different frequency, amplitude and speed, summed. One wave
/// reads as a repeating pattern almost immediately — the eye locks onto the period. Two whose
/// frequencies are not simple multiples of each other beat against one another and never visibly
/// repeat, which is what makes it read as liquid rather than as an animation.
///
/// THREE THINGS THIS CONTROL REFUSES TO DO:
///
///  1. Animate when <see cref="Motion.Active"/> is false. People who disable animations often do
///     so because motion makes them ill, and a decorative liquid is exactly the kind of thing that
///     ignores that. With motion off it draws a flat, still fill — the information, none of the
///     movement.
///  2. Render while off screen. It unhooks from <see cref="CompositionTarget.Rendering"/> on
///     Unloaded AND on becoming invisible. A per-frame callback left running behind a hidden page
///     is a background CPU cost in a tool whose whole pitch is that it is cheap to leave on.
///  3. Jump. The level eases toward its target instead of snapping, because measured progress
///     arrives in lumps — one directory finishing can move a scan several percent at once.
/// </summary>
internal sealed class FluidProgress : FrameworkElement
{
    // ------------------------------------------------------------------ properties

    internal static readonly DependencyProperty ProgressProperty = DependencyProperty.Register(
        nameof(Progress), typeof(double), typeof(FluidProgress),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>Fraction filled, 0 to 1. Ignored while <see cref="IsIndeterminate"/>.</summary>
    internal double Progress
    {
        get => (double)GetValue(ProgressProperty);
        set => SetValue(ProgressProperty, Math.Clamp(value, 0d, 1d));
    }

    internal static readonly DependencyProperty IsIndeterminateProperty = DependencyProperty.Register(
        nameof(IsIndeterminate), typeof(bool), typeof(FluidProgress),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>
    /// True while the total is unknown — which is the honest state for most of a disk walk, because
    /// the only way to know how many files there are is to have finished walking them.
    /// </summary>
    internal bool IsIndeterminate
    {
        get => (bool)GetValue(IsIndeterminateProperty);
        set => SetValue(IsIndeterminateProperty, value);
    }

    internal static readonly DependencyProperty AnimationsEnabledProperty = DependencyProperty.Register(
        nameof(AnimationsEnabled), typeof(bool), typeof(FluidProgress), new PropertyMetadata(true));

    internal bool AnimationsEnabled
    {
        get => (bool)GetValue(AnimationsEnabledProperty);
        set => SetValue(AnimationsEnabledProperty, value);
    }

    internal static readonly DependencyProperty AccentProperty = DependencyProperty.Register(
        nameof(Accent), typeof(Color), typeof(FluidProgress),
        new FrameworkPropertyMetadata(Color.FromRgb(0x3B, 0xA5, 0x5D),
                                      FrameworkPropertyMetadataOptions.AffectsRender));

    internal Color Accent
    {
        get => (Color)GetValue(AccentProperty);
        set => SetValue(AccentProperty, value);
    }

    /// <summary>Only property call sites should test. Mirrors ScoreRing and Sparkline.</summary>
    /// <summary>
    /// Motion.Active is consulted live rather than cached into AnimationsEnabled, so that the
    /// Settings toggle and the Windows accessibility setting both take effect immediately. The
    /// AnimationsEnabled property remains as a per-instance override for a caller that wants a
    /// still bar regardless.
    /// </summary>
    private bool MotionAllowed => AnimationsEnabled && Motion.Active;

    // ------------------------------------------------------------------ state

    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private double _lastFrameSeconds;
    private double _phase;          // seconds of accumulated wave time
    private double _level;          // eased fill fraction actually drawn
    private bool _hooked;

    internal FluidProgress()
    {
        // 18, not the 10 this started at.
        //
        // Amplitude is capped as a fraction of height so the wave can never breach its own vessel,
        // which meant a 10px bar got a 2px wave — and at 90% fill the surface sat under a pixel of
        // headroom, so the "liquid" was a barely perceptible wobble on a solid block. A liquid
        // needs somewhere to move. 18px is still a header-weight element, and it gives the surface
        // a 5px swing plus room for the body to read as a volume.
        Height = 18;
        SnapsToDevicePixels = true;
        UseLayoutRounding = true;

        Loaded += (_, _) => { Motion.Changed += OnMotionChanged; Rehook(); };
        Unloaded += (_, _) => { Motion.Changed -= OnMotionChanged; Hook(false); };

        // Visibility, not just Loaded. A page that is still in the visual tree but hidden behind
        // another one stays Loaded, so Loaded alone would leave the callback running forever.
        IsVisibleChanged += (_, _) => Rehook();
    }

    /// <summary>
    /// The Settings toggle has to reach a control that is ALREADY on screen.
    ///
    /// Without this the switch only took effect on pages built afterwards: this control reads
    /// Motion.Active when its owner constructs it, so a user turning animations off while watching
    /// a scan would have gone on watching it move. Motion.cs promises "one switch ... including
    /// ones added later", and a control that samples the value once does not keep that promise.
    /// </summary>
    private void OnMotionChanged()
    {
        Dispatcher.BeginInvoke(() =>
        {
            Rehook();
            InvalidateVisual();     // repaint flat immediately when motion has just been switched off
        });
    }

    private void Rehook() => Hook(IsVisible && IsLoaded && MotionAllowed);

    private void Hook(bool on)
    {
        if (on == _hooked) return;
        _hooked = on;

        if (on)
        {
            _lastFrameSeconds = _clock.Elapsed.TotalSeconds;
            CompositionTarget.Rendering += OnFrame;
        }
        else
        {
            CompositionTarget.Rendering -= OnFrame;
        }
    }

    private void OnFrame(object? sender, EventArgs e)
    {
        double now = _clock.Elapsed.TotalSeconds;
        double dt = now - _lastFrameSeconds;
        _lastFrameSeconds = now;

        // A frame that claims to be a second long is a stall — the machine was busy, or the app was
        // minimised and WPF coalesced frames. Advancing the phase by the real gap makes the wave
        // visibly jump on recovery, so the step is capped at roughly two frames' worth.
        if (dt > 0.05) dt = 0.05;

        _phase += dt;

        // Indeterminate sweeps the level instead of holding it.
        //
        // This used to hold a constant 0.42 and translate the leading edge by _phase * 34 to
        // suggest travel. _phase is seconds since the control loaded and never wraps, so the edge
        // marched off the right-hand end within about ten seconds and the bar read as FULL while
        // the scan was still counting — reported from a live run at "538,543 files seen". An
        // unbounded translation is not a travelling wave, it is a slow escape.
        //
        // A bounded oscillation says the same thing honestly: something is happening, and the
        // total is not known. It can never reach either end, so it cannot be mistaken for done.
        double target = IsIndeterminate
            ? 0.30 + 0.35 * (0.5 + 0.5 * Math.Sin(_phase * 0.85))
            : Progress;

        // Exponential ease, frame-rate independent: the same fraction of the remaining distance is
        // covered per second regardless of how often frames arrive. A fixed per-frame step would
        // move at 144 Hz twice as fast as at 72 Hz.
        _level += (target - _level) * (1 - Math.Exp(-6 * dt));

        InvalidateVisual();
    }

    // ------------------------------------------------------------------ drawing

    protected override void OnRender(DrawingContext dc)
    {
        double w = RenderSize.Width, h = RenderSize.Height;
        if (w <= 1 || h <= 1) return;

        double radius = h / 2;
        var vessel = new RectangleGeometry(new Rect(0, 0, w, h), radius, radius);

        // The track. Drawn from the accent at low alpha rather than a separate token so the two can
        // never drift apart when the theme changes.
        dc.DrawGeometry(new SolidColorBrush(Color.FromArgb(0x22, Accent.R, Accent.G, Accent.B)),
                        null, vessel);

        double level = MotionAllowed ? _level : (IsIndeterminate ? 0.42 : Progress);
        if (level <= 0.001)
        {
            return;
        }

        dc.PushClip(vessel);
        try
        {
            var fill = new LinearGradientBrush(
                Color.FromArgb(0xFF, Accent.R, Accent.G, Accent.B),
                Color.FromArgb(0xCC, Accent.R, Accent.G, Accent.B),
                new Point(0, 0), new Point(0, 1));
            fill.Freeze();

            if (!MotionAllowed)
            {
                // Still, and correct. Disabling animation must never mean losing the reading.
                dc.DrawRectangle(fill, null, new Rect(0, 0, w * level, h));
                return;
            }

            var body = Surface(w, h, level);
            dc.DrawGeometry(fill, null, body);

            // A second, fainter wave a little behind the first. This is the whole illusion: one
            // wave is a shape moving, two are a volume of liquid.
            var trailing = new SolidColorBrush(Color.FromArgb(0x3A, 0xFF, 0xFF, 0xFF));
            trailing.Freeze();
            dc.DrawGeometry(trailing, null, Surface(w, h, level, secondary: true));

            // Bubbles, inside the liquid body only.
            //
            // These are what make the difference at high fill. Once the level passes about 85% the
            // surface has almost no headroom left and the waves flatten against the top of the
            // vessel — exactly when a long scan spends most of its time. Rising bubbles keep the
            // body itself in motion at any fill, so the control never reads as frozen just because
            // it is nearly done.
            dc.PushClip(body);
            try { DrawBubbles(dc, w, h, level); }
            finally { dc.Pop(); }

            // A brighter line riding the surface. Water reads as water largely because of the
            // specular edge where it meets air; without it the wave is just a coloured shape
            // changing outline.
            var crest = new Pen(new SolidColorBrush(Color.FromArgb(0x99, 0xFF, 0xFF, 0xFF)), 1.4);
            crest.Freeze();
            dc.DrawGeometry(null, crest, SurfaceLine(w, h, level));
        }
        finally
        {
            dc.Pop();
        }
    }

    /// <summary>
    /// The liquid body: a filled path whose top edge is the summed wave.
    ///
    /// In indeterminate mode the whole body also travels horizontally, because a surface that
    /// ripples while the level never changes still reads as stalled after a few seconds — the eye
    /// needs something making progress across the control, not just moving in place.
    /// </summary>
    /// <summary>
    /// The liquid body: filled from the LEFT, with a wavy vertical meniscus at the leading edge.
    ///
    /// The first two attempts filled from the bottom like a glass, and both failed for the same
    /// geometric reason: this control is 108 times wider than it is tall. A rising-level liquid in
    /// that shape has its entire character in the top few pixels, and a scan sits above 85% for
    /// most of its life — at 91% there was 1.6px of headroom, so the wave had nowhere to be. It
    /// read as a bar with a wobbly top, which is what it was.
    ///
    /// Filling horizontally puts the moving edge where the aspect ratio has room for it, and the
    /// edge stays fully visible at every value instead of being squeezed out exactly when the user
    /// spends longest looking at it.
    /// </summary>
    private StreamGeometry Surface(double w, double h, double level, bool secondary = false)
    {
        double k1 = secondary ? 2.3 : 1.7;
        double amp = WaveAmplitude(h) * (secondary ? 0.55 : 1.0);
        double speed = secondary ? 1.35 : 1.0;

        double edge = level * w;

        // The top surface ripples along the WHOLE filled width, not just at the edge.
        //
        // Filling horizontally fixed the cramped-wave problem but created a worse one: a meniscus
        // moves a strip about 5px wide, so measured motion fell from 11-13% of the band's pixels to
        // 0.5%. It read as a static bar with a wiggling right end. The vertical version at least
        // had motion everywhere. This keeps the always-visible leading edge AND puts a full
        // amplitude ripple across the body, which is only possible because the fill is horizontal —
        // the top edge is no longer carrying the progress reading, so it is free to move.
        double topAmp = Math.Min(h * 0.18, 3.0) * (secondary ? 0.6 : 1.0);
        double rest = topAmp + 0.5;

        var geometry = new StreamGeometry { FillRule = FillRule.Nonzero };
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(new Point(0, h), isFilled: true, isClosed: true);

            const double step = 4.0;
            for (double x = 0; x <= edge; x += step)
            {
                double u = (x / Math.Max(1, w)) * Math.Tau * 3.0;
                double y = rest
                         + Math.Sin(u * 1.7 + _phase * speed * 2.4) * topAmp
                         + Math.Sin(u * 3.1 - _phase * speed * 1.7) * topAmp * 0.45;

                ctx.LineTo(new Point(x, y), true, false);
            }

            // Down the leading edge, a travelling wave rather than a straight cut. Sampled every
            // device pixel: the edge is only ~18px tall, so coarser sampling makes it polygonal.
            for (double y = rest; y <= h; y += 1.0)
            {
                double v = (y / Math.Max(1, h)) * Math.Tau;
                double x = edge
                         + Math.Sin(v * k1 + _phase * speed * 3.4) * amp
                         + Math.Sin(v * 3.1 - _phase * speed * 2.2) * amp * 0.4;

                ctx.LineTo(new Point(x, y), true, false);
            }
        }

        geometry.Freeze();
        return geometry;
    }

    /// <summary>
    /// How far the surface swings. 30% of height, which at 18px is a 5px wave — visible without
    /// letting a crest breach the vessel and clip flat against the top.
    /// </summary>
    private static double WaveAmplitude(double h) => Math.Min(h * 0.30, 5.0);

    /// <summary>
    /// The meniscus as an open path, for the specular highlight. Identical maths to the body's
    /// leading edge, so the highlight cannot drift off the liquid it is meant to sit on.
    /// </summary>
    private StreamGeometry SurfaceLine(double w, double h, double level)
    {
        double amp = WaveAmplitude(h);
        double edge = level * w;

        double topAmp = Math.Min(h * 0.18, 3.0);
        double rest = topAmp + 0.5;

        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            // The crest runs along the rippling top surface, then turns down the meniscus. Same
            // maths as the body in both segments, so the highlight cannot part company with the
            // liquid it is meant to sit on.
            bool started = false;
            const double step = 4.0;
            for (double x = 0; x <= edge; x += step)
            {
                double u = (x / Math.Max(1, w)) * Math.Tau * 3.0;
                double y = rest
                         + Math.Sin(u * 1.7 + _phase * 2.4) * topAmp
                         + Math.Sin(u * 3.1 - _phase * 1.7) * topAmp * 0.45;

                if (!started) { ctx.BeginFigure(new Point(x, y), isFilled: false, isClosed: false); started = true; }
                else ctx.LineTo(new Point(x, y), true, false);
            }

            for (double y = rest; y <= h; y += 1.0)
            {
                double v = (y / Math.Max(1, h)) * Math.Tau;
                double x = edge
                         + Math.Sin(v * 1.7 + _phase * 3.4) * amp
                         + Math.Sin(v * 3.1 - _phase * 2.2) * amp * 0.4;

                if (!started) { ctx.BeginFigure(new Point(x, y), isFilled: false, isClosed: false); started = true; }
                else ctx.LineTo(new Point(x, y), true, false);
            }
        }

        geometry.Freeze();
        return geometry;
    }

    /// <summary>
    /// Rising bubbles, positioned entirely from the phase clock.
    ///
    /// No per-bubble state is stored, and that is deliberate: state would have to be reset whenever
    /// the control is unhooked while off screen, and a bubble field that restarts every time the
    /// user changes page is a visible glitch. Deriving each bubble from (index, phase) means the
    /// field is a pure function of time — pause it and resume it and nothing jumps.
    ///
    /// The multipliers are irrational-ish on purpose so the bubbles do not fall into a visible
    /// column or pulse in unison.
    /// </summary>
    private void DrawBubbles(DrawingContext dc, double w, double h, double level)
    {
        const int count = 9;

        var brush = new SolidColorBrush(Color.FromArgb(0x40, 0xFF, 0xFF, 0xFF));
        brush.Freeze();

        double edge = Math.Max(1, level * w);

        for (int i = 0; i < count; i++)
        {
            // Vertical position: fixed per bubble, spread by a golden-ratio step so nine of them
            // distribute across the height without falling into a visible row.
            double y = 2 + ((i * 0.618034) % 1.0) * Math.Max(1, h - 4);

            double speed = 0.055 + (i % 4) * 0.022;
            double radius = 0.9 + (i % 3) * 0.5;

            // Travels left to right with the flow and wraps at the meniscus. Scaled by the filled
            // width rather than the whole control, so bubbles never appear ahead of the liquid.
            double t = ((_phase * speed) + i * 0.37) % 1.0;
            double x = t * edge;

            // Fade in and out at both ends, so bubbles arrive and dissolve rather than popping into
            // existence at a hard boundary.
            double falloff = Math.Min(t, 1 - t) * 4;
            byte alpha = (byte)(0x46 * Math.Clamp(falloff, 0, 1));
            if (alpha < 6) continue;

            var faded = new SolidColorBrush(Color.FromArgb(alpha, 0xFF, 0xFF, 0xFF));
            faded.Freeze();
            dc.DrawEllipse(faded, null, new Point(x, y), radius, radius);
        }
    }
}
