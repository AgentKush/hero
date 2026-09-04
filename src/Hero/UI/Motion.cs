using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace Hero.UI;

/// <summary>
/// HERO's motion system.
///
/// Every animation in the app goes through here rather than being hand-rolled at the call site,
/// for three reasons:
///
///  1. **One switch.** The user can turn animations off in Settings, and that has to actually turn
///     off ALL of them, including ones added later. A helper that call sites are merely encouraged
///     to use would drift.
///  2. **Accessibility.** Windows has its own "Show animations in Windows" setting, and people who
///     turn it off frequently do so because motion makes them ill. Honouring only an in-app toggle
///     while ignoring the OS one is the wrong behaviour, so both are consulted.
///  3. **Consistency.** Durations and easings are a small fixed vocabulary. Scattering magic
///     numbers across controls is how an interface starts to feel arbitrary rather than designed.
///
/// When motion is disabled, every helper still applies the FINAL value immediately. Disabling
/// animation must never leave an element stuck at its starting opacity or offset.
/// </summary>
internal static class Motion
{
    /// <summary>The user's preference from Settings. Defaults on.</summary>
    internal static bool UserEnabled { get; set; } = true;

    /// <summary>
    /// Windows' own animation preference (Settings &gt; Accessibility &gt; Visual effects &gt;
    /// Animation effects). Read live rather than cached, because the user can change it while
    /// HERO is running.
    /// </summary>
    internal static bool SystemAllows
    {
        get { try { return SystemParameters.ClientAreaAnimation; } catch { return true; } }
    }

    /// <summary>The only property call sites should test.</summary>
    internal static bool Active => UserEnabled && SystemAllows;

    /// <summary>Raised when the effective setting changes, so open views can restyle.</summary>
    internal static event Action? Changed;

    internal static void SetUserEnabled(bool value)
    {
        if (UserEnabled == value) return;
        UserEnabled = value;
        Changed?.Invoke();
    }

    // ------------------------------------------------------------------ vocabulary

    /// <summary>Hover, press, colour shifts. Fast enough to feel like direct response.</summary>
    internal static readonly Duration Fast = new(TimeSpan.FromMilliseconds(120));

    /// <summary>The default. Panel fades, list entrances, value changes.</summary>
    internal static readonly Duration Normal = new(TimeSpan.FromMilliseconds(220));

    /// <summary>Deliberate, attention-carrying moves such as the score ring sweeping to a new value.</summary>
    internal static readonly Duration Slow = new(TimeSpan.FromMilliseconds(420));

    /// <summary>
    /// Decelerating ease for anything entering or settling. Motion that starts fast and slows
    /// reads as physical; linear motion reads as mechanical.
    /// </summary>
    internal static IEasingFunction Standard => new CubicEase { EasingMode = EasingMode.EaseOut };

    /// <summary>Symmetric ease for values moving between two meaningful states.</summary>
    internal static IEasingFunction Emphasised => new QuarticEase { EasingMode = EasingMode.EaseInOut };

    /// <summary>Per-item delay for staggered list entrances. Beyond about 8 items this is capped,
    /// because a long stagger stops reading as polish and starts reading as lag.</summary>
    internal static readonly TimeSpan StaggerStep = TimeSpan.FromMilliseconds(28);
    private const int MaxStaggeredItems = 8;

    // ------------------------------------------------------------------ helpers

    /// <summary>Animates a double property, or sets it immediately when motion is off.</summary>
    internal static void AnimateDouble(
        UIElement target, DependencyProperty property, double to,
        Duration? duration = null, IEasingFunction? easing = null, TimeSpan? delay = null)
    {
        if (!Active)
        {
            target.BeginAnimation(property, null);
            target.SetValue(property, to);
            return;
        }

        var anim = new DoubleAnimation
        {
            To = to,
            Duration = duration ?? Normal,
            EasingFunction = easing ?? Standard,
            BeginTime = delay,
            FillBehavior = FillBehavior.HoldEnd,
        };
        target.BeginAnimation(property, anim);
    }

    /// <summary>Animates a double property on any Animatable (brushes, transforms, custom controls).</summary>
    internal static void AnimateDouble(
        IAnimatable target, DependencyProperty property, double to,
        Duration? duration = null, IEasingFunction? easing = null, TimeSpan? delay = null)
    {
        if (!Active)
        {
            target.BeginAnimation(property, null);
            if (target is DependencyObject d) d.SetValue(property, to);
            return;
        }

        target.BeginAnimation(property, new DoubleAnimation
        {
            To = to,
            Duration = duration ?? Normal,
            EasingFunction = easing ?? Standard,
            BeginTime = delay,
            FillBehavior = FillBehavior.HoldEnd,
        });
    }

    /// <summary>Fades an element in, optionally rising slightly as it does.</summary>
    internal static void FadeIn(UIElement element, double riseFrom = 8, TimeSpan? delay = null)
    {
        if (!Active)
        {
            element.Opacity = 1;
            if (element.RenderTransform is TranslateTransform t) t.Y = 0;
            return;
        }

        element.Opacity = 0;

        // A fresh transform per call: sharing one across elements makes them animate in lockstep.
        var translate = element.RenderTransform as TranslateTransform;
        if (translate is null || element.RenderTransform is not TranslateTransform)
        {
            translate = new TranslateTransform();
            element.RenderTransform = translate;
        }
        translate.Y = riseFrom;

        element.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation
        {
            From = 0,
            To = 1,
            Duration = Normal,
            EasingFunction = Standard,
            BeginTime = delay,
        });

        translate.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation
        {
            From = riseFrom,
            To = 0,
            Duration = Normal,
            EasingFunction = Standard,
            BeginTime = delay,
        });
    }

    /// <summary>
    /// Diagnostic breadcrumb. Goes to the per-user log, not the guardian's state directory —
    /// see <see cref="Core.HeroPaths.UserLogDir"/>.
    /// </summary>
    internal static void Trace(string message)
        => Core.HeroPaths.WriteUserLog("motion.log",
            $"{DateTime.Now:HH:mm:ss.fff} {message}{Environment.NewLine}");

    /// <summary>
    /// Fades in a sequence with a small stagger. The stagger is capped so a long list does not
    /// take a second and a half to finish appearing.
    /// </summary>
    internal static void StaggerIn(IEnumerable<UIElement> elements, double riseFrom = 8)
    {
        int i = 0;
        var list = elements.ToList();
        Trace($"StaggerIn: {list.Count} elements, Active={Active} (UserEnabled={UserEnabled}, SystemAllows={SystemAllows})");
        foreach (var e in list)
        {
            var delay = i < MaxStaggeredItems ? StaggerStep * i : StaggerStep * MaxStaggeredItems;
            FadeIn(e, riseFrom, delay);
            i++;
        }
    }

    /// <summary>Cross-fades content when switching screens.</summary>
    internal static void TransitionIn(UIElement incoming)
    {
        if (!Active) { incoming.Opacity = 1; return; }
        incoming.Opacity = 0;
        incoming.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation
        {
            From = 0,
            To = 1,
            Duration = Normal,
            EasingFunction = Standard,
        });
    }

    /// <summary>
    /// Animates a brush's colour. Used for severity changes, where a hard colour swap reads as a
    /// glitch but a 220ms blend reads as the value moving.
    /// </summary>
    internal static void AnimateBrushColour(SolidColorBrush brush, Color to, Duration? duration = null)
    {
        if (!Active)
        {
            brush.BeginAnimation(SolidColorBrush.ColorProperty, null);
            brush.Color = to;
            return;
        }

        // A frozen brush cannot be animated; callers should hand over a mutable clone.
        if (brush.IsFrozen) return;

        brush.BeginAnimation(SolidColorBrush.ColorProperty, new ColorAnimation
        {
            To = to,
            Duration = duration ?? Normal,
            EasingFunction = Standard,
            FillBehavior = FillBehavior.HoldEnd,
        });
    }

    /// <summary>
    /// A slow, low-amplitude pulse for a live indicator — the "still watching" dot. Runs forever,
    /// so it is only ever started when motion is active, and callers must stop it on unload or the
    /// composition thread keeps working for a hidden element.
    /// </summary>
    internal static void StartPulse(UIElement element, double from = 0.45, double to = 1.0)
    {
        if (!Active) { element.Opacity = to; return; }

        element.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation
        {
            From = from,
            To = to,
            Duration = new Duration(TimeSpan.FromMilliseconds(1400)),
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
        });
    }

    internal static void StopPulse(UIElement element)
    {
        element.BeginAnimation(UIElement.OpacityProperty, null);
        element.Opacity = 1;
    }
}
