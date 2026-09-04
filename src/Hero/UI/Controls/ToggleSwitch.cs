using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace Hero.UI.Controls;

/// <summary>
/// A Windows 11-style toggle switch, hand-built because WPF ships no such control and a
/// restyled CheckBox never quite loses its checkbox-ness.
///
/// The thumb slide and the track colour cross-fade both go through <see cref="Motion"/>, so the
/// "animations" setting governs this control too — including, satisfyingly, the toggle that
/// turns animations off. Switching it off animates one last time and then stops.
/// </summary>
internal sealed class ToggleSwitch : ButtonBase_Toggle
{
    private const double TrackWidth = 44;
    private const double TrackHeight = 24;
    private const double ThumbSize = 18;
    private const double ThumbInset = 3;

    private readonly Border _track;
    private readonly Border _thumb;
    private readonly TranslateTransform _thumbOffset = new();
    private readonly SolidColorBrush _trackBrush;

    private Color OnColour => (Color)FindResourceOr("SevSafeColor", Color.FromRgb(0x3F, 0xB9, 0x84));
    private Color OffColour => Color.FromRgb(0x36, 0x40, 0x4D);

    internal ToggleSwitch()
    {
        _trackBrush = new SolidColorBrush(OffColour);

        _thumb = new Border
        {
            Width = ThumbSize,
            Height = ThumbSize,
            CornerRadius = new CornerRadius(ThumbSize / 2),
            Background = new SolidColorBrush(Color.FromRgb(0xED, 0xF1, 0xF7)),
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(ThumbInset, 0, 0, 0),
            RenderTransform = _thumbOffset,
        };

        _track = new Border
        {
            Width = TrackWidth,
            Height = TrackHeight,
            CornerRadius = new CornerRadius(TrackHeight / 2),
            Background = _trackBrush,
            Child = _thumb,
            SnapsToDevicePixels = true,
        };

        Content = _track;
        Cursor = Cursors.Hand;
        Focusable = true;
        HorizontalAlignment = HorizontalAlignment.Left;
        VerticalAlignment = VerticalAlignment.Center;

        // Apply the visual state without animating on first layout, otherwise every switch on the
        // page slides in from "off" when the settings screen opens, which reads as a glitch.
        Loaded += (_, _) => ApplyState(animate: false);
        Toggled += () => ApplyState(animate: true);
    }

    private void ApplyState(bool animate)
    {
        double target = IsOn ? TrackWidth - ThumbSize - (ThumbInset * 2) : 0;
        var colour = IsOn ? OnColour : OffColour;

        if (animate && Motion.Active)
        {
            _thumbOffset.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation
            {
                To = target,
                Duration = Motion.Fast,
                // A slight overshoot makes the thumb feel physical rather than driven.
                EasingFunction = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.35 },
                FillBehavior = FillBehavior.HoldEnd,
            });
            Motion.AnimateBrushColour(_trackBrush, colour, Motion.Fast);
        }
        else
        {
            _thumbOffset.BeginAnimation(TranslateTransform.XProperty, null);
            _thumbOffset.X = target;
            _trackBrush.BeginAnimation(SolidColorBrush.ColorProperty, null);
            _trackBrush.Color = colour;
        }
    }

    private object FindResourceOr(string key, object fallback)
    {
        try { return TryFindResource(key) ?? fallback; }
        catch { return fallback; }
    }
}

/// <summary>
/// Minimal toggle base. Deriving from the framework's ToggleButton would drag in its default
/// template and focus visuals, which then have to be fought back off; this is smaller than the
/// restyling would have been.
/// </summary>
internal abstract class ButtonBase_Toggle : ContentControl
{
    internal static readonly DependencyProperty IsOnProperty =
        DependencyProperty.Register(nameof(IsOn), typeof(bool), typeof(ButtonBase_Toggle),
            new PropertyMetadata(false, OnIsOnChanged));

    internal bool IsOn
    {
        get => (bool)GetValue(IsOnProperty);
        set => SetValue(IsOnProperty, value);
    }

    /// <summary>Raised after <see cref="IsOn"/> changes, from any cause.</summary>
    internal event Action? Toggled;

    /// <summary>Raised only when the change came from the user, so loading settings does not
    /// re-save them or fire side effects.</summary>
    internal event Action<bool>? UserToggled;

    private static void OnIsOnChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((ButtonBase_Toggle)d).Toggled?.Invoke();

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        Flip();
        e.Handled = true;
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key is Key.Space or Key.Enter) { Flip(); e.Handled = true; }
        else base.OnKeyDown(e);
    }

    private void Flip()
    {
        IsOn = !IsOn;
        Focus();
        UserToggled?.Invoke(IsOn);
    }
}
