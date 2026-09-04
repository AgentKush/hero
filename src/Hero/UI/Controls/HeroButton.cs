using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Hero.UI.Controls;

/// <summary>
/// The one button factory for the whole app.
///
/// It exists because there were two copies of this code — one on the Threats screen and one in
/// the vault — and only one of them got the margin fix. The orange border on the other kept
/// getting shaved off, which is exactly the failure duplication produces: a fix that is applied
/// to the copy someone happened to be looking at.
///
/// The margin is not cosmetic. Cards clip to a rounded rectangle, the window applies a
/// non-integer <c>ScaleTransform</c> (1.28x at the default scale on a 4K display), and
/// <c>UseLayoutRounding</c> then resolves a 1px border to a boundary that the clip can cut. A 1px
/// outer margin keeps every edge of the border inside the clip at any scale factor.
/// </summary>
internal static class HeroButton
{
    /// <summary>Shared template. Built once: a ControlTemplate is freezable and reusable.</summary>
    private static readonly ControlTemplate FlatTemplate = BuildTemplate();

    internal static Button Create(string text, ButtonTone tone, double fontSize)
    {
        var button = new Button
        {
            Content = text,
            FontSize = fontSize,
            Padding = new Thickness(15, 9, 15, 9),
            // 1px on every side, plus the gap to the next button. Never zero on any edge.
            Margin = new Thickness(1, 1, 9, 9),
            MinHeight = 34,
            BorderThickness = new Thickness(1),
            Cursor = Cursors.Hand,
            SnapsToDevicePixels = true,
            UseLayoutRounding = false,
            Template = FlatTemplate,
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Center,
        };

        // Every HeroButton reported an EMPTY accessibility name. Content is a plain string, which
        // WPF would normally surface as the automation Name — but FlatTemplate replaces the control
        // template, and a ContentPresenter inside a custom template does not always carry the text
        // through to the automation peer. Measured: all three buttons on the Duplicates page came
        // back with name='' from a UI Automation enumeration.
        //
        // That is a screen reader announcing "button" and nothing else, on every action in the
        // product — including "Quarantine target file" and "End process tree". Setting it from the
        // same string the button displays is the whole fix.
        System.Windows.Automation.AutomationProperties.SetName(button, text);

        Apply(button, tone);
        return button;
    }

    private static void Apply(Button button, ButtonTone tone)
    {
        // Resources are resolved lazily: the button is not in the visual tree yet, so
        // TryFindResource would return null if called here.
        button.Loaded += (_, _) =>
        {
            Brush Find(string key) => button.TryFindResource(key) as Brush ?? Brushes.Gray;

            switch (tone)
            {
                case ButtonTone.Destructive:
                    button.Foreground = Find("SevHigh");
                    button.Background = Find("Surface1");
                    button.BorderBrush = Find("SevHigh");
                    break;
                case ButtonTone.Primary:
                    button.Foreground = Find("TextPrimary");
                    button.Background = Find("AccentMuted");
                    button.BorderBrush = Find("Accent");
                    break;
                default:
                    button.Foreground = Find("TextPrimary");
                    button.Background = Find("Surface3");
                    button.BorderBrush = Find("HairLine");
                    break;
            }
        };
    }

    private static ControlTemplate BuildTemplate()
    {
        var template = new ControlTemplate(typeof(Button));

        var border = new FrameworkElementFactory(typeof(Border));
        border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
        border.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Control.BorderBrushProperty));
        border.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Control.BorderThicknessProperty));
        border.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
        border.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
        border.SetValue(Border.SnapsToDevicePixelsProperty, true);
        border.Name = "Chrome";

        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        presenter.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        border.AppendChild(presenter);

        template.VisualTree = border;

        // Hover and press feedback. Without these the buttons look painted on.
        var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
        hover.Setters.Add(new Setter(UIElement.OpacityProperty, 0.82, "Chrome"));
        template.Triggers.Add(hover);

        var pressed = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true };
        pressed.Setters.Add(new Setter(UIElement.OpacityProperty, 0.65, "Chrome"));
        template.Triggers.Add(pressed);

        var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
        disabled.Setters.Add(new Setter(UIElement.OpacityProperty, 0.45, "Chrome"));
        template.Triggers.Add(disabled);

        template.Seal();
        return template;
    }
}

internal enum ButtonTone { Neutral, Primary, Destructive }

file static class ButtonBase
{
    internal static readonly DependencyProperty IsPressedProperty =
        System.Windows.Controls.Primitives.ButtonBase.IsPressedProperty;
}
