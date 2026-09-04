using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Hero.Guardian;
using Hero.UI.Controls;

namespace Hero.UI;

/// <summary>The nine screens HERO routes between. Order here is the order in the rail.</summary>
internal enum NavDestination
{
    Overview,
    Threats,
    Processes,
    Network,
    Persistence,
    Maintenance,
    DiskAnalyzer,
    Duplicates,
    Quarantine,
    Timeline,
    Settings,
}

/// <summary>
/// One rail entry. Badge state is mutable and raises <see cref="Changed"/>, so a live count can be
/// updated from the engine without rebuilding the list or touching the selection.
/// </summary>
internal sealed class NavItem
{
    private string? _badgeText;
    private Severity _badgeSeverity = Severity.Low;
    private bool _isEnabled = true;

    internal NavItem(NavDestination destination, string label, string glyph)
    {
        Destination = destination;
        Label = label;
        Glyph = glyph;
    }

    internal NavDestination Destination { get; }

    internal string Label { get; }

    /// <summary>Segoe Fluent Icons code point. Every default was rendered and eyeballed.</summary>
    internal string Glyph { get; }

    /// <summary>Uppercase group heading drawn above this item, or null for none.</summary>
    internal string? Section { get; init; }

    /// <summary>Draws a hairline above this item. Used to float Settings off the group above it.</summary>
    internal bool DividerAbove { get; init; }

    /// <summary>Optional explanation, e.g. why a destination is unavailable unelevated.</summary>
    internal string? Description { get; set; }

    /// <summary>
    /// Badge text. Keep the denominator in the tooltip, not the badge: a bare alarming count with
    /// nothing to divide it by is the thing this product is trying not to be.
    /// </summary>
    internal string? BadgeText
    {
        get => _badgeText;
        set { if (_badgeText != value) { _badgeText = value; Changed?.Invoke(); } }
    }

    /// <summary>
    /// Colours the badge. Only the HIGHEST open severity should colour it, and Quarantine's badge
    /// must stay neutral — items in the vault are a sign the system worked, not an emergency.
    /// </summary>
    internal Severity BadgeSeverity
    {
        get => _badgeSeverity;
        set { if (_badgeSeverity != value) { _badgeSeverity = value; Changed?.Invoke(); } }
    }

    internal bool IsEnabled
    {
        get => _isEnabled;
        set { if (_isEnabled != value) { _isEnabled = value; Changed?.Invoke(); } }
    }

    internal event Action? Changed;
}

/// <summary>
/// The left navigation rail: icon plus label, a sliding selection indicator, group headings, live
/// badges, and an explicit collapse toggle.
///
/// Two behaviours are deliberate and should not be "improved":
///
/// * Expansion is an explicit toggle, never hover-to-expand. Hover expansion demos beautifully and
///   is infuriating daily, because the whole content area reflows when the pointer merely crosses
///   the rail on its way somewhere else.
/// * The rail's width changes in ONE step. Width is a layout property; animating it re-runs
///   measure and arrange for the entire window on every frame, which drops frames the moment a
///   virtualised table is on screen. Only the label opacity and the selection indicator animate.
/// </summary>
internal sealed class NavigationRail : UserControl
{
    internal const double ExpandedWidth = 248d;
    internal const double CollapsedWidth = 72d;

    internal const double ItemHeight = 44d;
    internal const double SectionHeight = 30d;
    internal const double DividerHeight = 17d;
    internal const double ItemMargin = 10d;
    internal const double IconColumn = 26d;
    internal const double IconGap = 10d;

    private readonly RailList _list;
    private readonly RailToggle _toggle;
    private readonly ContentPresenter _headerHost;
    private readonly ContentPresenter _footerHost;
    private readonly Border _footerDivider;
    private bool _syncing;

    internal NavigationRail()
    {
        Items = new ObservableCollection<NavItem>(DefaultItems());

        Focusable = false;
        IsTabStop = false;
        SnapsToDevicePixels = true;
        UseLayoutRounding = true;
        Width = ExpandedWidth;

        // Opaque so the labels keep ClearType. Set Background="Transparent" from the host if you
        // want the Mica backdrop through the gutter and accept grayscale-antialiased labels.
        SetResourceReference(BackgroundProperty, "Surface1");

        _list = new RailList(this) { ItemsSource = Items };
        _list.SelectionChanged += OnListSelectionChanged;

        _toggle = new RailToggle(this);
        _toggle.Click += (_, _) => ToggleCollapse();

        _headerHost = new ContentPresenter();
        _footerHost = new ContentPresenter { Margin = new Thickness(ItemMargin, 4, ItemMargin, 0) };

        _footerDivider = new Border
        {
            Height = 1,
            Margin = new Thickness(ItemMargin + 4, 8, ItemMargin + 4, 8),
        };
        _footerDivider.SetResourceReference(Border.BackgroundProperty, "Divider");

        var footer = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
        footer.Children.Add(_footerDivider);
        footer.Children.Add(_toggle);
        footer.Children.Add(_footerHost);

        var dock = new DockPanel { LastChildFill = true };
        DockPanel.SetDock(_headerHost, Dock.Top);
        DockPanel.SetDock(footer, Dock.Bottom);
        dock.Children.Add(_headerHost);
        dock.Children.Add(footer);
        dock.Children.Add(_list);

        Content = dock;

        _list.SelectedIndex = 0;
    }

    /// <summary>Rail entries, in display order. Mutable if a build wants a different set.</summary>
    internal ObservableCollection<NavItem> Items { get; }

    /// <summary>
    /// Content shown above the first section — the product wordmark.
    ///
    /// Without it the rail opened straight onto the "GUARDIAN" section heading, so the app looked
    /// as though it were called Guardian. A navigation rail that never says the product's name is
    /// a rail with a missing header, not a minimal one.
    /// </summary>
    internal object? Header
    {
        get => _headerHost.Content;
        set => _headerHost.Content = value;
    }

    /// <summary>Content shown below the collapse toggle.</summary>
    internal object? Footer
    {
        get => _footerHost.Content;
        set => _footerHost.Content = value;
    }

    // ---------------------------------------------------------------- dependency properties

    internal static readonly DependencyProperty SelectedDestinationProperty = DependencyProperty.Register(
        nameof(SelectedDestination), typeof(NavDestination), typeof(NavigationRail),
        new FrameworkPropertyMetadata(NavDestination.Overview,
            FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnSelectedDestinationChanged));

    internal NavDestination SelectedDestination
    {
        get => (NavDestination)GetValue(SelectedDestinationProperty);
        set => SetValue(SelectedDestinationProperty, value);
    }

    internal static readonly DependencyProperty IsCollapsedProperty = DependencyProperty.Register(
        nameof(IsCollapsed), typeof(bool), typeof(NavigationRail),
        new PropertyMetadata(false, OnIsCollapsedChanged));

    internal bool IsCollapsed
    {
        get => (bool)GetValue(IsCollapsedProperty);
        set => SetValue(IsCollapsedProperty, value);
    }

    /// <summary>Brand block above the destinations.</summary>
    internal static readonly DependencyProperty HeaderContentProperty = DependencyProperty.Register(
        nameof(HeaderContent), typeof(object), typeof(NavigationRail),
        new PropertyMetadata(null, (d, e) => ((NavigationRail)d)._headerHost.Content = e.NewValue));

    internal object? HeaderContent
    {
        get => GetValue(HeaderContentProperty);
        set => SetValue(HeaderContentProperty, value);
    }

    /// <summary>
    /// Bottom-docked slot. The master protection switch belongs here — and per the safety review
    /// it needs a confirm, a timed-pause option and a persistent banner while it is off, none of
    /// which is the rail's business.
    /// </summary>
    internal static readonly DependencyProperty FooterContentProperty = DependencyProperty.Register(
        nameof(FooterContent), typeof(object), typeof(NavigationRail),
        new PropertyMetadata(null, (d, e) => ((NavigationRail)d)._footerHost.Content = e.NewValue));

    internal object? FooterContent
    {
        get => GetValue(FooterContentProperty);
        set => SetValue(FooterContentProperty, value);
    }

    /// <summary>Raised after the selection actually changes. Screens hang off this.</summary>
    internal event EventHandler<NavDestination>? DestinationChanged;

    // ------------------------------------------------------------------------------ commands

    internal void ToggleCollapse() => IsCollapsed = !IsCollapsed;

    internal NavItem? Find(NavDestination destination)
    {
        foreach (var item in Items)
            if (item.Destination == destination) return item;
        return null;
    }

    /// <summary>Sets a live badge. Pass null to clear it.</summary>
    internal void SetBadge(NavDestination destination, string? text, Severity severity = Severity.Low)
    {
        var item = Find(destination);
        if (item is null) return;
        item.BadgeSeverity = severity;
        item.BadgeText = text;
    }

    private static IEnumerable<NavItem> DefaultItems()
    {
        // Every code point below was rendered from the installed SegoeIcons.ttf and checked by eye
        // before being used. That matters: the obvious "shield" code point (E9D9) is actually a
        // heartbeat, E7C4 is TaskView rather than an anchor, and E7B8 is a waste bin — putting a
        // bin on Quarantine would contradict the copy promising nothing is ever deleted.
        yield return new NavItem(NavDestination.Overview, "Overview", "\uEA18") { Section = "GUARDIAN" };   // shield
        yield return new NavItem(NavDestination.Threats, "Threats", "\uE7BA");                             // warning
        yield return new NavItem(NavDestination.Processes, "Processes", "\uE950");                         // chip
        yield return new NavItem(NavDestination.Network, "Network", "\uE774");                             // globe
        yield return new NavItem(NavDestination.Persistence, "Persistence", "\uE945");                     // bolt
        yield return new NavItem(NavDestination.Maintenance, "Maintenance", "\uE90F") { Section = "MAINTENANCE" }; // spanner
        yield return new NavItem(NavDestination.DiskAnalyzer, "Disk usage", "\uE9D9");                            // pie chart
        yield return new NavItem(NavDestination.Duplicates, "Duplicates", "\uE8C8");                              // copy
        yield return new NavItem(NavDestination.Quarantine, "Quarantine", "\uE72E") { Section = "RECORDS" };// padlock
        yield return new NavItem(NavDestination.Timeline, "Timeline", "\uE81C");                           // history
        yield return new NavItem(NavDestination.Settings, "Settings", "\uE713") { DividerAbove = true };    // gear
    }

    // ----------------------------------------------------------------------------- plumbing

    private static void OnSelectedDestinationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var rail = (NavigationRail)d;
        if (rail._syncing) return;

        var target = rail.Find((NavDestination)e.NewValue);
        if (target is null) return;

        rail._syncing = true;
        rail._list.SelectedItem = target;
        rail._syncing = false;
        rail.DestinationChanged?.Invoke(rail, (NavDestination)e.NewValue);
    }

    private void OnListSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_list.SelectedItem is not NavItem item)
        {
            // Never leave the rail with nothing selected; the content area would have nothing to show.
            if (Items.Count > 0) _list.SelectedIndex = 0;
            return;
        }

        if (_syncing) return;
        _syncing = true;
        SelectedDestination = item.Destination;
        _syncing = false;
        DestinationChanged?.Invoke(this, item.Destination);
    }

    private static void OnIsCollapsedChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var rail = (NavigationRail)d;
        bool collapsed = (bool)e.NewValue;

        rail.Width = collapsed ? CollapsedWidth : ExpandedWidth;
        rail._footerDivider.Margin = collapsed
            ? new Thickness(14, 8, 14, 8)
            : new Thickness(ItemMargin + 4, 8, ItemMargin + 4, 8);
        rail._headerHost.Visibility = collapsed ? Visibility.Collapsed : Visibility.Visible;
        rail._footerHost.Visibility = collapsed ? Visibility.Collapsed : Visibility.Visible;
        rail._toggle.SyncLabels();
        rail._toggle.InvalidateVisual();

        // The rail does not virtualise (nine fixed items), so every container exists and can be
        // told to fade its label rather than having the fade driven from a template trigger.
        for (int i = 0; i < rail.Items.Count; i++)
        {
            if (rail._list.ItemContainerGenerator.ContainerFromIndex(i) is NavItemContainer container)
                container.SetCollapsed(collapsed);
        }
    }

    // ------------------------------------------------------------------------ nested visuals

    private sealed class RailList : ListBox
    {
        private readonly NavigationRail _rail;

        internal RailList(NavigationRail rail)
        {
            _rail = rail;
            Background = Brushes.Transparent;
            BorderThickness = new Thickness(0);
            Padding = new Thickness(0, 8, 0, 8);
            HorizontalContentAlignment = HorizontalAlignment.Stretch;

            // Nine items, all cheap, and the collapse animation needs every container to exist.
            VirtualizingPanel.SetIsVirtualizing(this, false);
            ScrollViewer.SetHorizontalScrollBarVisibility(this, ScrollBarVisibility.Disabled);
        }

        protected override bool IsItemItsOwnContainerOverride(object item) => item is NavItemContainer;

        protected override DependencyObject GetContainerForItemOverride() => new NavItemContainer(_rail);
    }

    /// <summary>Explicit expand/collapse control. Drawn, so it carries no stock button chrome.</summary>
    private sealed class RailToggle : FrameworkElement
    {
        private readonly NavigationRail _rail;
        private Typeface? _icon;

        internal RailToggle(NavigationRail rail)
        {
            _rail = rail;
            Height = 34;
            Focusable = true;
            Margin = new Thickness(ItemMargin, 0, ItemMargin, 0);
            SyncLabels();
        }

        internal event EventHandler? Click;

        /// <summary>
        /// Keeps the accessible name and the tooltip in step with the state. Both used to say
        /// "Collapse" in either direction, so once collapsed the control announced the opposite of
        /// what it did — and collapsed is precisely the state in which nothing else on the rail
        /// carries a visible label.
        /// </summary>
        internal void SyncLabels()
        {
            string verb = _rail.IsCollapsed ? "Expand" : "Collapse";
            System.Windows.Automation.AutomationProperties.SetName(this, verb + " navigation");
            ToolTip = $"{verb} (Ctrl+B)";
        }

        protected override void OnMouseEnter(MouseEventArgs e) { base.OnMouseEnter(e); InvalidateVisual(); }

        protected override void OnMouseLeave(MouseEventArgs e) { base.OnMouseLeave(e); InvalidateVisual(); }

        protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
        {
            base.OnMouseLeftButtonUp(e);
            Click?.Invoke(this, EventArgs.Empty);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (e.Key is Key.Space or Key.Enter)
            {
                Click?.Invoke(this, EventArgs.Empty);
                e.Handled = true;
            }
        }

        protected override void OnGotKeyboardFocus(KeyboardFocusChangedEventArgs e)
        {
            base.OnGotKeyboardFocus(e);
            InvalidateVisual();
        }

        protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
        {
            base.OnLostKeyboardFocus(e);
            InvalidateVisual();
        }

        protected override void OnRender(DrawingContext dc)
        {
            double w = RenderSize.Width, h = RenderSize.Height;
            if (w <= 0 || h <= 0) return;

            var rect = new Rect(0, 0, w, h);
            dc.DrawRectangle(Brushes.Transparent, null, rect);

            if (IsMouseOver)
            {
                var hover = SeverityPalette.ResolveBrush(this, "SurfaceHover", Color.FromRgb(0x1F, 0x25, 0x2D));
                dc.DrawRoundedRectangle(hover, null, rect, 10, 10);
            }

            if (IsKeyboardFocused)
            {
                var focus = new Pen(SeverityPalette.ResolveBrush(this, "BorderFocus", Color.FromRgb(0x7F, 0xB1, 0xFF)), 2);
                dc.DrawRoundedRectangle(null, focus, new Rect(1, 1, Math.Max(0, w - 2), Math.Max(0, h - 2)), 10, 10);
            }

            _icon ??= new Typeface(new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"),
                                   FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

            var ink = SeverityPalette.ResolveBrush(this, IsMouseOver ? "TextPrimary" : "TextTertiary",
                                                   Color.FromRgb(0x78, 0x84, 0x9A));
            double ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip;

            // E76B chevron-left collapses, E76C chevron-right expands. Both verified in the font.
            var glyph = GlyphText.Make(_rail.IsCollapsed ? "\uE76C" : "\uE76B", _icon, 13, ink, ppd);
            double gx = _rail.IsCollapsed ? (w - glyph.Width) / 2 : 14;
            dc.DrawText(glyph, new Point(gx, (h - glyph.Height) / 2));

            if (!_rail.IsCollapsed)
            {
                var face = new Typeface(
                    TryFindResource("UIFont") as FontFamily ?? new FontFamily("Segoe UI Variable Text, Segoe UI"),
                    FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
                double size = SeverityPalette.ResolveDouble(this, "FsCaption", 12.5);
                var label = GlyphText.Make("Collapse", face, size, ink, ppd);
                dc.DrawText(label, new Point(14 + glyph.Width + 10, (h - label.Height) / 2));
            }
        }
    }
}

/// <summary>
/// A rail entry container. Like the table row it paints itself with the stock ListBoxItem chrome
/// removed entirely, because the default template's selection trigger sets the system highlight on
/// a template child where a local Background cannot reach it.
/// </summary>
internal sealed class NavItemContainer : ListBoxItem
{
    private readonly NavigationRail _rail;
    private NavItem? _item;
    private Typeface? _icon;
    private Typeface? _label;
    private Typeface? _labelSemi;

    internal NavItemContainer(NavigationRail rail)
    {
        _rail = rail;
        OverridesDefaultStyle = true;
        Template = null;
        FocusVisualStyle = null;
        SnapsToDevicePixels = true;
        UseLayoutRounding = true;
        HorizontalAlignment = HorizontalAlignment.Stretch;
    }

    /// <summary>Selection indicator growth, 0-1. A ScaleY stand-in for the forbidden Height animation.</summary>
    internal static readonly DependencyProperty IndicatorScaleProperty = DependencyProperty.Register(
        nameof(IndicatorScale), typeof(double), typeof(NavItemContainer),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

    internal double IndicatorScale
    {
        get => (double)GetValue(IndicatorScaleProperty);
        set => SetValue(IndicatorScaleProperty, value);
    }

    internal static readonly DependencyProperty LabelOpacityProperty = DependencyProperty.Register(
        nameof(LabelOpacity), typeof(double), typeof(NavItemContainer),
        new FrameworkPropertyMetadata(1d, FrameworkPropertyMetadataOptions.AffectsRender));

    internal double LabelOpacity
    {
        get => (double)GetValue(LabelOpacityProperty);
        set => SetValue(LabelOpacityProperty, value);
    }

    protected override Size MeasureOverride(Size constraint)
    {
        double w = double.IsInfinity(constraint.Width) ? _rail.Width : constraint.Width;
        double h = NavigationRail.ItemHeight;
        if (_item?.Section is not null && !_rail.IsCollapsed) h += NavigationRail.SectionHeight;
        if (_item?.DividerAbove == true) h += NavigationRail.DividerHeight;
        return new Size(Math.Max(0, w), h);
    }

    protected override void OnContentChanged(object oldContent, object newContent)
    {
        base.OnContentChanged(oldContent, newContent);

        if (oldContent is NavItem previous) previous.Changed -= OnItemChanged;
        _item = newContent as NavItem;
        if (_item is not null)
        {
            _item.Changed += OnItemChanged;
            System.Windows.Automation.AutomationProperties.SetName(this, _item.Label);
            IsEnabled = _item.IsEnabled;
            UpdateToolTip();
        }

        LabelOpacity = _rail.IsCollapsed ? 0d : 1d;
        InvalidateMeasure();
        InvalidateVisual();
    }

    private void OnItemChanged()
    {
        if (_item is not null) IsEnabled = _item.IsEnabled;
        UpdateToolTip();
        InvalidateVisual();
    }

    private void UpdateToolTip()
    {
        if (_item is null) { ToolTip = null; return; }

        // Collapsed, the label is the only thing gone, so it becomes the tooltip. Icon-only
        // controls with no accessible name are the classic retemplating regression.
        string? detail = _item.Description;
        ToolTip = _rail.IsCollapsed
            ? string.IsNullOrEmpty(detail) ? _item.Label : $"{_item.Label} — {detail}"
            : detail;
    }

    internal void SetCollapsed(bool collapsed)
    {
        UpdateToolTip();
        InvalidateMeasure();

        double target = collapsed ? 0d : 1d;
        if (!Motion.Active)
        {
            BeginAnimation(LabelOpacityProperty, null);
            LabelOpacity = target;
            return;
        }

        BeginAnimation(LabelOpacityProperty, new DoubleAnimation(target, new Duration(TimeSpan.FromMilliseconds(140)))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
            FillBehavior = FillBehavior.HoldEnd,
        });
    }

    protected override void OnSelected(RoutedEventArgs e)
    {
        base.OnSelected(e);
        AnimateIndicator(1d);
        InvalidateVisual();
    }

    protected override void OnUnselected(RoutedEventArgs e)
    {
        base.OnUnselected(e);
        AnimateIndicator(0d);
        InvalidateVisual();
    }

    private void AnimateIndicator(double target)
    {
        if (!Motion.Active)
        {
            BeginAnimation(IndicatorScaleProperty, null);
            IndicatorScale = target;
            return;
        }

        BeginAnimation(IndicatorScaleProperty, new DoubleAnimation(target, new Duration(TimeSpan.FromMilliseconds(200)))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
            FillBehavior = FillBehavior.HoldEnd,
        });
    }

    protected override void OnMouseEnter(MouseEventArgs e) { base.OnMouseEnter(e); InvalidateVisual(); }

    protected override void OnMouseLeave(MouseEventArgs e) { base.OnMouseLeave(e); InvalidateVisual(); }

    protected override void OnGotKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnGotKeyboardFocus(e);
        InvalidateVisual();
    }

    protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnLostKeyboardFocus(e);
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        if (_item is null) return;

        double w = RenderSize.Width, h = RenderSize.Height;
        if (w <= 0 || h <= 0) return;

        double ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        bool collapsed = _rail.IsCollapsed;
        double margin = collapsed ? 8 : NavigationRail.ItemMargin;

        _icon ??= new Typeface(new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"),
                               FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        var uiFamily = TryFindResource("UIFont") as FontFamily ?? new FontFamily("Segoe UI Variable Text, Segoe UI");
        _label ??= new Typeface(uiFamily, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        _labelSemi ??= new Typeface(uiFamily, FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);

        var tertiary = SeverityPalette.ResolveBrush(this, "TextTertiary", Color.FromRgb(0x78, 0x84, 0x9A));
        double y = 0;

        if (_item.Section is not null && !collapsed)
        {
            double size = SeverityPalette.ResolveDouble(this, "FsMicro", 11.5);
            double tracking = size * 0.055;
            double th = GlyphText.Height(_item.Section, _labelSemi, size, ppd);
            GlyphText.DrawTracked(dc, _item.Section, _labelSemi, size, tertiary, ppd, tracking,
                new Point(margin + 14, y + NavigationRail.SectionHeight - th - 6));
            y += NavigationRail.SectionHeight;
        }

        if (_item.DividerAbove)
        {
            var divider = SeverityPalette.ResolveBrush(this, "Divider", Color.FromRgb(0x23, 0x2B, 0x36));
            dc.DrawRectangle(divider, null,
                new Rect(margin + 6, y + NavigationRail.DividerHeight / 2, Math.Max(0, w - (margin + 6) * 2), 1));
            y += NavigationRail.DividerHeight;
        }

        var row = new Rect(margin, y, Math.Max(0, w - margin * 2), NavigationRail.ItemHeight);

        // Only the item row is hit-testable; the section heading above it is decoration and must
        // not look clickable.
        dc.DrawRectangle(Brushes.Transparent, null, row);

        if (IsSelected)
        {
            var fill = SeverityPalette.ResolveBrush(this, "SurfaceSelected", Color.FromRgb(0x16, 0x26, 0x3D));
            dc.DrawRoundedRectangle(fill, null, row, 10, 10);
        }
        else if (IsMouseOver && IsEnabled)
        {
            var fill = SeverityPalette.ResolveBrush(this, "SurfaceHover", Color.FromRgb(0x1F, 0x25, 0x2D));
            dc.DrawRoundedRectangle(fill, null, row, 10, 10);
        }

        if (IsKeyboardFocused)
        {
            var focus = new Pen(SeverityPalette.ResolveBrush(this, "BorderFocus", Color.FromRgb(0x7F, 0xB1, 0xFF)), 2);
            dc.DrawRoundedRectangle(null, focus,
                new Rect(row.X + 1, row.Y + 1, Math.Max(0, row.Width - 2), Math.Max(0, row.Height - 2)), 10, 10);
        }

        var accent = SeverityPalette.ResolveBrush(this, "Accent", Color.FromRgb(0x4C, 0x8D, 0xFF));

        double scale = Math.Clamp(IndicatorScale, 0d, 1d);
        if (scale > 0.01)
        {
            const double indicatorHeight = 22d;
            double ih = indicatorHeight * scale;
            double iy = y + (NavigationRail.ItemHeight - ih) / 2;
            dc.DrawRoundedRectangle(accent, null, new Rect(0, iy, 3, ih), 1.5, 1.5);
        }

        var ink = !IsEnabled
            ? SeverityPalette.ResolveBrush(this, "TextTertiary", Color.FromRgb(0x78, 0x84, 0x9A))
            : IsSelected
                ? accent
                : IsMouseOver
                    ? SeverityPalette.ResolveBrush(this, "TextPrimary", Color.FromRgb(0xED, 0xF1, 0xF7))
                    : SeverityPalette.ResolveBrush(this, "TextSecondary", Color.FromRgb(0xA6, 0xB2, 0xC2));

        double iconX = collapsed ? row.X + (row.Width - NavigationRail.IconColumn) / 2 : row.X + 14;
        var glyph = GlyphText.Make(_item.Glyph, _icon, 19, ink, ppd);
        double glyphY = y + (NavigationRail.ItemHeight - glyph.Height) / 2;
        dc.DrawText(glyph, new Point(iconX + (NavigationRail.IconColumn - glyph.Width) / 2, glyphY));

        double badgeRight = row.X + row.Width - 12;

        if (!collapsed && LabelOpacity > 0.01)
        {
            double size = SeverityPalette.ResolveDouble(this, "FsBody", 14.5);
            var face = IsSelected ? _labelSemi : _label;
            var labelInk = !IsEnabled
                ? tertiary
                : IsSelected || IsMouseOver
                    ? SeverityPalette.ResolveBrush(this, "TextPrimary", Color.FromRgb(0xED, 0xF1, 0xF7))
                    : SeverityPalette.ResolveBrush(this, "TextSecondary", Color.FromRgb(0xA6, 0xB2, 0xC2));

            double labelX = iconX + NavigationRail.IconColumn + NavigationRail.IconGap;
            double available = Math.Max(0, badgeRight - labelX - (_item.BadgeText is null ? 0 : 46));
            string text = GlyphText.Fit(GlyphText.Sanitise(_item.Label), face, size, ppd, available, middle: false);
            var label = GlyphText.Make(text, face, size, labelInk, ppd);

            dc.PushOpacity(Math.Clamp(LabelOpacity, 0d, 1d));
            dc.DrawText(label, new Point(labelX, y + (NavigationRail.ItemHeight - label.Height) / 2));
            dc.Pop();
        }

        DrawBadge(dc, ppd, collapsed, iconX, y, badgeRight);
    }

    private void DrawBadge(DrawingContext dc, double ppd, bool collapsed, double iconX, double y, double badgeRight)
    {
        if (_item?.BadgeText is not { Length: > 0 } badgeText) return;

        var basis = SeverityPalette.Base(this, _item.BadgeSeverity);

        if (collapsed)
        {
            // Collapsed there is no room for a count, so the badge degrades to a dot at the icon's
            // top-right. The count still reaches the user through the tooltip.
            dc.DrawEllipse(SeverityPalette.Brush(basis), null,
                new Point(iconX + NavigationRail.IconColumn - 2, y + NavigationRail.ItemHeight / 2 - 9), 4, 4);
            return;
        }

        var ground = SeverityPalette.Resolve(this, "Surface1", Color.FromRgb(0x15, 0x1A, 0x21));
        var fill = SeverityPalette.Brush(SeverityPalette.PillBackground(basis, ground));
        var ink = SeverityPalette.Brush(SeverityPalette.PillForeground(basis));

        double size = SeverityPalette.ResolveDouble(this, "FsMicro", 11.5);
        double bh = Math.Round(size * 1.6);
        string text = GlyphText.Sanitise(badgeText);
        var ft = GlyphText.Make(text, _labelSemi!, size, ink, ppd);
        double bw = Math.Max(bh, ft.Width + bh * 0.7);
        double bx = badgeRight - bw;
        double by = y + (NavigationRail.ItemHeight - bh) / 2;

        dc.DrawRoundedRectangle(fill, null, new Rect(bx, by, bw, bh), bh / 2, bh / 2);
        dc.DrawText(ft, new Point(bx + (bw - ft.Width) / 2, by + (bh - ft.Height) / 2));
    }
}
