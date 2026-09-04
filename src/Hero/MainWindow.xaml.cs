using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Hero.Core;
using Hero.Guardian;
using Hero.UI;
using Hero.UI.Views;

namespace Hero;

/// <summary>
/// The shell: navigation rail, title bar, and a host for one page at a time.
///
/// The window owns no engine and no state of its own beyond presentation. It is a view onto
/// <see cref="GuardianService"/>, which runs whether or not any window exists.
/// </summary>
public partial class MainWindow : Window
{
    private readonly GuardianService _guardian = GuardianService.Current;
    private readonly NavigationRail _rail = new();
    private readonly Dictionary<NavDestination, PageBase> _pages = new();
    private PageBase? _current;

    /// <summary>
    /// Manual zoom on top of the automatic responsive scale. Ctrl +/- / Ctrl+0 adjust it and the
    /// value persists, because "the text is too small" is a per-display judgement that no
    /// automatic formula gets right for everyone.
    /// </summary>
    private double _userScale = 1.15;

    private const double ScaleBaselineWidth = 1400;
    private const double ResponsiveMin = 1.00;
    private const double ResponsiveMax = 1.40;

    /// <summary>Set while hidden so the next show repaints from the latest snapshot.</summary>
    private bool _pendingWhileHidden;

    public MainWindow()
    {
        InitializeComponent();
        WindowEffects.PrepareForBackdrop(this);
        SourceInitialized += (_, _) => WindowEffects.Apply(this);

        LoadPreferences();
        SizeChanged += (_, _) => ApplyScale();

        // Tables cap their height to a share of the visible area, so they need to know how big
        // that area is. Measured from the scroll viewer rather than the window, because the rail,
        // the title bar and the root scale transform all sit between the two.
        MainScroll.SizeChanged += (_, _) => PublishViewport();
        MainScroll.Loaded += (_, _) => PublishViewport();
        PreviewKeyDown += OnZoomKeys;

        RailHost.Child = _rail;
        _rail.Header = BuildWordmark();
        _rail.DestinationChanged += (_, destination) => Navigate(destination);

        // Alt+F4, the taskbar's Close, and the system menu all call Close() directly and bypass
        // the title-bar button. Left alone they DESTROY the window, after which the tray's "Open
        // HERO" threw "Cannot set Visibility or call Show after a Window has closed". Cancelling
        // the close and hiding keeps the one shell alive for the life of the process.
        Closing += (_, e) =>
        {
            if (App.IsShuttingDown) return;
            e.Cancel = true;
            Hide();
        };

        _guardian.Observed += OnGuardianObserved;
        _guardian.VerdictRaised += _ => Dispatcher.BeginInvoke(UpdateBadges);
        _guardian.Engine.Faulted += ex => Dispatcher.BeginInvoke(() =>
            CrumbText.Text = "Monitor error: " + ex.GetType().Name);

        IsVisibleChanged += (_, _) =>
        {
            if (IsVisible && _pendingWhileHidden)
            {
                _pendingWhileHidden = false;
                RefreshCurrent();
            }
        };

        Loaded += (_, _) =>
        {
            ApplyScale();
            if (Motion.Active) Motion.StartPulse(LiveDot, 0.35, 1.0);
            Navigate(NavDestination.Overview);
            MainScroll.ScrollToTop();
        };
    }

    /// <summary>
    /// The product wordmark at the top of the rail: the same shield-and-tick mark as the
    /// application icon, the name, and what the name stands for.
    /// </summary>
    private UIElement BuildWordmark()
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal };

        // The mark comes from the shared renderer, so the rail, the tray and the exe icon are
        // guaranteed to be the same drawing.
        var mark = new System.Windows.Controls.Image
        {
            Width = 24,
            Height = 24,
            Margin = new Thickness(0, 0, 11, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Source = MarkImage(64),
        };
        RenderOptions.SetBitmapScalingMode(mark, BitmapScalingMode.HighQuality);
        row.Children.Add(mark);

        row.Children.Add(new TextBlock
        {
            Text = "HERO",
            FontSize = (double)FindResource("FsTitle"),
            FontWeight = FontWeights.SemiBold,
            FontFamily = (FontFamily)FindResource("DisplayFont"),
            Foreground = (Brush)FindResource("TextPrimary"),
            VerticalAlignment = VerticalAlignment.Center,
        });

        var stack = new StackPanel { Margin = new Thickness(22, 20, 22, 24) };
        stack.Children.Add(row);
        stack.Children.Add(new TextBlock
        {
            Text = "Help Eliminate Rogue Oddities",
            FontSize = (double)FindResource("FsMicro"),
            Foreground = (Brush)FindResource("TextTertiary"),
            Margin = new Thickness(35, 4, 0, 0),
            TextWrapping = TextWrapping.Wrap,
        });
        return stack;
    }

    private static System.Windows.Media.Imaging.BitmapSource MarkImage(int size)
    {
        using var bmp = HeroMark.Render(size, HeroMark.Clear, flat: false);
        using var stream = new MemoryStream();
        bmp.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
        stream.Position = 0;

        var image = new System.Windows.Media.Imaging.BitmapImage();
        image.BeginInit();
        image.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return image;
    }

    /// <summary>
    /// Tells the pages how much vertical room they actually have.
    ///
    /// The viewport is reported in the scaled coordinate space the pages are laid out in, so no
    /// correction for the root ScaleTransform is needed here — dividing by the scale as well would
    /// shrink every table twice over.
    /// </summary>
    private void PublishViewport()
    {
        double height = MainScroll.ViewportHeight;
        if (height > 0) PageBase.SetViewportHeight(height);
        if (_current is not null) ApplyPageSizing(_current);
    }

    /// <summary>
    /// Decides whether the shell scrolls a page or sizes it to the window.
    ///
    /// A page that fills the viewport is given exactly the visible height and the outer scrollbar
    /// is turned off, so its own star-sized table row absorbs the remaining space. Leaving the
    /// outer scroller on as well would let the page grow past the window and reintroduce the
    /// unreachable-scrollbar problem it exists to solve.
    /// </summary>
    private void ApplyPageSizing(PageBase page)
    {
        if (page.FillsViewport)
        {
            MainScroll.VerticalScrollBarVisibility = ScrollBarVisibility.Disabled;
            double h = MainScroll.ViewportHeight;
            page.Height = h > 0 ? h : double.NaN;
        }
        else
        {
            MainScroll.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            page.Height = double.NaN;   // back to natural height
        }
    }

    // ---------------------------------------------------------------- navigation

    private void Navigate(NavDestination destination)
    {
        if (!_pages.TryGetValue(destination, out var page))
        {
            page = Create(destination);
            _pages[destination] = page;
        }

        _current = page;
        CrumbText.Text = destination.ToString();
        PageHost.Content = page;
        ApplyPageSizing(page);

        // Each page pulls its own data when shown, rather than every page being kept warm.
        page.Refresh();
        MainScroll.ScrollToTop();
        Motion.TransitionIn(page);
    }

    private PageBase Create(NavDestination destination) => destination switch
    {
        NavDestination.Overview => new OverviewPage(),
        NavDestination.Threats => new ThreatsPage(),
        NavDestination.Processes => new ProcessesPage(),
        NavDestination.Network => new NetworkPage(),
        NavDestination.Persistence => new PersistencePage(),
        NavDestination.Quarantine => new QuarantinePage(),
        NavDestination.Maintenance => new MaintenancePage(),
        NavDestination.DiskAnalyzer => new DiskAnalyzerPage(),
        NavDestination.Duplicates => new DuplicatesPage(),
        NavDestination.Timeline => new TimelinePage(),
        NavDestination.Settings => BuildSettings(),
        _ => new OverviewPage(),
    };

    private PageBase BuildSettings()
    {
        var page = new SettingsPage();
        page.ScaleChanged += value => { _userScale = value; ApplyScale(); };
        return page;
    }

    private void UpdateBadges()
    {
        int findings = _guardian.Verdicts.Count;
        _rail.SetBadge(NavDestination.Threats, findings > 0 ? findings.ToString() : null,
            findings > 0 ? Guardian.Severity.Medium : Guardian.Severity.Low);

        int vault = _guardian.Vault.List().Count;
        _rail.SetBadge(NavDestination.Quarantine, vault > 0 ? vault.ToString() : null, Guardian.Severity.Low);
    }

    // ---------------------------------------------------------------- live updates

    private void OnGuardianObserved(SnapshotDelta delta)
    {
        Dispatcher.BeginInvoke(() =>
        {
            // HERO lives in the tray, so most of its life this window is hidden. Rebuilding WPF
            // visuals for an audience of nobody measured at roughly 3% of a core, so the
            // projection is skipped while hidden. The engine keeps observing regardless.
            if (!IsVisible || WindowState == WindowState.Minimized)
            {
                _pendingWhileHidden = true;
                return;
            }
            RefreshCurrent();
        });
    }

    /// <summary>
    /// Only the Overview follows the one-second tick. The table pages hold hundreds of rows and
    /// rebuilding them every second would be both expensive and unusable, since the row under the
    /// pointer would move continuously.
    /// </summary>
    private void RefreshCurrent()
    {
        if (_current is OverviewPage overview)
        {
            overview.Refresh();
        }
        else if (_current is { } page && page.LiveInterval > TimeSpan.Zero &&
                 DateTime.UtcNow - page.LastRefreshUtc >= page.LiveInterval)
        {
            // Slower than the engine tick on purpose — see PageBase.LiveInterval.
            page.LastRefreshUtc = DateTime.UtcNow;
            page.Refresh();
        }

        UpdateBadges();
    }

    // ---------------------------------------------------------------- scaling

    private void ApplyScale()
    {
        // Window.ActualWidth is unaffected by a LayoutTransform on its child, so reading it here
        // cannot feed back into the transform and oscillate.
        double responsive = Math.Clamp(ActualWidth / ScaleBaselineWidth, ResponsiveMin, ResponsiveMax);
        double scale = Math.Clamp(_userScale * responsive, 0.8, 2.4);
        RootScale.ScaleX = scale;
        RootScale.ScaleY = scale;
    }

    private void OnZoomKeys(object sender, KeyEventArgs e)
    {
        if ((Keyboard.Modifiers & ModifierKeys.Control) == 0) return;

        switch (e.Key)
        {
            case Key.OemPlus or Key.Add: _userScale = Math.Min(2.0, _userScale + 0.05); break;
            case Key.OemMinus or Key.Subtract: _userScale = Math.Max(0.7, _userScale - 0.05); break;
            case Key.D0 or Key.NumPad0: _userScale = 1.15; break;
            default: return;
        }
        e.Handled = true;
        ApplyScale();

        // Applied instantly, saved lazily. Two reasons, and the second is the one that matters.
        //
        // 1. This used to call HeroSettings.SaveSafe() directly, bypassing the guardian entirely.
        //    That was a write to %ProgramData%\HERO\settings.json from the unelevated dashboard,
        //    which the state-directory lockdown now denies — and SaveSafe swallows the denial, so
        //    the zoom level would simply never persist and never say why. Routing it through
        //    GuardianService.SaveSettings sends it to the service, which owns that file, exactly as
        //    the Settings page's own scale slider already does.
        //
        // 2. That route is a blocking pipe call on the UI thread, and this is a KEY REPEAT handler.
        //    Holding Ctrl+= would issue one synchronous round trip per repeat. The debounce lets
        //    the scale track the keyboard while only the final value is sent.
        _scaleSave ??= new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(400),
        };
        _scaleSave.Tick -= SaveScale;
        _scaleSave.Tick += SaveScale;
        _scaleSave.Stop();
        _scaleSave.Start();
    }

    private System.Windows.Threading.DispatcherTimer? _scaleSave;

    private void SaveScale(object? sender, EventArgs e)
    {
        _scaleSave?.Stop();
        try
        {
            var settings = HeroSettings.Load();
            settings.UiScale = _userScale;
            _guardian.SaveSettings(settings);
        }
        catch { /* a zoom level is not worth an exception dialog */ }
    }

    private void LoadPreferences()
    {
        try
        {
            var settings = HeroSettings.Load();
            _userScale = settings.UiScale;

            // The animation preference is a purely cosmetic key kept outside the settings schema.
            if (File.Exists(HeroPaths.Settings))
            {
                using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(HeroPaths.Settings));
                if (doc.RootElement.TryGetProperty("animationsEnabled", out var a) &&
                    a.ValueKind is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False)
                    Motion.UserEnabled = a.GetBoolean();
            }
        }
        catch { /* a corrupt settings file must never stop the app starting */ }
    }

    /// <summary>
    /// WPF raises RequestBringIntoView while the initial layout settles, which scrolls the view
    /// past the page heading before the user has touched anything. Suppressing it keeps every page
    /// anchored at the top on open; explicit ScrollToTop still works.
    /// </summary>
    private void OnSuppressBringIntoView(object sender, RequestBringIntoViewEventArgs e)
        => e.Handled = true;

    // ---------------------------------------------------------------- chrome

    private void OnMinimise(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximise(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    /// <summary>
    /// Closing hides rather than exits: HERO is a resident guardian, and a defence system that
    /// stops when you close its window is not a defence system. Exit lives in the tray menu.
    /// </summary>
    private void OnCloseToTray(object sender, RoutedEventArgs e) => Hide();
}
