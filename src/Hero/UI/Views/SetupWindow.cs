using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Hero.Core;
using Hero.UI.Controls;

namespace Hero.UI.Views;

/// <summary>
/// HERO's installer and uninstaller.
///
/// BUILT INTO HERO.exe rather than shipped as a separate setup program, for one reason that
/// matters more than the convenience: the theme. App.xaml merges UI/Theme.xaml at application
/// level, so a window opened inside this process gets the same tokens, the same type scale and the
/// same chrome as the dashboard, and cannot drift from them. A separate setup executable would
/// have to copy the palette and would be wrong the first time either changed.
///
/// It also means there is one file to hand someone. Run HERO.exe on a machine with no HERO on it
/// and this is what appears; run it once installed and it offers to remove itself.
///
/// The window does no privileged work itself. Install and uninstall both re-launch HERO elevated
/// with a switch and wait for it, so exactly one UAC prompt appears at the moment the user presses
/// the button — not at start-up, and not once per step.
/// </summary>
internal sealed class SetupWindow : Window
{
    private readonly TextBlock _headline = new();
    private readonly TextBlock _detail = new();
    private readonly TextBlock _status = new();
    private readonly FluidProgress _progress = new();
    private readonly StackPanel _buttons = new() { Orientation = Orientation.Horizontal };

    private double Fs(string key) => TryFindResource(key) is double d ? d : 14.0;
    private Brush Brush(string key) => TryFindResource(key) as System.Windows.Media.Brush ?? Brushes.Gray;
    private FontFamily Font(string key) => TryFindResource(key) as FontFamily ?? new FontFamily("Segoe UI");

    internal SetupWindow()
    {
        Title = "HERO Setup";
        Width = 640;
        Height = 460;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        ResizeMode = ResizeMode.NoResize;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = false;
        Background = Brush("Surface0") is SolidColorBrush s && s.Color.A > 0
            ? Brush("Surface0")
            : new SolidColorBrush(Color.FromRgb(0x0E, 0x11, 0x16));

        try { Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/Assets/hero.ico")); }
        catch { /* the icon is decoration; never block setup on it */ }

        var root = new Grid { Margin = new Thickness(0) };
        foreach (var h in new[] { GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto })
            root.RowDefinitions.Add(new RowDefinition { Height = h });

        root.Children.Add(BuildTitleBar());

        var body = new StackPanel { Margin = new Thickness(28, 10, 28, 0) };
        Grid.SetRow(body, 1);
        root.Children.Add(body);

        _headline.FontSize = Fs("FsDisplay");
        _headline.FontFamily = Font("DisplayFont");
        _headline.FontWeight = FontWeights.SemiBold;
        _headline.Foreground = Brush("TextPrimary");
        _headline.Margin = new Thickness(0, 6, 0, 6);
        body.Children.Add(_headline);

        _detail.FontSize = Fs("FsBodyLarge");
        _detail.Foreground = Brush("TextSecondary");
        _detail.TextWrapping = TextWrapping.Wrap;
        body.Children.Add(_detail);

        _progress.Height = 18;
        _progress.Margin = new Thickness(0, 20, 0, 0);
        _progress.IsIndeterminate = true;
        _progress.AnimationsEnabled = Motion.Active;
        _progress.Accent = SeverityPalette.Resolve(this, "Accent", Color.FromRgb(0x3B, 0xA5, 0x5D));
        _progress.Visibility = Visibility.Collapsed;
        body.Children.Add(_progress);

        _status.FontSize = Fs("FsCaption");
        _status.Foreground = Brush("TextTertiary");
        _status.TextWrapping = TextWrapping.Wrap;
        _status.Margin = new Thickness(0, 14, 0, 0);
        body.Children.Add(_status);

        _buttons.Margin = new Thickness(28, 0, 28, 22);
        _buttons.HorizontalAlignment = HorizontalAlignment.Right;
        Grid.SetRow(_buttons, 2);
        root.Children.Add(_buttons);

        Content = root;
        Describe();
    }

    private UIElement BuildTitleBar()
    {
        // Matches the shell: no stock Windows title bar, drag anywhere along the top, one close
        // button. A setup window wearing a different frame from the app it installs looks like a
        // different program, which for an installer is exactly the wrong impression to give.
        var bar = new Grid { Height = 46, Background = Brush("Surface1") };
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetRow(bar, 0);

        var title = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(18, 0, 0, 0),
        };
        // The app icon rather than UI.HeroMark: that one draws the tray icon through GDI and is not
        // a WPF element. Failure to load leaves the title text, which is enough.
        try
        {
            title.Children.Add(new Image
            {
                Source = new System.Windows.Media.Imaging.BitmapImage(
                    new Uri("pack://application:,,,/Assets/hero.ico")),
                Width = 20,
                Height = 20,
                VerticalAlignment = VerticalAlignment.Center,
            });
        }
        catch { }
        title.Children.Add(new TextBlock
        {
            Text = "HERO Setup",
            Margin = new Thickness(10, 0, 0, 0),
            FontSize = Fs("FsBody"),
            Foreground = Brush("TextSecondary"),
            VerticalAlignment = VerticalAlignment.Center,
        });
        bar.Children.Add(title);

        var close = new Button
        {
            Content = "",
            FontFamily = new FontFamily("Segoe MDL2 Assets"),
            FontSize = 11,
            Width = 46,
            Height = 46,
            Background = Brushes.Transparent,
            Foreground = Brush("TextSecondary"),
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
        };
        System.Windows.Automation.AutomationProperties.SetName(close, "Close");
        close.Click += (_, _) => Close();
        Grid.SetColumn(close, 1);
        bar.Children.Add(close);

        bar.MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) DragMove(); };
        return bar;
    }

    // ------------------------------------------------------------------ state

    /// <summary>Where an installed HERO lives.</summary>
    private static string InstallDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "HERO");

    private static bool IsInstalled =>
        File.Exists(Path.Combine(InstallDirectory, "HERO.exe"));

    /// <summary>True when THIS executable is the installed copy rather than a downloaded one.</summary>
    private static bool RunningFromInstall
    {
        get
        {
            try
            {
                var here = Path.GetDirectoryName(Environment.ProcessPath) ?? "";
                return string.Equals(
                    Path.GetFullPath(here).TrimEnd(Path.DirectorySeparatorChar),
                    Path.GetFullPath(InstallDirectory).TrimEnd(Path.DirectorySeparatorChar),
                    StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }
    }

    private void Describe()
    {
        _buttons.Children.Clear();
        _progress.Visibility = Visibility.Collapsed;
        _status.Text = "";

        if (IsInstalled)
        {
            _headline.Text = "HERO is installed";
            _detail.Text =
                $"HERO is installed in {InstallDirectory} and its guardian service runs at startup. " +
                "Removing it stops and unregisters the service, deletes the program files, and takes " +
                "away the startup entry.\n\n" +
                "Reinstalling over the top updates the program files in place and keeps everything " +
                "HERO has learned about this machine.";

            Add("Reinstall", ButtonTone.Neutral, () => RunAsync(App.SetupInstallSwitch, "Installing"));
            Add("Uninstall", ButtonTone.Destructive, ConfirmUninstall);
            Add("Close", ButtonTone.Neutral, Close);
        }
        else
        {
            _headline.Text = "Install HERO";
            _detail.Text =
                $"HERO will be installed to {InstallDirectory}, and a guardian service will be " +
                "registered to run from startup so the machine is watched whether or not the window " +
                "is open.\n\n" +
                "It makes no network requests except an optional reverse DNS lookup you can turn " +
                "off, keeps everything it records on this machine, and has no account to create.";

            Add("Install", ButtonTone.Primary, () => RunAsync(App.SetupInstallSwitch, "Installing"));
            Add("Cancel", ButtonTone.Neutral, Close);
        }
    }

    private void Add(string text, ButtonTone tone, Action onClick)
    {
        var button = HeroButton.Create(text, tone, Fs("FsBody"));
        button.Click += (_, _) => onClick();
        _buttons.Children.Add(button);
    }

    private void ConfirmUninstall()
    {
        var answer = MessageBox.Show(
            "Remove HERO from this machine?\n\n" +
            "The guardian service is stopped and unregistered, the program files are deleted, and " +
            "the startup entry is removed.\n\n" +
            $"What HERO has recorded — its timeline, quarantine vault and learned baseline in " +
            $"{HeroPaths.Root} — is KEPT, so reinstalling picks up where it left off. Delete that " +
            "folder by hand if you want it gone.",
            "Uninstall HERO", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);

        if (answer == MessageBoxResult.OK) RunAsync(App.SetupUninstallSwitch, "Removing");
    }

    // ------------------------------------------------------------------ running the privileged half

    private async void RunAsync(string switchName, string verb)
    {
        _buttons.Children.Clear();
        _progress.Visibility = Visibility.Visible;
        _status.Foreground = Brush("TextSecondary");
        _status.Text = $"{verb}… Windows will ask for permission.";

        int exit = await Task.Run(() => SetupActions.RunElevated(switchName));

        _progress.Visibility = Visibility.Collapsed;

        if (exit == SetupActions.ExitDeclined)
        {
            _status.Foreground = Brush("SevMedium");
            _status.Text = "Cancelled at the permission prompt. Nothing was changed.";
            Describe();
            return;
        }

        if (exit != 0)
        {
            _status.Foreground = Brush("SevHigh");
            _status.Text = $"{verb} failed (exit {exit}). {SetupActions.LogHint}";
            Describe();
            return;
        }

        _status.Foreground = Brush("SevSafe");

        if (switchName == App.SetupInstallSwitch)
        {
            _headline.Text = "HERO is installed";
            _detail.Text =
                "The guardian service is running and will start with the machine. HERO is in your " +
                "Start menu, and can be removed from Settings > Apps like anything else.";
            _status.Text = $"Installed to {InstallDirectory}.";
            _buttons.Children.Clear();
            Add("Open HERO", ButtonTone.Primary, () =>
            {
                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                        Path.Combine(InstallDirectory, "HERO.exe")) { UseShellExecute = true });
                }
                catch { }
                Close();
            });
            Add("Close", ButtonTone.Neutral, Close);
        }
        else
        {
            _headline.Text = "HERO has been removed";
            _detail.Text =
                "The service is unregistered and the program files are gone. What HERO recorded is " +
                $"still in {HeroPaths.Root} if you want it; delete that folder to remove every trace.";
            _status.Text = "";
            _buttons.Children.Clear();
            Add("Close", ButtonTone.Primary, Close);
        }
    }
}
