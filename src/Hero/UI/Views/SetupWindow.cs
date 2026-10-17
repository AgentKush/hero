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

    /// <summary>Shortcut tick boxes. Rebuilt by <see cref="Describe"/>, so never null in use.</summary>
    private readonly StackPanel _options = new();
    private CheckBox _startMenuShortcut = new();
    private CheckBox _desktopShortcut = new();
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

        _options.Margin = new Thickness(0, 18, 0, 0);
        body.Children.Add(_options);

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

    // Read from disk rather than remembered, so the boxes show what is actually there. Both are
    // all-users locations, matching where SetupActions writes them.
    private static bool StartMenuShortcutExists => File.Exists(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "HERO.lnk"));

    private static bool DesktopShortcutExists => File.Exists(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "HERO.lnk"));

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

    /// <summary>
    /// The shortcut options, as arguments for the elevated install child.
    ///
    /// Read at click time rather than stored, so the boxes are the single source of truth. Phrased
    /// as opt-out for the Start menu and opt-in for the Desktop, so a bare
    /// <c>--setup-install</c> from a command line still does the conventional thing.
    /// </summary>
    private string[] ShortcutArgs()
    {
        var args = new List<string>(2);
        if (_startMenuShortcut.IsChecked != true) args.Add(App.NoStartMenuShortcutSwitch);
        if (_desktopShortcut.IsChecked == true) args.Add(App.DesktopShortcutSwitch);
        return args.ToArray();
    }

    private CheckBox Option(string text, bool chequed)
    {
        var box = new CheckBox
        {
            Content = text,
            IsChecked = chequed,
            Foreground = Brush("TextSecondary"),
            FontSize = Fs("FsBody"),
            Margin = new Thickness(0, 0, 0, 6),
            Cursor = System.Windows.Input.Cursors.Hand,
        };
        return box;
    }

    private void Describe()
    {
        _buttons.Children.Clear();
        _options.Children.Clear();
        _options.Visibility = Visibility.Visible;
        _progress.Visibility = Visibility.Collapsed;
        _status.Text = "";

        // Rebuilt each time so that reopening the panel after an install reflects what is on disk
        // rather than what was ticked last time.
        _startMenuShortcut = Option("Start menu shortcut", StartMenuShortcutExists || !IsInstalled);
        _desktopShortcut = Option("Desktop shortcut", DesktopShortcutExists);
        _options.Children.Add(_startMenuShortcut);
        _options.Children.Add(_desktopShortcut);

        if (IsInstalled)
        {
            _headline.Text = "HERO is installed";
            _detail.Text =
                $"HERO is installed in {InstallDirectory} and its guardian service runs at startup. " +
                "Removing it stops and unregisters the service, deletes the program files, and takes " +
                "away the startup entry.\n\n" +
                "Reinstalling over the top updates the program files in place and keeps everything " +
                "HERO has learned about this machine.";

            Add("Reinstall", ButtonTone.Neutral,
                () => RunAsync(App.SetupInstallSwitch, "Installing", ShortcutArgs()));
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

            Add("Install", ButtonTone.Primary,
                () => RunAsync(App.SetupInstallSwitch, "Installing", ShortcutArgs()));
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

    private async void RunAsync(string switchName, string verb, params string[] extraArgs)
    {
        _buttons.Children.Clear();
        _options.Visibility = Visibility.Collapsed;
        _progress.Visibility = Visibility.Visible;
        _status.Foreground = Brush("TextSecondary");
        _status.Text = $"{verb}… Windows will ask for permission.";

        int exit = await Task.Run(() => SetupActions.RunElevated(switchName, extraArgs));

        _progress.Visibility = Visibility.Collapsed;

        // DESCRIBE() FIRST IN EVERY BRANCH, THEN THE MESSAGE. Describe rebuilds the buttons, which
        // the user needs in order to try again — but it also resets the headline and detail and
        // clears the status line. It used to be called AFTER each message below, so every one of
        // them was erased the instant it was shown, and replaced by whatever Describe says about the
        // files on disk. After a half-finished install those files are there, so a failed install
        // read "HERO is installed", and a partial uninstall read the same with no warning at all —
        // the exact outcome the ExitIncomplete code was created to prevent.
        if (exit == SetupActions.ExitDeclined)
        {
            Describe();
            _status.Foreground = Brush("SevMedium");
            _status.Text = "Cancelled at the permission prompt. Nothing was changed.";
            return;
        }

        // Distinct from a plain failure: the uninstall ran to the end and removed some of HERO but
        // not all of it. Saying "failed" would be wrong — things were removed — and saying nothing
        // would leave a service registered behind a success message, which is the whole reason this
        // exit code exists.
        if (exit == SetupActions.ExitIncomplete)
        {
            Describe();
            _headline.Text = "HERO was only partly removed";
            _detail.Text =
                "Some of HERO could not be removed, so parts of it are still on this machine. The " +
                "log lists exactly which steps failed and why.";
            _status.Foreground = Brush("SevHigh");
            _status.Text = SetupActions.LogHint;
            return;
        }

        // Installed and removable, but NOT being watched. A security tool turning this screen green
        // would be telling a stranger their machine is protected when it is not.
        if (exit == SetupActions.ExitInstalledNotStarted)
        {
            Describe();
            _headline.Text = "HERO is installed, but its guardian is not running";
            _detail.Text =
                "The guardian service is registered to start with Windows, but it is not running now, " +
                "so this machine is not being watched yet. Restarting Windows will try again. The " +
                $"reason is in {Path.Combine(HeroPaths.Root, "service.log")}.";
            _status.Foreground = Brush("SevHigh");
            _status.Text = $"Installed to {InstallDirectory}. {SetupActions.LogHint}";
            return;
        }

        if (exit != 0)
        {
            Describe();
            _headline.Text = $"{verb} did not finish";
            _detail.Text = "A step failed part-way through. The log says which one, and why.";
            _status.Foreground = Brush("SevHigh");
            _status.Text = $"{verb} failed (exit {exit}). {SetupActions.LogHint}";
            return;
        }

        _status.Foreground = Brush("SevSafe");

        if (switchName == App.SetupInstallSwitch)
        {
            // True now, where it used to be assumed: exit 0 is only returned once --install-service
            // has seen the service actually running.
            _headline.Text = "HERO is installed";
            _detail.Text =
                "The guardian service is running and will start with the machine. " +
                (StartMenuShortcutExists ? "HERO is in your Start menu, and it " : "HERO ") +
                "can be removed from Settings > Apps like anything else.";
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
                "The service is unregistered, and the program files are deleted as soon as this " +
                "window closes. What HERO recorded is still in " +
                $"{HeroPaths.Root}, and its logs are in {HeroPaths.UserLogDir} — both are kept so a " +
                "reinstall picks up where it left off. Delete those two folders by hand if you " +
                "want nothing left; the first one needs administrator rights.";
            _status.Text = "";
            _buttons.Children.Clear();
            Add("Close", ButtonTone.Primary, Close);
        }
    }
}
