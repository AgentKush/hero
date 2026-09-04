using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Hero.Core;
using Hero.Guardian;
using Hero.UI.Controls;

namespace Hero.UI.Views;

/// <summary>
/// The Settings screen.
///
/// Built in code rather than XAML so it composes from the same token set as everything else and
/// cannot drift into hard-coded colours. Each row is (label, description, control), because a
/// security tool whose settings need explaining in a manual will simply be left on its defaults.
/// </summary>
internal sealed class SettingsPage : PageBase
{
    private readonly HeroSettings _settings;

    internal SettingsPage()
    {
        _settings = HeroSettings.Load();

        var stack = new StackPanel { Margin = new Thickness(0, 4, 0, 30) };

        stack.Children.Add(PageTitle("Settings"));
        stack.Children.Add(PageSubtitle(
            "HERO runs unelevated by default. The only request it ever makes to the network is a " +
            "reverse DNS lookup to name the addresses your programs connect to, and that can be " +
            $"turned off below. Everything here is stored in {HeroPaths.Settings}."));

        // ---------------------------------------------------------- appearance
        var appearance = Section("Appearance");
        appearance.Children.Add(Row(
            "Animations",
            "Fades, slides and the score ring sweeping to a new value. Turning this off applies " +
            "final values instantly rather than skipping them. HERO also honours the Windows " +
            "\"animation effects\" accessibility setting, so if that is off, animations stay off.",
            BuildAnimationsToggle()));

        appearance.Children.Add(Row(
            "Interface scale",
            "Type and spacing also scale automatically with window width. Ctrl+Plus, Ctrl+Minus " +
            "and Ctrl+0 adjust this from anywhere in the app.",
            BuildScaleControl()));
        stack.Children.Add(appearance);

        // ---------------------------------------------------------- protection
        var protection = Section("Protection");
        protection.Children.Add(Row(
            "Autonomy",
            "What HERO is allowed to do on its own. Every action it takes is reversible from the " +
            "quarantine vault.",
            BuildAutonomyControl()));

        protection.Children.Add(Row(
            "Require a hard indicator before acting alone",
            "When on, HERO will not act autonomously on circumstantial evidence alone, however " +
            "high the score. Recommended: nine unsigned binaries are running on this machine right " +
            "now and all of them are legitimate developer tooling.",
            BuildHardIndicatorToggle()));

        protection.Children.Add(Row(
            "Administrator rights",
            SelfElevate.AlreadyElevated
                ? "HERO is running with administrator rights this session."
                : SelfElevate.DescribeBenefit(
                    GuardianService.Current.Engine.Latest?.Processes.Count(p => p.PathUnavailable) ?? 0),
            BuildElevateControl()));

        protection.Children.Add(Row(
            "Autonomous actions per hour",
            $"A circuit breaker. If HERO exceeds this it stops acting on its own and reverts to " +
            $"asking, on the assumption that something is wrong with its own judgement rather than " +
            $"with the machine. Currently {_settings.MaxAutoActionsPerHour}.",
            BuildActionLimitControl()));

        // One notice for the whole section: every guarded control routes through SaveGuarded, and
        // a refusal from any of them says the same thing.
        protection.Children.Add(_refusalNotice);
        stack.Children.Add(protection);

        // ---------------------------------------------------------- learning
        var learning = Section("What HERO has learned here");
        learning.Children.Add(Row(
            "Corrections",
            "Every time you tell HERO it is wrong about a program, it remembers which check was " +
            "wrong. Once the same check has been wrong about three different programs, HERO starts " +
            "counting it for slightly less on this machine — never below four fifths, and never at " +
            "all for the hard indicators it is allowed to act on by itself. The evidence fades: a " +
            "correction is worth half after two months, so this follows the machine as it changes.",
            BuildForgetButton()));
        learning.Children.Add(_learningList);
        stack.Children.Add(learning);
        LoadLearningAsync();

        // ---------------------------------------------------------- privacy
        var privacy = Section("Privacy");
        privacy.Children.Add(Row(
            "Name network peers",
            "Looks up the hostname behind each address on the Network screen, so you see " +
            "\"spclient.wg.spotify.com\" instead of \"35.186.224.24\". This is the only outbound " +
            "request HERO makes. It goes to the DNS resolver this machine already uses, which " +
            "performed the forward lookup moments earlier, so it learns nothing new. Turn it off " +
            "and HERO shows raw addresses and makes no network requests at all.",
            BuildToggle(ReadRaw("resolveHostnames", true), v =>
            {
                Guardian.SaveRawSetting("resolveHostnames", v);
                GuardianService.Current.Peers.ResolveHostnames = v;
            })));
        stack.Children.Add(privacy);

        // ---------------------------------------------------------- startup
        var startup = Section("Startup");
        startup.Children.Add(Row(
            "Start with Windows",
            "HERO starts hidden in the tray. A guardian that only runs when you remember to launch " +
            "it is not a guardian.",
            BuildToggle(_settings.RunAtStartup, v =>
            {
                _settings.RunAtStartup = v;
                Guardian.SaveSettings(_settings);
                ApplyStartup(v);
            })));
        stack.Children.Add(startup);

        Content = stack;
    }

    // ------------------------------------------------------------ learning

    private readonly StackPanel _learningList = new();

    /// <summary>
    /// Fills the learning list without blocking the UI thread.
    ///
    /// The ledger lives in the state root, which the dashboard cannot read once HERO is properly
    /// installed, so this is a pipe call — and a pipe call on a page constructor is how a window
    /// comes up frozen for two seconds on a machine where the service is not answering.
    /// </summary>
    private async void LoadLearningAsync()
    {
        ShowLearningNote("Reading what HERO has seen…");

        Service.Ipc.LearningReply reply;
        try { reply = await Task.Run(() => GuardianService.Current.Learning()); }
        catch { ShowLearningNote("HERO could not read its own record just now."); return; }

        RenderLearning(reply);
    }

    private void RenderLearning(Service.Ipc.LearningReply reply)
    {
        _learningList.Children.Clear();

        if (!reply.Sealed)
        {
            // Not a shrug. The record only means anything if the user cannot author it, and on a
            // machine where HERO was never installed %ProgramData%\HERO inherits an ACL that lets
            // any unelevated process write these files — so HERO deliberately concludes nothing,
            // and says so rather than showing a list it is quietly ignoring.
            ShowLearningNote(
                "HERO is not learning on this machine yet. Its record lives in a folder any program " +
                "could write to until HERO is installed, and a record anything can edit is not " +
                "evidence of anything. Installing HERO closes that folder and turns this on.");
            return;
        }

        if (reply.Rules.Count == 0)
        {
            ShowLearningNote(
                "Nothing yet. When HERO flags something and you tell it \"HERO is wrong about " +
                "this\", the check that was wrong appears here.");
            return;
        }

        foreach (var rule in reply.Rules) _learningList.Children.Add(LearningRow(rule));
    }

    private void ShowLearningNote(string text)
    {
        _learningList.Children.Clear();
        _learningList.Children.Add(new TextBlock
        {
            Text = text,
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextTertiary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(2, 0, 2, 10),
        });
    }

    private UIElement LearningRow(Service.Ipc.LearnedRule rule)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var text = new StackPanel { Margin = new Thickness(0, 0, 20, 0) };
        text.Children.Add(new TextBlock
        {
            Text = rule.Description.Length > 0 ? rule.Description : rule.RuleId,
            FontSize = Fs("FsBody"),
            Foreground = Brush("TextPrimary"),
            TextWrapping = TextWrapping.Wrap,
        });

        // The counts, in the user's own terms. "You corrected this" is a claim they can check
        // against their memory; a bare multiplier is one they can only accept.
        var parts = new List<string>();
        if (rule.Allows > 0) parts.Add($"{rule.Allows} correction{(rule.Allows == 1 ? "" : "s")}");
        if (rule.Acts > 0) parts.Add($"{rule.Acts} time{(rule.Acts == 1 ? "" : "s")} you acted");
        if (rule.Dismisses > 0) parts.Add($"{rule.Dismisses} hidden");

        text.Children.Add(new TextBlock
        {
            Text = parts.Count > 0 ? string.Join("  ·  ", parts) : rule.RuleId,
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextTertiary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 3, 0, 0),
        });

        var weight = new TextBlock
        {
            Text = rule.Influence < 1
                ? $"counts ×{rule.Influence:0.00} · {rule.Programs} program{(rule.Programs == 1 ? "" : "s")}"
                : "full weight",
            FontSize = Fs("FsCaption"),
            Foreground = Brush(rule.Influence < 1 ? "TextSecondary" : "TextTertiary"),
            VerticalAlignment = VerticalAlignment.Center,
            TextAlignment = TextAlignment.Right,
        };

        Grid.SetColumn(text, 0);
        Grid.SetColumn(weight, 1);
        grid.Children.Add(text);
        grid.Children.Add(weight);

        return new Border
        {
            Style = TryFindResource("Card") as Style,
            Margin = new Thickness(0, 0, 0, 8),
            Child = grid,
        };
    }

    private UIElement BuildForgetButton()
    {
        var status = new TextBlock
        {
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 260,
            TextAlignment = TextAlignment.Right,
            Visibility = Visibility.Collapsed,
        };

        var button = new Button
        {
            Content = "Forget what you've learned",
            Padding = new Thickness(15, 9, 15, 9),
            MinHeight = 34,
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextPrimary"),
            Background = Brush("Surface3"),
            BorderBrush = Brush("HairLine"),
            BorderThickness = new Thickness(1),
            Cursor = System.Windows.Input.Cursors.Hand,
        };
        button.Template = FlatButtonTemplate();

        button.Click += async (_, _) =>
        {
            button.IsEnabled = false;
            Service.Ipc.CommandReply reply;
            try { reply = await Task.Run(() => GuardianService.Current.ResetLearning()); }
            catch
            {
                reply = new Service.Ipc.CommandReply { Message = "HERO could not be reached." };
            }

            status.Visibility = Visibility.Visible;
            status.Text = reply.Message;
            button.IsEnabled = true;

            // The list is derived from the same record the reset just annotated, so re-read it
            // rather than guessing what it now says.
            LoadLearningAsync();
        };

        var panel = new StackPanel();
        panel.Children.Add(button);
        panel.Children.Add(status);
        return panel;
    }

    // ------------------------------------------------------------ controls

    private UIElement BuildAnimationsToggle()
    {
        var toggle = new ToggleSwitch { IsOn = Motion.UserEnabled };
        toggle.UserToggled += on =>
        {
            Motion.SetUserEnabled(on);
            Guardian.SaveRawSetting("animationsEnabled", on);
        };

        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        panel.Children.Add(toggle);

        // If Windows itself has animations disabled, say so rather than letting the user toggle a
        // switch that appears to do nothing.
        if (!Motion.SystemAllows)
        {
            panel.Children.Add(new TextBlock
            {
                Text = "Windows has animation effects turned off, so these stay off.",
                Margin = new Thickness(12, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = Fs("FsMicro"),
                Foreground = Brush("SevMedium"),
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 240,
            });
        }
        return panel;
    }

    private UIElement BuildScaleControl()
    {
        var slider = new Slider
        {
            Minimum = 0.8,
            Maximum = 1.8,
            TickFrequency = 0.05,
            IsSnapToTickEnabled = true,
            Width = 200,
            Value = _settings.UiScale,
            VerticalAlignment = VerticalAlignment.Center,
        };
        var label = new TextBlock
        {
            Text = $"{_settings.UiScale:P0}",
            Margin = new Thickness(12, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            FontFamily = Font("MonoFont"),
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            MinWidth = 48,
        };
        slider.ValueChanged += (_, e) =>
        {
            label.Text = $"{e.NewValue:P0}";
            _settings.UiScale = e.NewValue;
            Guardian.SaveSettings(_settings);
            ScaleChanged?.Invoke(e.NewValue);
        };

        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        panel.Children.Add(slider);
        panel.Children.Add(label);
        return panel;
    }

    /// <summary>
    /// Shown when the service refuses a change. Empty and collapsed the rest of the time.
    ///
    /// These controls used to fire and forget: set the value, call SaveSettings, ignore the reply.
    /// Now that the service refuses changes to how it responds from a caller that has not elevated,
    /// ignoring the reply leaves the control showing a setting HERO never adopted — the exact
    /// silent disagreement between the UI and the engine that this page's own comment on
    /// ReloadSettings calls out as the thing that destroys trust in a security tool.
    /// </summary>
    private readonly TextBlock _refusalNotice = new()
    {
        FontSize = 12,
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 2, 0, 10),
        Visibility = Visibility.Collapsed,
    };

    /// <summary>Set while a refusal is being undone, so the revert does not re-enter the handler.</summary>
    private bool _reverting;

    /// <summary>
    /// Saves through the guardian and, if the change is refused, undoes it and says why.
    ///
    /// EVERY control that touches a guarded setting must go through here, and that is not tidiness.
    /// <paramref name="revert"/> puts BOTH the model and the control back, because <c>_settings</c>
    /// is a single object shared by every control on this page: a refused change left in it is
    /// carried by the next save, and the next, so one refused toggle would go on to refuse the
    /// deliberately-ungated zoom slider for the rest of the session. Measured as a cascade before
    /// this existed — the hard-indicator toggle and the actions-per-hour box both ignored the reply.
    /// </summary>
    private bool SaveGuarded(Action revert)
    {
        var reply = Guardian.SaveSettings(_settings);

        if (reply is { Acted: false })
        {
            _reverting = true;
            try { revert(); }
            finally { _reverting = false; }

            _refusalNotice.Text = reply.Message;
            _refusalNotice.Foreground = Brush("SevMedium");
            _refusalNotice.Visibility = Visibility.Visible;
            return false;
        }

        _refusalNotice.Visibility = Visibility.Collapsed;
        return true;
    }

    private UIElement BuildAutonomyControl()
    {
        var panel = new StackPanel();
        var radios = new Dictionary<AutonomyLevel, RadioButton>();
        var options = new (AutonomyLevel Level, string Title, string Detail)[]
        {
            (AutonomyLevel.Observe, "Observe only",
                "Detect, score and explain. Never act."),
            (AutonomyLevel.AskAlways, "Always ask",
                "Prompt before every action, however confident."),
            (AutonomyLevel.AutoHighConfidence, "Act on high confidence, ask otherwise",
                "Kill and quarantine only when several independent signals agree. Recommended."),
            (AutonomyLevel.Autopilot, "Autopilot",
                "Act on medium confidence too, and report afterwards. Highest false-positive exposure."),
        };

        foreach (var (level, title, detail) in options)
        {
            var radio = new RadioButton
            {
                GroupName = "autonomy",
                IsChecked = _settings.Autonomy == level,
                Margin = new Thickness(0, 5, 0, 5),
                Foreground = Brush("TextPrimary"),
                FontSize = Fs("FsBody"),
                Content = new StackPanel
                {
                    Children =
                    {
                        new TextBlock { Text = title, FontSize = Fs("FsBody"), Foreground = Brush("TextPrimary") },
                        new TextBlock
                        {
                            Text = detail,
                            FontSize = Fs("FsMicro"),
                            Foreground = Brush("TextTertiary"),
                            TextWrapping = TextWrapping.Wrap,
                            MaxWidth = 420,
                            Margin = new Thickness(0, 1, 0, 0),
                        },
                    },
                },
            };
            // Content is a StackPanel so the title and its explanation can be styled separately,
            // and WPF surfaces no automation name for a non-string content — measured: a UI
            // Automation walk found four radio buttons here, every one of them named "". A screen
            // reader announces "radio button" and nothing else for the control that decides whether
            // HERO is allowed to defend the machine. Same defect, same fix, as HeroButton.
            System.Windows.Automation.AutomationProperties.SetName(radio, title);
            System.Windows.Automation.AutomationProperties.SetHelpText(radio, detail);

            var captured = level;
            radios[level] = radio;
            radio.Checked += (_, _) =>
            {
                if (_reverting) return;

                var previous = _settings.Autonomy;
                _settings.Autonomy = captured;

                bool saved = SaveGuarded(() =>
                {
                    // Put back BOTH the model and the radio, to the level HERO is actually at.
                    _settings.Autonomy = previous;
                    if (radios.TryGetValue(previous, out var restore)) restore.IsChecked = true;
                });

                if (!saved) return;

                // The running engine must pick this up immediately. Without this the user changes
                // autonomy, sees the radio move, and HERO carries on at the previous level until
                // the next restart - which is exactly the kind of silent disagreement between the
                // UI and the engine that destroys trust in a security tool.
                Guardian.ReloadSettings();
            };
            panel.Children.Add(radio);
        }

        return panel;
    }

    private UIElement BuildElevateControl()
    {
        if (SelfElevate.AlreadyElevated)
            return new TextBlock
            {
                Text = "Elevated",
                FontSize = Fs("FsBody"),
                Foreground = Brush("SevSafe"),
                VerticalAlignment = VerticalAlignment.Center,
            };

        var status = new TextBlock
        {
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 260,
            Visibility = Visibility.Collapsed,
        };

        var button = new Button
        {
            Content = "Restart as administrator",
            Padding = new Thickness(15, 9, 15, 9),
            MinHeight = 34,
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextPrimary"),
            Background = Brush("Surface3"),
            BorderBrush = Brush("HairLine"),
            BorderThickness = new Thickness(1),
            Cursor = System.Windows.Input.Cursors.Hand,
        };
        button.Template = FlatButtonTemplate();

        button.Click += (_, _) =>
        {
            var (started, message) = SelfElevate.Relaunch(tray: false);
            status.Visibility = Visibility.Visible;
            status.Text = message;
            status.Foreground = Brush(started ? "SevSafe" : "SevMedium");

            // Only shut down once the elevated copy is confirmed running, so a cancelled prompt
            // never leaves the machine with no HERO at all.
            if (started) App.ExitApplication();
        };

        var panel = new StackPanel();
        panel.Children.Add(button);
        panel.Children.Add(status);
        return panel;
    }

    private static ControlTemplate FlatButtonTemplate()
    {
        var template = new ControlTemplate(typeof(Button));
        var border = new FrameworkElementFactory(typeof(Border));
        border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
        border.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Control.BorderBrushProperty));
        border.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Control.BorderThicknessProperty));
        border.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
        border.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        presenter.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        border.AppendChild(presenter);
        template.VisualTree = border;
        return template;
    }

    private UIElement BuildActionLimitControl()
    {
        var box = new ComboBox
        {
            Width = 90,
            VerticalAlignment = VerticalAlignment.Center,
            ItemsSource = new[] { 1, 2, 3, 5, 10, 20 },
            SelectedItem = _settings.MaxAutoActionsPerHour,
        };
        box.SelectionChanged += (_, _) =>
        {
            if (_reverting || box.SelectedItem is not int v) return;

            int previous = _settings.MaxAutoActionsPerHour;
            _settings.MaxAutoActionsPerHour = v;
            SaveGuarded(() =>
            {
                _settings.MaxAutoActionsPerHour = previous;
                box.SelectedItem = previous;
            });
        };
        return box;
    }

    /// <summary>
    /// The hard-indicator toggle, built here rather than inline so a refusal can put the switch
    /// back. It is a guarded setting: turning it off makes HERO act on circumstantial evidence.
    /// </summary>
    private UIElement BuildHardIndicatorToggle()
    {
        var toggle = new ToggleSwitch { IsOn = _settings.RequireHardIndicatorForAutoAction };
        toggle.UserToggled += v =>
        {
            if (_reverting) return;

            bool previous = _settings.RequireHardIndicatorForAutoAction;
            _settings.RequireHardIndicatorForAutoAction = v;
            SaveGuarded(() =>
            {
                _settings.RequireHardIndicatorForAutoAction = previous;
                toggle.IsOn = previous;
            });
        };
        return toggle;
    }

    private static UIElement BuildToggle(bool initial, Action<bool> onChanged)
    {
        var toggle = new ToggleSwitch { IsOn = initial };
        toggle.UserToggled += onChanged;
        return toggle;
    }

    /// <summary>Raised when the user drags the scale slider, so the shell can re-apply it live.</summary>
    internal event Action<double>? ScaleChanged;

    private void ApplyStartup(bool enable)
    {
        try
        {
            // DisableAll rather than Disable(method): if the registered method has been changed
            // since the entry was created, disabling only the currently-selected one would leave
            // the other mechanism silently starting HERO forever.
            if (enable) StartupRegistration.Enable(_settings.StartupMethod);
            else StartupRegistration.DisableAll();
        }
        catch { /* surfaced by the next settings read; never crash the settings page */ }
    }

    /// <summary>Settings are read once on construction; nothing here changes underneath the user.</summary>
    internal override void Refresh() { }

    // ------------------------------------------------------------ raw key access

    /// <summary>
    /// Writes a single key into settings.json without disturbing anything else.
    /// The animation preference is deliberately kept out of <see cref="HeroSettings"/> for now
    /// because that file is a security-behaviour contract, and a purely cosmetic preference does
    /// not belong in the same schema version history.
    /// </summary>
    /// <summary>Reads a cosmetic/privacy flag kept outside the security settings schema.</summary>
    private static bool ReadRaw(string key, bool fallback)
    {
        try
        {
            if (!File.Exists(HeroPaths.Settings)) return fallback;
            using var doc = JsonDocument.Parse(File.ReadAllText(HeroPaths.Settings));
            if (doc.RootElement.TryGetProperty(key, out var v) &&
                v.ValueKind is JsonValueKind.True or JsonValueKind.False)
                return v.GetBoolean();
        }
        catch { }
        return fallback;
    }


    // ------------------------------------------------------------ layout helpers

    private StackPanel Section(string title)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
        panel.Children.Add(new TextBlock
        {
            Text = title.ToUpperInvariant(),
            FontSize = Fs("FsMicro"),
            FontWeight = FontWeights.SemiBold,
            Foreground = Brush("TextTertiary"),
            Margin = new Thickness(0, 20, 0, 10),
        });
        return panel;
    }

    private UIElement Row(string label, string description, UIElement control)
    {
        var grid = new Grid { Margin = new Thickness(0, 0, 0, 4) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var text = new StackPanel { Margin = new Thickness(0, 0, 24, 0) };
        text.Children.Add(new TextBlock
        {
            Text = label,
            FontSize = Fs("FsBodyLarge"),
            Foreground = Brush("TextPrimary"),
        });
        text.Children.Add(new TextBlock
        {
            Text = description,
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextTertiary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 3, 0, 0),
        });

        Grid.SetColumn(text, 0);
        Grid.SetColumn(control, 1);
        control.SetValue(VerticalAlignmentProperty, VerticalAlignment.Center);
        grid.Children.Add(text);
        grid.Children.Add(control);

        return new Border
        {
            Style = TryFindResource("Card") as Style,
            Margin = new Thickness(0, 0, 0, 10),
            Child = grid,
        };
    }

    private TextBlock PageTitle(string text) => new()
    {
        Text = text,
        FontSize = Fs("FsDisplay"),
        FontWeight = FontWeights.SemiBold,
        FontFamily = Font("DisplayFont"),
        Foreground = Brush("TextPrimary"),
        Margin = new Thickness(0, 4, 0, 2),
    };

    private TextBlock PageSubtitle(string text) => new()
    {
        Text = text,
        FontSize = Fs("FsBodyLarge"),
        Foreground = Brush("TextSecondary"),
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 0, 0, 8),
    };

}
