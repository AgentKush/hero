using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Hero.Core;
using Hero.Guardian;
using Hero.Interop;
using Hero.UI.Controls;

namespace Hero.UI.Views;

/// <summary>
/// The Threats screen: what HERO thinks, why it thinks it, and what you can do about it.
///
/// Every finding shows its working. That is not decoration — an autonomous tool that says
/// "trust me, this is bad" trains the user to click through its prompts, which is the same
/// failure mode as an antivirus that cries wolf. Showing the individual signals, their weights
/// and the gate decision lets the user disagree with HERO on the evidence.
/// </summary>
internal sealed class ThreatsPage : PageBase
{
    private readonly StackPanel _list = new();
    private readonly TextBlock _sub = new();
    private readonly TextBlock _mode = new();

    internal ThreatsPage()
    {
        var page = Page("Threats", "");
        page.Children.Add(_sub);
        _sub.FontSize = Fs("FsBodyLarge");
        _sub.Foreground = Brush("TextSecondary");
        _sub.Margin = new Thickness(0, -18, 0, 6);
        _sub.TextWrapping = TextWrapping.Wrap;

        _mode.FontSize = Fs("FsCaption");
        _mode.Foreground = Brush("TextTertiary");
        _mode.TextWrapping = TextWrapping.Wrap;
        _mode.Margin = new Thickness(0, 0, 0, 22);
        page.Children.Add(_mode);

        page.Children.Add(_list);
        Content = page;
    }

    internal override void Refresh()
    {
        _list.Children.Clear();

        var verdicts = Guardian.Verdicts;
        var plans = Guardian.Plans;
        var detections = DefenderOracle.RecentDetections(TimeSpan.FromDays(14));

        _sub.Text = verdicts.Count == 0
            ? "Nothing currently scores above the reporting threshold."
            : $"{verdicts.Count} subject(s) above the reporting threshold.";

        bool dryRun = Guardian.Response?.DryRun ?? true;
        _mode.Text = dryRun
            ? "HERO is in observe mode: it works out what it would do and records that, but takes no " +
              "action on its own. The buttons below still work — they are your decision, not its."
            : $"Autonomy: {Guardian.Settings.Autonomy}. HERO may act by itself on high-confidence " +
              "findings only, and everything it does is reversible from the vault.";

        if (verdicts.Count == 0 && detections.Count == 0)
        {
            _list.Children.Add(Card(Empty("All clear",
                "HERO has found nothing worth raising, and Windows Defender has logged no detections " +
                "in the last fortnight.")));
            return;
        }

        foreach (var v in verdicts.Take(30))
            _list.Children.Add(BuildVerdict(v, plans.TryGetValue(v.Subject.Key, out var p) ? p : null));

        if (detections.Count > 0) _list.Children.Add(BuildDefenderCard(detections));
    }

    // ------------------------------------------------------------------ verdict card

    private UIElement BuildVerdict(Verdict v, ResponsePlan? plan)
    {
        var panel = new StackPanel();

        // ---- headline
        var header = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
        header.Children.Add(new SeverityPill { Severity = v.Severity, VerticalAlignment = VerticalAlignment.Center });
        header.Children.Add(new TextBlock
        {
            Text = v.Subject.Display,
            FontSize = Fs("FsSection"),
            FontWeight = FontWeights.SemiBold,
            FontFamily = Font("DisplayFont"),
            Foreground = Brush("TextPrimary"),
            Margin = new Thickness(12, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
        });
        panel.Children.Add(header);

        panel.Children.Add(new TextBlock
        {
            Text = $"Score {v.Score:F1} · {v.Confidence} confidence · " +
                   $"{v.CorroboratingFamilies} independent signal " +
                   (v.CorroboratingFamilies == 1 ? "family" : "families"),
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            Margin = new Thickness(0, 0, 0, 4),
        });

        // ---- what HERO has learned about this thing
        panel.Children.Add(BuildLearning(v));

        // Declared before the evidence because each signal now carries its own "this check is
        // wrong about this program" control, and they report through the same status line as the
        // buttons below rather than growing one apiece.
        var status = new TextBlock
        {
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 12, 0, 0),
            Visibility = Visibility.Collapsed,
        };

        // ---- the evidence
        foreach (var s in v.Signals.OrderByDescending(s => s.Weight).Take(8))
            panel.Children.Add(BuildSignal(s, v, status));

        // ---- what the ladder decided
        if (plan is not null) panel.Children.Add(BuildPlan(plan));

        // ---- actions
        panel.Children.Add(BuildActions(v, status));
        panel.Children.Add(status);

        return Card(panel);
    }

    /// <summary>
    /// The adaptive half, made visible. Without this the learning is a black box, and a user
    /// cannot tell "HERO has never seen this" from "HERO has seen this a hundred times and still
    /// dislikes it" — which are completely different situations.
    /// </summary>
    private UIElement BuildLearning(Verdict v)
    {
        var entity = Guardian.Baseline.Find(v.Subject);
        string text;

        if (entity is null)
        {
            text = "First time HERO has ever seen this. Everything is unfamiliar on day one, which " +
                   "is why novelty alone carries little weight.";
        }
        else
        {
            var age = DateTime.UtcNow - entity.FirstSeenUtc;
            string seen = entity.Count < 1.5 ? "once" : $"{entity.Count:F0} times";
            string ageText = age.TotalDays < 1
                ? $"first seen {age.TotalHours:F0}h ago"
                : $"first seen {age.TotalDays:F0} days ago";
            string signer = entity.Signer.Length > 0 ? $" · signed by {entity.Signer}" : " · no publisher recorded";
            text = $"Seen {seen} across {entity.Boots} boot(s), {ageText}{signer}. " +
                   $"Known parents: {entity.Parents.Count}, known remote peers: {entity.Peers.Count}.";
        }

        return new Border
        {
            Background = Brush("Surface1"),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 9, 12, 9),
            Margin = new Thickness(0, 6, 0, 12),
            Child = new TextBlock
            {
                Text = text,
                FontSize = Fs("FsCaption"),
                Foreground = Brush("TextSecondary"),
                TextWrapping = TextWrapping.Wrap,
            },
        };
    }

    /// <summary>
    /// One piece of evidence, with a way to say it is wrong about THIS program.
    ///
    /// The narrowest correction the product offers, and until now the only one it could not
    /// record. "This is expected" approves the whole file by hash and is refused without
    /// administrator rights; this silences one check for one program, needs no elevation, pins no
    /// hash and grants no standing trust to the path — so it is safe to leave in the hands of
    /// whoever is sitting there, which is exactly why it is the useful one.
    /// </summary>
    private UIElement BuildSignal(Signal s, Verdict v, TextBlock status)
    {
        var line = new StackPanel { Margin = new Thickness(0, 4, 0, 4) };

        var head = new StackPanel { Orientation = Orientation.Horizontal };
        head.Children.Add(new TextBlock
        {
            Text = $"{s.Weight:F0}",
            FontSize = Fs("FsCaption"),
            FontFamily = Font("MonoFont"),
            Foreground = Brush("TextTertiary"),
            Width = 30,
        });
        head.Children.Add(new TextBlock
        {
            Text = s.Title,
            FontSize = Fs("FsBody"),
            Foreground = Brush("TextPrimary"),
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 520,
        });

        if (s.RuleId.Length > 0)
        {
            var wrong = new TextBlock
            {
                Text = "wrong about this",
                FontSize = Fs("FsMicro"),
                Foreground = Brush("TextTertiary"),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 2, 0, 0),
                Cursor = System.Windows.Input.Cursors.Hand,
                TextDecorations = System.Windows.TextDecorations.Underline,
            };
            System.Windows.Automation.AutomationProperties.SetName(
                wrong, $"Tell HERO the check \"{s.Title}\" is wrong about this program");

            wrong.MouseLeftButtonUp += (_, _) =>
            {
                var result = Guardian.Allow(v.Subject, AllowScope.RuleForEntity, s.RuleId);
                status.Visibility = Visibility.Visible;

                if (result.Accepted)
                {
                    status.Text = $"Noted — \"{s.Title}\" will not be counted against this program " +
                                  "again. Every other check still applies to it, and this check " +
                                  "still applies to everything else.";
                    status.Foreground = Brush("SevSafe");
                    Refresh();
                }
                else
                {
                    status.Text = result.Reason;
                    status.Foreground = Brush("SevMedium");
                }
            };

            head.Children.Add(wrong);
        }

        line.Children.Add(head);

        line.Children.Add(new TextBlock
        {
            Text = s.Explanation,
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(30, 1, 0, 0),
        });

        if (s.Evidence.Length > 0)
            line.Children.Add(new TextBlock
            {
                Text = Core.Text.OneLine(s.Evidence, 260),
                FontSize = Fs("FsMono"),
                FontFamily = Font("MonoFont"),
                Foreground = Brush("TextTertiary"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(30, 2, 0, 0),
            });

        return line;
    }

    private UIElement BuildPlan(ResponsePlan plan)
    {
        var text = plan.Autonomous
            ? $"HERO acted on this by itself (up to {plan.Ceiling})."
            : plan.MeetsAutonomyBar
                ? $"The evidence clears HERO's bar for acting alone (up to {plan.Ceiling}), but it did not act: {plan.GateExplanation}"
                : $"Below HERO's bar for acting alone. {plan.GateExplanation}";

        var panel = new StackPanel();
        panel.Children.Add(new TextBlock
        {
            Text = text,
            FontSize = Fs("FsCaption"),
            Foreground = Brush(plan.Autonomous ? "SevMedium" : "TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
        });

        foreach (var r in plan.Results.Where(r => r.Acted || r.Refused).Take(6))
            panel.Children.Add(new TextBlock
            {
                Text = $"{r.Rung}: {r.Message}",
                FontSize = Fs("FsCaption"),
                FontFamily = Font("MonoFont"),
                Foreground = Brush(r.Refused ? "TextTertiary" : "SevSafe"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 3, 0, 0),
            });

        return new Border
        {
            Background = Brush("Surface1"),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 9, 12, 9),
            Margin = new Thickness(0, 12, 0, 0),
            Child = panel,
        };
    }

    // ------------------------------------------------------------------ actions

    private UIElement BuildActions(Verdict v, TextBlock status)
    {
        // A 1px outer margin keeps each button's border off the card's rounded clip boundary,
        // which was shaving the edge off the first and last buttons at non-integer UI scales.
        var wrap = new WrapPanel { Margin = new Thickness(1, 14, 1, 2) };
        var incident = $"user-{DateTime.UtcNow:yyyyMMddHHmmss}";
        var engine = Guardian.Response;

        // Every action goes through the guardian by SUBJECT KEY rather than straight at the
        // response engine with a process or an entry in hand.
        //
        // When HERO runs as a service the engine is in another process running as LocalSystem, so
        // the call has to cross the pipe regardless. Naming the target by key rather than by path
        // or pid is what stops that pipe being a way to ask SYSTEM to terminate any process or
        // quarantine any file: the service resolves the key against findings it independently
        // raised, and refuses anything else.
        Task<ResponseResult> Act(string action, string reason)
            => Guardian.ActAsync(v.Subject.Key, action, reason, incident);

        void Report(ResponseResult r)
        {
            status.Visibility = Visibility.Visible;
            status.Text = $"{r.Rung}: {r.Message}";
            status.Foreground = Brush(r.Acted ? "SevSafe" : r.Refused ? "SevMedium" : "TextSecondary");

            // When Windows refused for want of rights, offer to do it properly rather than
            // leaving the user to copy a command into an elevated terminal.
            if (r.Outcome == ActionOutcome.RefusedNeedsElevation)
                OfferElevation(v, wrap, status, r);

            // If something actually changed, VERIFY it and update the list. Leaving the finding on
            // screen after acting on it makes the user unable to tell whether anything happened —
            // the action succeeded, the UI simply never re-checked.
            if (r.Acted) _ = ConfirmAndRefreshAsync(v, status);
        }

        if (v.Subject is ProcessSubject ps)
        {
            var process = ps.Process;

            // The protected set is consulted here as well as inside the engine, so the button is
            // visibly disabled with a reason rather than failing when pressed.
            bool protectedTarget = engine is not null
                && new ProtectedSet().IsProtected(process, out _);

            wrap.Children.Add(Action("Suspend", false, protectedTarget, async () =>
                Report(await Act("suspend", "User suspended from the Threats screen"))));

            wrap.Children.Add(Action("Resume", false, false, async () =>
                Report(await Act("resume", "User resumed from the Threats screen"))));

            wrap.Children.Add(Action("Block network", false, protectedTarget, async () =>
                Report(await Act("blockNetwork", "User blocked from the Threats screen"))));

            // Kill is irreversible and the engine requires the target to be suspended first, which
            // is what preserves the evidence. The button says so rather than failing cryptically.
            wrap.Children.Add(Action("Suspend, then end process tree", true, protectedTarget, async () =>
            {
                if (!Confirm($"End the process tree for {process.FileName} (pid {process.Pid})?\n\n" +
                             "This cannot be undone. HERO will suspend it first so a forensic snapshot " +
                             "is captured before anything is terminated.")) return;

                var suspended = await Act("suspend", "Suspended prior to termination");
                if (!suspended.Acted && !suspended.Message.Contains("already", StringComparison.OrdinalIgnoreCase))
                {
                    Report(suspended);
                    return;
                }
                Report(await Act("killTree", "User ended the process tree"));
            }));

            if (!process.PathUnavailable)
                wrap.Children.Add(Action("Quarantine file", true, false, async () =>
                {
                    if (!Confirm($"Move this file to HERO's vault?\n\n{process.ImagePath}\n\n" +
                                 "It can be restored exactly as it was, including timestamps and permissions.")) return;
                    Report(await Act("quarantine", "User quarantined from the Threats screen"));
                }));
        }
        else if (v.Subject is PersistenceSubject pe)
        {
            wrap.Children.Add(Action("Remove this auto-start", true, false, async () =>
            {
                if (!Confirm($"Remove this auto-start entry?\n\n{pe.Entry.Name}\n{pe.Entry.Target}\n\n" +
                             "HERO writes an undo record first, so the entry can be recreated exactly.")) return;
                Report(await Act("removePersistence", "User removed from the Threats screen"));
            }));

            if (pe.Entry.ImagePath.Length > 0 && File.Exists(pe.Entry.ImagePath))
                wrap.Children.Add(Action("Quarantine target file", true, false, async () =>
                {
                    if (!Confirm($"Move this file to HERO's vault?\n\n{pe.Entry.ImagePath}")) return;
                    Report(await Act("quarantine", "User quarantined from the Threats screen"));
                }));
        }

        // Second opinion from the antivirus that already ships with Windows. Free, local, and
        // nothing leaves the machine.
        var targetPath = v.Subject switch
        {
            ProcessSubject p when !p.Process.PathUnavailable => p.Process.ImagePath,
            PersistenceSubject e => e.Entry.ImagePath,
            _ => "",
        };
        if (targetPath.Length > 0)
        {
            wrap.Children.Add(Action("Ask Defender", false, false, async () =>
            {
                status.Visibility = Visibility.Visible;
                status.Text = "Asking Windows Defender to scan this file…";
                status.Foreground = Brush("TextSecondary");
                var result = await DefenderOracle.ScanFileAsync(targetPath);
                status.Text = result.Verdict switch
                {
                    OracleVerdict.Clean => $"Defender scanned it and found nothing ({result.Elapsed.TotalSeconds:F1}s).",
                    OracleVerdict.Threat => $"Defender identified {result.ThreatName}. {result.Detail}",
                    OracleVerdict.Inaccessible => "The file is no longer there.",
                    _ => result.Detail,
                };
                status.Foreground = Brush(result.IsThreat ? "SevCritical" : "SevSafe");
            }));
        }

        // ---- teaching HERO
        wrap.Children.Add(Action("This is expected", false, false, () =>
        {
            // Hash scope, not path scope. A path-only allowlist is a persistence primitive:
            // anything that can later write to that path inherits the approval.
            var result = Guardian.Allow(v.Subject, AllowScope.Hash);
            status.Visibility = Visibility.Visible;

            if (result.Accepted)
            {
                status.Text = "Approved for these exact bytes. This will not come back unless the " +
                              "file itself changes — an approval tied to a path would be a way in " +
                              "for anything that later replaces it.";
                status.Foreground = Brush("SevSafe");
                Refresh();
            }
            else
            {
                // Say why, and offer the fallback, rather than leaving a button that silently
                // does nothing and a finding that reappears ten minutes later.
                status.Text = $"Could not approve this permanently: {result.Reason} " +
                              "Use \"Hide for a week\" instead.";
                status.Foreground = Brush("SevMedium");
            }
        }));

        // Labelled with its actual duration. "Dismiss" implied permanence and delivered none:
        // the persistence inventory refreshes every ten minutes and simply raised it again.
        wrap.Children.Add(Action("Hide for a week", false, false, () =>
        {
            Guardian.Dismiss(v.Subject.Key, TimeSpan.FromDays(7));
            Refresh();
        }));

        return wrap;
    }

    /// <summary>
    /// Re-reads the machine after an action and reports what is actually true now, rather than
    /// what HERO believed a moment ago. This is the difference between "the command returned
    /// success" and "the thing is genuinely gone".
    /// </summary>
    private async Task ConfirmAndRefreshAsync(Verdict v, TextBlock status)
    {
        try
        {
            if (v.Subject is PersistenceSubject ps)
            {
                status.Text += "  Re-checking…";
                var still = await Task.Run(() => Guardian.Recheck(ps.Entry));

                if (still is null)
                    status.Text = "Verified: that auto-start entry is gone.";
                else if (!still.Enabled)
                    status.Text = "Verified: the entry still exists but is now disabled, so it will not run.";
                else
                    status.Text = "Warning: re-checking found the entry still enabled. The change did not take effect.";

                status.Foreground = Brush(still is null || !still.Enabled ? "SevSafe" : "SevHigh");
                if (still is null || !still.Enabled) Guardian.Dismiss(v.Subject.Key);
            }
            else if (v.Subject is ProcessSubject prs)
            {
                await Task.Delay(600);
                bool alive = Guardian.Engine.Latest?.ByPid.ContainsKey(prs.Process.Pid) ?? false;
                status.Text = alive
                    ? status.Text + "  The process is still running."
                    : "Verified: that process is no longer running.";
                if (!alive) Guardian.Dismiss(v.Subject.Key);
            }

            // Rebuild the list so a resolved finding actually leaves the screen.
            await Dispatcher.InvokeAsync(Refresh);
        }
        catch { /* verification is best-effort; the status text already says what was attempted */ }
    }

    private bool Confirm(string message) =>
        MessageBox.Show(message, "HERO", MessageBoxButton.OKCancel,
            MessageBoxImage.Warning, MessageBoxResult.Cancel) == MessageBoxResult.OK;

    private Button Action(string text, bool destructive, bool disabled, Action onClick)
    {
        var button = MakeButton(text, destructive);
        button.IsEnabled = !disabled;
        if (disabled)
        {
            button.Opacity = 0.45;
            button.ToolTip = "This target is on HERO's protected list and cannot be touched, whatever it scores.";
        }
        button.Click += (_, _) => onClick();
        return button;
    }

    private Button Action(string text, bool destructive, bool disabled, Func<Task> onClick)
    {
        var button = MakeButton(text, destructive);
        button.IsEnabled = !disabled;
        button.Click += async (_, _) => await onClick();
        return button;
    }

    private Button MakeButton(string text, bool destructive)
        => HeroButton.Create(text, destructive ? ButtonTone.Destructive : ButtonTone.Neutral, Fs("FsCaption"));

    /// <summary>One Defender detection after grouping. Defender logs the same file repeatedly.</summary>
    internal sealed record DetectionRow(
        DateTime Latest, string ThreatName, string Severity, string Resource, int Occurrences)
    {
        internal string WhenText => Latest.ToString("dd MMM HH:mm");
        internal string CountText => Occurrences == 1 ? "" : $"x{Occurrences}";

        internal Hero.Guardian.Severity Band => Severity switch
        {
            "Severe" => Hero.Guardian.Severity.Critical,
            "High" => Hero.Guardian.Severity.High,
            "Moderate" => Hero.Guardian.Severity.Medium,
            _ => Hero.Guardian.Severity.Low,
        };
    }

    private UIElement BuildDefenderCard(IReadOnlyList<DefenderDetection> detections)
    {
        // Defender writes a 1116 and a 1117 for the same file, and re-logs on every access
        // attempt. Raw, that produced eight identical rows for one trojan. Grouping by
        // (threat, resource) turns the log back into a list of events a person can read.
        var rows = detections
            .Select(d => new { d.When, d.ThreatName, d.Severity, Resource = CleanResource(d.Path) })
            .Where(d => d.ThreatName.Length > 0)
            .GroupBy(d => (d.ThreatName, d.Resource))
            .Select(g => new DetectionRow(
                g.Max(x => x.When),
                g.Key.ThreatName,
                g.Select(x => x.Severity).FirstOrDefault(s => s.Length > 0) ?? "",
                g.Key.Resource,
                g.Count()))
            .OrderByDescending(r => r.Latest)
            .Take(25)
            .ToList();

        var table = new DataTable();
        table.Columns.Add(DataColumn.For<DetectionRow>("When", 130, ColumnKind.Text, r => r.WhenText));
        table.Columns.Add(DataColumn.Risk<DetectionRow>("Severity", 110, (DetectionRow r) => r.Band));
        table.Columns.Add(DataColumn.For<DetectionRow>("Threat", 260, ColumnKind.Identity, r => r.ThreatName));
        table.Columns.Add(DataColumn.For<DetectionRow>("Seen", 70, ColumnKind.Numeric, r => r.CountText));
        table.Columns.Add(DataColumn.For<DetectionRow>("Item", 460, ColumnKind.Mono,
            r => r.Resource, flex: true, middleEllipsis: true));
        table.ItemsSource = rows;

        return Card(table, "Windows Defender detections",
            "Defender's own history, grouped by threat and file. HERO reads it so a detection and " +
            "the process that caused it appear as one story rather than two.");
    }

    /// <summary>
    /// Turns a Defender resource string into something readable.
    ///
    /// Defender records resources as "file:_C:\path", "regkeyvalue:_hklm\...", "driver:_name",
    /// and joins several with semicolons. Showing that raw leaked its internal prefixes into the
    /// UI and made a six-driver detection an unreadable wall of text.
    /// </summary>
    private static string CleanResource(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";

        var parts = raw.Split(';', StringSplitOptions.RemoveEmptyEntries)
                       .Select(p => p.Trim())
                       .Select(StripPrefix)
                       .Where(p => p.Length > 0)
                       .Distinct(StringComparer.OrdinalIgnoreCase)
                       .ToList();

        if (parts.Count == 0) return "";
        if (parts.Count == 1) return parts[0];

        // Several resources: show the first and say how many more, rather than one long line.
        return $"{parts[0]}  (+{parts.Count - 1} more)";
    }

    private static string StripPrefix(string part)
    {
        int marker = part.IndexOf(":_", StringComparison.Ordinal);
        var value = marker >= 0 ? part[(marker + 2)..] : part;

        // Defender appends its own metadata to the path in some events.
        foreach (var tail in new[] { " Detection Origin:", " Detection Type:", " Detection Source:", " Process Name:", " User:", " Signature Version:", " Action:" })
        {
            int cut = value.IndexOf(tail, StringComparison.Ordinal);
            if (cut > 0) value = value[..cut];
        }
        return value.Trim();
    }

    /// <summary>
    /// Adds a "Do it as administrator" button after Windows refused an action for want of rights.
    ///
    /// HERO deliberately runs unelevated, so this relaunches a copy of itself with a single
    /// explicit operation on its command line, which does that one job and exits. The elevated
    /// copy never becomes resident and never holds a token longer than the operation takes.
    /// </summary>
    private void OfferElevation(Verdict v, WrapPanel wrap, TextBlock status, ResponseResult refused)
    {
        const string label = "Do it as administrator";
        if (wrap.Children.OfType<Button>().Any(b => (b.Content as string) == label)) return;

        var request = BuildElevationRequest(v);
        if (request is null) return;

        if (!Elevation.CanElevate)
        {
            status.Text += "  " + Elevation.ExplainState();
            return;
        }

        var button = MakeButton(label, destructive: true);
        button.Click += (_, _) =>
        {
            if (!Confirm("Windows will ask you to approve an administrator prompt.\n\n" +
                         $"HERO will then perform exactly one operation: {request.Operation}.\n\n" +
                         "The elevated copy does that job and exits immediately.")) return;

            var result = Elevation.RunElevated(request, TimeSpan.FromSeconds(90));
            status.Visibility = Visibility.Visible;
            status.Text = result.Message;
            status.Foreground = Brush(result.Ok ? "SevSafe" : "SevMedium");
        };
        wrap.Children.Add(button);
    }

    private static ElevationRequest? BuildElevationRequest(Verdict v) => v.Subject switch
    {
        PersistenceSubject p when p.Entry.Category == PersistenceCategory.Service =>
            new ElevationRequest(ElevatedOperation.ReconfigureService, new[] { p.Entry.Name, "disabled" }),

        // IFEO joins Run and Winlogon here: it is always HKLM, so without an elevated route a
        // detected Debugger hijack had no way to be removed at all.
        PersistenceSubject p when p.Entry.Category is PersistenceCategory.RunKey
                                      or PersistenceCategory.Winlogon
                                      or PersistenceCategory.ImageFileExecutionOptions
                                  && p.Entry.Location.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) =>
            new ElevationRequest(ElevatedOperation.RemoveMachinePersistence,
                new[]
                {
                    p.Entry.Location[5..].Replace(" (WOW64)", ""),

                    // The VALUE, which for IFEO is Debugger rather than the entry's own name.
                    p.Entry.EffectiveValueName,

                    // The marker stripped from the path above says which registry view the value
                    // lives in, and dropping it entirely was the bug: a 32-bit application's Run
                    // entry was deleted from the 64-bit key, which never held it, and the helper
                    // reported success.
                    p.Entry.Location.Contains("(WOW64)", StringComparison.OrdinalIgnoreCase) ? "32" : "64",
                }),

        ProcessSubject p when !p.Process.PathUnavailable =>
            new ElevationRequest(ElevatedOperation.BlockProcessNetwork,
                new[] { p.Process.ImagePath, $"HERO block {p.Process.FileName}" }),

        _ => null,
    };
}
