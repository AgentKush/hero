using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Hero.Maintenance;
using Hero.UI.Controls;

namespace Hero.UI.Views;

/// <summary>
/// Duplicate files.
///
/// This is the only screen in HERO whose output leads a user to delete their own documents, so it
/// is built to be doubted. Three things follow from that and none of them are decoration:
///
///  1. NOTHING RUNS ON ARRIVAL. Every other page starts working the moment it opens; this one
///     waits to be asked. A duplicate scan reads real files and takes real minutes, and starting
///     one because somebody clicked the wrong rail item is a poor trade.
///  2. THE HEADLINE IS WHAT WOULD ACTUALLY BE FREED, not the size of everything that matched.
///     Reporting the group total is the standard way these tools overstate, by exactly one copy
///     per group; and hardlinked names are excluded entirely, because deleting one frees nothing.
///  3. THE KEEPER IS NAMED AND ITS REASON IS SHOWN. A nomination the user cannot interrogate is
///     one they either trust blindly or ignore, and both are bad outcomes for a delete button.
///
/// The page shows results and explains them. It does not delete: that goes through the same
/// measure/preview/execute path as the rest of Maintenance.
/// </summary>
internal sealed class DuplicatesPage : PageBase
{
    internal override bool FillsViewport => true;

    private readonly DataTable _table = new();
    private readonly TextBlock _sub;
    private readonly TextBlock _status = new();
    private readonly FluidProgress _fluid = new();
    private readonly StackPanel _detail = new();
    private readonly Border _detailCard;
    private readonly WrapPanel _drives = new();
    private readonly Button _scan;

    private readonly Dictionary<string, CheckBox> _driveBoxes = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _work;
    private DuplicateReport? _report;

    internal DuplicatesPage()
    {
        _table.Columns.Add(DataColumn.For<GroupRow>("Size", 110, ColumnKind.Numeric, r => r.SizeText));
        _table.Columns.Add(DataColumn.For<GroupRow>("Copies", 80, ColumnKind.Numeric, r => r.Group.Copies.Count.ToString()));
        _table.Columns.Add(DataColumn.For<GroupRow>("Frees", 110, ColumnKind.Numeric, r => r.FreesText));
        // Keep is nullable and genuinely can be null — a group where every copy was disqualified
        // has no keeper. DuplicateGroup.Display already words that case as "nothing (no valid
        // keeper)"; dereferencing it here would instead throw while rendering the row.
        _table.Columns.Add(DataColumn.For<GroupRow>("Keep", 320, ColumnKind.Mono,
            r => r.Group.Keep is { } keep ? Core.Text.MiddleTrim(keep.PrimaryPath, 120) : "no valid keeper",
            middleEllipsis: true));
        _table.Columns.Add(DataColumn.For<GroupRow>("Why this one", 260, ColumnKind.Text,
            r => r.Group.KeepRationale, flex: true));
        _table.SelectionChanged += (_, _) => ShowDetail(_table.SelectedItem as GroupRow);

        // Built explicitly rather than through FillPage, which defines exactly three rows — title,
        // subtitle, and one star row for content. This page needs a fourth for the scan controls
        // and a fifth for the detail panel; putting the controls in the subtitle's row drew the
        // drive checkboxes straight through the sentence underneath them.
        var page = new Grid { Margin = new Thickness(0, 4, 0, 8) };
        foreach (var height in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto })
            page.RowDefinitions.Add(new RowDefinition { Height = height });
        page.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        page.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var head = new TextBlock
        {
            Text = "Duplicates",
            FontSize = Fs("FsDisplay"),
            FontWeight = FontWeights.SemiBold,
            FontFamily = Font("DisplayFont"),
            Foreground = Brush("TextPrimary"),
            Margin = new Thickness(0, 4, 0, 2),
        };
        Grid.SetRow(head, 0);
        page.Children.Add(head);

        _sub = new TextBlock
        {
            FontSize = Fs("FsBodyLarge"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 4),
            Text = "Byte-identical copies of the same file. Nothing is scanned until you ask, and " +
                   "nothing is deleted from this screen.",
        };
        Grid.SetRow(_sub, 1);
        page.Children.Add(_sub);

        // ---- drives + the button that starts it

        var controls = new StackPanel { Margin = new Thickness(0, 6, 0, 14) };

        _drives.Margin = new Thickness(0, 0, 0, 10);
        foreach (var drive in DiskCleanup.FixedDrives())
        {
            var box = new CheckBox
            {
                Content = drive.Name.TrimEnd('\\'),
                IsChecked = true,
                Margin = new Thickness(0, 0, 18, 0),
                Foreground = Brush("TextSecondary"),
                FontSize = Fs("FsBody"),
                VerticalContentAlignment = VerticalAlignment.Center,
            };
            _driveBoxes[drive.Name] = box;
            _drives.Children.Add(box);
        }
        controls.Children.Add(_drives);

        _scan = HeroButton.Create("Find duplicates", ButtonTone.Primary, Fs("FsBody"));
        _scan.HorizontalAlignment = HorizontalAlignment.Left;
        _scan.Click += async (_, _) => await ScanAsync();
        controls.Children.Add(_scan);

        _status.FontSize = Fs("FsCaption");
        _status.Foreground = Brush("TextTertiary");
        _status.Margin = new Thickness(0, 10, 0, 0);
        _status.TextWrapping = TextWrapping.Wrap;
        _status.Text = "Select drives and start a scan. A full scan of four volumes reads a lot of " +
                       "disk, so it is never started for you.";
        controls.Children.Add(_status);

        _fluid.Margin = new Thickness(0, 8, 0, 0);
        _fluid.Height = 18;
        _fluid.Accent = SeverityPalette.Resolve(this, "Accent", Color.FromRgb(0x3B, 0xA5, 0x5D));
        _fluid.Visibility = Visibility.Collapsed;
        controls.Children.Add(_fluid);

        Grid.SetRow(controls, 2);
        page.Children.Add(controls);

        var tableCard = FillCard(_table, "Duplicate sets",
            "Select a set to see every copy, which one HERO would keep and why.");
        Grid.SetRow(tableCard, 3);
        page.Children.Add(tableCard);

        _detailCard = Card(_detail);
        _detailCard.Visibility = Visibility.Collapsed;
        Grid.SetRow(_detailCard, 4);
        page.Children.Add(_detailCard);

        Content = page;
        Unloaded += (_, _) => _work?.Cancel();
    }

    /// <summary>Deliberately empty. See the class comment: this page does not start work by itself.</summary>
    internal override void Refresh() { }

    // ------------------------------------------------------------------ rows

    private sealed class GroupRow
    {
        internal required DuplicateGroup Group { get; init; }

        internal string SizeText => Human.Bytes(Group.LogicalBytes);

        /// <summary>
        /// The group's own reclaim figure, which already excludes the keeper and any copy whose
        /// blocks survive a deletion. A group can legitimately read 0 here — that is the honest
        /// answer for a set that is entirely hardlinked, and hiding it would leave the user
        /// wondering why the totals do not add up.
        /// </summary>
        internal string FreesText => Group.ReclaimableBytes > 0 ? Human.Bytes(Group.ReclaimableBytes) : "nothing";
    }

    // ------------------------------------------------------------------ scanning

    private async Task ScanAsync()
    {
        if (_work is not null) { _work.Cancel(); return; }

        var roots = _driveBoxes.Where(kv => kv.Value.IsChecked == true).Select(kv => kv.Key).ToList();
        if (roots.Count == 0)
        {
            _status.Text = "Pick at least one drive.";
            return;
        }

        _work = new CancellationTokenSource();
        var token = _work.Token;

        _scan.Content = "Stop";
        _fluid.Visibility = Visibility.Visible;
        _fluid.IsIndeterminate = true;
        _fluid.AnimationsEnabled = Motion.Active;
        _table.ItemsSource = null;
        _detailCard.Visibility = Visibility.Collapsed;

        var progress = new Progress<DuplicateProgress>(p =>
        {
            _status.Text = Describe(p);

            // Fraction is -1 for the enumeration stages, which genuinely do not know their total
            // until they finish. Inventing a denominator there produces a bar that jumps backwards,
            // so those stages stay indeterminate and the liquid simply keeps moving.
            if (p.Fraction >= 0) { _fluid.IsIndeterminate = false; _fluid.Progress = p.Fraction; }
            else _fluid.IsIndeterminate = true;
        });

        try
        {
            var report = await Task.Run(() => DuplicateFinder.Scan(roots, null, progress, token), token);
            _report = report;

            _table.ItemsSource = report.Groups
                .Select(g => new GroupRow { Group = g })
                .OrderByDescending(r => r.Group.ReclaimableBytes)
                .ToList();

            _status.Text = report.Display;
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Stopped. Nothing was changed.";
        }
        catch (Exception ex)
        {
            _status.Text = "The scan failed: " + ex.Message;
        }
        finally
        {
            _work?.Dispose();
            _work = null;
            _scan.Content = "Find duplicates";
            _fluid.Visibility = Visibility.Collapsed;
        }
    }

    private static string Describe(DuplicateProgress p) => p.Stage switch
    {
        DuplicateStage.Counting => $"Counting files… {Human.Count(p.FilesSeen)} seen",
        DuplicateStage.Collecting => $"Collecting same-size candidates… {Human.Count(p.Candidates)} so far",
        DuplicateStage.Identity => "Checking which names share one physical file…",
        DuplicateStage.Sampling => $"Sampling {Human.Count(p.Candidates)} candidates…",
        DuplicateStage.Hashing => $"Hashing… {Human.Bytes(p.BytesRead)} of {Human.Bytes(p.BytesToRead)}",
        DuplicateStage.Verifying => "Verifying byte for byte…",
        DuplicateStage.Building => "Building the result…",
        _ => "Done.",
    };

    // ------------------------------------------------------------------ detail

    private void ShowDetail(GroupRow? row)
    {
        _detail.Children.Clear();
        if (row is null) { _detailCard.Visibility = Visibility.Collapsed; return; }

        _detailCard.Visibility = Visibility.Visible;
        var g = row.Group;

        _detail.Children.Add(new TextBlock
        {
            Text = g.Display,
            FontSize = Fs("FsBodyLarge"),
            Foreground = Brush("TextPrimary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10),
        });

        for (int i = 0; i < g.Copies.Count; i++)
        {
            var copy = g.Copies[i];
            bool keep = i == g.KeepIndex;

            var line = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 3, 0, 3) };

            line.Children.Add(new TextBlock
            {
                Text = keep ? "KEEP" : "copy",
                FontSize = Fs("FsMicro"),
                FontWeight = keep ? FontWeights.SemiBold : FontWeights.Normal,
                Foreground = Brush(keep ? "SevSafe" : "TextTertiary"),
                Width = 52,
                VerticalAlignment = VerticalAlignment.Center,
            });

            var paths = new StackPanel();
            foreach (var path in copy.Paths)
            {
                paths.Children.Add(new TextBlock
                {
                    Text = path,
                    FontSize = Fs("FsMono"),
                    FontFamily = Font("MonoFont"),
                    Foreground = Brush(keep ? "TextPrimary" : "TextSecondary"),
                    TextWrapping = TextWrapping.Wrap,
                });
            }

            // Say plainly when a copy cannot free anything, and why. These are the rows a user
            // would otherwise select, delete, and discover had bought them nothing.
            string caveat =
                copy.HasLinksOutsideScan
                    ? $"{copy.LinkCount} hard links exist, some outside this scan — removing these names frees nothing"
                : copy.HasMultipleNamesInScan
                    ? $"{copy.Paths.Count} names for one physical file — all of them must go to free anything"
                : copy.InCloudSyncFolder
                    ? "in a synced folder: deleting here removes it from every device on the account"
                : "";

            if (caveat.Length > 0)
            {
                paths.Children.Add(new TextBlock
                {
                    Text = caveat,
                    FontSize = Fs("FsCaption"),
                    Foreground = Brush("SevMedium"),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 1, 0, 0),
                });
            }

            line.Children.Add(paths);
            _detail.Children.Add(line);
        }
    }
}
