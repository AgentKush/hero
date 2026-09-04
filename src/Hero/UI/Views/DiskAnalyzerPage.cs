using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Hero.Maintenance;
using Hero.UI.Controls;

namespace Hero.UI.Views;

/// <summary>
/// Disk usage: where the space actually went.
///
/// The Maintenance screen answers "what can I safely delete" from a fixed catalogue of known
/// locations. This answers the question people actually arrive with — "the drive is full and I do
/// not know why" — by walking whatever they point at and reporting what is there, including things
/// no cleanup catalogue would ever list because they are not junk. A 40 GB folder of your own video
/// is not a cleanup target, but it is very often the answer.
///
/// Like Duplicates, it does nothing until asked: a full walk of a 930 GB volume reads a lot of
/// disk, and starting one because somebody clicked the wrong rail item is a poor trade.
/// </summary>
internal sealed class DiskAnalyzerPage : PageBase
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

    private readonly List<RadioButton> _driveButtons = new();
    private CancellationTokenSource? _work;

    internal DiskAnalyzerPage()
    {
        // No Depth column. The rollup is three levels deep and the path in the same row already
        // shows how deep each entry goes, so an integer column restated what was next to it.
        _table.Columns.Add(DataColumn.For<FolderRow>("Folder", 460, ColumnKind.Mono,
            r => Core.Text.MiddleTrim(r.Usage.Path, 140), middleEllipsis: true));
        _table.Columns.Add(DataColumn.For<FolderRow>("Size", 120, ColumnKind.Numeric, r => Human.Bytes(r.Usage.Bytes)));
        _table.Columns.Add(DataColumn.For<FolderRow>("Files", 100, ColumnKind.Numeric, r => r.Usage.FileCount.ToString("N0")));
        _table.Columns.Add(DataColumn.For<FolderRow>("Share", 90, ColumnKind.Numeric, r => r.ShareText, flex: true));

        var page = new Grid { Margin = new Thickness(0, 4, 0, 8) };
        // Every row is Auto because the page scrolls; a star row would have nothing to take a share
        // of inside a ScrollViewer that measures its content at infinite height.
        foreach (var h in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto })
            page.RowDefinitions.Add(new RowDefinition { Height = h });

        var head = new TextBlock
        {
            Text = "Disk usage",
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
            Text = "What is using the space on a drive, by folder, by file and by type. Read-only — " +
                   "this screen measures and explains, it never deletes.",
        };
        Grid.SetRow(_sub, 1);
        page.Children.Add(_sub);

        // ---- one drive at a time, because the answer is per-volume

        var controls = new StackPanel { Margin = new Thickness(0, 6, 0, 14) };

        _drives.Margin = new Thickness(0, 0, 0, 10);
        bool first = true;
        foreach (var drive in DiskCleanup.FixedDrives())
        {
            // Radio, not checkbox. "Where did my space go" is a question about ONE volume: free
            // space is per-volume, folder shares are per-volume, and merging four drives into one
            // ranked list produces a table whose percentages mean nothing.
            var button = new RadioButton
            {
                Content = $"{drive.Name.TrimEnd('\\')}  {Human.Bytes(drive.AvailableFreeSpace)} free",
                GroupName = "analyzerDrive",
                IsChecked = first,
                Margin = new Thickness(0, 0, 20, 0),
                Foreground = Brush("TextSecondary"),
                FontSize = Fs("FsBody"),
                Tag = drive.Name,
                VerticalContentAlignment = VerticalAlignment.Center,
            };
            first = false;
            _driveButtons.Add(button);
            _drives.Children.Add(button);
        }
        controls.Children.Add(_drives);

        _scan = HeroButton.Create("Analyse this drive", ButtonTone.Primary, Fs("FsBody"));
        _scan.HorizontalAlignment = HorizontalAlignment.Left;
        _scan.Click += async (_, _) => await AnalyseAsync();
        controls.Children.Add(_scan);

        _status.FontSize = Fs("FsCaption");
        _status.Foreground = Brush("TextTertiary");
        _status.Margin = new Thickness(0, 10, 0, 0);
        _status.TextWrapping = TextWrapping.Wrap;
        _status.Text = "Pick a drive and start. A full volume walk takes a minute or two and is never " +
                       "started for you.";
        controls.Children.Add(_status);

        _fluid.Margin = new Thickness(0, 8, 0, 0);
        _fluid.Height = 18;
        _fluid.Accent = SeverityPalette.Resolve(this, "Accent", Color.FromRgb(0x3B, 0xA5, 0x5D));
        _fluid.Visibility = Visibility.Collapsed;
        controls.Children.Add(_fluid);

        Grid.SetRow(controls, 2);
        page.Children.Add(controls);

        // Both panels are full width and the PAGE scrolls. That is the third arrangement tried here
        // and the only one that fits the content:
        //
        //   stacked, table on a star row  — the summary is Auto and grew to eight categories, ten
        //                                   extensions and ten files, taking the row and collapsing
        //                                   the table to a header strip with zero rows.
        //   side by side                  — gave both their full height but starved both of width:
        //                                   the table clipped mid-value after Size (measured: Files
        //                                   and Share gone entirely) and the summary's count column
        //                                   ran to x=4071 against a content edge at x=4045.
        //
        // Width was never actually scarce — full width fits all five columns and every count. Only
        // vertical space was, so vertical space is what gets a scrollbar.
        var tableCard = FillCard(_table, "Biggest folders",
            "Rolled up three levels from the drive root. Select one to see the largest files inside it.");
        // A fixed height, not a star: inside a scrolling page a star row has no height to take a
        // share of. The table scrolls internally past this many rows.
        tableCard.Height = 460;
        // Belt and braces — DataTable does not clip to its container, so a column set wider than
        // the card paints straight over whatever sits next to it. That is not hypothetical: it drew
        // its header strip across the summary card's rows before this was added.
        tableCard.ClipToBounds = true;
        Grid.SetRow(tableCard, 3);
        page.Children.Add(tableCard);

        _detailCard = Card(_detail);
        _detailCard.Margin = new Thickness(0, 14, 0, 0);
        _detailCard.Visibility = Visibility.Collapsed;
        Grid.SetRow(_detailCard, 4);
        page.Children.Add(_detailCard);

        Content = new ScrollViewer
        {
            Content = page,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        };
        Unloaded += (_, _) => _work?.Cancel();
    }

    /// <summary>Deliberately empty — this page does not start work by itself.</summary>
    internal override void Refresh() { }

    private sealed class FolderRow
    {
        internal required DiskAnalyzer.DirectoryUsage Usage { get; init; }
        internal required long Total { get; init; }

        internal string ShareText => Total > 0 ? $"{100.0 * Usage.Bytes / Total:0.#}%" : "";
    }

    // ------------------------------------------------------------------ scanning

    private async Task AnalyseAsync()
    {
        if (_work is not null) { _work.Cancel(); return; }

        string? root = _driveButtons.FirstOrDefault(b => b.IsChecked == true)?.Tag as string;
        if (string.IsNullOrEmpty(root)) { _status.Text = "Pick a drive first."; return; }

        _work = new CancellationTokenSource();
        var token = _work.Token;

        _scan.Content = "Stop";
        _fluid.Visibility = Visibility.Visible;
        _fluid.IsIndeterminate = true;   // a walk cannot know its own total until it finishes
        _fluid.AnimationsEnabled = Motion.Active;
        _table.ItemsSource = null;
        _detailCard.Visibility = Visibility.Collapsed;

        var progress = new Progress<DiskAnalyzer.AnalyzeProgress>(p =>
            _status.Text = $"Walking {p.CurrentRoot} — {Human.Count(p.FilesSeen)} files, {Human.Bytes(p.BytesSeen)} so far");

        try
        {
            var report = await Task.Run(() => DiskAnalyzer.Analyze(root, progress, token), token);

            _table.ItemsSource = report.TopDirectories
                .Select(d => new FolderRow { Usage = d, Total = report.TotalBytes })
                .ToList();

            _status.Text = report.Display;
            ShowSummary(report);
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Stopped.";
        }
        catch (Exception ex)
        {
            _status.Text = "The scan failed: " + ex.Message;
        }
        finally
        {
            _work?.Dispose();
            _work = null;
            _scan.Content = "Analyse this drive";
            _fluid.Visibility = Visibility.Collapsed;
        }
    }

    // ------------------------------------------------------------------ summary

    private void ShowSummary(DiskAnalyzer.DiskUsageReport report)
    {
        _detail.Children.Clear();
        _detailCard.Visibility = Visibility.Visible;

        _detail.Children.Add(Heading("By type"));

        foreach (var type in report.ByType.Take(8))
        {
            var line = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            line.Children.Add(new TextBlock
            {
                Text = type.Category, Width = 170, FontSize = Fs("FsBody"),
                Foreground = Brush("TextSecondary"),
            });
            line.Children.Add(new TextBlock
            {
                Text = Human.Bytes(type.Bytes), Width = 110, FontSize = Fs("FsBody"),
                FontFamily = Font("MonoFont"), Foreground = Brush("TextPrimary"),
            });
            line.Children.Add(new TextBlock
            {
                Text = $"{type.FileCount:N0} files", FontSize = Fs("FsCaption"),
                Foreground = Brush("TextTertiary"), VerticalAlignment = VerticalAlignment.Center,
            });
            _detail.Children.Add(line);
        }

        // Extensions, because categories alone were not an answer: on E: the biggest category was
        // "Other" at 1.71 TB of 2.61 TB. A user looking at that learns nothing. The extension list
        // needs no vocabulary and names whatever is actually there.
        _detail.Children.Add(Heading("Biggest file types"));

        foreach (var ext in report.ByExtension.Take(10))
        {
            var line = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            line.Children.Add(new TextBlock
            {
                Text = ext.Category, Width = 170, FontSize = Fs("FsMono"),
                FontFamily = Font("MonoFont"), Foreground = Brush("TextSecondary"),
            });
            line.Children.Add(new TextBlock
            {
                Text = Human.Bytes(ext.Bytes), Width = 110, FontSize = Fs("FsBody"),
                FontFamily = Font("MonoFont"), Foreground = Brush("TextPrimary"),
            });
            line.Children.Add(new TextBlock
            {
                Text = $"{ext.FileCount:N0} files", FontSize = Fs("FsCaption"),
                Foreground = Brush("TextTertiary"), VerticalAlignment = VerticalAlignment.Center,
            });
            _detail.Children.Add(line);
        }

        _detail.Children.Add(Heading("Largest files"));

        foreach (var file in report.LargestFiles.Take(10))
        {
            var line = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            line.Children.Add(new TextBlock
            {
                Text = Human.Bytes(file.Bytes), Width = 110, FontSize = Fs("FsBody"),
                FontFamily = Font("MonoFont"), Foreground = Brush("TextPrimary"),
            });
            var path = new TextBlock
            {
                Text = file.Path, FontSize = Fs("FsMono"), FontFamily = Font("MonoFont"),
                Foreground = Brush("TextSecondary"), TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = 900,
            };
            line.Children.Add(path);

            // A sparse file is the one case where the number a user sees elsewhere is wrong. Say so
            // on the row rather than leaving them to wonder why Explorer disagrees.
            if (file.Overstated)
            {
                line.Children.Add(new TextBlock
                {
                    Text = $"  (sparse: {Human.Bytes(file.LogicalBytes)} apparent)",
                    FontSize = Fs("FsCaption"), Foreground = Brush("SevMedium"),
                    VerticalAlignment = VerticalAlignment.Center,
                });
            }

            _detail.Children.Add(line);
        }
    }

    private TextBlock Heading(string text) => new()
    {
        Text = text,
        FontSize = Fs("FsBodyLarge"),
        FontWeight = FontWeights.SemiBold,
        Foreground = Brush("TextPrimary"),
        Margin = new Thickness(0, 10, 0, 6),
    };
}
