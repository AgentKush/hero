using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using Hero.Guardian;
using Hero.Interop;
using Hero.UI.Controls;

namespace Hero.UI.Views;

/// <summary>
/// The Overview: posture at a glance, then the evidence behind it.
///
/// The hero visual is a score, not a threat count, because "3 threats" is frightening and
/// uninformative while a single number with a band label answers the only question the user
/// actually has when they open a security tool: am I all right?
/// </summary>
internal sealed class OverviewPage : PageBase
{
    private readonly ScoreRing _ring = new();
    private readonly TextBlock _postureHeadline = new();
    private readonly TextBlock _postureDetail = new();
    private readonly UniformGrid _stats = new() { Columns = 4, Margin = new Thickness(0, 0, 0, 22) };
    private readonly Sparkline _cpuTrend = new();
    private readonly StackPanel _body = new();
    private readonly TextBlock _sub = new();

    internal OverviewPage()
    {
        var page = Page("Overview", "");
        page.Children.Add(_sub);
        _sub.FontSize = Fs("FsBodyLarge");
        _sub.Foreground = Brush("TextSecondary");
        _sub.Margin = new Thickness(0, -18, 0, 22);
        _sub.TextWrapping = TextWrapping.Wrap;

        page.Children.Add(BuildPostureCard());
        page.Children.Add(_stats);
        page.Children.Add(_body);
        Content = page;
    }

    private UIElement BuildPostureCard()
    {
        _ring.Width = 168;
        _ring.Height = 168;
        _ring.VerticalAlignment = VerticalAlignment.Center;

        var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(28, 0, 0, 0) };
        _postureHeadline.FontSize = Fs("FsTitle");
        _postureHeadline.FontWeight = FontWeights.SemiBold;
        _postureHeadline.FontFamily = Font("DisplayFont");
        _postureHeadline.Foreground = Brush("TextPrimary");
        _postureDetail.FontSize = Fs("FsBody");
        _postureDetail.Foreground = Brush("TextSecondary");
        _postureDetail.TextWrapping = TextWrapping.Wrap;
        _postureDetail.Margin = new Thickness(0, 6, 0, 0);
        _postureDetail.MaxWidth = 620;
        text.Children.Add(_postureHeadline);
        text.Children.Add(_postureDetail);

        _cpuTrend.Height = 44;
        _cpuTrend.Margin = new Thickness(0, 16, 0, 0);
        text.Children.Add(_cpuTrend);

        var row = new StackPanel { Orientation = Orientation.Horizontal };
        row.Children.Add(_ring);
        row.Children.Add(text);
        return Card(row);
    }

    internal override void Refresh()
    {
        var snap = Guardian.Engine.Latest;
        if (snap is null) return;

        var verdicts = Guardian.Verdicts;

        // Distinct image PATHS, not processes. The posture line has always said "distinct images"
        // while counting one entry per process, and those are not the same number anywhere near
        // each other: this machine runs ~350 processes off well under a hundred binaries, with
        // dozens of svchost.exe instances sharing a single file. That inflated the denominator
        // several-fold and made "N unsigned images are running" count one file once per process
        // using it.
        var distinctPaths = snap.Processes
            .Where(p => !p.PathUnavailable && !string.IsNullOrEmpty(p.ImagePath))
            .Select(p => p.ImagePath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Ask for the images this page is about to count. Nothing did, which is why the posture
        // line stuck: the service verifies persistence entries, its own start-up snapshot, and
        // whatever the Network page asks about for connection owners — and nothing else. Any
        // program started after the service warmed up, holding no network connection and absent
        // from the persistence inventory, was therefore counted in the denominator and never
        // looked at, so "Still checking signatures: 31 of 104" could never finish.
        //
        // This is the same omission Pages.cs already fixed for the Network table; the Overview
        // page needed the identical request and never made it. RequestVerification only forwards
        // paths with no answer yet, so repeating it every refresh costs nothing.
        Guardian.RequestVerification(distinctPaths);

        var sigs = distinctPaths
            .Select(Guardian.Verifier.TryGetCached)
            .Where(s => s is not null)
            .ToList();

        int unsigned = sigs.Count(s => s!.State == SignatureState.Unsigned);
        int invalid = sigs.Count(s => s!.State == SignatureState.Invalid);
        int external = snap.Connections.Count(c => c.IsExternal && c.Pid != 0);
        int blind = snap.Processes.Count(p => p.PathUnavailable);

        double score = ComputeScore(verdicts, invalid);
        _ring.AnimationsEnabled = Motion.Active;
        _ring.HasData = true;
        _ring.Score = score;

        var band = ScoreRing.BandFor(score);
        (_postureHeadline.Text, _postureDetail.Text) =
            Narrate(band, verdicts, invalid, unsigned, sigs.Count, distinctPaths.Count);

        // Said before anything else, and said plainly. HERO is watching but writing nothing down,
        // and a reassuring posture line above an empty ledger is exactly the kind of quiet
        // dishonesty this app is supposed to be the opposite of.
        if (Guardian.PersistenceBlocked)
        {
            _postureHeadline.Text = "Watching, but not recording";
            _postureDetail.Text =
                "The guardian service is not running, so nothing seen in this session is being " +
                "written to the timeline, the baseline or the vault. Live views below are accurate. " +
                "Starting the HERO Guardian service restores the record.";
        }

        _sub.Text = $"{snap.Processes.Count} processes · {snap.Connections.Count} sockets · " +
                    $"poll {Guardian.Engine.LastPollMilliseconds:F0}ms " +
                    $"(avg {Guardian.Engine.AveragePollMilliseconds:F0}ms)";

        _cpuTrend.Push(Guardian.Engine.LastPollMilliseconds);

        // Tiles are built once and then updated in place. Rebuilding them every tick discarded and
        // recreated visual elements once a second, which is both wasteful and a source of flicker.
        SetStat(0, "Processes", snap.Processes.Count.ToString(), "SevSafe");
        SetStat(1, "External peers", external.ToString(), "SevLow");
        SetStat(2, "Findings", verdicts.Count.ToString(), verdicts.Count > 0 ? "SevMedium" : "SevSafe");
        SetStat(3, "Needs elevation", blind.ToString(), "SevLow");

        // The lists below only change when their contents change. Rebuilding them on every tick
        // made rows flicker and made text impossible to select.
        var fingerprint = string.Join("|", Guardian.RecentStarts.Take(10).Select(p => p.Pid))
                        + "#" + string.Join("|", snap.Processes
                              .Where(p => !p.PathUnavailable)
                              .Select(p => Guardian.Verifier.TryGetCached(p.ImagePath))
                              .Count(s => s is not null && s.State is SignatureState.Unsigned or SignatureState.Invalid));
        if (fingerprint == _bodyFingerprint) return;
        _bodyFingerprint = fingerprint;

        _body.Children.Clear();

        // Recently started processes: the highest-signal thing HERO sees.
        var recent = Guardian.RecentStarts.Take(10).ToList();
        if (recent.Count > 0)
        {
            var panel = new StackPanel();
            foreach (var p in recent)
                panel.Children.Add(Row(p.FileName,
                    p.CommandLine.Length > 0 ? p.CommandLine : p.ImagePath,
                    Guardian.Verifier.TryGetCached(p.ImagePath)?.Describe() ?? "checking…"));
            _body.Children.Add(Card(panel, "Recently started", null));
        }

        // Unsigned images, framed honestly rather than alarmingly.
        var unsignedList = snap.Processes
            .Where(p => !p.PathUnavailable)
            .Select(p => (p, s: Guardian.Verifier.TryGetCached(p.ImagePath)))
            .Where(x => x.s is not null && x.s.State is SignatureState.Unsigned or SignatureState.Invalid)
            .GroupBy(x => x.p.ImagePath, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        if (unsignedList.Count > 0)
        {
            var panel = new StackPanel();
            foreach (var (p, s) in unsignedList.Take(12))
                panel.Children.Add(Row(p.FileName, p.ImagePath, s!.State.ToString()));

            _body.Children.Add(Card(panel, "Unsigned running images",
                "Unsigned is a weak signal on a developer machine — Python venv shims, uv caches and " +
                "toolchain binaries are routinely unsigned, and so is one of Microsoft's own Widgets " +
                "components. HERO scores these low alone and acts only when unsigned coincides with " +
                "other independent evidence."));
        }

        // Entrance motion plays ONCE, when the page is first shown.
        //
        // Running it on every refresh made the whole page visibly flash once a second, because
        // each pass reset opacity to zero and faded back in. Entrance animation is for arriving
        // at a screen; a live screen that keeps re-arriving is just a strobe.
        if (!_hasAnimatedIn)
        {
            _hasAnimatedIn = true;
            Motion.StaggerIn(_stats.Children.OfType<UIElement>());
            Motion.StaggerIn(_body.Children.OfType<UIElement>(), riseFrom: 12);
        }
    }

    private bool _hasAnimatedIn;

    /// <summary>
    /// Posture score, 0 (bad) to 100 (good).
    ///
    /// Deliberately starts at 100 and subtracts for concrete findings, rather than accumulating
    /// points for vague "risk factors". A machine with nothing wrong should read 100, not 84,
    /// because a gauge that never reaches full teaches the user to ignore it.
    /// </summary>
    private static double ComputeScore(IReadOnlyList<Verdict> verdicts, int invalidSignatures)
    {
        double score = 100;
        foreach (var v in verdicts)
        {
            score -= v.Confidence switch
            {
                Confidence.High => 35,
                Confidence.Medium => 15,
                Confidence.Low => 4,
                _ => 0,
            };
        }
        // A binary whose signature is present but broken means tampering, expiry or an untrusted
        // issuer. That is materially worse than unsigned and always worth points.
        score -= invalidSignatures * 10;
        return Math.Clamp(score, 0, 100);
    }

    private static (string, string) Narrate(Severity band, IReadOnlyList<Verdict> verdicts,
                                            int invalid, int unsigned, int checkedImages, int totalImages)
    {
        if (verdicts.Count == 0 && invalid == 0)
        {
            // Do not report a count until it means something. Signature verification runs in the
            // background at roughly 22ms per unseen image, so for the first seconds after launch
            // the cache is nearly empty — and "0 unsigned images are running" read as a finding
            // when it was really "nothing checked yet". Stating a reassuring number HERO has not
            // earned is exactly the habit that makes a security tool untrustworthy.
            if (checkedImages < totalImages)
                return ("All clear so far",
                    $"Nothing on this machine is behaving suspiciously. Still checking signatures: " +
                    $"{checkedImages} of {totalImages} distinct images verified.");

            return ("All clear",
                unsigned == 0
                    ? "Nothing on this machine is behaving suspiciously, and every running image is signed."
                    : $"Nothing on this machine is behaving suspiciously. {unsigned} unsigned " +
                      (unsigned == 1 ? "image is" : "images are") +
                      " running, which on a developer machine is normal and not by itself a concern.");
        }

        int high = verdicts.Count(v => v.Confidence == Confidence.High);
        if (high > 0)
            return ($"{high} high-confidence finding{(high == 1 ? "" : "s")}",
                "Several independent signals agree on these. Open Threats to see the evidence behind each one.");

        return ($"{verdicts.Count} thing{(verdicts.Count == 1 ? "" : "s")} worth a look",
            "Nothing here is conclusive on its own. HERO is showing you the working rather than acting on it.");
    }

    private string _bodyFingerprint = "";
    private readonly List<(TextBlock Value, TextBlock Label)> _statCells = new();

    /// <summary>
    /// Builds a tile the first time, then only rewrites its text and colour.
    ///
    /// The tiles update once a second. Recreating four Borders, eight TextBlocks and their
    /// layout every tick is pure churn, and combined with the entrance animation it was visible
    /// as a flash. Mutating two strings is what an update actually is.
    /// </summary>
    private void SetStat(int index, string label, string value, string severityKey)
    {
        if (index >= _stats.Children.Count)
            _stats.Children.Add(Stat(label, value, severityKey));

        if (index >= _statCells.Count) return;

        var (valueBlock, labelBlock) = _statCells[index];
        if (valueBlock.Text != value) valueBlock.Text = value;
        if (labelBlock.Text != label) labelBlock.Text = label;
        valueBlock.Foreground = Brush(severityKey);
    }

    private UIElement Stat(string label, string value, string severityKey)
    {
        var panel = new StackPanel();
        var valueBlock = new TextBlock
        {
            Text = value,
            FontSize = Fs("FsStatValue"),
            FontWeight = FontWeights.SemiBold,
            FontFamily = Font("DisplayFont"),
            Foreground = Brush(severityKey),
        };
        panel.Children.Add(valueBlock);

        var labelBlock = new TextBlock
        {
            Text = label,
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            Margin = new Thickness(0, 3, 0, 0),
        };
        panel.Children.Add(labelBlock);
        _statCells.Add((valueBlock, labelBlock));

        return new Border
        {
            Background = Brush("Surface2"),
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(18, 16, 18, 16),
            Margin = new Thickness(0, 0, 14, 0),
            Child = panel,
        };
    }

    /// <summary>
    /// One aligned row. Every value is flattened to a single line first: these strings come from
    /// the machine and routinely contain newlines, which no amount of TextTrimming will fix.
    /// </summary>
    private UIElement Row(string primary, string secondary, string tag)
    {
        primary = Core.Text.OneLine(primary, 60);
        secondary = Core.Text.OneLine(secondary, 220);
        tag = Core.Text.OneLine(tag, 40);

        var grid = new Grid { Margin = new Thickness(0, 4, 0, 4) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var a = new TextBlock { Text = primary, FontSize = Fs("FsBody"), Foreground = Brush("TextPrimary"), TextTrimming = TextTrimming.CharacterEllipsis };
        var b = new TextBlock
        {
            Text = secondary,
            TextWrapping = TextWrapping.NoWrap,
            FontSize = Fs("FsMono"),
            FontFamily = Font("MonoFont"),
            Foreground = Brush("TextTertiary"),
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(10, 1, 10, 0),
        };
        var c = new TextBlock { Text = tag, FontSize = Fs("FsCaption"), Foreground = Brush("TextSecondary") };
        Grid.SetColumn(a, 0); Grid.SetColumn(b, 1); Grid.SetColumn(c, 2);
        grid.Children.Add(a); grid.Children.Add(b); grid.Children.Add(c);
        return grid;
    }
}
