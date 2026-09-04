using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Hero.Guardian;
using Hero.Interop;
using Hero.UI.Controls;

namespace Hero.UI.Views;

/// <summary>
/// Shared page furniture. Every screen gets the same title block, the same card treatment and the
/// same empty state, so the app reads as one product rather than nine separately-built screens.
/// </summary>
internal abstract class PageBase : UserControl
{
    protected readonly GuardianService Guardian = GuardianService.Current;

    /// <summary>Called when the page becomes visible. Pages pull; nothing pushes into a hidden page.</summary>
    internal abstract void Refresh();

    protected StackPanel Page(string title, string subtitle)
    {
        var stack = new StackPanel { Margin = new Thickness(0, 4, 0, 30) };
        stack.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = Fs("FsDisplay"),
            FontWeight = FontWeights.SemiBold,
            FontFamily = Font("DisplayFont"),
            Foreground = Brush("TextPrimary"),
            Margin = new Thickness(0, 4, 0, 2),
        });
        stack.Children.Add(new TextBlock
        {
            Name = "Sub",
            Text = subtitle,
            FontSize = Fs("FsBodyLarge"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 22),
        });
        return stack;
    }

    protected Border Card(UIElement child, string? heading = null, string? note = null)
    {
        var inner = new StackPanel();
        if (heading is not null)
            inner.Children.Add(new TextBlock
            {
                Text = heading,
                FontSize = Fs("FsSection"),
                FontWeight = FontWeights.SemiBold,
                FontFamily = Font("DisplayFont"),
                Foreground = Brush("TextPrimary"),
            });
        if (note is not null)
            inner.Children.Add(new TextBlock
            {
                Text = note,
                FontSize = Fs("FsCaption"),
                Foreground = Brush("TextSecondary"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 12),
            });
        inner.Children.Add(child);

        return new Border
        {
            Style = TryFindResource("Card") as Style,
            Child = inner,
        };
    }

    protected UIElement Empty(string headline, string detail)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 28, 0, 32), HorizontalAlignment = HorizontalAlignment.Center };
        panel.Children.Add(new TextBlock
        {
            Text = headline,
            FontSize = Fs("FsSection"),
            Foreground = Brush("TextSecondary"),
            HorizontalAlignment = HorizontalAlignment.Center,
        });
        panel.Children.Add(new TextBlock
        {
            Text = detail,
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextTertiary"),
            TextWrapping = TextWrapping.Wrap,
            TextAlignment = TextAlignment.Center,
            MaxWidth = 460,
            Margin = new Thickness(0, 6, 0, 0),
            HorizontalAlignment = HorizontalAlignment.Center,
        });
        return panel;
    }

    protected double Fs(string key) => TryFindResource(key) is double d ? d : 14.0;
    protected Brush Brush(string key) => TryFindResource(key) as Brush ?? Brushes.Gray;
    protected FontFamily Font(string key) => TryFindResource(key) as FontFamily ?? new FontFamily("Segoe UI");

    // ------------------------------------------------------------------ viewport fitting

    /// <summary>
    /// Height of the area a page is drawn into, in device-independent pixels. Set by the shell
    /// whenever the window is resized.
    /// </summary>
    internal static double ViewportHeight { get; private set; } = 800;

    private static readonly List<WeakReference<PageBase>> LivePages = new();
    private readonly List<(FrameworkElement Element, double Fraction, double Minimum)> _fitted = new();

    protected PageBase()
    {
        // Weak, because pages are cached by the shell for the life of the window and a strong
        // static list would be a leak by construction.
        lock (LivePages) LivePages.Add(new WeakReference<PageBase>(this));
    }

    /// <summary>Called by the shell on resize; re-fits every page that has registered elements.</summary>
    internal static void SetViewportHeight(double height)
    {
        if (height <= 0 || Math.Abs(height - ViewportHeight) < 1) return;
        ViewportHeight = height;

        lock (LivePages)
        {
            LivePages.RemoveAll(w => !w.TryGetTarget(out _));
            foreach (var w in LivePages)
                if (w.TryGetTarget(out var page)) page.ApplyFit();
        }
    }

    /// <summary>
    /// Caps an element's height to a share of the visible area.
    ///
    /// Kept for pages that genuinely scroll. Pages whose main content is one big table should
    /// override <see cref="FillsViewport"/> and use <see cref="FillPage"/> instead: a fixed
    /// fraction either overflows a short window or, on a maximised 4K display, leaves a third of
    /// the screen empty below the table.
    /// </summary>
    protected void FitToViewport(FrameworkElement element, double fraction = 0.58, double minimum = 240)
    {
        _fitted.Add((element, fraction, minimum));
        ApplyFit();
    }

    private void ApplyFit()
    {
        foreach (var (element, fraction, minimum) in _fitted)
            element.MaxHeight = Math.Max(minimum, ViewportHeight * fraction);
    }

    /// <summary>
    /// True when this page should be sized to the viewport rather than scrolled by the shell.
    ///
    /// A page dominated by a table wants the table to grow into whatever room the window has:
    /// the shell stops scrolling it, gives it exactly the viewport height, and the table's own
    /// star-sized row takes the remainder. That is what makes a maximised window show more rows
    /// instead of more background.
    /// </summary>
    internal virtual bool FillsViewport => false;

    /// <summary>
    /// How often this page wants re-reading while it is on screen. Zero means only on navigation.
    ///
    /// Tables deliberately do NOT refresh at the engine's 1 Hz: rebuilding several hundred rows
    /// every second moves the row under the pointer and makes text impossible to select. A slower
    /// beat is enough for background work — signature verification, reverse DNS — to appear.
    /// </summary>
    internal virtual TimeSpan LiveInterval => TimeSpan.Zero;

    /// <summary>When this page last pulled data. Used by the shell to honour LiveInterval.</summary>
    internal DateTime LastRefreshUtc { get; set; } = DateTime.MinValue;

    /// <summary>
    /// Page scaffolding for a fill-the-viewport page: title and subtitle at natural height, then
    /// one star-sized row that the caller puts the table into.
    /// </summary>
    protected Grid FillPage(string title, out TextBlock subtitle)
    {
        var grid = new Grid { Margin = new Thickness(0, 4, 0, 8) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // title
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // subtitle
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        var head = new TextBlock
        {
            Text = title,
            FontSize = Fs("FsDisplay"),
            FontWeight = FontWeights.SemiBold,
            FontFamily = Font("DisplayFont"),
            Foreground = Brush("TextPrimary"),
            Margin = new Thickness(0, 4, 0, 2),
        };
        Grid.SetRow(head, 0);
        grid.Children.Add(head);

        subtitle = new TextBlock
        {
            FontSize = Fs("FsBodyLarge"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 18),
        };
        Grid.SetRow(subtitle, 1);
        grid.Children.Add(subtitle);

        return grid;
    }

    /// <summary>Places content in the star-sized row of a <see cref="FillPage"/> grid.</summary>
    protected void FillWith(Grid page, UIElement content, int row = 2)
    {
        Grid.SetRow(content, row);
        page.Children.Add(content);
    }

    /// <summary>
    /// A card whose body grows to fill the space the card is given.
    ///
    /// <see cref="Card"/> lays its contents out in a StackPanel, which hands every child its
    /// natural height — so a table inside one keeps rendering all 358 rows no matter how much
    /// room the card has. This uses a Grid with a star row so the body gets exactly the leftover
    /// space and scrolls within it.
    /// </summary>
    protected Border FillCard(UIElement child, string? heading = null, string? note = null)
    {
        var grid = new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // heading
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // note
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        if (heading is not null)
        {
            var h = new TextBlock
            {
                Text = heading,
                FontSize = Fs("FsSection"),
                FontWeight = FontWeights.SemiBold,
                FontFamily = Font("DisplayFont"),
                Foreground = Brush("TextPrimary"),
            };
            Grid.SetRow(h, 0);
            grid.Children.Add(h);
        }

        if (note is not null)
        {
            var n = new TextBlock
            {
                Text = note,
                FontSize = Fs("FsCaption"),
                Foreground = Brush("TextSecondary"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 12),
            };
            Grid.SetRow(n, 1);
            grid.Children.Add(n);
        }

        Grid.SetRow(child, 2);
        grid.Children.Add(child);

        return new Border
        {
            Style = TryFindResource("Card") as Style,
            Child = grid,
        };
    }
}

// ===================================================================== processes

internal sealed class ProcessesPage : PageBase
{
    internal override bool FillsViewport => true;

    private readonly DataTable _table = new();
    private readonly TextBlock _sub;

    internal ProcessesPage()
    {
        _table.Columns.Add(DataColumn.For<ProcessRecord>("Process", 210, ColumnKind.Identity, p => p.FileName));
        _table.Columns.Add(DataColumn.For<ProcessRecord>("PID", 70, ColumnKind.MonoNumeric, p => p.Pid.ToString()));
        _table.Columns.Add(DataColumn.For<ProcessRecord>("Parent", 150, ColumnKind.Text, p => ParentName(p)));
        _table.Columns.Add(DataColumn.For<ProcessRecord>("Integrity", 90, ColumnKind.Text, p => p.Integrity.ToString()));
        _table.Columns.Add(DataColumn.For<ProcessRecord>("Signature", 190, ColumnKind.Text, SignatureText));
        _table.Columns.Add(DataColumn.For<ProcessRecord>("Command line", 420, ColumnKind.Mono,
            p => Core.Text.OneLine(p.CommandLine.Length > 0 ? p.CommandLine : p.ImagePath, 300), flex: true, middleEllipsis: true));

        // Fill the window: the table takes every pixel the shell can spare, so a maximised
        // window shows more rows rather than more empty background.
        var page = FillPage("Processes", out _sub);
        FillWith(page, FillCard(_table));
        Content = page;
    }

    private static string ParentName(ProcessRecord p)
    {
        var snap = GuardianService.Current.Engine.Latest;
        return snap is not null && snap.ByPid.TryGetValue(p.ParentPid, out var parent) ? parent.Name : $"({p.ParentPid})";
    }

    private static string SignatureText(ProcessRecord p)
    {
        if (p.PathUnavailable) return "requires elevation";
        var sig = GuardianService.Current.Verifier.TryGetCached(p.ImagePath);
        return sig?.Describe() ?? "checking…";
    }

    internal override void Refresh()
    {
        var snap = Guardian.Engine.Latest;
        if (snap is null) return;

        int blind = snap.Processes.Count(p => p.PathUnavailable);
        _sub.Text = $"{snap.Processes.Count} running. {blind} cannot be fully read without elevation — " +
                    "these are SYSTEM-integrity processes, which is also the one thing malware cannot " +
                    "become without already owning the machine.";

        _table.ItemsSource = snap.Processes
            .OrderBy(p => p.PathUnavailable)
            .ThenBy(p => p.FileName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}

// ===================================================================== network

internal sealed class NetworkPage : PageBase
{
    internal override bool FillsViewport => true;

    private readonly DataTable _table = new();
    private readonly TextBlock _sub;

    private PeerAssessor Assessor => Guardian.Peers;

    internal NetworkPage()
    {
        // Verdict as a WORD, not only a pill: SeverityPill deliberately draws nothing at Safe, so
        // a pill-only column left most rows blank and read as broken rather than reassuring.
        _table.Columns.Add(DataColumn.For<ConnectionRow>("Verdict", 140, ColumnKind.Text,
            r => r.VerdictText));
        _table.Columns.Add(DataColumn.For<ConnectionRow>("Process", 180, ColumnKind.Identity, r => r.ProcessName));
        _table.Columns.Add(DataColumn.For<ConnectionRow>("Peer", 280, ColumnKind.Mono,
            r => r.PeerText, middleEllipsis: true));
        _table.Columns.Add(DataColumn.For<ConnectionRow>("Port", 70, ColumnKind.MonoNumeric,
            r => r.Connection.RemotePort > 0 ? r.Connection.RemotePort.ToString() : ""));
        _table.Columns.Add(DataColumn.For<ConnectionRow>("Why", 520, ColumnKind.Text,
            r => r.Assessment.Reason, flex: true));

        // Fill the window: the table takes every pixel the shell can spare, so a maximised
        // window shows more rows rather than more empty background.
        var page = FillPage("Network", out _sub);
        FillWith(page, FillCard(_table));
        Content = page;
    }

    internal sealed record ConnectionRow(Connection Connection, string ProcessName, PeerAssessment Assessment)
    {
        /// <summary>Hostname when one is known, otherwise the address.</summary>
        internal string PeerText => Assessment.Host.Length > 0
            ? Assessment.Host
            : Connection.RemoteAddress?.ToString() ?? "";

        internal string VerdictText => Assessment.Verdict switch
        {
            PeerVerdict.Local => Connection.IsListening ? "listening" : "local",
            PeerVerdict.Unknown => "checking…",
            PeerVerdict.Familiar => "familiar",
            PeerVerdict.Ordinary => "ordinary",
            PeerVerdict.Unusual => "worth a look",
            PeerVerdict.Suspicious => "suspicious",
            _ => "",
        };

        /// <summary>External first, then worst first. Local chatter must never bury a real peer.</summary>
        internal int SortRank => (Connection.IsExternal ? 0 : 100) + Assessment.Verdict switch
        {
            PeerVerdict.Suspicious => 0,
            PeerVerdict.Unusual => 1,
            PeerVerdict.Unknown => 2,
            PeerVerdict.Ordinary => 3,
            PeerVerdict.Familiar => 4,
            _ => 4,
        };
    }

    internal override TimeSpan LiveInterval => TimeSpan.FromSeconds(3);

    internal override void Refresh()
    {
        var snap = Guardian.Engine.Latest;
        if (snap is null) return;

        // Make sure the owners of live connections actually get verified. Without this the table
        // could sit on "still checking" indefinitely for a program that started before HERO did
        // and has not been re-seen since.
        Guardian.RequestVerification(snap.Connections
            .Where(c => c.Pid != 0 && c.IsExternal)
            .Select(c => snap.ByPid.TryGetValue(c.Pid, out var o) ? o.ImagePath : "")
            .Where(p => p.Length > 0));

        var rows = snap.Connections
            // PID 0 owns TIME_WAIT rows; attributing them to a process would invent one.
            .Where(c => c.Pid != 0)
            // One row per (program, peer, port). A browser opens a dozen sockets to the same
            // endpoint; listing each separately filled the screen with identical lines and buried
            // everything else.
            .GroupBy(c => (c.Pid, Peer: c.RemoteAddress?.ToString() ?? "", c.RemotePort, c.IsListening))
            .Select(g => g.First())
            .Select(c =>
            {
                snap.ByPid.TryGetValue(c.Pid, out var owner);
                var signature = owner is { PathUnavailable: false }
                    ? Guardian.Verifier.TryGetCached(owner.ImagePath)
                    : null;
                var assessment = Assessor.Assess(c, owner, signature, Guardian.Baseline);
                return new ConnectionRow(c, owner?.FileName ?? $"pid {c.Pid}", assessment);
            })
            // External first, worst first. Eighty rows of loopback chatter must never sit above
            // the one connection that actually leaves the machine.
            .OrderBy(r => r.SortRank)
            .ThenBy(r => r.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        int external = rows.Count(r => r.Connection.IsExternal);
        int suspicious = rows.Count(r => r.Assessment.Verdict == PeerVerdict.Suspicious);
        int unusual = rows.Count(r => r.Assessment.Verdict == PeerVerdict.Unusual);

        _sub.Text =
            $"{external} connections leave this machine; {rows.Count - external} are loopback or " +
            $"this network. " +
            (suspicious + unusual == 0
                ? "None of the outbound ones look out of place."
                : $"{suspicious} suspicious, {unusual} worth a look — those are listed first.") +
            " Judged from the owning program's signature, whether HERO has seen that program use " +
            "this endpoint before, and what the port conventionally means. No third-party lookups.";

        _table.ItemsSource = rows;
    }
}

// ===================================================================== persistence

internal sealed class PersistencePage : PageBase
{
    internal override bool FillsViewport => true;

    private readonly DataTable _table = new();
    private readonly TextBlock _sub;

    internal PersistencePage()
    {
        _table.Columns.Add(DataColumn.For<PersistenceEntry>("Name", 240, ColumnKind.Identity, e => e.Name));
        _table.Columns.Add(DataColumn.For<PersistenceEntry>("Kind", 150, ColumnKind.Text, e => e.Category.ToString()));
        _table.Columns.Add(DataColumn.For<PersistenceEntry>("On", 60, ColumnKind.Text, e => e.Enabled ? "yes" : "no"));
        _table.Columns.Add(DataColumn.For<PersistenceEntry>("Signature", 190, ColumnKind.Text, SignatureText));
        _table.Columns.Add(DataColumn.For<PersistenceEntry>("Target", 460, ColumnKind.Mono,
            e => Core.Text.OneLine(e.ImagePath.Length > 0 ? e.ImagePath : e.Target, 300), flex: true, middleEllipsis: true));

        // Fill the window: the table takes every pixel the shell can spare, so a maximised
        // window shows more rows rather than more empty background.
        var page = FillPage("Persistence", out _sub);
        FillWith(page, FillCard(_table));
        Content = page;
    }

    private static string SignatureText(PersistenceEntry e)
    {
        if (e.ImagePath.Length == 0) return "";
        var sig = GuardianService.Current.Verifier.TryGetCached(e.ImagePath);
        return sig?.Describe() ?? "not checked";
    }

    internal override void Refresh()
    {
        var entries = Guardian.Persistence;
        if (entries.Count == 0)
        {
            _sub.Text = "Taking the first inventory…";
            return;
        }

        int untrusted = entries.Count(e =>
        {
            if (e.ImagePath.Length == 0) return false;
            var s = GuardianService.Current.Verifier.TryGetCached(e.ImagePath);
            return s is not null && s.State is SignatureState.Unsigned or SignatureState.Invalid;
        });

        var scanned = Guardian.PersistenceScannedUtc?.ToLocalTime().ToString("HH:mm:ss") ?? "—";
        _sub.Text = $"{entries.Count} ways software has arranged to run again on this machine. " +
                    (untrusted == 0
                        ? "All of their targets are signed. "
                        : untrusted == 1
                            ? "One of them is unsigned or invalidly signed. "
                            : $"{untrusted} of them are unsigned or invalidly signed. ") +
                    $"Last inventory {scanned}.";

        _table.ItemsSource = entries
            .OrderBy(e => e.Category.ToString(), StringComparer.Ordinal)
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}

// ===================================================================== quarantine

internal sealed class QuarantinePage : PageBase
{
    private readonly TextBlock _sub = new();
    private readonly StackPanel _items = new();
    private readonly StackPanel _host;

    internal QuarantinePage()
    {
        _host = Page("Quarantine vault", "");
        _host.Children.Add(_sub);
        _sub.FontSize = Fs("FsBodyLarge");
        _sub.Foreground = Brush("TextSecondary");
        _sub.Margin = new Thickness(0, -18, 0, 22);
        _sub.TextWrapping = TextWrapping.Wrap;
        _host.Children.Add(_items);
        Content = _host;
    }

    internal override void Refresh()
    {
        var items = Guardian.Vault.List();
        _items.Children.Clear();

        _sub.Text = items.Count == 0
            ? "Nothing is quarantined. HERO never deletes on its own: anything it removes is moved " +
              "here with a manifest complete enough to restore it byte-for-byte, including " +
              "timestamps and permissions."
            : $"{items.Count} item(s) held in {Core.HeroPaths.VaultDir}. Each can be put back exactly " +
              "as it was, or destroyed permanently.";

        if (items.Count == 0)
        {
            _items.Children.Add(Card(Empty("Vault is empty",
                "This is the state you want. When HERO does quarantine something, it appears here " +
                "with everything needed to undo the decision.")));
            return;
        }

        foreach (var m in items) _items.Children.Add(BuildItem(m));
    }

    /// <summary>
    /// One vault entry, rendered as a card rather than a table row.
    ///
    /// A vault holds few items and each one poses a decision, so the actions belong next to the
    /// evidence. A table would make the user select a row and then hunt for a toolbar.
    /// </summary>
    private UIElement BuildItem(QuarantineManifest m)
    {
        var panel = new StackPanel();

        panel.Children.Add(new TextBlock
        {
            Text = Path.GetFileName(m.OriginalPath),
            FontSize = Fs("FsSection"),
            FontWeight = FontWeights.SemiBold,
            FontFamily = Font("DisplayFont"),
            Foreground = Brush("TextPrimary"),
        });

        panel.Children.Add(new TextBlock
        {
            Text = m.OriginalPath,
            FontSize = Fs("FsMono"),
            FontFamily = Font("MonoFont"),
            Foreground = Brush("TextTertiary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 0, 0),
        });

        panel.Children.Add(new TextBlock
        {
            Text = $"Quarantined {m.QuarantinedUtc.ToLocalTime():dd MMM yyyy HH:mm} · {m.Length:N0} bytes · " +
                   (m.ContentEncoded ? "content masked" : "content stored verbatim") +
                   (string.IsNullOrEmpty(m.Sha256) ? " · hash unavailable" : $" · SHA-256 {m.Sha256[..16]}…"),
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0),
        });

        if (m.Reason.Length > 0)
            panel.Children.Add(new TextBlock
            {
                Text = m.Reason,
                FontSize = Fs("FsCaption"),
                Foreground = Brush("TextTertiary"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 6, 0, 0),
            });

        var status = new TextBlock
        {
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 10, 0, 0),
            Visibility = Visibility.Collapsed,
        };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 14, 0, 0) };

        var restore = ActionButton("Restore to original location", false);
        restore.Click += (_, _) =>
        {
            // Routed through the guardian rather than straight at the vault: when HERO runs as a
            // service the vault lives under %ProgramData% and only SYSTEM may write it.
            var result = Guardian.VaultRestore(m.Id);
            status.Visibility = Visibility.Visible;
            status.Text = result.Message;
            status.Foreground = Brush(result.Acted ? "SevSafe" : "SevHigh");
            if (result.Acted) Refresh();
        };

        var delete = ActionButton("Delete permanently", true);
        delete.Click += (_, _) =>
        {
            // Destroying data is the one thing HERO cannot undo, so it asks even though the user
            // clicked the button. The dialog names the file rather than saying "this item".
            var answer = MessageBox.Show(
                $"Permanently destroy the quarantined copy of:\n\n{m.OriginalPath}\n\n" +
                "The file is overwritten before being removed and cannot be recovered afterwards.",
                "Delete from vault",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning,
                MessageBoxResult.Cancel);

            if (answer != MessageBoxResult.OK) return;

            var result = Guardian.VaultDelete(m.Id);
            status.Visibility = Visibility.Visible;
            status.Text = result.Message;
            status.Foreground = Brush(result.Acted ? "TextSecondary" : "SevHigh");
            if (result.Acted) Refresh();
        };

        buttons.Children.Add(restore);
        buttons.Children.Add(delete);
        panel.Children.Add(buttons);
        panel.Children.Add(status);

        return Card(panel);
    }

    private Button ActionButton(string text, bool destructive)
        => HeroButton.Create(text, destructive ? ButtonTone.Destructive : ButtonTone.Neutral, Fs("FsCaption"));
}
