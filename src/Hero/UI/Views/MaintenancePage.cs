using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Hero.Maintenance;
using Hero.UI.Controls;

namespace Hero.UI.Views;

/// <summary>
/// The Maintenance screen.
///
/// C: has 88.5 GB free of roughly 930 GB on this machine and is its tightest resource, so
/// reclaimable space is the headline number.
///
/// The page shows every target the moment it opens and fills in sizes as they are measured.
/// It previously started blank and populated in one go when the whole sweep finished, which
/// looked broken: a walk over the Windows Update cache and the uv cache takes tens of seconds,
/// and for all of that time the screen said nothing at all.
///
/// Nothing here deletes without an explicit, named confirmation. Measure, preview and execute are
/// three separate operations and the page never runs the third on its own.
/// </summary>
internal sealed class MaintenancePage : PageBase
{
    internal override bool FillsViewport => true;

    private readonly DataTable _table = new();
    private readonly TextBlock _sub = new();
    private readonly TextBlock _progress = new();
    private readonly FluidProgress _fluid = new();
    private readonly StackPanel _drives = new();
    private readonly StackPanel _detail = new();
    private readonly Border _detailCard;

    private readonly List<TargetRow> _rows = new();
    private readonly Button _cleanSafe;
    private readonly TextBlock _bulkStatus = new();
    private readonly TextBlock _currentFile = new();
    private CancellationTokenSource? _work;
    private CancellationTokenSource? _cleaning;
    private bool _started;

    internal MaintenancePage()
    {
        _table.Columns.Add(DataColumn.For<TargetRow>("What", 300, ColumnKind.Identity, r => r.Target.DisplayName));
        _table.Columns.Add(DataColumn.For<TargetRow>("Category", 170, ColumnKind.Text, r => Humanise(r.Target.Category)));
        _table.Columns.Add(DataColumn.For<TargetRow>("Reclaimable", 130, ColumnKind.Numeric, r => r.SizeText));
        _table.Columns.Add(DataColumn.For<TargetRow>("Files", 90, ColumnKind.Numeric, r => r.CountText));
        // "What stands between this row and being cleaned", from the USER's point of view.
        //
        // It used to read "admin" for anything NeedsAdmin, which is now wrong twice over: the
        // guardian service does those without the user doing anything, so "admin" asked them for
        // something they no longer have to provide — while a row held open by a running
        // application, which they DO have to act on, said nothing at all. The one they could act on
        // was the invisible one.
        _table.Columns.Add(DataColumn.For<TargetRow>("Needs", 90, ColumnKind.Text, r =>
            r.BlockedBy.Length > 0 ? "in use"
            : r.Target.NeedsAdmin && !Guardian.IsRemote ? "admin"
            : ""));
        _table.Columns.Add(DataColumn.Risk<TargetRow>("Risk", 110, (TargetRow r) => r.Severity));
        _table.SelectionChanged += (_, _) => ShowDetail(_table.SelectedItem as TargetRow);

        // Rows: title, subtitle, progress, drives, TABLE (fills), detail.
        // The table row is the only star row, so it absorbs whatever the window has spare and a
        // maximised display shows more rows instead of empty background.
        var page = new Grid { Margin = new Thickness(0, 4, 0, 8) };
        foreach (var h in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto })
            page.RowDefinitions.Add(new RowDefinition { Height = h });
        page.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        page.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var head = new TextBlock
        {
            Text = "Maintenance",
            FontSize = Fs("FsDisplay"),
            FontWeight = FontWeights.SemiBold,
            FontFamily = Font("DisplayFont"),
            Foreground = Brush("TextPrimary"),
            Margin = new Thickness(0, 4, 0, 2),
        };
        Grid.SetRow(head, 0);
        page.Children.Add(head);

        _sub.FontSize = Fs("FsBodyLarge");
        _sub.Foreground = Brush("TextSecondary");
        _sub.TextWrapping = TextWrapping.Wrap;
        Grid.SetRow(_sub, 1);
        page.Children.Add(_sub);

        // Progress text and the liquid together, in one row.
        //
        // The text alone was the original complaint: measuring 74 targets takes tens of seconds and
        // the count moves in lumps — one directory finishing can jump it several places at once —
        // so between lumps the page looked identical to a page that had hung. The liquid keeps
        // moving while the number does not, which is the part that says "still working".
        // Two columns, not two rows: the table below is the only star row on this page, so every
        // pixel spent stacking things above it comes straight out of how many rows the user can
        // see. Putting the action beside the progress line rather than under it costs nothing.
        var progressRow = new Grid { Margin = new Thickness(0, 2, 0, 18) };
        progressRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        progressRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var progressText = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(progressText, 0);
        progressRow.Children.Add(progressText);

        _progress.FontSize = Fs("FsCaption");
        _progress.Foreground = Brush("TextTertiary");
        progressText.Children.Add(_progress);

        _fluid.Margin = new Thickness(0, 8, 0, 0);
        _fluid.Height = 18;
        _fluid.Accent = SeverityPalette.Resolve(this, "Accent", Color.FromRgb(0x3B, 0xA5, 0x5D));
        _fluid.AnimationsEnabled = Motion.Active;
        _fluid.IsIndeterminate = true;      // until the first target reports
        progressText.Children.Add(_fluid);

        // One click for the rows that were always meant to need no decision.
        //
        // AutomationTier.Automatic is not a new judgement invented for this button — it is the
        // line the maintenance half already draws, and EffectiveTier enforces it: a target that
        // needs administrator rights is forced to Prompt however it declares itself, and one whose
        // risk is NeverClean is forced to ReadOnly. So "Automatic" already means "regenerable or
        // fully reversible, AND nothing here needs elevation". Every other row keeps its
        // one-at-a-time button and its own confirmation.
        //
        // The button never hides what it is about to do: it names every target and the total
        // before deleting anything, because the whole point of this screen is that a cleaner
        // which will not show you its list is a cleaner you cannot check.
        _cleanSafe = HeroButton.Create("Clean safe items", ButtonTone.Primary, Fs("FsBody"));
        _cleanSafe.Margin = new Thickness(16, 1, 1, 1);
        _cleanSafe.VerticalAlignment = VerticalAlignment.Center;
        _cleanSafe.IsEnabled = false;
        _cleanSafe.Click += async (_, _) => await CleanSafeAsync();
        Grid.SetColumn(_cleanSafe, 1);
        progressRow.Children.Add(_cleanSafe);

        _bulkStatus.FontSize = Fs("FsCaption");
        _bulkStatus.Foreground = Brush("TextTertiary");
        _bulkStatus.TextWrapping = TextWrapping.Wrap;
        _bulkStatus.Margin = new Thickness(0, 4, 0, 0);
        _bulkStatus.Visibility = Visibility.Collapsed;
        progressText.Children.Add(_bulkStatus);

        // The file being removed right now. Mono, dim and one line — it is reassurance that
        // something is happening, not a log to read.
        _currentFile.FontSize = Fs("FsMicro");
        _currentFile.FontFamily = Font("MonoFont");
        _currentFile.Foreground = Brush("TextTertiary");
        _currentFile.TextTrimming = TextTrimming.CharacterEllipsis;
        _currentFile.Margin = new Thickness(0, 2, 0, 0);
        _currentFile.Visibility = Visibility.Collapsed;
        progressText.Children.Add(_currentFile);

        Grid.SetRow(progressRow, 2);
        page.Children.Add(progressRow);

        var drivesCard = Card(_drives, "Drives", null);
        Grid.SetRow(drivesCard, 3);
        page.Children.Add(drivesCard);

        var tableCard = FillCard(_table, "Reclaimable space",
            "Select a row to see exactly what would be removed and what breaks if HERO is wrong. " +
            "Nothing is deleted until you say so.");
        Grid.SetRow(tableCard, 4);
        page.Children.Add(tableCard);

        _detailCard = Card(_detail);
        _detailCard.Visibility = Visibility.Collapsed;
        Grid.SetRow(_detailCard, 5);
        page.Children.Add(_detailCard);

        Content = page;
        Unloaded += (_, _) => _work?.Cancel();
    }

    // ------------------------------------------------------------------ rows

    internal sealed class TargetRow
    {
        internal required CleanupTarget Target { get; init; }
        internal Measurement? Measurement { get; set; }
        internal bool Measuring { get; set; }

        internal string SizeText => Measurement is null
            ? (Measuring ? "measuring…" : "queued")
            : Measurement.Bytes > 0 ? Format(Measurement.Bytes)
            : Measurement.State == AccessState.NotPresent ? "not present"
            : Measurement.State == AccessState.AccessDenied ? "needs admin"
            : "nothing";

        internal string CountText => Measurement is null || Measurement.Files <= 0 ? "" : Measurement.Files.ToString("N0");

        /// <summary>
        /// Why this target cannot be cleaned at this moment, or empty when it can.
        ///
        /// Computed once after measuring rather than per render: CurrentBlockers() probes the
        /// running process list, and asking it per row per refresh would put a process enumeration
        /// on the UI's critical path for a value that changes when an application starts or stops.
        /// </summary>
        internal string BlockedBy { get; set; } = "";

        /// <summary>True when HERO looked and there was nothing there.</summary>
        internal bool MeasuredEmpty =>
            Measurement is { Bytes: <= 0 } m &&
            m.State is AccessState.Measured or AccessState.PartiallyMeasured or AccessState.NotPresent;

        /// <summary>
        /// The risk badge says what you would LOSE by cleaning this row. When the row is empty
        /// there is nothing to lose, so it says nothing.
        ///
        /// The four Recycle Bin rows are what made this obvious: all four measured "nothing" and
        /// all four still displayed HIGH. Emptying a recycle bin genuinely IS high risk — it is the
        /// user's own deleted files and there is no second undo — but an empty one holds no files
        /// to be wrong about. Four red badges over four empty rows is noise, and noise in the risk
        /// column trains the eye to skip the column exactly where it matters.
        ///
        /// AccessDenied deliberately keeps its declared risk. "There is nothing here" is not
        /// something HERO knows about a directory it could not read, and quietly downgrading an
        /// unreadable row to Safe would be the dishonest version of this fix.
        /// </summary>
        internal Hero.Guardian.Severity Severity => MeasuredEmpty
            ? Hero.Guardian.Severity.Safe
            : Target.Risk switch
            {
                CleanupRisk.Regenerable => Hero.Guardian.Severity.Safe,
                CleanupRisk.Low => Hero.Guardian.Severity.Low,
                CleanupRisk.Medium => Hero.Guardian.Severity.Medium,
                CleanupRisk.High => Hero.Guardian.Severity.High,
                CleanupRisk.NeverClean => Hero.Guardian.Severity.Critical,
                _ => Hero.Guardian.Severity.Low,
            };

        internal static string Format(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes;
            int i = 0;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return $"{v:0.#} {units[i]}";
        }
    }

    private static string Humanise(CleanupCategory c)
    {
        // "WindowsUpdateCache" -> "Windows update cache".
        var s = System.Text.RegularExpressions.Regex.Replace(c.ToString(), "(?<!^)([A-Z])", " $1");
        return char.ToUpperInvariant(s[0]) + s[1..].ToLowerInvariant();
    }

    // ------------------------------------------------------------------ measuring

    internal override void Refresh()
    {
        ShowDrives();
        if (_started) return;
        _started = true;

        // Show every target immediately, unmeasured. The list itself is useful before a single
        // byte has been counted, and an empty screen for thirty seconds is not.
        try
        {
            foreach (var target in DiskCleanup.Enumerate())
                _rows.Add(new TargetRow { Target = target });
        }
        catch (Exception ex)
        {
            _sub.Text = $"Could not enumerate cleanup targets: {ex.Message}";
            return;
        }

        _rows.Sort((a, b) => string.Compare(a.Target.DisplayName, b.Target.DisplayName, StringComparison.OrdinalIgnoreCase));
        _table.ItemsSource = _rows.ToList();
        _sub.Text = $"{_rows.Count} places worth checking. Measuring…";

        _work = new CancellationTokenSource();
        _ = MeasureAllAsync(_work.Token);
    }

    /// <summary>
    /// Re-measures, through the guardian service, every row this process could not read itself.
    ///
    /// Runs after the local sweep rather than instead of it. The dashboard measures the ~69 targets
    /// it can see perfectly well and in parallel; only the handful that came back AccessDenied are
    /// worth a round trip, and asking the service for all of them would put a serial pipe call in
    /// front of work that is already fast.
    ///
    /// Six rows on this machine — roughly 11.5 GB of Windows Update cache, setup logs, Delivery
    /// Optimization, font cache and crash dumps — read "needs admin" before this existed, and the
    /// rights to read them had been sitting in the service the whole time.
    /// </summary>
    private async Task MeasureDeniedThroughServiceAsync(CancellationToken ct)
    {
        if (!Guardian.IsRemote) return;

        var denied = _rows.Where(r => r.Measurement?.State == AccessState.AccessDenied).ToList();
        if (denied.Count == 0) return;

        foreach (var row in denied)
        {
            if (ct.IsCancellationRequested) return;

            var reply = await Service.Ipc.GuardianClient
                .MaintenanceMeasureAsync(row.Target.Id, ct).ConfigureAwait(true);

            if (reply is not { Found: true }) continue;

            // Only overwrite when the service genuinely got further. A service that also could not
            // read it should leave the honest "needs admin" in place rather than replace it with a
            // confident zero.
            if (!Enum.TryParse<AccessState>(reply.State, out var state)) continue;
            if (state == AccessState.AccessDenied) continue;

            row.Measurement = new Measurement
            {
                State = state,
                Bytes = reply.Bytes,
                Files = reply.Files,
            };

            OnMeasured(_rows.Count);
        }
    }

    private async Task MeasureAllAsync(CancellationToken ct)
    {
        int done = 0;
        var lockObj = new object();

        // Bounded parallelism. Measuring walks very large trees, and saturating every core to
        // count bytes would make the machine feel worse than the clutter it is counting.
        await Task.Run(() =>
        {
            try
            {
                Parallel.ForEach(_rows, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = ct }, row =>
                {
                    lock (lockObj) row.Measuring = true;
                    Measurement m;
                    try { m = row.Target.Measure(ct); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) { m = Measurement.NotPresent(ex.GetType().Name); }

                    lock (lockObj)
                    {
                        row.Measurement = m;
                        row.Measuring = false;
                        done++;
                    }

                    // Report as each one lands, so the number climbs visibly rather than
                    // appearing all at once at the end.
                    Dispatcher.BeginInvoke(() => OnMeasured(done));
                });
            }
            catch (OperationCanceledException) { /* page navigated away */ }
        }, ct);

        // Then ask the service about the ones this process was refused.
        try { await MeasureDeniedThroughServiceAsync(ct); }
        catch (OperationCanceledException) { }
        catch { /* the service may be absent; the rows keep their honest "needs admin" */ }

        // And only now work out what is actually cleanable, so the button's number is one the
        // button can keep.
        try { await RefreshBlockersAsync(ct); }
        catch (OperationCanceledException) { }
        catch { /* a blocker probe that fails leaves the target looking clear, which the run re-checks */ }
    }

    private void OnMeasured(int done)
    {
        long total = _rows.Where(r => r.Measurement is not null).Sum(r => Math.Max(0, r.Measurement!.Bytes));
        long adminOnly = _rows.Where(r => r.Measurement?.State == AccessState.AccessDenied).Count();

        bool finished = done >= _rows.Count;

        _progress.Text = !finished
            ? $"Measured {done} of {_rows.Count}…"
            : adminOnly > 0
                ? $"Measured all {_rows.Count}. {adminOnly} could not be read without administrator rights."
                : $"Measured all {_rows.Count}.";

        // The count IS known here, so the liquid stops guessing and reports it. It only stays
        // indeterminate before the first target lands, when "how many of how many" has no answer.
        _fluid.IsIndeterminate = false;
        _fluid.Progress = _rows.Count == 0 ? 0 : (double)done / _rows.Count;

        // Gone once there is nothing left to wait for. A completed progress bar sitting full on
        // screen is just clutter that implies something is still happening.
        _fluid.Visibility = finished ? Visibility.Collapsed : Visibility.Visible;

        // "Reclaimable" must mean reclaimable.
        //
        // This line used to sum EVERY measured row, which included the read-only observations —
        // virtual machine disks, the WinSxS component store, the Windows and Visual Studio
        // installer caches. Those are measured precisely so HERO can explain why it will NOT
        // touch them, and they are the biggest rows on the page: the headline read "203.4 GB
        // reclaimable" on this machine when 177 GB of that was material HERO refuses to delete.
        // A cleaner that inflates its own headline with space it will not free is doing the thing
        // this product exists not to do.
        bool Cleanable(TargetRow r) =>
            r.Target.Tier != AutomationTier.ReadOnly && r.Target.Risk != CleanupRisk.NeverClean;

        long free = _rows.Where(r => Cleanable(r) && r.Measurement is not null)
                         .Sum(r => Math.Max(0, r.Measurement!.Bytes));
        int freePlaces = _rows.Count(r => Cleanable(r) && r.Measurement?.Bytes > 0);
        long observed = total - free;

        _sub.Text = observed > 0
            ? $"{TargetRow.Format(free)} reclaimable across {freePlaces} places. " +
              $"A further {TargetRow.Format(observed)} is measured but never cleaned — " +
              "select those rows to see why."
            : $"{TargetRow.Format(free)} reclaimable across {freePlaces} places.";

        // Re-sort largest first once everything is in; sorting while measuring would make rows
        // jump under the pointer.
        var view = done < _rows.Count
            ? _rows.ToList()
            : _rows.OrderByDescending(r => r.Measurement?.Bytes ?? 0).ToList();

        var selected = _table.SelectedItem;
        _table.ItemsSource = view;
        if (selected is not null) _table.SelectedItem = selected;

        UpdateCleanButton();
    }

    // ------------------------------------------------------------------ one-click clean

    /// <summary>
    /// The rows the "Clean safe items" button will act on: measured, non-empty, and already
    /// classified by the target itself as needing no decision.
    ///
    /// <see cref="CleanupTarget.EffectiveTier"/> rather than the declared Tier, deliberately.
    /// EffectiveTier is where the two hard constraints live — NeverClean becomes ReadOnly, and
    /// anything NeedsAdmin becomes Prompt no matter what it declared — so reading it here means
    /// this button cannot be widened by a careless declaration in a target file. Nothing needing
    /// elevation is ever in this set, which is the property that makes a bulk delete defensible
    /// at all.
    /// </summary>
    /// <summary>Every row the button is allowed to touch, whether or not it can right now.</summary>
    private List<TargetRow> EligibleRows() => _rows
        .Where(r => r.Target.EffectiveTier == AutomationTier.Automatic
                 && r.Measurement is { Bytes: > 0 })
        .OrderByDescending(r => r.Measurement!.Bytes)
        .ToList();

    /// <summary>The rows the button can actually clean at this moment.</summary>
    private List<TargetRow> SafeRows() => EligibleRows().Where(r => r.BlockedBy.Length == 0).ToList();

    /// <summary>
    /// Recomputes which eligible targets are held open by a running application.
    ///
    /// This is what stops the button promising space it cannot free. Measured on this machine the
    /// first time it ran: of 10.73 GB in the eligible set, 10.49 GB was blocked — uv holding 6.74
    /// GB, Opera GX 1.49, Steam 0.99, then Spotify, Discord, Edge, NuGet and Chrome — leaving 0.24
    /// GB that could actually be deleted. The button said "Clean 10.9 GB from 15 safe places",
    /// removed nothing, and reported eight targets left alone.
    ///
    /// A cleaner that inflates its own headline with space it will not free is doing the thing this
    /// product exists not to do. That sentence is already in this file, about the page headline; the
    /// button had to learn it separately.
    /// </summary>
    private async Task RefreshBlockersAsync(CancellationToken ct)
    {
        var eligible = EligibleRows();
        if (eligible.Count == 0) return;

        var found = await Task.Run(() =>
        {
            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var row in eligible)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var blocking = row.Target.CurrentBlockers().Where(b => b.Blocking).ToList();
                    map[row.Target.Id] = blocking.Count == 0
                        ? ""
                        : string.Join("; ", blocking.Select(b => b.Reason).Distinct());
                }
                catch { map[row.Target.Id] = ""; }
            }
            return map;
        }, ct);

        foreach (var row in eligible)
            if (found.TryGetValue(row.Target.Id, out var why)) row.BlockedBy = why;

        // OnMeasured, not UpdateCleanButton: the Needs column reads BlockedBy, and the table
        // renders its cells when ItemsSource is assigned. Updating only the button left every row
        // showing the value it had before this probe ran — measured, eight blocked rows and not one
        // "in use" cell among them.
        OnMeasured(_rows.Count);
    }

    private void UpdateCleanButton()
    {
        if (_cleaning is not null) return;      // mid-run; the handler owns the button

        var safe = SafeRows();
        long bytes = safe.Sum(r => r.Measurement!.Bytes);

        _cleanSafe.IsEnabled = safe.Count > 0;
        _cleanSafe.Content = safe.Count > 0
            ? $"Clean {TargetRow.Format(bytes)} from {safe.Count} safe {(safe.Count == 1 ? "place" : "places")}"
            : "Nothing to clean right now";

        // Name what is holding the rest, and name the applications rather than the targets — the
        // user cannot act on "uv package cache is blocked", but they can act on "close uv".
        var blocked = EligibleRows().Where(r => r.BlockedBy.Length > 0).ToList();
        if (blocked.Count == 0)
        {
            if (_bulkStatus.Text.StartsWith("A further", StringComparison.Ordinal))
                _bulkStatus.Visibility = Visibility.Collapsed;
            return;
        }

        long held = blocked.Sum(r => r.Measurement!.Bytes);
        var apps = blocked.OrderByDescending(r => r.Measurement!.Bytes)
                          .Select(r => r.Target.DisplayName)
                          .Take(5)
                          .ToList();

        _bulkStatus.Visibility = Visibility.Visible;
        _bulkStatus.Foreground = Brush("TextTertiary");
        _bulkStatus.Text =
            $"A further {TargetRow.Format(held)} across {blocked.Count} " +
            $"{(blocked.Count == 1 ? "place is" : "places are")} in use right now — " +
            $"{string.Join(", ", apps)}{(blocked.Count > apps.Count ? " and others" : "")}. " +
            "Close those and the figure above will grow.";
    }

    /// <summary>
    /// Cleans every row in <see cref="SafeRows"/>, after one confirmation that names all of them.
    ///
    /// Deletion goes through exactly the same two calls as the per-row button — Preview then
    /// CleanupExecutor.Execute — and there is deliberately no second code path. A bulk cleaner
    /// that grew its own delete loop would be the place a protected-path check quietly goes
    /// missing.
    /// </summary>
    private async Task CleanSafeAsync()
    {
        // Second click stops the run rather than starting another.
        if (_cleaning is not null) { _cleaning.Cancel(); return; }

        var safe = SafeRows();
        if (safe.Count == 0) return;

        long expected = safe.Sum(r => r.Measurement!.Bytes);

        // Name every one of them. "Clean 12.4 GB from 9 places" is a summary; this is the list,
        // and a confirmation that will not show its list is how a cleaner earns its reputation.
        var names = string.Join(Environment.NewLine,
            safe.Take(20).Select(r => $"  • {r.Target.DisplayName} — {TargetRow.Format(r.Measurement!.Bytes)}"));
        if (safe.Count > 20) names += $"{Environment.NewLine}  • …and {safe.Count - 20} more";

        var answer = MessageBox.Show(
            $"Delete {TargetRow.Format(expected)} from {safe.Count} places:{Environment.NewLine}{Environment.NewLine}" +
            names + Environment.NewLine + Environment.NewLine +
            "These are caches that rebuild themselves — nothing here needs administrator rights " +
            "and nothing here is user data." + Environment.NewLine + Environment.NewLine +
            "This cannot be undone from HERO's vault: cleanup deletes rather than quarantines.",
            "Clean safe items", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);

        if (answer != MessageBoxResult.OK)
        {
            _bulkStatus.Visibility = Visibility.Visible;
            _bulkStatus.Text = "Cancelled. Nothing was removed.";
            _bulkStatus.Foreground = Brush("TextTertiary");
            return;
        }

        _cleaning = new CancellationTokenSource();
        var token = _cleaning.Token;
        _cleanSafe.Content = "Stop";
        _bulkStatus.Visibility = Visibility.Visible;
        _bulkStatus.Foreground = Brush("TextSecondary");

        // The bar comes back for the cleaning phase. It was hidden when measuring finished, and a
        // delete of 171,544 files behind a single unchanging line of text is exactly the "looks
        // identical to a page that has hung" failure the measuring phase already had — reported as
        // "this seems to be stuck on the removal process", which is a fair reading of a screen
        // that said the same eleven words for four minutes.
        _fluid.IsIndeterminate = false;
        _fluid.Progress = 0;
        _fluid.Visibility = Visibility.Visible;
        _currentFile.Visibility = Visibility.Visible;

        long freed = 0;
        long files = 0;
        int cleaned = 0;
        var problems = new List<string>();

        try
        {
            for (int i = 0; i < safe.Count && !token.IsCancellationRequested; i++)
            {
                var row = safe[i];
                int index = i;
                _bulkStatus.Text = $"Cleaning {i + 1} of {safe.Count}: {row.Target.DisplayName} — building the list…";
                _fluid.Progress = (double)i / safe.Count;

                var plan = await Task.Run(() => row.Target.Preview(int.MaxValue), token);

                // Re-checked here, not just trusted from the measurement: a build or a game can
                // start between the scan and this moment, and the blocker is what notices.
                var blocking = plan.Blockers.Where(b => b.Blocking).ToList();
                if (blocking.Count > 0)
                {
                    problems.Add($"{row.Target.DisplayName}: {string.Join("; ", blocking.Select(b => b.Reason))}");
                    continue;
                }

                if (plan.Measurement.Files == 0) continue;

                // Progress<T> captures this (UI) synchronisation context, so the executor reports
                // from its worker thread and these updates land back on the dispatcher.
                long soFar = freed;
                var report = new Progress<CleanupOutcome>(o =>
                {
                    double within = o.FilesPlanned > 0
                        ? Math.Clamp((double)o.FilesDeleted / o.FilesPlanned, 0, 1)
                        : 0;
                    _fluid.Progress = (index + within) / safe.Count;

                    _bulkStatus.Text =
                        $"Cleaning {index + 1} of {safe.Count}: {row.Target.DisplayName} — " +
                        $"{o.FilesDeleted:N0} of {o.FilesPlanned:N0} files, " +
                        $"{TargetRow.Format(soFar + o.BytesDeleted)} freed so far.";

                    // The actual file, so "is it stuck?" is answerable at a glance. Middle-trimmed
                    // because these paths are long and the interesting half is the end.
                    _currentFile.Text = o.CurrentPath.Length > 0
                        ? Core.Text.MiddleTrim(o.CurrentPath, 120)
                        : "";
                });

                var outcome = await Task.Run(() => CleanupExecutor.Execute(row.Target, plan, report, token), token);

                freed += outcome.BytesDeleted;
                files += outcome.FilesDeleted;
                if (outcome.BytesDeleted > 0 || outcome.FilesDeleted > 0) cleaned++;
                if (outcome.AbortedByBlocker) problems.Add($"{row.Target.DisplayName}: {outcome.AbortReason}");

                // Re-measure as we go so the table never shows a figure that has already been freed.
                row.Measurement = await Task.Run(() => row.Target.Measure(), token);
            }
        }
        catch (OperationCanceledException) { /* reported as "stopped" below */ }
        catch (Exception ex)
        {
            problems.Add($"Stopped after an unexpected error: {ex.GetType().Name}");
        }
        finally
        {
            _cleaning?.Dispose();
            _cleaning = null;
        }

        bool stopped = token.IsCancellationRequested;
        var summary = new System.Text.StringBuilder();
        summary.Append(stopped ? "Stopped. " : "Done. ");
        summary.Append($"Removed {files:N0} files, {TargetRow.Format(freed)} reclaimed from {cleaned} " +
                       $"{(cleaned == 1 ? "place" : "places")}.");
        if (problems.Count > 0)
            summary.Append($" {problems.Count} left alone: {string.Join("; ", problems.Take(3))}");

        _fluid.Visibility = Visibility.Collapsed;
        _currentFile.Visibility = Visibility.Collapsed;
        _currentFile.Text = "";

        OnMeasured(_rows.Count);
        ShowDrives();

        // Re-probe before reporting: an application may have started or stopped during the run, and
        // the button's next number should reflect the machine as it is now.
        try { await RefreshBlockersAsync(CancellationToken.None); } catch { }

        // Written last so it survives UpdateCleanButton's own status line.
        _bulkStatus.Visibility = Visibility.Visible;
        _bulkStatus.Text = summary.ToString();
        _bulkStatus.Foreground = Brush(problems.Count > 0 || stopped ? "SevMedium" : "SevSafe");
    }

    // ------------------------------------------------------------------ detail and actions

    private void ShowDetail(TargetRow? row)
    {
        _detail.Children.Clear();
        if (row is null) { _detailCard.Visibility = Visibility.Collapsed; return; }
        _detailCard.Visibility = Visibility.Visible;

        _detail.Children.Add(Head(row.Target.DisplayName));
        _detail.Children.Add(Body(row.Target.Description));

        if (row.Target.WhatBreaksIfWrong.Length > 0)
            _detail.Children.Add(Note("If HERO is wrong about this: " + row.Target.WhatBreaksIfWrong, "SevMedium"));

        if (row.Target.Risk == CleanupRisk.NeverClean)
            _detail.Children.Add(Note(
                "HERO measures this and deliberately refuses to clean it. It is shown so you know " +
                "where the space has gone, not so it can be reclaimed here.", "SevHigh"));

        if (row.Target.Paths.Count > 0)
        {
            _detail.Children.Add(Note("Locations:", "TextTertiary"));
            foreach (var p in row.Target.Paths.Take(6))
                _detail.Children.Add(Mono(p));
        }

        var status = new TextBlock
        {
            FontSize = Fs("FsCaption"),
            Foreground = Brush("TextSecondary"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 12, 0, 0),
            Visibility = Visibility.Collapsed,
        };

        var buttons = new WrapPanel { Margin = new Thickness(1, 14, 1, 2) };

        var preview = HeroButton.Create("Show me what would go", ButtonTone.Neutral, Fs("FsCaption"));
        preview.Click += async (_, _) => await PreviewAsync(row, status);
        buttons.Children.Add(preview);

        if (row.Target.Risk != CleanupRisk.NeverClean)
        {
            var clean = HeroButton.Create("Clean this", ButtonTone.Destructive, Fs("FsCaption"));
            clean.Click += async (_, _) => await CleanAsync(row, status);
            buttons.Children.Add(clean);
        }

        _detail.Children.Add(buttons);
        _detail.Children.Add(status);
    }

    private async Task PreviewAsync(TargetRow row, TextBlock status)
    {
        status.Visibility = Visibility.Visible;
        status.Text = "Building the list…";
        status.Foreground = Brush("TextSecondary");

        var plan = await Task.Run(() => row.Target.Preview(400));

        var sb = new System.Text.StringBuilder();
        sb.Append($"{plan.Measurement.Files:N0} files, {TargetRow.Format(plan.Measurement.Bytes)}");
        if (plan.Truncated) sb.Append(" (showing the first few)");
        sb.AppendLine(".");

        foreach (var blocker in plan.Blockers)
            sb.AppendLine($"Blocked: {blocker.Reason} — {blocker.Detail}");

        foreach (var f in plan.Files.Take(12))
            sb.AppendLine(Core.Text.MiddleTrim(f.ToString(), 110));

        status.Text = sb.ToString().TrimEnd();
        status.Foreground = plan.Blockers.Any(b => b.Blocking) ? Brush("SevMedium") : Brush("TextSecondary");
    }

    /// <summary>
    /// Cleans one target through the guardian service, and reports its progress.
    ///
    /// Used for targets this process cannot touch itself. The service does the work as LocalSystem
    /// — which it already was — and this polls it, so no pipe call is held open for the minutes a
    /// 734,915-file cache takes.
    /// </summary>
    private async Task CleanThroughServiceAsync(TargetRow row, TextBlock status)
    {
        var started = await Service.Ipc.GuardianClient.MaintenanceCleanAsync(row.Target.Id);

        if (started is not { Accepted: true })
        {
            status.Text = started?.Message is { Length: > 0 } m ? m : "The guardian service did not accept that.";
            status.Foreground = Brush("SevMedium");
            return;
        }

        Service.Ipc.MaintenanceJobReply final;
        while (true)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(700));

            var s = await Service.Ipc.GuardianClient.MaintenanceStatusAsync(started.JobId);
            if (s is null) { status.Text = "Lost contact with the guardian service."; return; }

            if (s.Finished) { final = s; break; }

            status.Text = s.FilesPlanned > 0
                ? $"Cleaning as administrator: {s.FilesDeleted:N0} of {s.FilesPlanned:N0} files, " +
                  $"{TargetRow.Format(s.BytesDeleted)} freed…"
                : "Cleaning as administrator: building the list…";

            if (s.CurrentPath.Length > 0)
                status.Text += Environment.NewLine + Core.Text.MiddleTrim(s.CurrentPath, 110);
        }

        status.Text = final.Message.Length > 0
            ? final.Message
            : $"Removed {final.FilesDeleted:N0} files, {TargetRow.Format(final.BytesDeleted)} reclaimed.";
        status.Foreground = Brush("SevSafe");

        // Re-measure through the service too — this process still cannot read the directory.
        var remeasured = await Service.Ipc.GuardianClient.MaintenanceMeasureAsync(row.Target.Id);
        if (remeasured is { Found: true } && Enum.TryParse<AccessState>(remeasured.State, out var st))
            row.Measurement = new Measurement { State = st, Bytes = remeasured.Bytes, Files = remeasured.Files };

        OnMeasured(_rows.Count);
        ShowDrives();
    }

    private async Task CleanAsync(TargetRow row, TextBlock status)
    {
        status.Visibility = Visibility.Visible;
        status.Text = "Checking what would be removed…";
        status.Foreground = Brush("TextSecondary");

        // Anything this process cannot reach goes to the service, which can. HERO has held the
        // rights since boot; the maintenance half simply never asked for them, which is why these
        // rows read "needs admin" and did nothing when pressed.
        if (row.Target.NeedsAdmin && Guardian.IsRemote && !Core.Elevation.IsElevated)
        {
            var consent = MessageBox.Show(
                $"Delete {row.SizeText} from:{Environment.NewLine}{Environment.NewLine}" +
                $"{row.Target.DisplayName}{Environment.NewLine}{Environment.NewLine}" +
                (row.Target.WhatBreaksIfWrong.Length > 0
                    ? $"If this is wrong: {row.Target.WhatBreaksIfWrong}{Environment.NewLine}{Environment.NewLine}"
                    : "") +
                "This needs administrator rights, so the HERO guardian service will do it." +
                Environment.NewLine + Environment.NewLine +
                "This cannot be undone from HERO's vault — cleanup deletes rather than quarantines.",
                "Clean up", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);

            if (consent != MessageBoxResult.OK) { status.Text = "Cancelled. Nothing was removed."; return; }

            await CleanThroughServiceAsync(row, status);
            return;
        }

        var plan = await Task.Run(() => row.Target.Preview(int.MaxValue));

        var blocking = plan.Blockers.Where(b => b.Blocking).ToList();
        if (blocking.Count > 0)
        {
            status.Text = "Cannot clean this right now: " +
                          string.Join("; ", blocking.Select(b => $"{b.Reason} — {b.Detail}"));
            status.Foreground = Brush("SevMedium");
            return;
        }

        if (plan.Measurement.Files == 0)
        {
            status.Text = "Nothing to remove.";
            return;
        }

        // Advisories are the ones HERO will not refuse over but the user should still see. They
        // were being computed and then dropped: only Blocking entries were ever read, so a
        // CleanupBlocker constructed with Blocking:false — which the type documents as "an advisory
        // the user may override" — reached nobody. An advisory nobody is shown is a comment.
        var advisories = plan.Blockers.Where(b => !b.Blocking).ToList();
        string advisoryText = advisories.Count == 0
            ? ""
            : string.Join(Environment.NewLine + Environment.NewLine,
                  advisories.Select(a => $"Worth knowing: {a.Detail}")) +
              Environment.NewLine + Environment.NewLine;

        // Name the target, the size and the consequence. A confirmation that says "are you sure?"
        // teaches people to click yes.
        var answer = MessageBox.Show(
            $"Delete {plan.Measurement.Files:N0} files ({TargetRow.Format(plan.Measurement.Bytes)}) from:\n\n" +
            $"{row.Target.DisplayName}\n\n" +
            advisoryText +
            (row.Target.WhatBreaksIfWrong.Length > 0 ? $"If this is wrong: {row.Target.WhatBreaksIfWrong}\n\n" : "") +
            "This cannot be undone from HERO's vault — cleanup deletes rather than quarantines.",
            "Clean up", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);

        if (answer != MessageBoxResult.OK) { status.Text = "Cancelled. Nothing was removed."; return; }

        status.Text = "Cleaning…";
        var outcome = await Task.Run(() => CleanupExecutor.Execute(row.Target, plan));

        status.Text = outcome.AbortedByBlocker
            ? $"Stopped: {outcome.AbortReason}"
            : $"Removed {outcome.FilesDeleted:N0} files, {TargetRow.Format(outcome.BytesDeleted)} reclaimed" +
              (outcome.Skipped.Count > 0 ? $". {outcome.Skipped.Count} items were in use and left alone." : ".");
        status.Foreground = Brush(outcome.AbortedByBlocker ? "SevMedium" : "SevSafe");

        // Re-measure this row so the table reflects reality rather than the pre-clean figure.
        row.Measurement = await Task.Run(() => row.Target.Measure());
        OnMeasured(_rows.Count);
        ShowDrives();
    }

    // ------------------------------------------------------------------ drives

    /// <summary>One drive's numbers, read once, off the UI thread.</summary>
    private readonly record struct DriveSizes(string Name, long Total, long Free);

    /// <summary>
    /// Draws the drive bars.
    ///
    /// THE NUMBERS ARE READ ON A BACKGROUND THREAD, and that is the whole point of the split.
    /// DriveInfo.TotalSize and AvailableFreeSpace are not property reads, they are synchronous
    /// GetDiskFreeSpaceEx calls, and on a drive that has spun down Windows blocks them until the
    /// platters are back — seconds, on the UI thread, with the message pump stopped. That is the
    /// "click Maintenance, the app freezes, then the page appears" the user reported, and it only
    /// happens after an idle spell because that is when a disk is asleep.
    ///
    /// Navigation therefore paints immediately and the bars fill in when the disks answer.
    /// </summary>
    private void ShowDrives()
    {
        _drives.Children.Clear();
        _ = ShowDrivesAsync();
    }

    private async Task ShowDrivesAsync()
    {
        List<DriveSizes> drives;
        try
        {
            drives = await Task.Run(() => DiskCleanup.FixedDrives()
                .Select(d =>
                {
                    try { return new DriveSizes(d.Name, d.TotalSize, d.AvailableFreeSpace); }
                    catch { return new DriveSizes(d.Name, 0, 0); }
                })
                .ToList());
        }
        catch { return; }

        // The page may have been navigated away from while a disk was waking.
        if (!IsLoaded && _drives.Children.Count > 0) return;

        _drives.Children.Clear();
        try
        {
            foreach (var drive in drives)
            {
                double usedFraction = drive.Total > 0
                    ? 1.0 - ((double)drive.Free / drive.Total)
                    : 0;

                var row = new Grid { Margin = new Thickness(0, 6, 0, 6) };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200) });

                var name = new TextBlock
                {
                    Text = drive.Name.TrimEnd('\\'),
                    FontSize = Fs("FsBodyLarge"),
                    Foreground = Brush("TextPrimary"),
                    VerticalAlignment = VerticalAlignment.Center,
                };

                // Coloured by how little is LEFT, not how much is used: free space is the number
                // that matters when a drive is the constraint.
                var brushKey = usedFraction > 0.92 ? "SevCritical"
                             : usedFraction > 0.85 ? "SevHigh"
                             : usedFraction > 0.75 ? "SevMedium"
                             : "SevSafe";

                var track = new Border
                {
                    Height = 8,
                    CornerRadius = new CornerRadius(4),
                    Background = Brush("Surface3"),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 16, 0),
                };
                var fill = new Border
                {
                    Height = 8,
                    CornerRadius = new CornerRadius(4),
                    Background = Brush(brushKey),
                    HorizontalAlignment = HorizontalAlignment.Left,
                };
                track.Child = fill;
                track.SizeChanged += (_, e) => fill.Width = Math.Max(0, e.NewSize.Width * usedFraction);

                var detail = new TextBlock
                {
                    Text = drive.Total > 0
                        ? $"{TargetRow.Format(drive.Free)} free of {TargetRow.Format(drive.Total)}"
                        : "could not be read",
                    FontSize = Fs("FsCaption"),
                    FontFamily = Font("MonoFont"),
                    Foreground = Brush("TextSecondary"),
                    VerticalAlignment = VerticalAlignment.Center,
                    TextAlignment = TextAlignment.Right,
                };

                Grid.SetColumn(name, 0); Grid.SetColumn(track, 1); Grid.SetColumn(detail, 2);
                row.Children.Add(name); row.Children.Add(track); row.Children.Add(detail);
                _drives.Children.Add(row);
            }
        }
        catch { }
    }

    // ------------------------------------------------------------------ small builders

    private TextBlock Head(string text) => new()
    {
        Text = text,
        FontSize = Fs("FsSection"),
        FontWeight = FontWeights.SemiBold,
        FontFamily = Font("DisplayFont"),
        Foreground = Brush("TextPrimary"),
        TextWrapping = TextWrapping.Wrap,
    };

    private TextBlock Body(string text) => new()
    {
        Text = text,
        FontSize = Fs("FsBody"),
        Foreground = Brush("TextSecondary"),
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 6, 0, 0),
    };

    private TextBlock Note(string text, string brushKey) => new()
    {
        Text = text,
        FontSize = Fs("FsCaption"),
        Foreground = Brush(brushKey),
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 8, 0, 0),
    };

    private TextBlock Mono(string text) => new()
    {
        Text = Core.Text.OneLine(text, 160),
        FontSize = Fs("FsMono"),
        FontFamily = Font("MonoFont"),
        Foreground = Brush("TextTertiary"),
        TextWrapping = TextWrapping.NoWrap,
        TextTrimming = TextTrimming.CharacterEllipsis,
        Margin = new Thickness(0, 2, 0, 0),
    };
}

/// <summary>
/// The Timeline: what HERO has actually done, in order. An autonomous tool that cannot show its
/// own history is asking to be trusted on nothing.
/// </summary>
internal sealed class TimelinePage : PageBase
{
    private readonly StackPanel _list = new();
    private readonly TextBlock _sub = new();

    internal TimelinePage()
    {
        var page = Page("Timeline", "");
        page.Children.Add(_sub);
        _sub.FontSize = Fs("FsBodyLarge");
        _sub.Foreground = Brush("TextSecondary");
        _sub.Margin = new Thickness(0, -18, 0, 22);
        _sub.TextWrapping = TextWrapping.Wrap;
        page.Children.Add(_list);
        Content = page;
    }

    internal override void Refresh()
    {
        _list.Children.Clear();

        var detections = Hero.Guardian.DefenderOracle.RecentDetections(TimeSpan.FromDays(30));
        var vault = Guardian.Vault.List();

        var events = new List<(DateTime When, string What, string Detail, string Kind)>();
        foreach (var d in detections)
            events.Add((d.When, $"Defender: {d.ThreatName}",
                        Core.Text.OneLine(d.Path, 140) + (d.Action.Length > 0 ? $" — {d.Action}" : ""), d.Severity));
        foreach (var v in vault)
            events.Add((v.QuarantinedUtc.ToLocalTime(), "Quarantined by HERO", Core.Text.OneLine(v.OriginalPath, 140), "vault"));

        if (events.Count == 0)
        {
            _sub.Text = "Nothing has happened yet.";
            _list.Children.Add(Card(Empty("No history",
                "HERO records every action it takes, plus Windows Defender's own detections, so " +
                "there is always a record of what happened and why.")));
            return;
        }

        _sub.Text = $"{events.Count} event(s) in the last 30 days, newest first.";

        var panel = new StackPanel();
        foreach (var (when, what, detail, kind) in events.OrderByDescending(e => e.When).Take(60))
        {
            var row = new Grid { Margin = new Thickness(0, 5, 0, 5) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(260) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var t = new TextBlock { Text = when.ToString("dd MMM HH:mm"), FontSize = Fs("FsCaption"), Foreground = Brush("TextTertiary") };
            var w = new TextBlock
            {
                Text = what,
                FontSize = Fs("FsBody"),
                Foreground = Brush(kind == "Severe" ? "SevCritical" : kind == "vault" ? "SevSafe" : "SevMedium"),
                TextWrapping = TextWrapping.NoWrap,
                TextTrimming = TextTrimming.CharacterEllipsis,
            };
            var d2 = new TextBlock
            {
                Text = detail,
                FontSize = Fs("FsMono"),
                FontFamily = Font("MonoFont"),
                Foreground = Brush("TextTertiary"),
                TextWrapping = TextWrapping.NoWrap,
                TextTrimming = TextTrimming.CharacterEllipsis,
            };
            Grid.SetColumn(t, 0); Grid.SetColumn(w, 1); Grid.SetColumn(d2, 2);
            row.Children.Add(t); row.Children.Add(w); row.Children.Add(d2);
            panel.Children.Add(row);
        }
        _list.Children.Add(Card(panel));
    }
}
