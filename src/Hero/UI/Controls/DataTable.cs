using System.Collections;
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Hero.Guardian;

namespace Hero.UI.Controls;

/// <summary>How a column's value is typeset. This is a correctness decision, not a style one.</summary>
internal enum ColumnKind
{
    /// <summary>Proportional body text. Publisher names, states, human-readable labels.</summary>
    Text,

    /// <summary>The row's identity column: same face, primary ink, semibold.</summary>
    Identity,

    /// <summary>
    /// Machine identifiers the user may need to compare character by character or paste into a
    /// terminal: paths, command lines, hashes, registry keys, addresses, service names.
    /// </summary>
    Mono,

    /// <summary>A number in the UI face, right-aligned and laid out on a fixed digit advance.</summary>
    Numeric,

    /// <summary>A number that is also an identifier — PIDs, ports. Mono, right-aligned.</summary>
    MonoNumeric,

    /// <summary>A severity pill, drawn only when the severity is above Safe.</summary>
    Severity,
}

/// <summary>
/// One column of a <see cref="DataTable"/>.
///
/// Values are pulled through a delegate rather than a binding path. That is deliberate: it keeps
/// the row at a single visual element with no per-cell binding machinery, and it is type-checked
/// at the call site instead of failing silently at runtime the way a mistyped path does.
/// </summary>
internal sealed class DataColumn
{
    internal required string Header { get; init; }

    /// <summary>Fixed width in device-independent units. Ignored when <see cref="Flex"/> is set.</summary>
    internal double Width { get; init; } = 120d;

    /// <summary>Shares the leftover width with the other flex columns.</summary>
    internal bool Flex { get; init; }

    internal double MinWidth { get; init; } = 56d;

    internal ColumnKind Kind { get; init; } = ColumnKind.Text;

    /// <summary>Cell text for an item. Return an empty string to draw nothing.</summary>
    internal Func<object, string>? Text { get; init; }

    /// <summary>Severity for <see cref="ColumnKind.Severity"/> columns.</summary>
    internal Func<object, Severity>? SeverityOf { get; init; }

    /// <summary>
    /// Truncate in the middle rather than at the end. Set this for every path: the filename is
    /// the load-bearing part and a tail ellipsis throws it away.
    /// </summary>
    internal bool MiddleEllipsis { get; init; }

    internal bool Sortable { get; init; } = true;

    /// <summary>Typed helper that avoids an unchecked cast at every call site.</summary>
    internal static DataColumn For<T>(string header, double width, ColumnKind kind, Func<T, string> text,
                                      bool flex = false, bool middleEllipsis = false, bool sortable = true)
        => new()
        {
            Header = header,
            Width = width,
            Flex = flex,
            Kind = kind,
            MiddleEllipsis = middleEllipsis,
            Sortable = sortable,
            Text = o => o is T typed ? text(typed) : string.Empty,
        };

    internal static DataColumn Risk<T>(string header, double width, Func<T, Severity> severity)
        => new()
        {
            Header = header,
            Width = width,
            Kind = ColumnKind.Severity,
            Sortable = true,
            SeverityOf = o => o is T typed ? severity(typed) : Guardian.Severity.Safe,
        };
}

/// <summary>
/// The data-dense list used for processes, connections, persistence entries and timelines.
///
/// Two structural decisions carry the whole design:
///
/// 1. Column widths are resolved ONCE by this control and used by both the header and every row.
///    The obvious alternative, Grid.IsSharedSizeScope with SharedSizeGroup, is a trap: shared-size
///    groups require every participant to be measured, which forces the VirtualizingStackPanel to
///    realise all N containers. It looks perfect with twenty test rows and hangs for seconds on a
///    real thousand-row persistence dump.
///
/// 2. A row is ONE visual element that paints its own cells. No ContentPresenter, no per-cell
///    TextBlock, no per-cell Border, and specifically no read-only TextBox per mono cell — the
///    obvious way to make paths selectable would put 1,600+ TextBoxes through recycling on the
///    Activity screen and would swallow the clicks and arrow keys that row selection needs.
///    Selection is offered at row level instead: Ctrl+C copies the selected row's untruncated
///    values, and the detail pane owns character-level selection.
///
/// Every string drawn here is passed through <see cref="GlyphText.Sanitise"/> first, because all
/// of it — paths, command lines, service names — is written by whatever HERO is watching.
/// </summary>
internal sealed class DataTable : UserControl
{
    private readonly RowList _rows;
    private readonly HeaderStrip _header;
    private readonly Border _empty;
    private readonly TextBlock _emptyGlyph;
    private readonly TextBlock _emptyTitle;
    private readonly TextBlock _emptyBody;
    private readonly Spinner _spinner;
    private readonly HashSet<DataTableRow> _live = new();

    private double[] _widths = Array.Empty<double>();
    private double _widthsFor = -1;
    private bool _widthsDirty = true;
    private bool _syncing;
    private TableTokens? _tokens;
    private INotifyCollectionChanged? _watched;

    internal DataTable()
    {
        Columns = new ObservableCollection<DataColumn>();

        Focusable = false;
        IsTabStop = false;
        SnapsToDevicePixels = true;
        UseLayoutRounding = true;

        // Opaque by default. A table drawn over a transparent (Mica-composited) region loses
        // ClearType and every cell goes visibly soft — the commonest reason a hand-built WPF app
        // looks unfinished.
        SetResourceReference(BackgroundProperty, "Surface1");

        _header = new HeaderStrip(this);
        _rows = new RowList(this);

        Columns.CollectionChanged += (_, _) =>
        {
            _widthsDirty = true;
            _header.InvalidateVisual();
            Refresh();
        };

        _rows.SelectionChanged += OnRowsSelectionChanged;
        _rows.MouseDoubleClick += (_, _) => RaiseActivated();
        _rows.PreviewKeyDown += OnRowsKeyDown;
        _rows.MouseEnter += (_, _) => UpdateInteracting();
        _rows.MouseLeave += (_, _) => UpdateInteracting();
        _rows.IsKeyboardFocusWithinChanged += (_, _) => UpdateInteracting();

        _emptyGlyph = new TextBlock
        {
            FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"),
            FontSize = 40,
            Opacity = 0.32,                                  // a full-strength green tick reads as a marketing badge
            HorizontalAlignment = HorizontalAlignment.Center,
            Text = "\uE73E",                                 // CheckMark, verified against the installed font
            Margin = new Thickness(0, 0, 0, 16),
        };
        // Neutral until a caller explicitly claims the emptiness is good news. An empty table also
        // means "the first scan has not finished" and "this needed elevation and was refused", and
        // painting either of those as a green tick is the one thing a guardian must never do.
        _emptyGlyph.SetResourceReference(TextBlock.ForegroundProperty, "TextTertiary");

        _emptyTitle = new TextBlock
        {
            HorizontalAlignment = HorizontalAlignment.Center,
            TextAlignment = TextAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 8),
        };
        _emptyTitle.SetResourceReference(TextBlock.FontSizeProperty, "FsSection");
        _emptyTitle.SetResourceReference(TextBlock.FontFamilyProperty, "DisplayFont");
        _emptyTitle.SetResourceReference(TextBlock.ForegroundProperty, "TextPrimary");

        _emptyBody = new TextBlock
        {
            HorizontalAlignment = HorizontalAlignment.Center,
            TextAlignment = TextAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 520,                                  // ~72ch: past that a centred paragraph stops being readable
        };
        _emptyBody.SetResourceReference(TextBlock.FontSizeProperty, "FsBody");
        _emptyBody.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondary");

        var emptyStack = new StackPanel();
        emptyStack.Children.Add(_emptyGlyph);
        emptyStack.Children.Add(_emptyTitle);
        emptyStack.Children.Add(_emptyBody);

        _empty = new Border
        {
            CornerRadius = new CornerRadius(14),
            Padding = new Thickness(32),
            MaxWidth = 560,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            BorderThickness = new Thickness(1),
            Child = emptyStack,
            Visibility = Visibility.Collapsed,
            Margin = new Thickness(24),
        };
        _empty.SetResourceReference(Border.BackgroundProperty, "Surface2");
        _empty.SetResourceReference(Border.BorderBrushProperty, "Divider");

        _spinner = new Spinner { Visibility = Visibility.Collapsed };

        var body = new Grid();
        body.Children.Add(_rows);
        body.Children.Add(_empty);
        body.Children.Add(_spinner);

        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        Grid.SetRow(_header, 0);
        Grid.SetRow(body, 1);
        root.Children.Add(_header);
        root.Children.Add(body);

        Content = root;

        // The DP changed-callbacks only fire on a change, so seed the empty-state text from the
        // property defaults rather than leaving it blank until someone assigns them.
        _emptyTitle.Text = EmptyTitle;
        _emptyBody.Text = EmptyBody;
        UpdateEmptyState();
    }

    /// <summary>Column definitions. Mutating this rebuilds the layout and repaints every row.</summary>
    internal ObservableCollection<DataColumn> Columns { get; }

    /// <summary>
    /// Imposes a finite height budget when the parent supplies none.
    ///
    /// This is not a nicety. A VirtualizingStackPanel measured with an infinite height has an
    /// infinite viewport, so it realises EVERY container and item virtualisation is silently gone —
    /// every setting in <see cref="RowList"/> can be correct and it still happens, because the
    /// cause is outside the control. Measured on this machine with 400 rows: hosted the way
    /// MainWindow hosts a page (ScrollViewer &gt; StackPanel &gt; Card &gt; table) the table
    /// realised 400 of 400 containers, stood 16,038 DIP tall and cost 65ms per refresh; the same
    /// table given a finite height realised 24 and cost 2.8ms — a 23x difference, on the screens
    /// that hold the most rows (358 processes, 800+ persistence entries).
    ///
    /// Short tables are untouched: the cap only binds once the content would exceed it, so a
    /// six-row table still sizes to its content exactly as before. An empty table is left alone
    /// entirely, so the empty-state card keeps its natural height.
    /// </summary>
    protected override Size MeasureOverride(Size constraint)
    {
        if (double.IsInfinity(constraint.Height) && !double.IsInfinity(MaxUnconstrainedHeight))
        {
            int count = _rows.Items.Count;
            if (count > 0)
            {
                double content = HeaderHeight + count * RowHeight + 2;
                constraint = new Size(constraint.Width, Math.Min(MaxUnconstrainedHeight, content));
            }
        }
        return base.MeasureOverride(constraint);
    }

    // ---------------------------------------------------------------- dependency properties

    internal static readonly DependencyProperty ItemsSourceProperty = DependencyProperty.Register(
        nameof(ItemsSource), typeof(IEnumerable), typeof(DataTable),
        new PropertyMetadata(null, OnItemsSourceChanged));

    internal IEnumerable? ItemsSource
    {
        get => (IEnumerable?)GetValue(ItemsSourceProperty);
        set => SetValue(ItemsSourceProperty, value);
    }

    internal static readonly DependencyProperty SelectedItemProperty = DependencyProperty.Register(
        nameof(SelectedItem), typeof(object), typeof(DataTable),
        new FrameworkPropertyMetadata(null,
            FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnSelectedItemChanged));

    internal object? SelectedItem
    {
        get => GetValue(SelectedItemProperty);
        set => SetValue(SelectedItemProperty, value);
    }

    /// <summary>
    /// Fixed and uniform. Uniform row height is what makes pixel scrolling accurate and cheap;
    /// 40 rather than the reference design's 36 because this machine's panel is 4096x2160 and the
    /// app's type scale is one step up to match.
    /// </summary>
    internal static readonly DependencyProperty RowHeightProperty = DependencyProperty.Register(
        nameof(RowHeight), typeof(double), typeof(DataTable),
        new FrameworkPropertyMetadata(40d, OnMetricChanged));

    internal double RowHeight
    {
        get => (double)GetValue(RowHeightProperty);
        set => SetValue(RowHeightProperty, value);
    }

    internal static readonly DependencyProperty HeaderHeightProperty = DependencyProperty.Register(
        nameof(HeaderHeight), typeof(double), typeof(DataTable),
        new FrameworkPropertyMetadata(36d, OnMetricChanged));

    internal double HeaderHeight
    {
        get => (double)GetValue(HeaderHeightProperty);
        set => SetValue(HeaderHeightProperty, value);
    }

    internal static readonly DependencyProperty CellPaddingProperty = DependencyProperty.Register(
        nameof(CellPadding), typeof(double), typeof(DataTable),
        new FrameworkPropertyMetadata(14d, OnMetricChanged));

    internal double CellPadding
    {
        get => (double)GetValue(CellPaddingProperty);
        set => SetValue(CellPaddingProperty, value);
    }

    /// <summary>
    /// Height budget the table imposes on itself when its parent gives it NO height constraint —
    /// which is exactly what the shell does, because every page is hosted inside MainWindow's
    /// page ScrollViewer. See <see cref="MeasureOverride"/> for why that is not survivable.
    /// Set <see cref="double.PositiveInfinity"/> to opt out and grow to full content height.
    /// </summary>
    internal static readonly DependencyProperty MaxUnconstrainedHeightProperty = DependencyProperty.Register(
        nameof(MaxUnconstrainedHeight), typeof(double), typeof(DataTable),
        new FrameworkPropertyMetadata(720d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    internal double MaxUnconstrainedHeight
    {
        get => (double)GetValue(MaxUnconstrainedHeightProperty);
        set => SetValue(MaxUnconstrainedHeightProperty, value);
    }

    internal static readonly DependencyProperty ShowHeaderProperty = DependencyProperty.Register(
        nameof(ShowHeader), typeof(bool), typeof(DataTable),
        new PropertyMetadata(true, (d, e) =>
            ((DataTable)d)._header.Visibility = (bool)e.NewValue ? Visibility.Visible : Visibility.Collapsed));

    internal bool ShowHeader
    {
        get => (bool)GetValue(ShowHeaderProperty);
        set => SetValue(ShowHeaderProperty, value);
    }

    /// <summary>
    /// Note drawn at the right of the header. Its intended use is the live-table honesty label —
    /// "Sorting paused" while the pointer is over the list — so rows never move under the cursor.
    /// </summary>
    internal static readonly DependencyProperty HeaderNoteProperty = DependencyProperty.Register(
        nameof(HeaderNote), typeof(string), typeof(DataTable),
        new PropertyMetadata(null, (d, _) => ((DataTable)d)._header.InvalidateVisual()));

    internal string? HeaderNote
    {
        get => (string?)GetValue(HeaderNoteProperty);
        set => SetValue(HeaderNoteProperty, value);
    }

    internal static readonly DependencyProperty SortColumnProperty = DependencyProperty.Register(
        nameof(SortColumn), typeof(DataColumn), typeof(DataTable),
        new PropertyMetadata(null, (d, _) => ((DataTable)d)._header.InvalidateVisual()));

    internal DataColumn? SortColumn
    {
        get => (DataColumn?)GetValue(SortColumnProperty);
        set => SetValue(SortColumnProperty, value);
    }

    internal static readonly DependencyProperty SortAscendingProperty = DependencyProperty.Register(
        nameof(SortAscending), typeof(bool), typeof(DataTable),
        new PropertyMetadata(true, (d, _) => ((DataTable)d)._header.InvalidateVisual()));

    internal bool SortAscending
    {
        get => (bool)GetValue(SortAscendingProperty);
        set => SetValue(SortAscendingProperty, value);
    }

    internal static readonly DependencyProperty IsBusyProperty = DependencyProperty.Register(
        nameof(IsBusy), typeof(bool), typeof(DataTable),
        new PropertyMetadata(false, (d, _) => ((DataTable)d).UpdateEmptyState()));

    internal bool IsBusy
    {
        get => (bool)GetValue(IsBusyProperty);
        set => SetValue(IsBusyProperty, value);
    }

    /// <summary>Segoe Fluent Icons code point for the empty state. Default is CheckMark (E73E).</summary>
    internal static readonly DependencyProperty EmptyGlyphProperty = DependencyProperty.Register(
        nameof(EmptyGlyph), typeof(string), typeof(DataTable),
        new PropertyMetadata("\uE73E", (d, e) => ((DataTable)d)._emptyGlyph.Text = (string?)e.NewValue ?? ""));

    internal string EmptyGlyph
    {
        get => (string)GetValue(EmptyGlyphProperty);
        set => SetValue(EmptyGlyphProperty, value);
    }

    /// <summary>
    /// Empty-state headline. Every empty state in HERO states what was checked, quantifies it and
    /// timestamps it — "Checked 142 autorun entries 4 minutes ago" rather than "You're protected".
    /// </summary>
    internal static readonly DependencyProperty EmptyTitleProperty = DependencyProperty.Register(
        nameof(EmptyTitle), typeof(string), typeof(DataTable),
        new PropertyMetadata("Nothing to show", (d, e) => ((DataTable)d)._emptyTitle.Text = (string?)e.NewValue ?? ""));

    internal string EmptyTitle
    {
        get => (string)GetValue(EmptyTitleProperty);
        set => SetValue(EmptyTitleProperty, value);
    }

    internal static readonly DependencyProperty EmptyBodyProperty = DependencyProperty.Register(
        nameof(EmptyBody), typeof(string), typeof(DataTable),
        new PropertyMetadata("", (d, e) => ((DataTable)d)._emptyBody.Text = (string?)e.NewValue ?? ""));

    internal string EmptyBody
    {
        get => (string)GetValue(EmptyBodyProperty);
        set => SetValue(EmptyBodyProperty, value);
    }

    /// <summary>
    /// Set true ONLY when an empty table provably means "checked, and there is nothing wrong" —
    /// then, and only then, the empty state gets the reassuring green tick. It is false by default
    /// because zero rows far more often means the engine has not produced a snapshot yet, or the
    /// read was refused unelevated, and those states must look like absence of knowledge rather
    /// than absence of threats. Pair it with an <see cref="EmptyBody"/> that says what was checked,
    /// how much of it, and when.
    /// </summary>
    internal static readonly DependencyProperty EmptyIsReassuringProperty = DependencyProperty.Register(
        nameof(EmptyIsReassuring), typeof(bool), typeof(DataTable),
        new PropertyMetadata(false, (d, e) => ((DataTable)d)._emptyGlyph.SetResourceReference(
            TextBlock.ForegroundProperty, (bool)e.NewValue ? "SevSafe" : "TextTertiary")));

    internal bool EmptyIsReassuring
    {
        get => (bool)GetValue(EmptyIsReassuringProperty);
        set => SetValue(EmptyIsReassuringProperty, value);
    }

    private static readonly DependencyPropertyKey IsInteractingKey = DependencyProperty.RegisterReadOnly(
        nameof(IsInteracting), typeof(bool), typeof(DataTable), new PropertyMetadata(false));

    internal static readonly DependencyProperty IsInteractingProperty = IsInteractingKey.DependencyProperty;

    /// <summary>
    /// True while the pointer is over the list, the list has keyboard focus, or a row is selected.
    /// Bind a live view's re-sort to the inverse of this: reordering a 1 Hz table under the cursor
    /// makes rows leap away mid-click and is the fastest way to make a live view unusable.
    /// </summary>
    internal bool IsInteracting => (bool)GetValue(IsInteractingProperty);

    // -------------------------------------------------------------------------------- events

    internal event SelectionChangedEventHandler? SelectionChanged;

    /// <summary>Double-click or Enter on a row.</summary>
    internal event EventHandler<object>? RowActivated;

    /// <summary>A sortable header was clicked. The owner re-sorts; the table never touches data.</summary>
    internal event EventHandler<DataColumn>? SortRequested;

    // ----------------------------------------------------------------------------- plumbing

    private static void OnItemsSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var table = (DataTable)d;

        if (table._watched is not null) table._watched.CollectionChanged -= table.OnSourceCollectionChanged;
        table._watched = e.NewValue as INotifyCollectionChanged;
        if (table._watched is not null) table._watched.CollectionChanged += table.OnSourceCollectionChanged;

        table._rows.ItemsSource = (IEnumerable?)e.NewValue;
        table.UpdateEmptyState();
    }

    private void OnSourceCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => UpdateEmptyState();

    private static void OnSelectedItemChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var table = (DataTable)d;
        if (table._syncing) return;
        table._syncing = true;
        table._rows.SelectedItem = e.NewValue;
        table._syncing = false;
        table.UpdateInteracting();
    }

    private static void OnMetricChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var table = (DataTable)d;
        table._widthsDirty = true;
        table._header.InvalidateMeasure();
        table._header.InvalidateVisual();
        foreach (var row in table._live) { row.InvalidateMeasure(); row.InvalidateVisual(); }
    }

    private void OnRowsSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_syncing)
        {
            _syncing = true;
            SelectedItem = _rows.SelectedItem;
            _syncing = false;
        }
        UpdateInteracting();
        SelectionChanged?.Invoke(this, e);
    }

    private void OnRowsKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { RaiseActivated(); e.Handled = true; return; }

        if (e.Key == Key.C && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
        {
            CopySelectedRow();
            e.Handled = true;
        }
    }

    private void RaiseActivated()
    {
        var item = _rows.SelectedItem;
        if (item is not null) RowActivated?.Invoke(this, item);
    }

    /// <summary>
    /// Copies the selected row as tab-separated values. The FULL untruncated value is copied, not
    /// what fitted on screen — the point of copying is to paste the real string into a terminal or
    /// a hash lookup, so display truncation must not follow it.
    ///
    /// It is not, however, copied raw. Every value here was written by whatever HERO is watching,
    /// and a process is free to put a carriage return in its own command line. Pasted into a shell,
    /// text after a CR is not text at all — it is a line the terminal submits. HERO would then be
    /// the delivery mechanism for the thing it is meant to catch. Control characters and bidi
    /// overrides are therefore escaped to a visible \uXXXX; nothing else is altered and nothing is
    /// shortened, so a path or hash still round-trips exactly.
    /// </summary>
    internal void CopySelectedRow()
    {
        var item = _rows.SelectedItem;
        if (item is null || Columns.Count == 0) return;

        var parts = new List<string>(Columns.Count);
        foreach (var column in Columns)
        {
            if (column.Kind == ColumnKind.Severity)
                parts.Add(SeverityPalette.Word(column.SeverityOf?.Invoke(item) ?? Severity.Safe));
            else
                parts.Add(GlyphText.Neutralise(column.Text?.Invoke(item)));
        }

        try
        {
            Clipboard.SetText(string.Join('\t', parts));
        }
        catch (Exception ex)
        {
            // The clipboard is a shared OS resource and another process can hold it open. A failed
            // copy is not worth an error dialog, but it is worth not pretending it worked.
            Debug.WriteLine($"HERO: clipboard copy failed - {ex.Message}");
        }
    }

    /// <summary>
    /// True only when something is actually listening for <see cref="SortRequested"/>.
    ///
    /// The table never sorts its own data, so with no subscriber a header click would flip the
    /// chevron and change nothing else — leaving the table asserting an order the rows are not in.
    /// A security tool that displays a claim it cannot honour is worse than one that displays
    /// nothing, so the header stays inert instead. An explicitly assigned <see cref="SortColumn"/>
    /// is still drawn: that one is the owner stating a fact about its own data.
    /// </summary>
    internal bool CanSort => SortRequested is not null;

    internal void RequestSort(DataColumn column)
    {
        if (!column.Sortable || !CanSort) return;
        if (ReferenceEquals(SortColumn, column)) SortAscending = !SortAscending;
        else { SortColumn = column; SortAscending = true; }
        SortRequested?.Invoke(this, column);
    }

    private void UpdateInteracting()
        => SetValue(IsInteractingKey,
            _rows.IsMouseOver || _rows.IsKeyboardFocusWithin || _rows.SelectedIndex >= 0);

    private void UpdateEmptyState()
    {
        bool any = false;
        if (ItemsSource is not null)
        {
            foreach (var _ in ItemsSource) { any = true; break; }
        }

        _empty.Visibility = !any && !IsBusy ? Visibility.Visible : Visibility.Collapsed;

        if (IsBusy) { _spinner.Visibility = Visibility.Visible; _spinner.Start(); }
        else { _spinner.Visibility = Visibility.Collapsed; _spinner.Stop(); }
    }

    /// <summary>
    /// Repaints every realised row. This is the whole live-update path: mutate the bound items,
    /// then call this once per tick from a single Dispatcher hop, rather than raising a change
    /// notification per property per row.
    /// </summary>
    internal void Refresh()
    {
        foreach (var row in _live) row.InvalidateVisual();
        UpdateEmptyState();
    }

    /// <summary>Drops cached brushes, typefaces and fitted strings after a theme change.</summary>
    internal void RefreshTheme()
    {
        _tokens = null;
        TokenVersion++;
        _header.InvalidateVisual();
        Refresh();
    }

    internal int TokenVersion { get; private set; }

    internal TableTokens Tokens => _tokens ??= TableTokens.Build(this);

    internal void Register(DataTableRow row) => _live.Add(row);

    internal void Unregister(DataTableRow row) => _live.Remove(row);

    /// <summary>
    /// Resolves the pixel width of every column for a given total. Header and rows both call this
    /// with the same total, which is what keeps them aligned without a shared-size scope.
    /// </summary>
    internal double[] ResolveWidths(double total)
    {
        if (!_widthsDirty && _widths.Length == Columns.Count && Math.Abs(total - _widthsFor) < 0.5)
            return _widths;

        var widths = new double[Columns.Count];
        double fixedSum = 0;
        double flexWeight = 0;

        // If no column asked to flex, the widest one becomes elastic. That keeps a table filling
        // its container instead of leaving dead space on this machine's very wide display, and the
        // widest column is in practice always the path or command-line column — the one that
        // benefits most from spare room and degrades worst without it.
        int autoFlex = -1;
        bool anyFlex = false;
        for (int i = 0; i < Columns.Count; i++)
        {
            if (Columns[i].Flex) { anyFlex = true; break; }
            if (autoFlex < 0 || Columns[i].Width > Columns[autoFlex].Width) autoFlex = i;
        }
        if (anyFlex) autoFlex = -1;

        for (int i = 0; i < Columns.Count; i++)
        {
            var column = Columns[i];
            if (column.Flex || i == autoFlex) { flexWeight += Math.Max(1, column.Width); widths[i] = column.MinWidth; }
            else { widths[i] = Math.Max(0, column.Width); fixedSum += widths[i]; }
        }

        if (flexWeight > 0)
        {
            // A flex column's declared Width is its WEIGHT, not a fixed size. Splitting the
            // remainder equally instead would give a 300-wide path column the same room as a
            // 200-wide process name, and the path — the column that most needs width — ends up
            // truncated to "C:\U...\uv.exe", which tells the user nothing.
            double remaining = Math.Max(0, total - fixedSum);
            for (int i = 0; i < widths.Length; i++)
            {
                if (!Columns[i].Flex && i != autoFlex) continue;
                double share = remaining * (Math.Max(1, Columns[i].Width) / flexWeight);
                widths[i] = Math.Max(Columns[i].MinWidth, share);
            }
        }

        _widths = widths;
        _widthsFor = total;
        _widthsDirty = false;
        return widths;
    }

    // ------------------------------------------------------------------------ nested visuals

    /// <summary>
    /// The list itself. The stock ListBox template is kept (it already contains a properly
    /// virtualising panel and a ScrollViewer, which Theme.xaml has restyled) and neutralised with
    /// property values; only the item container is replaced.
    /// </summary>
    private sealed class RowList : ListBox
    {
        private readonly DataTable _owner;

        internal RowList(DataTable owner)
        {
            _owner = owner;
            Background = Brushes.Transparent;
            BorderThickness = new Thickness(0);
            Padding = new Thickness(0);
            HorizontalContentAlignment = HorizontalAlignment.Stretch;

            // Every one of these is required TOGETHER. CanContentScroll=false in particular looks
            // like a smoothness fix and silently disables item virtualisation outright; ScrollUnit
            // Pixel is the setting that actually gives smooth scrolling while keeping it.
            ScrollViewer.SetCanContentScroll(this, true);
            ScrollViewer.SetHorizontalScrollBarVisibility(this, ScrollBarVisibility.Disabled);
            ScrollViewer.SetVerticalScrollBarVisibility(this, ScrollBarVisibility.Auto);
            VirtualizingPanel.SetIsVirtualizing(this, true);
            VirtualizingPanel.SetVirtualizationMode(this, VirtualizationMode.Recycling);
            VirtualizingPanel.SetScrollUnit(this, ScrollUnit.Pixel);
            VirtualizingPanel.SetCacheLength(this, new VirtualizationCacheLength(1, 1));
            VirtualizingPanel.SetCacheLengthUnit(this, VirtualizationCacheLengthUnit.Page);

            // Grouping (severity bands, autorun categories, timeline days) turns virtualisation OFF
            // unless this is set explicitly — it defaults to false, and every other setting above
            // can be correct while a grouped 1,000-row list still realises every container.
            VirtualizingPanel.SetIsVirtualizingWhenGrouping(this, true);
        }

        protected override bool IsItemItsOwnContainerOverride(object item) => item is DataTableRow;

        protected override DependencyObject GetContainerForItemOverride() => new DataTableRow(_owner);
    }

    /// <summary>Column headings, drawn with the same resolved widths the rows use.</summary>
    private sealed class HeaderStrip : FrameworkElement
    {
        private readonly DataTable _owner;

        internal HeaderStrip(DataTable owner)
        {
            _owner = owner;
            SnapsToDevicePixels = true;
            UseLayoutRounding = true;
        }

        protected override Size MeasureOverride(Size availableSize)
            => new(double.IsInfinity(availableSize.Width) ? 0 : availableSize.Width, _owner.HeaderHeight);

        protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
        {
            base.OnMouseLeftButtonUp(e);
            var column = ColumnAt(e.GetPosition(this).X);
            if (column is not null) _owner.RequestSort(column);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            Cursor = ColumnAt(e.GetPosition(this).X) is not null ? Cursors.Hand : null;
        }

        private DataColumn? ColumnAt(double x)
        {
            if (!_owner.CanSort) return null;   // no listener: no hand cursor, no click response

            var widths = _owner.ResolveWidths(RenderSize.Width);
            double cursor = 0;
            for (int i = 0; i < widths.Length && i < _owner.Columns.Count; i++)
            {
                if (x >= cursor && x < cursor + widths[i])
                    return _owner.Columns[i].Sortable ? _owner.Columns[i] : null;
                cursor += widths[i];
            }
            return null;
        }

        protected override void OnRender(DrawingContext dc)
        {
            double w = RenderSize.Width, h = RenderSize.Height;
            if (w <= 0 || h <= 0) return;

            var t = _owner.Tokens;
            double ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip;

            dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
            dc.DrawLine(t.DividerPen, new Point(0, h - 0.5), new Point(w, h - 0.5));

            double noteWidth = 0;
            if (!string.IsNullOrEmpty(_owner.HeaderNote))
            {
                var note = GlyphText.Make(GlyphText.Sanitise(_owner.HeaderNote), t.Ui, t.SizeMicro, t.TextTertiary, ppd);
                noteWidth = note.Width + 12;
                dc.DrawText(note, new Point(w - note.Width - _owner.CellPadding, (h - note.Height) / 2));
            }

            var widths = _owner.ResolveWidths(w);
            double pad = _owner.CellPadding;
            double tracking = t.SizeMicro * 0.055;   // +0.6px at 11.5px: the overline treatment
            double x = 0;

            for (int i = 0; i < widths.Length && i < _owner.Columns.Count; i++)
            {
                var column = _owner.Columns[i];
                double cw = widths[i];
                if (cw <= pad * 2) { x += cw; continue; }

                string text = column.Header.ToUpperInvariant();
                bool active = ReferenceEquals(_owner.SortColumn, column);
                var ink = active ? t.Accent : t.TextTertiary;
                double tw = GlyphText.TrackedWidth(text, t.UiSemi, t.SizeMicro, ppd, tracking);
                double th = GlyphText.Height(text, t.UiSemi, t.SizeMicro, ppd);
                bool right = column.Kind is ColumnKind.Numeric or ColumnKind.MonoNumeric;

                double chevron = active ? t.SizeMicro + 4 : 0;
                double tx = right ? x + cw - pad - tw - chevron : x + pad;
                double ty = (h - th) / 2;

                // Suppress a heading only if its TEXT would actually run into the note, not merely
                // because its column does. A short heading such as RISK survives beside the note.
                if (noteWidth <= 0 || tx + tw + chevron <= w - noteWidth)
                {
                    GlyphText.DrawTracked(dc, text, t.UiSemi, t.SizeMicro, ink, ppd, tracking, new Point(tx, ty));

                    if (active)
                    {
                        // E70D / E70E are the verified chevron-down / chevron-up code points.
                        var glyph = GlyphText.Make(_owner.SortAscending ? "\uE70E" : "\uE70D",
                                                   t.Icon, t.SizeMicro, t.Accent, ppd);
                        dc.DrawText(glyph, new Point(tx + tw + 4, (h - glyph.Height) / 2));
                    }
                }

                x += cw;
            }
        }
    }

    /// <summary>
    /// A 20px arc that only appears for slow loads. Shown after the caller sets IsBusy; short
    /// operations should never flash one.
    /// </summary>
    private sealed class Spinner : FrameworkElement
    {
        private readonly RotateTransform _rotation = new();
        private Pen? _pen;

        internal Spinner()
        {
            Width = 24;
            Height = 24;
            HorizontalAlignment = HorizontalAlignment.Center;
            VerticalAlignment = VerticalAlignment.Center;
            RenderTransformOrigin = new Point(0.5, 0.5);
            RenderTransform = _rotation;
        }

        internal void Start()
        {
            // A forever-repeating rotation is the animation people who disable motion mind most,
            // so it obeys the app switch as well as the OS one.
            if (!Motion.Active) return;
            _rotation.BeginAnimation(RotateTransform.AngleProperty,
                new DoubleAnimation(0, 360, new Duration(TimeSpan.FromMilliseconds(900)))
                {
                    RepeatBehavior = RepeatBehavior.Forever,
                });
        }

        internal void Stop() => _rotation.BeginAnimation(RotateTransform.AngleProperty, null);

        protected override void OnRender(DrawingContext dc)
        {
            double d = Math.Min(RenderSize.Width, RenderSize.Height);
            if (d < 6) return;

            _pen ??= new Pen(SeverityPalette.ResolveBrush(this, "Accent", Color.FromRgb(0x4C, 0x8D, 0xFF)), 2)
            {
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round,
            };

            double r = d / 2 - 1;
            var centre = new Point(RenderSize.Width / 2, RenderSize.Height / 2);
            var start = new Point(centre.X, centre.Y - r);
            double rad = (270 - 90) * Math.PI / 180d;
            var end = new Point(centre.X + r * Math.Cos(rad), centre.Y + r * Math.Sin(rad));

            var geo = new StreamGeometry();
            using (var ctx = geo.Open())
            {
                ctx.BeginFigure(start, false, false);
                ctx.ArcTo(end, new Size(r, r), 0, true, SweepDirection.Clockwise, true, false);
            }
            geo.Freeze();
            dc.DrawGeometry(null, _pen, geo);
        }
    }
}

/// <summary>
/// One table row: a single visual element that paints its own background, selection rail, focus
/// ring and every cell. The stock ListBoxItem chrome is removed entirely (OverridesDefaultStyle
/// plus a null Template) rather than restyled, because the default template's selection trigger
/// paints the system highlight over a template child, where a local Background cannot reach it.
/// </summary>
internal sealed class DataTableRow : ListBoxItem
{
    private readonly DataTable _owner;

    private string[] _fitSource = Array.Empty<string>();
    private string[] _fitResult = Array.Empty<string>();
    private double[] _fitWidth = Array.Empty<double>();
    private FormattedText?[] _fitLayout = Array.Empty<FormattedText?>();
    private int _fitTokenVersion = -1;

    // Hovering a clipped cell reveals the whole value. The Network page's "Why" column is prose,
    // and prose does not fit a column: at any window width some rows end in an ellipsis. Clipping
    // is fine as long as the full text is one hover away — silently eating the second half of a
    // sentence is not. Paths in the Persistence and Threats tables get the same treatment.
    private readonly ToolTip _tip = new()
    {
        Content = new TextBlock { TextWrapping = TextWrapping.Wrap, MaxWidth = 420 },
        Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom,
    };
    private readonly DispatcherTimer _tipTimer;
    private int _tipColumn = -1;

    internal DataTableRow(DataTable owner)
    {
        _owner = owner;
        OverridesDefaultStyle = true;
        Template = null;
        FocusVisualStyle = null;
        SnapsToDevicePixels = true;
        UseLayoutRounding = true;

        // The tooltip is opened by hand rather than through ToolTipService, because the service
        // decides whether an element has a tooltip when the pointer ENTERS it and does not look
        // again while the pointer stays inside. A row is one element spanning every column, so a
        // tooltip attached on the way across one cell would never be noticed. Measured: nothing
        // opened at all until this timer replaced the service.
        _tipTimer = new DispatcherTimer(DispatcherPriority.Normal, Dispatcher)
        {
            Interval = TimeSpan.FromMilliseconds(450),   // not while merely crossing the table
        };
        _tipTimer.Tick += (_, _) =>
        {
            _tipTimer.Stop();
            if (IsMouseOver && _tip.Content is TextBlock { Text.Length: > 0 })
            {
                StyleTip();
                _tip.PlacementTarget = this;
                _tip.IsOpen = true;
            }
        };
    }

    private int _tipStyledForVersion = -1;

    /// <summary>
    /// Dresses the tooltip in HERO's palette.
    ///
    /// Theme.Controls.xaml carries a ToolTip style, but nothing merges that file — App.xaml takes
    /// Theme.xaml alone — so an unstyled tooltip came up as the pale Win32 relic on a dark
    /// window. Merging the file wholesale would also swap every table's row height and hover
    /// colour from their compiled-in fallbacks to its own, which is not a change to make in
    /// passing, so this control dresses its own tooltip from the tokens that are loaded.
    /// </summary>
    private void StyleTip()
    {
        var t = _owner.Tokens;
        if (_tipStyledForVersion == t.Version) return;
        _tipStyledForVersion = t.Version;

        var surface = new FrameworkElementFactory(typeof(Border));
        surface.SetValue(Border.BackgroundProperty,
            SeverityPalette.ResolveBrush(_owner, "Surface3", Color.FromRgb(0x24, 0x2D, 0x38)));
        surface.SetValue(Border.BorderBrushProperty,
            SeverityPalette.ResolveBrush(_owner, "HairLine", Color.FromRgb(0x2E, 0x39, 0x45)));
        surface.SetValue(Border.BorderThicknessProperty, new Thickness(1));
        surface.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
        surface.SetValue(Border.PaddingProperty, new Thickness(10, 6, 10, 6));
        surface.SetValue(SnapsToDevicePixelsProperty, true);
        surface.SetValue(UseLayoutRoundingProperty, true);
        surface.AppendChild(new FrameworkElementFactory(typeof(ContentPresenter)));

        _tip.OverridesDefaultStyle = true;
        _tip.HasDropShadow = false;
        _tip.Template = new ControlTemplate(typeof(ToolTip)) { VisualTree = surface };
        _tip.Foreground = t.TextSecondary;
        _tip.FontFamily = t.Ui.FontFamily;
        _tip.FontSize = t.SizeMicro;
    }

    private void HideTip()
    {
        _tipTimer.Stop();
        _tip.IsOpen = false;
        _tipColumn = -1;
    }

    protected override Size MeasureOverride(Size constraint)
    {
        double w = double.IsInfinity(constraint.Width) ? _owner.ActualWidth : constraint.Width;
        return new Size(Math.Max(0, w), _owner.RowHeight);
    }

    protected override void OnVisualParentChanged(DependencyObject oldParent)
    {
        base.OnVisualParentChanged(oldParent);

        // Recycled containers leave and re-enter the panel, so this is also the recycle hook.
        if (VisualParent is null) { HideTip(); _owner.Unregister(this); }
        else _owner.Register(this);
    }

    protected override void OnContentChanged(object oldContent, object newContent)
    {
        base.OnContentChanged(oldContent, newContent);

        // A recycled container is now showing a different item, so every cached cell is stale —
        // including whatever a tooltip is currently quoting.
        HideTip();
        Array.Clear(_fitSource);
        Array.Clear(_fitLayout);
        InvalidateVisual();
    }

    protected override void OnMouseEnter(MouseEventArgs e) { base.OnMouseEnter(e); InvalidateVisual(); }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        HideTip();
        InvalidateVisual();
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        UpdateTip(e.GetPosition(this).X);
    }

    /// <summary>
    /// Offers the untruncated value of the cell under the pointer, and only when that cell really
    /// was cut short. Nothing is measured here: the render pass already recorded both the full
    /// string and the fitted one, so a cell is clipped exactly when they differ.
    /// </summary>
    private void UpdateTip(double x)
    {
        int index = -1;
        var widths = _owner.ResolveWidths(RenderSize.Width);
        double cursor = 0;
        for (int i = 0; i < widths.Length && i < _fitSource.Length; i++)
        {
            if (x >= cursor && x < cursor + widths[i]) { index = i; break; }
            cursor += widths[i];
        }

        if (index == _tipColumn) return;
        _tipColumn = index;

        // Anything already showing belongs to the cell the pointer has just left.
        _tipTimer.Stop();
        _tip.IsOpen = false;

        string? full = index >= 0 && _fitSource[index] is { Length: > 0 } source && _fitResult[index] != source
            ? source
            : null;

        var label = (TextBlock)_tip.Content;
        label.Text = full ?? "";
        if (full is null) return;

        // Line the tooltip up under the cell it explains, not under the far-left edge of the row.
        _tip.HorizontalOffset = Math.Max(0, x - 24);
        _tipTimer.Start();
    }

    protected override void OnSelected(RoutedEventArgs e) { base.OnSelected(e); InvalidateVisual(); }

    protected override void OnUnselected(RoutedEventArgs e) { base.OnUnselected(e); InvalidateVisual(); }

    protected override void OnGotKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnGotKeyboardFocus(e);
        InvalidateVisual();
    }

    protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnLostKeyboardFocus(e);
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = RenderSize.Width, h = RenderSize.Height;
        if (w <= 0 || h <= 0) return;

        var t = _owner.Tokens;
        var full = new Rect(0, 0, w, h);

        // A control that paints nothing is not hit-testable, so hover would never fire.
        dc.DrawRectangle(Brushes.Transparent, null, full);

        if (IsSelected)
        {
            dc.DrawRectangle(t.SurfaceSelected, null, full);
            dc.DrawRectangle(t.Accent, null, new Rect(0, 0, 2, h));
        }
        else if (IsMouseOver)
        {
            dc.DrawRectangle(t.SurfaceHover, null, full);
        }

        var item = Content ?? DataContext;
        if (item is null || _owner.Columns.Count == 0) return;

        double ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var widths = _owner.ResolveWidths(w);
        EnsureCache(_owner.Columns.Count, t.Version);

        double x = 0;
        for (int i = 0; i < widths.Length && i < _owner.Columns.Count; i++)
        {
            DrawCell(dc, _owner.Columns[i], i, item, x, widths[i], h, ppd, t);
            x += widths[i];
        }

        if (IsKeyboardFocused && w > 4 && h > 4)
            dc.DrawRectangle(null, t.FocusPen, new Rect(1, 1, w - 2, h - 2));
    }

    private void DrawCell(DrawingContext dc, DataColumn column, int index, object item,
                          double x, double width, double h, double ppd, TableTokens t)
    {
        double pad = _owner.CellPadding;
        double available = width - pad * 2;
        if (available <= 4) return;

        if (column.Kind == ColumnKind.Severity)
        {
            var severity = column.SeverityOf?.Invoke(item) ?? Severity.Safe;

            // A healthy machine's risk column is almost entirely empty, and that emptiness is
            // itself the reassuring signal. Drawing "SAFE" on 400 rows would destroy it.
            if (severity == Severity.Safe) return;
            DrawInlinePill(dc, severity, x + pad, h, available, ppd, t);
            return;
        }

        string raw = column.Text?.Invoke(item) ?? string.Empty;
        if (raw.Length == 0) return;

        bool mono = column.Kind is ColumnKind.Mono or ColumnKind.MonoNumeric;
        var face = mono ? t.Mono : column.Kind == ColumnKind.Identity ? t.UiSemi : t.Ui;
        double size = mono ? t.SizeMono : t.SizeBody;
        var ink = column.Kind == ColumnKind.Identity ? t.TextPrimary : t.TextSecondary;

        string fitted = Fit(index, GlyphText.Sanitise(raw), face, size, ppd, available, column.MiddleEllipsis);
        if (fitted.Length == 0) return;

        double textHeight = GlyphText.Height(fitted, face, size, ppd);
        double y = (h - textHeight) / 2;

        if (column.Kind == ColumnKind.Numeric)
        {
            // The UI face is proportional, so a value ticking 8 -> 9 -> 10 would shuffle sideways
            // every second without a fixed digit advance. Mono columns are already tabular.
            double tw = GlyphText.TabularWidth(fitted, face, size, ppd, t.DigitAdvance);
            GlyphText.DrawTabular(dc, fitted, face, size, ink, ppd, t.DigitAdvance,
                new Point(x + width - pad - tw, y));
            return;
        }

        // The laid-out run is cached alongside the fitted string and only recoloured on each draw.
        // A steady-state 1 Hz repaint of a screenful then allocates nothing for text at all.
        var text = _fitLayout.Length > index ? _fitLayout[index] : null;
        if (text is null)
        {
            text = GlyphText.Make(fitted, face, size, ink, ppd);
            if (_fitLayout.Length > index) _fitLayout[index] = text;
        }
        else
        {
            text.SetForegroundBrush(ink);
        }

        double tx = column.Kind == ColumnKind.MonoNumeric ? x + width - pad - text.Width : x + pad;
        dc.DrawText(text, new Point(tx, y));
    }

    private void DrawInlinePill(DrawingContext dc, Severity severity, double x, double h,
                                double available, double ppd, TableTokens t)
    {
        var basis = SeverityPalette.Base(_owner, severity);
        var fill = SeverityPalette.Brush(SeverityPalette.PillBackground(basis, t.GroundColour));
        var ink = SeverityPalette.Brush(SeverityPalette.PillForeground(basis));

        double size = t.SizeMicro;
        double ph = Math.Round(size * 1.9);
        double tracking = size * 0.035;
        string word = SeverityPalette.Word(severity).ToUpperInvariant();
        double tw = GlyphText.TrackedWidth(word, t.UiSemi, size, ppd, tracking);
        double pw = Math.Min(available, tw + ph * 0.84);
        double py = (h - ph) / 2;

        dc.DrawRoundedRectangle(fill, null, new Rect(x, py, pw, ph), ph / 2, ph / 2);
        double th = GlyphText.Height(word, t.UiSemi, size, ppd);
        GlyphText.DrawTracked(dc, word, t.UiSemi, size, ink, ppd, tracking,
            new Point(x + ph * 0.42, py + (ph - th) / 2));
    }

    private void EnsureCache(int columns, int tokenVersion)
    {
        if (_fitSource.Length != columns)
        {
            _fitSource = new string[columns];
            _fitResult = new string[columns];
            _fitWidth = new double[columns];
            _fitLayout = new FormattedText?[columns];
            _fitTokenVersion = tokenVersion;
            return;
        }

        if (_fitTokenVersion != tokenVersion)
        {
            Array.Clear(_fitSource);
            Array.Clear(_fitLayout);
            _fitTokenVersion = tokenVersion;
        }
    }

    /// <summary>
    /// Memoised truncation. Without this, a 1 Hz repaint would re-run a binary search over a
    /// 260-character path for every visible row, every second, forever.
    /// </summary>
    private string Fit(int index, string text, Typeface face, double size, double ppd,
                       double available, bool middle)
    {
        if (index >= _fitSource.Length) return GlyphText.Fit(text, face, size, ppd, available, middle);

        if (_fitSource[index] == text && Math.Abs(_fitWidth[index] - available) < 0.5)
            return _fitResult[index];

        string result = GlyphText.Fit(text, face, size, ppd, available, middle);
        _fitSource[index] = text;
        _fitWidth[index] = available;
        _fitResult[index] = result;
        _fitLayout[index] = null;   // the laid-out run no longer matches
        return result;
    }
}

/// <summary>
/// Brushes, typefaces and metrics resolved once per table rather than once per row per frame.
/// Rebuilt on demand via <see cref="DataTable.RefreshTheme"/>.
/// </summary>
internal sealed class TableTokens
{
    private static int _version;

    internal required Brush TextPrimary { get; init; }
    internal required Brush TextSecondary { get; init; }
    internal required Brush TextTertiary { get; init; }
    internal required Brush Accent { get; init; }
    internal required Brush SurfaceHover { get; init; }
    internal required Brush SurfaceSelected { get; init; }
    internal required Pen DividerPen { get; init; }
    internal required Pen FocusPen { get; init; }
    internal required Typeface Ui { get; init; }
    internal required Typeface UiSemi { get; init; }
    internal required Typeface Mono { get; init; }
    internal required Typeface Icon { get; init; }
    internal required double SizeBody { get; init; }
    internal required double SizeMono { get; init; }
    internal required double SizeMicro { get; init; }
    internal required double DigitAdvance { get; init; }
    internal required Color GroundColour { get; init; }
    internal required int Version { get; init; }

    internal static TableTokens Build(FrameworkElement context)
    {
        var ui = context.TryFindResource("UIFont") as FontFamily
                 ?? new FontFamily("Segoe UI Variable Text, Segoe UI");
        var mono = context.TryFindResource("MonoFont") as FontFamily
                   ?? new FontFamily("Cascadia Mono, Consolas");
        var icon = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets");

        double body = SeverityPalette.ResolveDouble(context, "FsBody", 14.5);
        var uiFace = new Typeface(ui, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

        var focusBrush = SeverityPalette.ResolveBrush(context, "BorderFocus", Color.FromRgb(0x7F, 0xB1, 0xFF));
        var dividerBrush = SeverityPalette.ResolveBrush(context, "Divider", Color.FromRgb(0x23, 0x2B, 0x36));

        var dividerPen = new Pen(dividerBrush, 1);
        if (dividerPen.CanFreeze) dividerPen.Freeze();
        var focusPen = new Pen(focusBrush, 2);
        if (focusPen.CanFreeze) focusPen.Freeze();

        return new TableTokens
        {
            TextPrimary = SeverityPalette.ResolveBrush(context, "TextPrimary", Color.FromRgb(0xED, 0xF1, 0xF7)),
            TextSecondary = SeverityPalette.ResolveBrush(context, "TextSecondary", Color.FromRgb(0xA6, 0xB2, 0xC2)),
            TextTertiary = SeverityPalette.ResolveBrush(context, "TextTertiary", Color.FromRgb(0x78, 0x84, 0x9A)),
            Accent = SeverityPalette.ResolveBrush(context, "Accent", Color.FromRgb(0x4C, 0x8D, 0xFF)),

            // Surface.Hover / Surface.Selected are not in Theme.xaml; Theme.Controls.xaml adds
            // them, and these fallbacks keep the table correct if it has not been merged.
            SurfaceHover = SeverityPalette.ResolveBrush(context, "SurfaceHover", Color.FromRgb(0x1F, 0x25, 0x2D)),
            SurfaceSelected = SeverityPalette.ResolveBrush(context, "SurfaceSelected", Color.FromRgb(0x16, 0x26, 0x3D)),

            DividerPen = dividerPen,
            FocusPen = focusPen,
            Ui = uiFace,
            UiSemi = new Typeface(ui, FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal),
            Mono = new Typeface(mono, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
            Icon = new Typeface(icon, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
            SizeBody = body,
            SizeMono = SeverityPalette.ResolveDouble(context, "FsMono", 13.5),
            SizeMicro = SeverityPalette.ResolveDouble(context, "FsMicro", 11.5),
            DigitAdvance = GlyphText.DigitAdvance(uiFace, body, VisualTreeHelper.GetDpi(context).PixelsPerDip),
            GroundColour = SeverityPalette.Resolve(context, "Surface1", Color.FromRgb(0x15, 0x1A, 0x21)),
            Version = ++_version,
        };
    }
}
