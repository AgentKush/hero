# Warden Design System v1 — WPF Dashboard Visual & Interaction Specification (net10.0-windows, Win11 26200)

> Area: `premium-ui` · adversarial critique verdict: **sound_with_fixes**

## Summary
Warden's dashboard is a dark-first, borderless WPF shell that borrows its structural language from Linear and Raycast rather than from antivirus software: a Mica-backed custom title bar, a collapsible icon+label navigation rail, and an opaque content canvas built entirely from 1px-bordered elevation surfaces instead of drop shadows. The mood is calm confidence — the hero visual is a single 176px posture score ring that is green and near-full at rest, and whose arc gets SHORTER (not redder-and-bigger) as posture degrades, so a compromised machine reads as "less protection earned" rather than as a klaxon. Colour is a nine-step neutral ramp with a restrained #2F6FE0 accent and a five-stop severity ramp; all 172 foreground/background pairings were machine-verified for WCAG AA (4.5:1 text, 3:1 non-text) with zero failures, including every text role against every interactive surface state. Typography is Segoe UI Variable Display/Text/Small with Cascadia Mono mandatory for paths, hashes, PIDs, command lines and ports — the weight scale deliberately excludes 500, because the shipped Segoe UI Variable exposes only 300/350/400/600/700 and a Medium request silently snaps. Every stock control is retemplated to a bare Border+ContentPresenter — the default WPF ScrollBar, ListView/GridView header and TabControl chrome are treated as build-breaking and forbidden. Motion is a four-token duration scale (90/140/220/320ms) restricted to Opacity and RenderTransform so nothing re-enters layout per frame, with an explicit never-animate list covering live table reordering and virtualised item recycling.

## Items (32)
### [critical] SHELL — Window composition and WindowChrome configuration
Warden uses a fully custom, borderless shell: no OS title bar, no OS caption buttons. The window is one WindowChrome-hosted surface split into a 40px title strip, a nav rail gutter, and an opaque content canvas. This is the single largest contributor to 'not a WinForms utility' — the stock Win32 caption instantly reads as a system tool. Critically, the Mica backdrop is only allowed to show through in the title strip and the rail gutter; the content canvas must be painted with an opaque surface brush, because WPF disables ClearType subpixel text rendering anywhere the window is composited as transparent, and grayscale-antialiased 13px body text is the exact thing that makes a WPF app look cheap.

**How:** MainWindow: WindowStyle="None", AllowsTransparency="False" (MUST stay False — True forces the slow software render path and kills Mica), ResizeMode="CanResize", Background="Transparent", MinWidth="1040", MinHeight="680", Width="1280", Height="820".

<WindowChrome.WindowChrome>
  <WindowChrome CaptionHeight="40"
                ResizeBorderThickness="8"
                CornerRadius="0"
                GlassFrameThickness="-1"
                UseAeroCaptionButtons="False"
                NonClientFrameEdges="None"/>
</WindowChrome.WindowChrome>

GlassFrameThickness="-1" (sheet-of-glass) is REQUIRED for the DWM backdrop to reach the client area; verified working. CaptionHeight=40 makes the whole strip draggable for free. Mark every interactive element inside the strip (buttons, search field, caption buttons) with WindowChrome.IsHitTestVisibleInChrome="True" or it will be swallowed by the drag region.

Layout skeleton (root Grid inside the window):
Row0 Height=40  -> title strip (Background=Transparent, shows Mica)
Row1 Height=*   -> Grid: Col0=nav rail (64 or 232px, Background=Transparent -> Mica), Col1=content canvas (Background={DynamicResource Surface.Base}, opaque)
Content canvas gets CornerRadius="12,0,0,0" via a Border so it tucks under the title strip.

**False positives:** Do NOT set AllowsTransparency="True" to get rounded corners — it looks like it works, disables hardware acceleration and the DWM backdrop, and produces a black or milky rectangle instead of Mica. Rounded corners come from DWMWA_WINDOW_CORNER_PREFERENCE, not from WPF. Also do not set WindowChrome.CornerRadius to a non-zero value expecting rounded window corners; that property only clips the WPF content, and combined with DWM rounding it produces a visible double-radius seam.

### [critical] SHELL — DWM interop layer: exact verified P/Invoke signatures and constants
All window-level premium affordances (rounded corners, Mica, dark titlebar/border tint) come from four dwmapi.dll calls. Every signature and constant below was compiled and executed on the target machine (Windows 11 Pro 26200.8313, .NET 10.0.11 WindowsDesktop) and each returned HRESULT 0x00000000 (S_OK). Nothing here needs a NuGet package.

**How:** internal static class Dwm
{
    public const int DWMWA_USE_IMMERSIVE_DARK_MODE   = 20;
    public const int DWMWA_BORDER_COLOR              = 34;
    public const int DWMWA_CAPTION_COLOR             = 35;
    public const int DWMWA_TEXT_COLOR                = 36;
    public const int DWMWA_WINDOW_CORNER_PREFERENCE  = 33;
    public const int DWMWA_SYSTEMBACKDROP_TYPE       = 38;

    // DWM_WINDOW_CORNER_PREFERENCE
    public const int DWMWCP_DEFAULT = 0, DWMWCP_DONOTROUND = 1, DWMWCP_ROUND = 2, DWMWCP_ROUNDSMALL = 3;
    // DWM_SYSTEMBACKDROP_TYPE
    public const int DWMSBT_AUTO = 0, DWMSBT_NONE = 1, DWMSBT_MAINWINDOW = 2,   // Mica
                     DWMSBT_TRANSIENTWINDOW = 3,                               // Acrylic
                     DWMSBT_TABBEDWINDOW = 4;                                  // Mica Alt

    [DllImport("dwmapi.dll", SetLastError = true)]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    [StructLayout(LayoutKind.Sequential)]
    public struct MARGINS { public int cxLeftWidth, cxRightWidth, cyTopHeight, cyBottomHeight; }

    [DllImport("dwmapi.dll", SetLastError = true)]
    public static extern int DwmExtendFrameIntoClientArea(IntPtr hwnd, ref MARGINS m);
}

Call site — MUST be in Window.SourceInitialized (the HWND does not exist before it, and OnLoaded is too late for a flicker-free first paint):

protected override void OnSourceInitialized(EventArgs e)
{
    base.OnSourceInitialized(e);
    var h = new WindowInteropHelper(this).Handle;
    int v;
    v = 1;                        Dwm.DwmSetWindowAttribute(h, Dwm.DWMWA_USE_IMMERSIVE_DARK_MODE, ref v, sizeof(int));
    v = Dwm.DWMWCP_ROUND;         Dwm.DwmSetWindowAttribute(h, Dwm.DWMWA_WINDOW_CORNER_PREFERENCE, ref v, sizeof(int));
    v = Dwm.DWMSBT_MAINWINDOW;    Dwm.DwmSetWindowAttribute(h, Dwm.DWMWA_SYSTEMBACKDROP_TYPE, ref v, sizeof(int));
    v = 0x00332A24;               Dwm.DwmSetWindowAttribute(h, Dwm.DWMWA_BORDER_COLOR, ref v, sizeof(int));
    var m = new Dwm.MARGINS { cxLeftWidth=-1, cxRightWidth=-1, cyTopHeight=-1, cyBottomHeight=-1 };
    Dwm.DwmExtendFrameIntoClientArea(h, ref m);
    HwndSource.FromHwnd(h).AddHook(WndProc);
}

DWMWA_BORDER_COLOR / CAPTION_COLOR take a COLORREF in 0x00BBGGRR order, NOT 0xRRGGBB. #242A33 therefore encodes as 0x00332A24. Use flyouts/dialogs with DWMSBT_TRANSIENTWINDOW (Acrylic) and DWMWCP_ROUNDSMALL.

**False positives:** DWMWA_USE_IMMERSIVE_DARK_MODE was 19 on Windows 10 builds before 18985 and 20 from then onward. Do not write the 19/20 fallback dance — the target is pinned at 26200, so 20 is correct and unconditional. Also do not marshal the value as bool: the P/Invoke must pass a 4-byte int by ref with size sizeof(int); passing a managed bool marshals as 1 byte on some paths and the call silently no-ops with S_OK.

### [critical] SHELL — Backdrop, theme application order, and the ClearType trap
Mica is a desktop-wallpaper-derived tint, so it is beautiful behind chrome and actively harmful behind data. The rule is a two-zone window: chrome zones are transparent and let Mica through; every zone that contains body text, a table, or a card is painted opaque. This is not just taste — a WPF subtree composited over a transparent window region loses ClearType and renders grayscale-antialiased text, which at 13px is visibly softer and is the single most common reason hand-built WPF apps look unfinished.

**How:** Zone map:
  TRANSPARENT (Mica visible): title strip (Row0), nav rail gutter background, window edge padding.
  OPAQUE (must have a Background brush): content canvas root Border -> {DynamicResource Surface.Base}; every Card -> Surface.Raised; every flyout/menu/toast -> Surface.Overlay; every table row container.

Order of operations at startup, exactly:
  1. Load Tokens.{Dark|Light}.xaml into MergedDictionaries[0] BEFORE InitializeComponent's window shows.
  2. Window.SourceInitialized -> DWMWA_USE_IMMERSIVE_DARK_MODE (do this FIRST; it repaints the non-client area).
  3. -> DWMWA_WINDOW_CORNER_PREFERENCE.
  4. -> DWMWA_SYSTEMBACKDROP_TYPE.
  5. -> DwmExtendFrameIntoClientArea.
Setting backdrop before dark mode causes a one-frame light-grey flash on cold start.

On theme change at runtime re-issue step 2 with v=0 for light, then swap MergedDictionaries[0].
Follow the OS by default: read HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme (DWORD, 0=dark) and subscribe to SystemEvents.UserPreferenceChanged (UserPreferenceCategory.General).

On every text-bearing opaque surface set:
  TextOptions.TextFormattingMode="Display"   (for runs < 16px)
  TextOptions.TextRenderingMode="ClearType"
  RenderOptions.ClearTypeHint="Enabled"
Use TextFormattingMode="Ideal" only for the >=20px display sizes, where Display-mode pixel snapping distorts Segoe UI Variable's outlines.

**False positives:** A card that looks correct in a screenshot may still be transparent — if you set only a CornerRadius Border with no Background, Mica shows through and text silently drops to grayscale AA. Audit by setting the desktop wallpaper to a saturated photo: any card whose text sits over visible wallpaper colour is mis-specified. Separately, applying ANY Effect (including a DropShadowEffect) to a subtree also disables ClearType in that subtree — same visual symptom, different cause.

### [high] SHELL — Drag, resize, maximise, snap layouts and DPI correctness
Custom chrome breaks four Win32 behaviours that users unconsciously expect, and their absence is what makes a custom-chrome app feel broken: (a) hovering the maximise button must show the Windows 11 Snap Layouts flyout, (b) maximising must not spill over the taskbar, (c) double-clicking the title strip must toggle maximise, (d) the 8px resize grip must still work at the rounded corners. Snap Layouts in particular is a Win11 signature — a window that does not offer it feels non-native.

**How:** Add an HwndSource hook (registered in OnSourceInitialized above):

const int WM_NCHITTEST = 0x0084, WM_GETMINMAXINFO = 0x0024, HTMAXBUTTON = 9;

IntPtr WndProc(IntPtr hwnd, int msg, IntPtr w, IntPtr l, ref bool handled)
{
  if (msg == WM_NCHITTEST)
  {
      // Snap Layouts: return HTMAXBUTTON when the cursor is over OUR maximise button.
      int x = unchecked((short)(long)l), y = unchecked((short)((long)l >> 16));
      var p = MaxButton.PointFromScreen(new Point(x, y));
      if (new Rect(0, 0, MaxButton.ActualWidth, MaxButton.ActualHeight).Contains(p))
      { handled = true; return (IntPtr)HTMAXBUTTON; }
  }
  if (msg == WM_GETMINMAXINFO) { AdjustMaximisedBounds(hwnd, l); handled = false; }
  return IntPtr.Zero;
}

Because you returned HTMAXBUTTON you now own the button's own hover/click: handle WM_NCLBUTTONDOWN/WM_NCLBUTTONUP for HTMAXBUTTON to toggle WindowState, and WM_NCMOUSELEAVE to clear the hover visual (the button will never receive normal WPF mouse events again).

WM_GETMINMAXINFO: use MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) + GetMonitorInfo and write MINMAXINFO.ptMaxPosition/ptMaxSize from rcWork (not rcMonitor) so maximise respects the taskbar on the CURRENT monitor.

DPI: set in app.manifest <dpiAwareness>PerMonitorV2</dpiAwareness>; handle Window.DpiChanged to re-evaluate any px-fixed geometry (score ring stroke, sparkline sample spacing). Keep the nav rail widths (64/232) and row height (36) as device-independent units — WPF scales them — but recompute the sparkline's StreamGeometry point spacing from ActualWidth on DpiChanged.

Caption buttons (draw your own, right-aligned in the title strip): 46x40px each, no radius, Segoe Fluent Icons glyphs E921 (min) / E922 (max) / E923 (restore) / E8BB (close), 10px glyph size. Hover fill Surface.Hover; the CLOSE button alone hovers to #C42B32 with #FFFFFF glyph. Set WindowChrome.IsHitTestVisibleInChrome="True" on min/close (max is handled by the hook).

**False positives:** Do not implement window dragging with a MouseLeftButtonDown -> DragMove() handler on the title strip. It appears to work, but it throws InvalidOperationException if the mouse button is released during the drag, breaks double-click-to-maximise, and defeats the OS drag-to-snap and shake-to-minimise gestures. WindowChrome.CaptionHeight already provides correct native dragging — do nothing.

### [high] SHELL — Project configuration (verified build gotcha)
The obvious csproj for this stack does not compile. Targeting bare net10.0-windows pins TargetPlatformVersion to 7.0, so any SupportedOSPlatformVersion above that is a hard error, and the Windows 11-era APIs are not surfaced. This costs an hour if undiscovered, and the error message does not suggest the fix.

**How:** Verified-good csproj (this exact file built clean, 0 warnings, on SDK 10.0.303):

<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net10.0-windows10.0.26100.0</TargetFramework>
    <SupportedOSPlatformVersion>10.0.22621.0</SupportedOSPlatformVersion>
    <UseWPF>true</UseWPF>
    <UseWindowsForms>true</UseWindowsForms>
    <Nullable>enable</Nullable>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <ApplicationManifest>app.manifest</ApplicationManifest>
    <ApplicationIcon>Assets\warden.ico</ApplicationIcon>
  </PropertyGroup>
</Project>

The failing form is <TargetFramework>net10.0-windows</TargetFramework> + <SupportedOSPlatformVersion>10.0.22621.0</SupportedOSPlatformVersion>, which yields:
  error NETSDK1135: SupportedOSPlatformVersion 10.0.22621.0 cannot be higher than TargetPlatformVersion 7.0.
Set SupportedOSPlatformVersion to 22621 (not 26100) so the binary still launches on Win11 21H2/22H2 machines; all DWM attributes used here exist from 22621.

**False positives:** Do not 'fix' NETSDK1135 by deleting SupportedOSPlatformVersion. That silences the error but leaves TargetPlatformVersion at 7.0, and CA1416 platform-compatibility analysis then produces misleading warnings on every DWM call site.

### [critical] LAYOUT — Navigation rail and shell frame geometry
A left icon+label rail (not a top TabControl, not a hamburger) is the correct model: Warden has 8 destinations, several carry live counts, and the user needs to see 'Threats: 2' without navigating. The rail is the app's persistent status bar. Two groups — GUARDIAN and MAINTENANCE — make the product's two halves legible at a glance, which is a stated product requirement.

**How:** Geometry (device-independent units):
  Rail expanded 232 / collapsed 64. Default expanded when Window.ActualWidth >= 1280, else collapsed; persist the user's explicit choice.
  Rail top padding 8; item height 40; item corner radius 8; item horizontal margin 8 (so the selected fill inset-floats, Linear-style).
  Icon 20px Segoe Fluent Icons, fixed 24px column so labels align in both states.
  Label 14px/400; 14px/600 when selected. Label opacity animates 0->1 over 140ms on expand; the rail width itself animates 220ms (see Motion).
  Section header: 11px/600, +0.6px letter spacing, uppercase, Text.Tertiary, 8px top margin, hidden entirely when collapsed (do not show a divider stub).
  Bottom-docked block: Settings item, then a 1px Border.Subtle divider, then the master protection ToggleSwitch with the label 'Protection'.

States:
  rest        Background Transparent, icon Text.Secondary, label Text.Secondary
  hover       Background Surface.Hover, icon+label Text.Primary
  selected    Background Surface.Selected, icon Accent.Text, label Text.Primary/600,
              plus a 3px x 20px accent pill at x=0, vertically centred, CornerRadius 0,2,2,0,
              whose Height animates 0->20 over 200ms EaseOut on selection change.
  badge       right-aligned pill, min 18px wide, 16px tall, radius 8, 11px/600.
              Uses Sev.* pill tokens; only the HIGHEST open severity colours the badge.
              When collapsed, the badge becomes a 8px dot at the icon's top-right.

Implement the rail as a ListBox with a retemplated ListBoxItem (see the control-restyling item), NOT a TabControl. Bind the content area to a ContentControl with a DataTemplateSelector keyed on the selected view-model.

Content canvas: padding 24 top / 32 sides / 24 bottom. Inner content MaxWidth 1440, HorizontalAlignment=Center, so the layout does not sprawl on an ultrawide.

Command palette: Ctrl+K opens a centred 640x420 Acrylic flyout over a 40%-black scrim. Fuzzy-search across screens, processes, quarantine items and settings. This is a cheap, very high-signal premium affordance and should be built in v1.

**False positives:** Do not use hover-to-expand on the rail. It tests well in a demo and is infuriating in daily use because the content reflows when the pointer merely crosses the rail on its way elsewhere. Expansion must be an explicit toggle (chevron button, bottom of rail, plus Ctrl+B).

### [critical] LAYOUT — Screen inventory and routing map
Eight destinations, ordered by how often a healthy user will need them, not by system architecture. The ordering deliberately puts the two screens that justify the product's existence (Overview, Threats) above the two that generate the most user anxiety (Persistence, Quarantine), and isolates Maintenance so cleanup never visually contaminates the security half.

**How:** GUARDIAN
  1. Overview      glyph E9D9 (Shield)         badge: none (the ring carries state)
  2. Threats       glyph E7BA (Warning)        badge: count of OPEN incidents, coloured by max severity
  3. Activity      glyph E9D2 (Processes/Net)  badge: none; a 6px pulsing Sev.Safe dot when live-monitoring
  4. Persistence   glyph E7C4 (Anchor/Startup) badge: count of items NEW since baseline (Sev.Medium)
  5. Quarantine    glyph E7B8 (Lock)           badge: count of items held (Sev.Info, neutral — never red)
  6. Timeline      glyph E81C (History)        badge: none
MAINTENANCE
  7. Maintenance   glyph E9F5 (Broom/Disk)     badge: reclaimable GB as text when > 2 GB (Sev.Info)
---- bottom dock ----
  8. Settings      glyph E713

Routing: a single MainViewModel exposes CurrentScreen; each screen is a UserControl resolved by DataTemplate in Theme.xaml. Keep instantiated screens alive in a dictionary and reuse them (do not rebuild Activity's virtualised list on every navigation) but call OnNavigatedFrom to stop 1Hz timers on hidden screens — a background app must not spin the render thread for a screen nobody is looking at.

Universal screen header, identical on all 8 (this repetition is what makes it feel like one product):
  Row: Title 28px/600 Display  |  spacer  |  contextual actions (max 2, right-aligned)
  Row: one-line subtitle 13px/400 Text.Secondary stating scope and freshness,
       e.g. 'Watching 47 processes and 12 network peers - updated 3s ago'
  24px gap, then content.

**False positives:** Resist adding a 'Scan Now' button to every header. Warden is continuous, and a prominent Scan button retrains the user to think protection is manual and episodic — the exact mental model of the 2009 PC cleaner this design is trying not to be. One 'Run full sweep' action belongs on Overview only.

### [critical] LAYOUT — Overview screen (hero, above the fold)
Overview must answer 'am I OK, and how do you know?' in under two seconds, without the user reading a single row of data. It is the screen the tray click lands on. The information hierarchy is: posture verdict, evidence for the verdict, anything needing a decision, then ambient telemetry — never the reverse.

**How:** At 1280x820 the fold is roughly y=740 inside the content canvas. Above it, exactly three bands:

BAND 1 (h=216) — Posture.
  Left: the 176px score ring (see the score ring component), left-aligned with 24px right gutter.
  Beside it: status word 28px/600 ('Protected' / 'Watchful' / 'Needs attention' / 'At risk'),
  then a 3-line evidence stack, 13px/400 Text.Secondary, each with a 14px leading glyph:
     'Full sweep completed 12 minutes ago'
     '47 processes, 12 network peers, 0 unexplained'
     'Persistence baseline matched - 142 of 142 items recognised'
  Right (fixed 3-up, each 176x96 Card): 'Open threats' / 'In quarantine' / 'Reclaimable'.
  Each tile: 11px/600 overline label, 28px/600 tabular value, 12px/400 delta line.

BAND 2 (h=140) — Live.
  Three equal Cards with sparklines: CPU, Network (up/down as two stacked lines), Disk I/O.
  Each: 11px/600 overline label + current value 17px/600 mono right-aligned, then a 40px sparkline.

BAND 3 (fills to fold) — Needs your attention.
  Section header 17px/600 + count. Up to THREE incident cards, most severe first.
  A 'View all N' text button right-aligned in the section header, never a fourth card.
  When there are none, this band becomes the all-clear state (see that component).

Below the fold: 'Recent activity' — the last 10 Timeline entries in compact form, then
'Maintenance suggestions' — at most 2 cards, dismissible, never nagging.

The posture ring and the three stat tiles must be present in the same pixel positions in ALL states, including all-clear. Layout must not jump between a healthy and unhealthy machine; only the ring's arc, colour and the band-3 content change.

**False positives:** Do not let Band 3 grow to accommodate every open incident. An Overview that becomes a long scrolling threat list on a bad day is precisely when the user most needs a bounded, calm summary. Hard-cap at three cards and delegate to the Threats screen.

### [critical] LAYOUT — Threats / Incidents screen
This is where the product's core safety constraint (precision beats recall; false positives are the primary risk) becomes visible. Every incident must lead with a plain-English statement of observed behaviour and end with reversible actions. Rule IDs, MITRE technique codes and heuristic names are evidence, not headlines, and must never appear above the fold of a card.

**How:** Layout: filter bar, then a virtualised list of incident cards. No master/detail split — incidents expand in place, which preserves reading position.

Filter bar (h=36, sticky): segmented control [ Open | Resolved | All ] on the left; severity toggle chips (Critical/High/Medium/Low) centre; sort dropdown ('Newest' / 'Severity' / 'Confidence') right. Default: Open, all severities, sorted by Severity then Newest.

Grouping: a 32px sticky group header per severity band, 11px/600 overline + count, when sorted by severity.

Card collapsed (h~96) shows, in order:
  severity rail | icon | TITLE = plain-English behaviour, 15px/600
                        e.g. 'A background process read your browser's saved-password database'
                        NOT 'T1555.003 CredentialAccess heuristic fired'
  SUBTITLE 13px/400 secondary: the actor, e.g. 'svchost32.exe (PID 8814), unsigned, started 4 min ago'
  META row 12px mono tertiary: middle-ellipsised full path | first seen | confidence percentage
  RIGHT: severity pill + a confidence meter (see severity pill component)

Expanded adds:
  EVIDENCE — an ordered list of observed facts, each one line, each with a timestamp in mono.
  WHAT WARDEN DID — present tense, past action; if auto-killed, say so plainly with the exact time.
  ACTIONS — [Quarantine] primary, [Allow and remember] secondary, [Details] ghost, [Not a threat] ghost.

'Allow and remember' MUST show a one-line preview of the exclusion rule it will create, in mono, before committing. Silent allowlisting is how a defence tool becomes useless.

Already-actioned incidents render at 60% opacity with a Sev.Safe check and an [Undo] ghost button that stays live for the full quarantine retention window.

**False positives:** The confidence value must never be rendered as a bare percentage with no anchor; '71% confident' reads as authoritative precision the detector does not have. Pair it with a qualitative band ('Likely' / 'Possible' / 'Uncertain') and colour the meter with Sev.Low for anything below 85 so the UI itself signals when the user's judgement is required.

### [high] LAYOUT — Activity screen (Processes & Network live view)
A dense, live, sortable table is the screen that proves Warden is a real tool rather than a skin. It is also the highest-risk screen for performance and for motion sickness: naively re-sorting a 400-row table at 1Hz makes rows leap under the cursor and is unusable. The design freezes ordering during interaction.

**How:** Split view: master list left (60%), detail pane right (40%, min 380px, collapsible). Top segmented control [ Processes | Network | Modules ].

Processes columns (fixed px widths, defined once as GridLength resources — see the data table component):
  Name (icon 16px + text, 240, flex)  |  PID (64, mono, right)  |  CPU% (72, mono, right)
  Memory (88, mono, right)  |  Signer (160, text, ellipsis)  |  Net (56, mono, right)  |  Risk (88, pill)

Network columns:
  Process (200, flex) | Remote address (176, MONO) | Port (56, mono, right) | Proto (56)
  | State (88) | Up (72, mono, right) | Down (72, mono, right) | First seen (96, mono)

Live update policy — this is the load-bearing rule:
  * Values refresh at 1 Hz by writing to existing bound properties (INotifyPropertyChanged). No collection churn.
  * ROW ORDER is recomputed at most every 5s, and NEVER while the pointer is over the list or a row is selected or the list has keyboard focus. Track this with a bool 'SortFrozen'; show a subtle 'Sorting paused' 11px tertiary label in the header while frozen.
  * New rows fade in over 140ms (opacity only). Departing rows are held for 3s at 50% opacity with a strikethrough-free 'exited' state, then removed. Never remove a row from under the cursor.
  * Numeric deltas do NOT animate. A counting-up CPU% is noise.

Detail pane for a selected process: full path (mono, selectable, copy button), command line (mono, wrapped, 3-line clamp + expand), signer chain, parent process (clickable, navigates), loaded modules count, open handles summary, network peers, and a 'Behaviour' timeline of the last 20 observed syscall-class events. Every path/hash/command-line is Cascadia Mono and is text-selectable.

Risk column shows a pill only when risk is above baseline; a healthy machine's Risk column is almost entirely empty, which is itself the reassuring signal.

**False positives:** Do not colour whole rows by risk. Full-row tinting on a 400-row live table produces a flashing red/amber field that reads as catastrophic even when three rows are merely 'unsigned but known'. Confine severity colour to the pill in the Risk column and to a 2px left rail on the row.

### [high] LAYOUT — Persistence, Quarantine, Maintenance, Timeline, Settings
The five remaining screens. Persistence is the one with the highest genuine security value (it is where RATs and infostealers survive reboots) and it is designed around a baseline-diff, not a raw dump. Quarantine's entire job is to make destructive action feel safe and reversible. Maintenance must be quantitative to avoid the PC-cleaner idiom.

**How:** PERSISTENCE — grouped virtualised list.
  Default view is the filter chip 'New since baseline' (NOT 'All'), because 142 recognised autoruns is noise and 1 new one is the story.
  Groups: Run/RunOnce keys, Scheduled Tasks, Services, Startup folders, WMI event subscriptions, Winlogon, AppInit_DLLs, Image File Execution Options, COM/CLSID hijacks, Browser extensions, Drivers.
  Row: status dot | Name 13px/600 | Target path 12px MONO tertiary, middle-ellipsised | Publisher | First seen | [status pill]
  Status pills: 'Recognised' (Sev.Safe), 'New' (Sev.Medium), 'Unrecognised' (Sev.High), 'Modified' (Sev.Medium).
  Header action: [Re-baseline] — must open a confirm dialog listing exactly what will be accepted.
  Above the fold: a summary strip '142 items - 141 recognised - 1 new - 0 unrecognised'.
  EMPTY (all recognised): not an empty state; show the summary strip with a Sev.Safe check.

QUARANTINE — table + persistent reassurance banner.
  Banner (Surface.Inset, Sev.Info left rail, 12px/400): 'Items here are moved, renamed, stripped of execute permission and stored inert. Restore returns the file to its exact original path and ACLs. Items are kept for 30 days.'
  Columns: Original path (MONO, middle-ellipsis, flex) | Detected as | SHA-256 (MONO, first 12 chars + copy glyph) | Size | Quarantined (relative + absolute on hover) | [Restore] [Delete forever]
  [Delete forever] is a Danger ghost button; it opens a modal requiring the user to type the filename. Bulk delete is deliberately not offered.
  EMPTY: see empty-state catalogue.

MAINTENANCE — card grid, 2 columns at >=1280.
  One card per task: Disk cleanup, Temp files, Browser caches, Windows Update cache, Old restore points, Startup impact, Package updates (winget), Event log health, SMART status, TRIM/Optimise.
  Card: title 15px/600 | reclaimable size 24px/600 tabular (or a status word for non-reclaiming tasks) | 'Last run 3 days ago' 12px tertiary | [Run] secondary button | expander 'Show what will be removed' revealing an itemised MONO path list with per-item sizes.
  Header primary action: [Run all safe tasks] — 'safe' is defined in a tooltip and excludes anything irreversible.
  Absolutely no aggregate 'issues found' count, no red, no exclamation marks.

TIMELINE — reverse-chronological, day-grouped.
  Sticky day header 12px/600 overline ('TODAY', 'YESTERDAY', then 'Mon 1 Sep').
  Entry row h=44: time 12px MONO tertiary (fixed 64px col) | 16px category glyph | plain-English sentence 13px/400 with the object in 13px/600 | chevron to expand raw detail (MONO JSON).
  Filter chips by category: Detection, Action, Quarantine, Maintenance, Config, System.
  Header action: [Export] -> JSON or CSV, local file only.

SETTINGS — left sub-nav (200px) + right pane, sections:
  Protection (autonomy: 'Auto-act on high-confidence' toggle + a confidence threshold slider showing the numeric cutoff), Monitoring scope, Exclusions, Quarantine retention, Notifications, Privacy & Network, Startup, Appearance (Theme System/Dark/Light, Reduce motion), Advanced, About.
  Privacy & Network MUST show a live, factual trust statement at the top:
  'Warden has made 0 outbound network connections this session.' with the counter bound to the real egress counter, and the opt-in reputation lookup rendered OFF with its data-sharing consequences spelled out in body text before the toggle.

**False positives:** In Maintenance, do not present 'Old restore points' or 'Windows Update cache' inside [Run all safe tasks]. Both are recoverable-state deletions that a developer machine may depend on; they must remain individually opted-in, or the first 'safe' bulk run will destroy something the user wanted and permanently cost the product's trust.

### [medium] LAYOUT — Empty-state copy catalogue
Empty states are where a security product either earns trust or reveals itself as decoration. The rule for every one of them: state what was checked, quantify it, timestamp it. 'You're protected!' is worthless; 'Checked 142 autorun entries 4 minutes ago, all recognised' is evidence. Every empty state is a Card at Surface.Raised, centred, max-width 480, with a 40px Segoe Fluent glyph in Sev.Safe at 30% opacity, a 17px/600 headline, a 13px/400 secondary body, and at most one ghost action.

**How:** Overview / band 3 (all-clear):
  glyph E9D9  'Nothing needs your attention'
  'Warden has been watching continuously for 6 days. 3 incidents were handled automatically in that time; all are reversible from Quarantine.'
  action: [View timeline]

Threats (no open incidents):
  glyph EA80  'No open incidents'
  '2 resolved in the last 7 days. The most recent was 3 days ago.'
  action: [Show resolved]

Threats (filtered to nothing):
  glyph E721  'No incidents match these filters'  /  action: [Clear filters]

Activity (no suspicious network):
  glyph E968  'No unexplained connections'
  '12 network peers, all from signed binaries you have run before.'

Persistence (nothing new):
  glyph E7C4  'No new persistence since your last baseline'
  '142 autorun entries checked 4 minutes ago. Baseline set on 14 August.'
  action: [Review all 142]

Quarantine (empty):
  glyph E7B8  'The vault is empty'
  'Nothing has been quarantined. If Warden ever acts on its own, the file lands here first - never deleted, always restorable.'

Maintenance (nothing to reclaim):
  glyph E9F5  'Nothing worth cleaning'
  'Less than 200 MB reclaimable across all tasks. Last full pass 2 days ago.'

Timeline (no events for the filter):
  glyph E81C  'No events in this range'  /  action: [Widen to 30 days]

FIRST-RUN / no-data-yet (distinct from empty — do not reuse the reassuring copy):
  glyph E895  'Still building your baseline'
  'Warden is learning what normal looks like on this machine. Detection stays conservative for the first 24 hours to avoid false alarms.'
  with a determinate progress bar bound to real baseline completion.

**False positives:** Never render an empty state that cannot distinguish 'we checked and found nothing' from 'we have not checked yet' or 'the monitor crashed'. A reassuring all-clear shown while the detection engine is dead is the worst possible failure. Every all-clear string above is bound to a real freshness timestamp; if that timestamp is older than 2x the expected interval, the card must switch to Sev.Medium and read 'Last checked 4 hours ago - monitoring may have stopped' with a [Restart monitoring] action.

### [critical] COLOUR — Dark theme core tokens (surfaces, borders, text)
A nine-step cool-neutral ramp. The hue is a very slight blue (roughly 215deg at 3-8% saturation) rather than pure grey, which reads as engineered rather than flat, and separates cleanly from the warm-neutral Windows shell. Elevation is expressed by surface lightness plus a 1px border — never by a shadow. These are the exact values verified for contrast.

**How:** Define in Themes/Tokens.Dark.xaml as Color + SolidColorBrush pairs, all frozen.

Surfaces
  Surface.Canvas    #0B0D10   window ground, behind the content card; the darkest step
  Surface.Base      #101317   content canvas / screen background
  Surface.Raised    #161A20   cards, tiles, list containers
  Surface.Overlay   #1C2128   flyouts, menus, dialogs, toasts, command palette
  Surface.Inset     #0D1014   input wells, code/path blocks, evidence blocks
  Surface.Hover     #1F252D   any interactive rest -> hover
  Surface.Pressed   #242B34   pressed / active
  Surface.Selected  #16263D   selected row or nav item (accent-tinted, deliberately not grey)
  Surface.Track     #232A33   ring track, progress track, sparkline baseline, scrollbar trough

Borders
  Border.Subtle     #1A1F26   hairlines inside a card, table row separators
  Border.Default    #272E37   card and control outlines - the workhorse
  Border.Strong     #3D4650   text input outlines, scrollbar thumb at rest
  Border.Focus      #7FB1FF   keyboard focus ring only

Text
  Text.Primary      #E8ECF2   headings, values, row titles
  Text.Secondary    #A6B0BD   body, descriptions, column data
  Text.Tertiary     #8C96A5   metadata, timestamps, overlines, placeholder
  Text.Disabled     #6B7481   disabled control content
  Text.OnAccent     #FFFFFF   on any filled accent or danger button

Elevation recipe (use instead of shadows):
  level 0  Surface.Base,    no border
  level 1  Surface.Raised,  1px Border.Default, radius 12
  level 2  Surface.Overlay, 1px Border.Default, radius 12, + ONE DropShadowEffect (only for genuinely floating layers)
  inset    Surface.Inset,   1px Border.Subtle,  radius 8

**False positives:** Do not use pure #000000 for the canvas. On the OLED-adjacent panels this user may have, true black next to a #161A20 card produces a visible haloing/smear artifact during scroll, and it removes the headroom needed for Surface.Canvas to sit BELOW Surface.Base. Do not add a tenth surface step either; nine already exceeds what the eye can order, and the discipline of mapping every element to one of these is what keeps the UI coherent.

### [critical] COLOUR — Accent and interactive state tokens (both themes)
One accent, used sparingly. Accent means 'this is the primary action' or 'this is selected' — never decoration, never a chart series colour by default, never a heading colour. The accent is a mid-blue chosen to be legible as text on dark surfaces AND to carry white text when used as a fill, which required two different values: a lighter one for text and a darker one for fills.

**How:** DARK
  Accent.Text          #6AA1FF   links, selected nav icon, primary text buttons, sparkline stroke
  Accent.Fill          #2F6FE0   primary button background            (white text: 4.70:1)
  Accent.Fill.Hover    #3A72DE                                        (white text: 4.52:1)
  Accent.Fill.Pressed  #275FC4                                        (white text: 5.97:1)
  Accent.Tint          #12203A   subtle accent background (info banner, selected chip)
  Accent.Border        #2C4E85   1px outline on accent-tinted surfaces
  Accent.Graphic       #4C8DFF   sparklines, chart strokes, non-text graphics (5.46:1 vs Raised)

  Danger.Fill          #B8323A   destructive primary                  (white text: 5.91:1)
  Danger.Fill.Hover    #CC3A43                                        (white text: 4.94:1)
  Danger.Fill.Pressed  #9E2A31

LIGHT
  Accent.Text          #1A5FD0                                        (5.85:1 on white)
  Accent.Fill          #1A5FD0                                        (white text: 5.85:1)
  Accent.Fill.Hover    #1755BE
  Accent.Fill.Pressed  #134AA6
  Accent.Tint          #E4EDFB
  Accent.Border        #A9C4EE
  Danger.Fill          #B3242B                                        (white text: 6.55:1)

Button variant matrix (both themes, same structure):
  Primary    bg Accent.Fill,   fg Text.OnAccent,  no border
  Secondary  bg Surface.Raised, fg Text.Primary,  1px Border.Default
  Ghost      bg Transparent,   fg Text.Secondary, no border; hover -> Surface.Hover + Text.Primary
  Danger     bg Danger.Fill,   fg #FFFFFF
  DangerGhost bg Transparent,  fg Sev.Critical;   hover -> Sev.Critical.Tint
  Icon       32x32, radius 8, Ghost colours, 16px glyph

Heights 32 (default) / 36 (large, primary CTA) / 26 (small, in-row). Radius 8 (6 for small). Horizontal padding 12 (14 for large). Label 13px/600.

Focus ring, universal: 2px Border.Focus stroke, 2px offset outside the control bounds, CornerRadius = control radius + 2. Rendered only on IsKeyboardFocused, never on IsMouseCaptured.

**False positives:** Do not reuse Accent.Text as the fill for a primary button (white on #6AA1FF is 2.4:1 and fails badly), and do not reuse Accent.Fill as link text on Surface.Base (#2F6FE0 on #101317 is only 3.4:1). The two-value split is the whole point; a single 'brand blue' cannot do both jobs and passing AA is not optional here.

### [critical] COLOUR — Severity ramp and pill recipes
Five severity stops plus a neutral info stop. Each stop has four values with distinct jobs: a text colour for use on normal surfaces, a graphic colour for rings/rails/strokes (non-text, tuned for 3:1), a low-alpha tint for banner backgrounds, and a pill background+foreground pair. Keeping these separate is what prevents the classic mistake of using a bright warning colour as a large fill.

**How:** DARK — token, text, graphic, tint, pill.bg, pill.fg
  Sev.Critical  #FF7A80  #E85D63  #2A1417  #3A1A1D  #FFB3B6
  Sev.High      #FFA457  #E8913F  #2A1B0E  #3A2612  #FFC891
  Sev.Medium    #F5CE68  #D9B24C  #2A2412  #3A3116  #F7DD9B
  Sev.Low       #86B4E8  #5E8FC4  #16222E  #1C2C3C  #AFCDEC
  Sev.Safe      #4ED4A0  #3FBF8F  #0F2620  #12332A  #8CE3C0
  Sev.Info      #96A2B2  #6B7481  #1A1F26  #232A33  #C2CBD6

LIGHT — token, text/graphic, tint, pill.bg, pill.fg
  Sev.Critical  #B3242B  #FDECEC  #FBE3E4  #8F1C22
  Sev.High      #9A4A06  #FDF0E3  #FBE9D5  #7D3B05
  Sev.Medium    #7A5A00  #FBF3DA  #F7EDCE  #634900
  Sev.Low       #2C5C8F  #E9F1F9  #E1EBF6  #234B75
  Sev.Safe      #0B6B47  #E4F5EE  #D9F0E6  #08573A
  Sev.Info      #5A6472  #F1F3F7  #E9ECF1  #434C59

Severity pill geometry: height 20, radius 10, horizontal padding 8, label 11px/600 uppercase +0.4px tracking. Background = pill.bg, foreground = pill.fg, NO border. Optional 6px leading dot in the graphic colour.

Status chip (non-severity: 'Signed', 'Recognised', 'New'): height 20, radius 6 (square-ish, to distinguish it from a severity pill at a glance), same type, Surface.Inset bg + Text.Secondary fg unless it carries meaning.

Severity rail on cards/rows: 3px wide, full height, CornerRadius 2,0,0,2, filled with the GRAPHIC value.

Redundancy rule (colour-blind safety and the reason precision is legible): severity is ALWAYS encoded twice — colour plus the uppercase word in the pill. Never a bare coloured dot with no label anywhere a decision is made.

**False positives:** Note that light-theme Sev.Medium is #7A5A00, a dark olive, not a yellow. A 'true' amber cannot reach 4.5:1 on white and every attempt to use one produces illegible text; the yellow character has to live in the pill background instead. Do not 'fix' this back to a brighter yellow during visual polish.

### [high] COLOUR — Light theme mapping
Light is a genuine second theme, not an inversion. The canvas is a faint cool grey and cards are pure white, which is the opposite relationship to dark (where cards are LIGHTER than the canvas) — this is correct, because in both cases the card must advance toward the viewer relative to its ground.

**How:** Surfaces
  Surface.Canvas   #F5F7FA
  Surface.Base     #FFFFFF
  Surface.Raised   #FFFFFF   (separated from Base by border, not by fill)
  Surface.Overlay  #FFFFFF   (separated by shadow — overlays are the one place light theme uses one)
  Surface.Inset    #EFF2F6
  Surface.Hover    #EDF0F5
  Surface.Pressed  #E6EAF1
  Surface.Selected #E4EDFB
  Surface.Track    #DEE3EA
Borders
  Border.Subtle    #EBEEF3
  Border.Default   #D9DEE6
  Border.Strong    #A9B2BF
  Border.Focus     #1A5FD0
Text
  Text.Primary     #14181E
  Text.Secondary   #4B5563
  Text.Tertiary    #616A77
  Text.Disabled    #78828F
  Text.OnAccent    #FFFFFF

DWM in light mode: DWMWA_USE_IMMERSIVE_DARK_MODE = 0, DWMWA_BORDER_COLOR = 0x00E6DED9 (COLORREF for #D9DEE6).

Because Surface.Raised == Surface.Base in light, cards depend entirely on Border.Default; verify no card is ever rendered borderless in light theme. Card elevation in light gains an optional very soft shadow ONLY at level 2: Color #0F172A, Opacity 0.10, BlurRadius 20, ShadowDepth 4, Direction 270.

Key names are byte-identical across Tokens.Dark.xaml and Tokens.Light.xaml so that swapping MergedDictionaries[0] retheme the whole app with no other code.

**False positives:** Do not carry the dark theme's Mica configuration unchanged into light. Mica in light mode with an opaque white content canvas produces a title strip noticeably brighter than the canvas on light wallpapers and dimmer on dark ones, making the header look detached. Either keep the title strip Mica in both themes and accept the variance (recommended, it is the native Win11 look), or paint the strip Surface.Canvas in light only — but decide once and apply it consistently.

### [critical] COLOUR — Contrast verification result and the calm-confidence doctrine
Contrast was not eyeballed. Every foreground token was programmatically checked against every surface it can actually land on — including hover, pressed and selected states, which is where hand-tuned palettes usually fail — using the WCAG 2.x relative-luminance formula. The doctrine that the palette encodes: an infected machine is a state to be resolved, not an emergency to be performed. Red is a scalpel, used at pill and rail scale only.

**How:** VERIFICATION PERFORMED AND PASSED. 172 automated checks, 0 failures, using the WCAG relative-luminance formula (sRGB linearisation with the 0.03928 threshold, coefficients 0.2126/0.7152/0.0722, ratio (L1+0.05)/(L2+0.05)).

Coverage: 5 text roles x 8 dark surface states; 6 semantic colours x 5 dark surfaces; 5 text roles x 8 light surface states; 6 semantic colours x 5 light surfaces; all 6 filled-button variants with white text; all 10 pill fg/bg pairs; monospace on inset in both themes; and all non-text graphics (focus ring, ring segments, sparkline, borders) at the 3:1 threshold.

Thresholds applied: 4.5:1 for all text (AA normal), 3:1 for disabled text and non-text UI components (AA 1.4.11). No token relies on the AA-large 3:1 exemption, so every value stays valid if a type size is later reduced.

Tightest passing margins, to protect during any future colour edit:
  Text.Tertiary #8C96A5 on Surface.Pressed #242B34 = 4.78:1
  white on Accent.Fill.Hover #3A72DE          = 4.52:1
  white on Accent.Fill #2F6FE0                = 4.70:1
  Text.Disabled #6B7481 on Surface.Pressed    = 3.02:1
  Text.Tertiary (light) #616A77 on Surface.Selected #E4EDFB = 4.64:1
Any change to these five pairs must be re-verified.

CALM-CONFIDENCE RULES (binding):
  1. No screen ever takes a red background. The largest red region permitted anywhere is a severity pill or a 3px rail.
  2. The posture ring at a bad score gets a SHORT red arc, not a full red ring. Less arc = less protection. Filling the ring with red would encode 'lots of red' as 'lots of something', which is backwards.
  3. No animated pulsing, flashing, or attention-seeking motion on any severity indicator. One 200ms entrance, then still.
  4. Green is used for a resolved or verified state, never as a persistent decorative accent — otherwise it stops meaning anything.
  5. Numbers are always accompanied by their denominator ('1 of 142 autoruns is new'), never a bare alarming count.
  6. Neutral Sev.Info, not red, is used for the Quarantine badge. Items in quarantine are a sign the system worked.

**False positives:** Beware re-running verification with only the resting surfaces. Six of the eight failures found during design were on hover/pressed/selected states, which are exactly the surfaces a designer checks last and a user sees most. Any palette change must re-run against all eight surface states per theme.

### [critical] TYPOGRAPHY — Font stack and the verified weight gotcha
Segoe UI Variable is the Windows 11 optical-size family and is what makes Win11-era UI look current rather than like Windows 8. It has three optical cuts and they are not interchangeable: Display is drawn for large sizes with tight spacing, Text for body, Small for captions and legal-size runs. Using Segoe UI (the static family) anywhere is an immediate downgrade in perceived quality. Crucially, the installed variable family exposes a restricted weight set, which was enumerated directly on this machine.

**How:** VERIFIED PRESENT on the target machine (WPF SystemFontFamilies enumeration):
  'Segoe UI Variable Display'   weights 300, 350, 400, 600, 700
  'Segoe UI Variable Text'      weights 300, 350, 400, 600, 700
  'Segoe UI Variable Small'     weights 300, 350, 400, 600, 700
  'Segoe Fluent Icons'          (icon font, SegoeIcons.ttf)
  'Cascadia Mono'               weights 200, 300, 350, 400, 600, 700
  'Cascadia Code'               (ligatures — do NOT use in UI)

THERE IS NO WEIGHT 500. FontWeight="Medium" is silently resolved to a neighbouring face and produces inconsistent stem weights across the app. The scale below uses only 400, 600 and 700. Never write Medium, DemiBold, Light, or numeric 500.

There are also NO true italics in Segoe UI Variable — only synthesised obliques. Do not use italic anywhere in the UI; use Text.Tertiary or a smaller size for de-emphasis instead.

Declare as resources with explicit fallbacks (the comma-separated fallback list is a single FontFamily string):
  <FontFamily x:Key="Font.Display">Segoe UI Variable Display, Segoe UI, Segoe UI Variable, sans-serif</FontFamily>
  <FontFamily x:Key="Font.Text">Segoe UI Variable Text, Segoe UI, sans-serif</FontFamily>
  <FontFamily x:Key="Font.Small">Segoe UI Variable Small, Segoe UI, sans-serif</FontFamily>
  <FontFamily x:Key="Font.Mono">Cascadia Mono, Consolas, Courier New, monospace</FontFamily>
  <FontFamily x:Key="Font.Icon">Segoe Fluent Icons, Segoe MDL2 Assets</FontFamily>

Optical-size selection rule, non-negotiable:
  >= 20px -> Font.Display
  13-17px -> Font.Text
  <= 12px -> Font.Small

Tabular figures for every number that changes in place (counters, CPU%, sizes, PIDs):
  Typography.NumeralAlignment="Tabular"
Without it, proportional digits cause the value to jitter horizontally on each 1Hz tick, which is very visible and very cheap-looking.

**False positives:** 'Segoe UI Variable' with no optical suffix is NOT a resolvable family name in WPF and silently falls back to the default UI font — the app will look almost right, which is why this is missed. Always use one of the three suffixed names. Similarly, do not substitute Cascadia Code for Cascadia Mono: Code enables programming ligatures, so a path containing '->' or '!=' will render as a glyph the user cannot copy-match against the real string, which is unacceptable in a security tool.

### [high] TYPOGRAPHY — Modular type scale
Eleven roles on a ~1.18 ratio, all line heights on a 4px grid so that mixed-type rows stack cleanly against the 36px table row and 40px nav item rhythm. Every text element in the app must map to exactly one of these; there are no ad-hoc font sizes.

**How:** role            size/weight/line-height   family        usage
Display.Hero    40 / 700 / 48             Font.Display  posture score number ONLY
Display.1       28 / 600 / 36             Font.Display  screen titles, stat-tile values
Title.1         20 / 600 / 28             Font.Display  dialog titles, section heroes
Title.2         17 / 600 / 24             Font.Text     section headers, detail-pane title
Body.Strong     15 / 600 / 20             Font.Text     incident card title, card title
Body            14 / 400 / 20             Font.Text     default UI text, nav labels
Body.Sm         13 / 400 / 18             Font.Text     table cells, card body, buttons(600)
Caption         12 / 400 / 16             Font.Small    metadata, timestamps, helper text
Caption.Strong  12 / 600 / 16             Font.Small    stat labels, chip text
Overline        11 / 600 / 14  +0.6px ls  Font.Small    UPPERCASE section + column headers
Mono.Body       13 / 400 / 18             Font.Mono     paths, command lines
Mono.Sm         12 / 400 / 16             Font.Mono     table mono cells, addresses, PIDs
Mono.Micro      11 / 400 / 14             Font.Mono     SHA-256, long hashes

All sizes are WPF device-independent units; write them as FontSize="13" (not pt).

Spacing scale (use these, nothing between): 2, 4, 8, 12, 16, 20, 24, 32, 40, 48.
Radius scale: 4 (chip), 6 (small button, inset), 8 (button, nav item, input), 12 (card, dialog, toast), 999 (pill, avatar).

Define each role as a named TextBlock Style in Typography.xaml (Style x:Key="Type.Body.Sm" TargetType="TextBlock"), each setting FontFamily, FontSize, FontWeight, LineHeight, LineStackingStrategy="BlockLineHeight", TextOptions.TextFormattingMode, and Foreground. LineStackingStrategy is required or LineHeight is ignored for single-line runs and vertical rhythm drifts.

Max measure for any paragraph of prose: 72ch (~560px at Body.Sm). Applies to settings descriptions, empty-state bodies and the quarantine banner.

**False positives:** Do not set LineHeight without LineStackingStrategy="BlockLineHeight" — WPF's default MaxHeight strategy silently ignores a LineHeight smaller than the font's natural line box, so half the scale will appear to work and the other half will not, producing rows that are 1-2px off and a layout that never quite aligns.

### [high] TYPOGRAPHY — Where monospace is mandatory
In a security tool, monospace is not a stylistic choice; it is a correctness affordance. Any string the user might visually compare against another string, copy into a terminal, or scan character-by-character for a subtle substitution must be monospaced, because proportional rendering hides homoglyph and padding attacks (rundll32 vs rundll32, l vs I, trailing spaces).

**How:** MONOSPACE IS MANDATORY for:
  - full and partial filesystem paths
  - command lines and arguments
  - file hashes (SHA-256, MD5, Authenticode thumbprints)
  - registry keys and value names
  - process IDs, thread IDs, session IDs
  - IP addresses, port numbers, domain names, URLs
  - service names, scheduled-task paths, WMI queries
  - certificate subjects/issuers and serial numbers
  - any raw JSON/XML evidence blob
  - byte counts and durations WHEN COLUMN-ALIGNED in a table

MONOSPACE IS FORBIDDEN for:
  - any prose, including incident titles, evidence sentences and empty states
  - buttons, nav labels, section headers, publisher/signer display names
  - human-readable file names shown as a label rather than as a path

Rendering requirements for mono runs:
  FontFamily={StaticResource Font.Mono}, TextOptions.TextFormattingMode="Display",
  IsHitTestVisible for selection, and a copy affordance.
  Every mono value >= 24 chars gets a 16px copy glyph button (E8C8) revealed on row hover,
  copying the FULL untruncated value to the clipboard.
  Every mono value is rendered in a TextBox with IsReadOnly="True", BorderThickness="0",
  Background="Transparent", Padding="0" — NOT a TextBlock — so it is selectable.

Truncation: paths truncate in the MIDDLE, never at the end, because the filename is the most
load-bearing part. WPF has no built-in middle ellipsis; implement an attached behaviour that
measures with FormattedText against the available width and rebuilds the string as
  head + '…' + tail  keeping the last path segment whole whenever possible.
Hashes truncate to first 12 chars + ellipsis, with the full value in the ToolTip and on copy.

SHA-256 display block (quarantine detail): Mono.Micro, letter-spaced +0.5px, broken into
4-char groups separated by thin spaces, in a Surface.Inset well — this makes manual comparison
against VirusTotal actually feasible.

**False positives:** Do not apply monospace to the signer/publisher name just because it sits next to a path. Publisher strings are human names ('Microsoft Windows Publisher') and monospacing them makes the row look like a log dump and costs the 'premium product' read. The distinction is: machine identifier -> mono; human-facing name -> proportional.

### [critical] COMPONENT — Posture score ring (hero visual)
The single most important pixel budget in the app. It must communicate a 0-100 posture score at a glance, encode severity without alarm, and feel physically satisfying when it changes. WPF has no arc primitive, so this is a small custom Shape — roughly 60 lines — and building it properly (rather than faking it with a rotated image or a Border) is what allows smooth animation and crisp scaling at any DPI.

**How:** Geometry: outer diameter 176, stroke 12, so the arc's centre radius is 82. Track = Surface.Track #232A33, full 360deg, drawn first. Value arc drawn on top, starting at -90deg (12 o'clock), sweeping CLOCKWISE by (Value/100)*360. StrokeStartLineCap and StrokeEndLineCap = Round. StrokeThickness 12.

Implement as a Shape subclass, not a Path with a converter — this gives a single DependencyProperty that DoubleAnimation can drive at 60fps without rebuilding a binding each frame:

public sealed class ArcShape : Shape
{
    public static readonly DependencyProperty ValueProperty =
        DependencyProperty.Register(nameof(Value), typeof(double), typeof(ArcShape),
            new FrameworkPropertyMetadata(0d,
                FrameworkPropertyMetadataOptions.AffectsRender));   // AffectsRender, NOT AffectsMeasure
    public double Value { get => (double)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }

    protected override Geometry DefiningGeometry
    {
        get
        {
            double r = (Math.Min(RenderSize.Width, RenderSize.Height) - StrokeThickness) / 2;
            var c  = new Point(RenderSize.Width / 2, RenderSize.Height / 2);
            double sweep = Math.Max(0.01, Math.Min(359.99, Value / 100d * 360d));
            var start = new Point(c.X, c.Y - r);
            double rad = (sweep - 90) * Math.PI / 180d;
            var end   = new Point(c.X + r * Math.Cos(rad), c.Y + r * Math.Sin(rad));
            var fig = new PathFigure { StartPoint = start, IsClosed = false, IsFilled = false };
            fig.Segments.Add(new ArcSegment(end, new Size(r, r), 0,
                                            sweep > 180, SweepDirection.Clockwise, true));
            var g = new PathGeometry(); g.Figures.Add(fig); g.Freeze(); return g;
        }
    }
}

Bands (arc stroke colour, dark theme graphic values):
  90-100  #3FBF8F  'Protected'
  75-89   #D9B24C  'Watchful'
  50-74   #E8913F  'Needs attention'
  0-49    #E85D63  'At risk'

Centre stack, vertically centred inside the ring:
  score  Display.Hero 40/700, Typography.NumeralAlignment="Tabular", Text.Primary
  label  Overline 11/600 uppercase, Text.Tertiary, 'POSTURE'
Below the ring (outside it), 12px gap: the band word at Title.2 17/600 in the band colour.

Animation on value change: DoubleAnimation on ArcShape.Value, Duration 700ms,
  EasingFunction = QuinticEase{EasingMode=EaseOut}.
The centre number binds to the SAME animated DP through an IValueConverter that rounds to int,
so the digits and the arc are frame-locked and cannot desynchronise.
Band colour crossfades with a ColorAnimation on the stroke brush, 400ms, CubicEase EaseOut.
On first appearance the arc sweeps from 0 to value once; thereafter it animates from its current
value only. Never re-run the 0-sweep on navigation.

A faint 1px Surface.Track circle at radius+10 (a 'gauge shadow') adds depth at no perf cost.

**False positives:** Register Value with AffectsRender, not AffectsMeasure or AffectsArrange. AffectsMeasure appears to work and produces a full layout pass on every one of the ~42 animation frames, which will visibly stutter the whole window including the nav rail. Also clamp sweep below 360 (359.99 above): an ArcSegment whose start and end points are identical is degenerate and WPF renders it as nothing, so a perfect score of 100 would draw an empty ring.

### [critical] COMPONENT — Incident card
The unit of decision-making. Its design directly serves the constraint that false positives are the primary product risk: the card is structured so the user can judge Warden's reasoning before acting, and so that every action it offers is reversible. It is also the component that most needs to avoid looking like a security alert dialog.

**How:** Collapsed: width fill, height ~96 (content-driven, min 88), Surface.Raised, 1px Border.Default, radius 12, padding 16, margin-bottom 8. NO shadow.
Severity rail: 3px, full height, CornerRadius 2,0,0,2, Sev.*.Graphic, drawn as the first child of the card Border with negative margin so it sits flush inside the radius.

Grid columns: [rail 3][gap 13][icon 24][gap 12][content *][gap 16][meta auto]

Content column, three rows:
  r0  TITLE      Body.Strong 15/600 Text.Primary — plain-English observed behaviour, 1 line, ellipsis
  r1  SUBTITLE   Body.Sm 13/400 Text.Secondary — actor identity, 1 line
  r2  META       Mono.Sm 12/400 Text.Tertiary — middle-ellipsised path | relative time | trust signal

Meta column (right, vertically centred):
  severity pill (top)
  confidence meter (below, 8px gap): a 64x4 rounded track (Surface.Track) with a fill in the
  severity graphic colour, plus a 11px/600 qualitative word beneath it —
  'Likely' (>=85), 'Possible' (60-84), 'Uncertain' (<60). Show the numeric percentage only in the
  ToolTip; a bare percentage overstates precision.

States:
  rest       as above
  hover      Border.Default -> Border.Strong; the action row fades in (opacity 0->1, 140ms)
  focused    2px Border.Focus ring; action row shown and tab-navigable
  selected   Surface.Selected background
  actioned   whole card Opacity 0.62, Sev.Safe check glyph replaces the severity icon,
             action row collapses to a single [Undo] ghost button

Expanded (click anywhere, or Enter): height animates via Opacity+TranslateY on the revealed
block only — see Motion; do NOT animate the card's Height. Reveals:
  'WHAT WARDEN SAW'  — ordered evidence list, each row: Mono.Sm timestamp (64px col) + Body.Sm fact
  'WHAT WARDEN DID'  — one sentence, past tense, with the exact time; omitted if no action taken
  'ACTIONS' row      — [Quarantine] Primary 32h | [Allow and remember] Secondary | [Details] Ghost
                        | spacer | [Not a threat] DangerGhost

'Allow and remember' opens an inline confirmation strip (not a modal) showing the exact exclusion
rule in Mono.Sm, e.g.  allow sha256:9f2c… path:D:\My projects\**  , with [Confirm] / [Cancel].

The entire card is one focusable unit (Focusable=True, KeyboardNavigation.TabNavigation=Once);
Expand on Enter/Space, collapse on Escape.

**False positives:** Do not lead the title with the detector's name or a technique ID even though it is more precise. A user reading 'Credential Access - T1555.003' cannot evaluate whether Warden is wrong, so they either dismiss everything or accept everything; both destroy the precision-over-recall goal. The behavioural sentence is what makes an incorrect detection obviously incorrect ('read your browser's saved-password database' — 'that was my password manager's importer, allow it').

### [high] COMPONENT — Live sparkline (CPU / network / disk)
Small ambient charts that make the app feel alive and instrument-grade. The design constraint is that they update at 1Hz forever, including while the app sits in the tray, so their cost must be near-zero and they must never animate — the data movement is the motion.

**How:** Geometry: height 40, width fills. 60 samples at 1Hz (a rolling 60-second window). Sample spacing = ActualWidth / 59, recomputed on SizeChanged and DpiChanged.

Render: one Path whose Data is a StreamGeometry rebuilt on each tick. StreamGeometry (not PathGeometry) because it is lightweight, has no visual tree, and can be frozen.

void Rebuild()
{
    var g = new StreamGeometry { FillRule = FillRule.Nonzero };
    using (var ctx = g.Open())
    {
        ctx.BeginFigure(new Point(0, H), isFilled: true, isClosed: true);   // area under curve
        for (int i = 0; i < n; i++)
            ctx.LineTo(new Point(i * dx, H - (samples[i] / max) * (H - 2)), true, false);
        ctx.LineTo(new Point((n - 1) * dx, H), true, false);
    }
    g.Freeze();                 // Freeze is what makes this cheap
    AreaPath.Data = g;
}

Two layers:
  area  Fill = LinearGradientBrush top->bottom, Accent.Graphic @ 0.18 alpha -> @ 0.00 alpha, frozen
  line  Stroke = Accent.Graphic, StrokeThickness 1.5, StrokeLineJoin=Round, no fill
Baseline: 1px Surface.Track line at y=H.
Peak marker: a 3px-radius Ellipse in Accent.Graphic at the window maximum, with the peak value
in Mono.Sm above it (only if the peak is > 1.5x the mean, otherwise omit).
Current value: right-aligned Title.2 17/600 with Tabular figures, in the card header row.

Network variant: two stacked paths (up = Accent.Graphic, down = Sev.Low graphic #5E8FC4), each
half-height, mirrored about the centre line. Legend as two 8px dots + Caption labels.

Severity variant: when the metric crosses a threshold the STROKE colour crossfades to the
appropriate Sev graphic colour over 400ms. The chart geometry never changes colour abruptly.

Scaling: y-max is the rolling window max, rounded up to a 'nice' number, and it only ever
increases within a 60s window (it may drop when the window rolls). This prevents the whole trace
jumping vertically when a spike leaves the window.

RenderOptions.EdgeMode default (antialiased). Do NOT set EdgeMode=Aliased; a 1.5px aliased
polyline looks like a 1998 task manager.

**False positives:** Do not animate the geometry between ticks with a PointAnimation or by interpolating samples. It looks smoother in isolation and is actively misleading in a security tool — an interpolated network chart hides the single-frame burst that is exactly the signal of an exfiltration attempt. Show the raw 1Hz steps. Also do not use a DispatcherTimer per sparkline; one shared 1Hz timer drives all of them, or you get three independent redraw storms.

### [critical] COMPONENT — Data-dense table / live list
Warden shows tables of 400+ processes, 1000+ persistence entries and unbounded timelines. The table must be legible at 36px rows, must virtualise, and must not use any stock WPF grid chrome. The critical structural decision is fixed pixel column widths shared between a plain header Grid and the row template — because the natural instinct, Grid.IsSharedSizeScope, silently destroys virtualisation.

**How:** Structure: a Grid with Row0 = header (a plain Grid, not a control) and Row1 = a virtualised ListBox. Do NOT use ListView+GridView or DataGrid.

Column widths declared once and referenced by both header and row template:
  <sys:Double x:Key="Col.Pid">64</sys:Double>   ... etc, or a shared GridLength resource set.

Header row: height 32, Background Surface.Base, 1px bottom Border.Default, sticky.
  Cell = Overline 11/600 uppercase Text.Tertiary, 12px horizontal padding.
  Sortable headers are Ghost buttons; the active sort shows a 10px chevron (E70D/E70E) in Accent.Text.

Row: height 36 FIXED (uniform height is what makes pixel scrolling accurate and cheap).
  Body.Sm 13/400 Text.Secondary; the first (identity) column is Text.Primary.
  Numeric and identifier columns right-aligned, Font.Mono, Tabular figures.
  NO row separator lines and NO zebra striping — the 36px rhythm plus hover is enough, and
  striping is the strongest single visual marker of a dated table.
  hover     Surface.Hover
  selected  Surface.Selected + a 2px Accent.Fill left rail
  focused   2px inset Border.Focus ring

ListBox configuration (all of these are required together):
  ScrollViewer.CanContentScroll="True"
  VirtualizingPanel.IsVirtualizing="True"
  VirtualizingPanel.VirtualizationMode="Recycling"
  VirtualizingPanel.ScrollUnit="Pixel"
  VirtualizingPanel.CacheLength="1,1"
  VirtualizingPanel.CacheLengthUnit="Page"
  ItemsPanel = VirtualizingStackPanel (Orientation=Vertical)
(Verified present in .NET 10: VirtualizingPanel.ScrollUnitProperty, CacheLengthProperty,
 CacheLengthUnitProperty; ScrollUnit enum = {Pixel, Item}; CacheLengthUnit = {Pixel, Item, Page}.)

Row template must be flat: a single Grid with fixed ColumnDefinitions and TextBlocks. No nested
ItemsControls, no ContentPresenter chains, no per-cell Border with its own CornerRadius.
Target under 12 visual elements per row.

Empty and loading: a 3-row skeleton shimmer is NOT used (it is a web idiom and looks cheap here).
Use a single centred 16px spinner for <500ms loads, and the empty-state card otherwise.

Column resize/reorder: not in v1. Fixed, well-chosen columns read as more designed than a
user-configurable grid, and reordering re-introduces the SharedSizeGroup temptation.

**False positives:** Grid.IsSharedSizeScope with SharedSizeGroup on the columns is the obvious way to keep header and rows aligned, and it is a trap: shared-size groups require every participating element to be measured, which forces the VirtualizingStackPanel to realise all N containers. A 1000-row list will appear to work in development with 20 test rows and will hang for seconds on real data. Fixed pixel widths, duplicated between header and row, is the correct answer. Equally, setting ScrollViewer.CanContentScroll="False" to get smooth scrolling disables item virtualisation entirely — use ScrollUnit="Pixel" instead, which gives smooth scrolling WITH virtualisation.

### [high] COMPONENT — Toast / notification
Toasts are the receipt for autonomous action. Because Warden auto-kills and quarantines on high-confidence detections without asking, the toast is the only thing standing between 'the app protected me' and 'the app did something behind my back'. Its design requirements therefore differ from a normal app's: critical toasts never auto-dismiss, and every toast reporting an action carries Undo.

**How:** IN-APP TOAST (shown when the dashboard window is visible):
  Container: bottom-right of the content canvas, 24px inset, stack grows upward, 8px gap, max 3 visible.
  A 4th+ collapses the stack into a '+N more' summary row.
  Card: width 380, min height 64, Surface.Overlay, 1px Border.Default, radius 12, padding 14/16.
  Severity rail 3px on the left edge, CornerRadius 2,0,0,2.
  Layout: [rail][20px glyph][content *][close 24x24 ghost]
    title  Body.Strong 15/600 Text.Primary, max 2 lines
    body   Body.Sm 13/400 Text.Secondary, max 3 lines; any path inside is Mono.Sm
    actions (optional) 8px above the bottom: up to 2 text buttons, 26px small, left-aligned
  Shadow: this is one of the three places a DropShadowEffect is permitted —
    Color #000000, Opacity 0.45, BlurRadius 24, ShadowDepth 6, Direction 270,
    RenderingBias="Performance".

Dismissal policy:
  Sev.Safe / Sev.Info      auto-dismiss after 5000ms
  Sev.Low / Sev.Medium     auto-dismiss after 8000ms
  Sev.High                 auto-dismiss after 12000ms
  Sev.Critical             NEVER auto-dismiss; requires explicit close or action
  Any toast reporting an automatic kill/quarantine: NEVER auto-dismiss, and MUST carry [Undo].
  Hovering or focusing any toast pauses every timer in the stack; leaving restarts it at full duration.

Motion: enter = TranslateY +12 -> 0 plus Opacity 0 -> 1 over 220ms, KeySpline 0.1,0.9 0.2,1.0.
        exit  = Opacity 1 -> 0 plus TranslateX 0 -> +16 over 120ms, CubicEase EaseIn.
        Stack reflow when one is removed: TranslateY animation on the survivors, 180ms EaseOut.
        Never animate the container's Height or the stack's Margin.

OS-LEVEL (window hidden / minimised to tray): use the in-box WinForms NotifyIcon —
  notifyIcon.ShowBalloonTip(timeoutMs, title, text, ToolTipIcon.None);
  ToolTipIcon.None avoids the OS's own alarming red/yellow badges, keeping the calm register.
  Wire notifyIcon.BalloonTipClicked to open the dashboard on the relevant incident.
  Do NOT raise a balloon for anything below Sev.Medium; background nagging is how a tray app gets
  uninstalled. Coalesce: at most one balloon per 60s, summarising if multiple fired.

Respect Focus Assist: query the OS quiet-hours state before raising a balloon and queue instead;
suppressed toasts still appear in the in-app stack and Timeline.

**False positives:** Do not make the critical toast modal, and do not steal focus with Window.Activate(). A security tool that seizes the keyboard mid-typing during a game or a build will be disabled by the user within a week, and the detection it was reporting will go unseen forever. Persistent-until-dismissed is sufficient urgency; focus theft is not.

### [high] COMPONENT — Tray icon states
The tray icon is Warden's permanent presence and, most days, its only visible surface. It must follow the Windows tray convention (monochrome glyph) so it does not look like adware, while still conveying five states at 16px. The solution is a monochrome shield with a small coloured status dot in the lower-right quadrant.

**How:** Use the in-box System.Windows.Forms.NotifyIcon (this is the sole reason for UseWindowsForms=true).

Asset: one multi-resolution .ico per state containing 16, 20, 24, 32, 40 and 48px frames.
Windows selects by DPI; shipping only 32px produces a visibly soft icon at 100% scaling, which is
one of the most common tells of an amateur tray app.

States (glyph is always the same monochrome shield; only the dot changes):
  Protected     shield outline, no dot                          — the resting state, 99% of the time
  Scanning      shield outline + Accent #4C8DFF dot             — during an explicit sweep
  Attention     shield outline + Sev.Medium #D9B24C dot         — something needs a decision
  Acted         shield outline + Sev.Critical #E85D63 dot       — Warden auto-acted; unacknowledged
  Paused        shield outline at 50% + Text.Disabled #6B7481 slash — protection off

Glyph colour follows the tray's own theme, which is NOT the app theme. Read
HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\SystemUsesLightTheme
(note: SystemUsesLightTheme, not AppsUseLightTheme — the taskbar follows the system value) and
swap between a white-glyph and a black-glyph icon set. Re-read on
SystemEvents.UserPreferenceChanged.

Scanning animation: swap between 4 pre-rendered frames on a 250ms DispatcherTimer, and ONLY while
a sweep is actually running. Stop the timer immediately afterwards — a permanently animating tray
icon is both a battery cost and a strong 'bloatware' signal.

ToolTip text is dynamic and factual, max 127 chars (a hard Win32 limit; longer strings are
silently truncated):
  'Warden - Protected. Last sweep 12 min ago. 0 open incidents.'

Context menu: build it as a custom WPF ContextMenu shown from the NotifyIcon's MouseUp, NOT
System.Windows.Forms.ContextMenuStrip. The WinForms strip cannot be themed and will render as a
grey 2010 menu, undoing the entire design. Items: Open Warden / Run full sweep / --- /
Pause protection (submenu: 15 min, 1 hour, until restart) / --- / Settings / Quit.
Apply DWMWA_SYSTEMBACKDROP_TYPE=3 (Acrylic) and DWMWCP_ROUNDSMALL to the menu's HWND.

Left-click opens/focuses the dashboard. Double-click must do the same thing, not something else.

**False positives:** Do not use a red icon as the resting 'protected' state to make the brand visible. A permanently red tray icon trains the user to ignore red, which is the only escalation channel the product has. The resting state must be visually quiet; colour in the tray must mean 'something changed'.

### [high] COMPONENT — All-clear / reassurance state
The state the user will see most often, and the one that determines whether the product feels valuable or feels like it does nothing. The design principle: reassurance must be EARNED by showing the work, not asserted. It must also never be indistinguishable from a broken monitor.

**How:** Composition on Overview when there are no open incidents — Band 3 becomes:

  Card, Surface.Raised, 1px Border.Default, radius 12, padding 32, centred content, min-height 180.
  40px Segoe Fluent glyph E9D9 in Sev.Safe #4ED4A0 at 0.32 opacity (never full-strength green —
  a saturated green tick reads as a marketing badge).
  16px gap.
  Headline  Title.2 17/600 Text.Primary   'Nothing needs your attention'
  8px gap.
  Body      Body.Sm 13/400 Text.Secondary, max 56ch, centred:
            'Warden has been watching continuously for 6 days. 3 incidents were handled
             automatically in that time; all are reversible from Quarantine.'
  16px gap.
  A single row of three EVIDENCE CHIPS — this is the component that does the real work:
            [ 47 processes ]  [ 12 network peers ]  [ 142 autoruns ]
  each chip: Surface.Inset, radius 6, height 24, Caption.Strong 12/600, with a 12px Sev.Safe
  check glyph, and a ToolTip giving the exact check time.
  12px gap.
  Ghost text button  [View timeline]

FRESHNESS GUARD — mandatory, and the single most important rule of this component:
  Every string above is bound to a real 'lastCheckedUtc'. If (now - lastCheckedUtc) exceeds
  2x the configured monitoring interval, this card MUST switch presentation entirely:
    glyph -> E7BA in Sev.Medium, headline -> 'Monitoring may have stopped',
    body  -> 'Last successful check was 4 hours ago.', action -> [Restart monitoring] Primary.
  A green all-clear rendered by a dead engine is the worst failure this product can have.

Motion on entry: the card fades in (Opacity 0->1, 220ms) and the three chips stagger in at
40ms intervals with a 6px TranslateY. This runs ONCE per navigation, never on data refresh —
re-animating reassurance every 5 seconds reads as anxiety.

Do not use an illustration, mascot, or empty-box graphic. A single glyph plus real numbers is
both cheaper and more credible.

**False positives:** Avoid the phrase 'You're protected' and any variant with an exclamation mark. Unqualified safety claims are the register of free antivirus upsell screens, and a technically literate user reads them as marketing rather than as a status report. Every reassuring sentence in this component must contain either a count, a duration, or a timestamp.

### [high] MOTION — Token set, easing curves and the 60fps contract
Motion is what separates a hand-styled WPF app from a premium one, and it is also the fastest way to make it feel cheap. The governing rule for this product: motion exists to explain a change of state, never to decorate. Four durations, four curves, and a hard restriction on which properties may be animated.

**How:** Define in Themes/Motion.xaml as Duration and KeySpline resources.

Durations
  Motion.Instant   90ms   hover fills, press states, icon colour
  Motion.Fast     140ms   toggles, chips, pill state, checkbox, action-row reveal
  Motion.Base     220ms   panel/content transitions, toast enter, rail expand, card fade-in
  Motion.Slow     320ms   screen change, dialog enter, expander reveal
  Motion.Value    700ms   posture score ring only

Easing — use KeySpline via SplineDoubleKeyFrame for the Fluent curves, not the built-in eases,
where precision matters:
  Ease.Decelerate   KeySpline 0.1,0.9  0.2,1.0    entrances, anything appearing
  Ease.Standard     KeySpline 0.8,0.0  0.2,1.0    moves between two on-screen positions
  Ease.Accelerate   KeySpline 0.7,0.0  1.0,0.5    exits, anything leaving
  Ease.Value        QuinticEase{EasingMode=EaseOut}  the score ring only
Exits are always ~55% of the matching entrance duration (220 in -> 120 out).

ANIMATABLE PROPERTIES — this list is exhaustive:
  UIElement.Opacity
  TranslateTransform.X / .Y      (declare RenderTransform once in the template; never replace it)
  ScaleTransform.ScaleX / .ScaleY
  RotateTransform.Angle          (spinners only)
  SolidColorBrush.Color          (only on a brush that is NOT frozen and NOT shared — clone it into
                                  the template, or the animation throws or bleeds across instances)
  a custom DP registered with AffectsRender (the score ring's Value)

NEVER ANIMATE:
  Width, Height, Margin, Padding, GridLength, Canvas.Left/Top, FontSize, StrokeThickness,
  CornerRadius, or anything else that invalidates measure/arrange — each frame re-runs layout for
  the subtree, and with a virtualised list in the window this drops frames immediately.
  To 'grow' a panel, animate a ScaleTransform or the Opacity+TranslateY of the revealed content
  while its layout size changes in a single step.

Always set RenderTransformOrigin explicitly (usually 0.5,0.5) and put the RenderTransform in the
template, then animate its sub-properties by path:
  Storyboard.TargetProperty="RenderTransform.(TranslateTransform.Y)"

Accessibility / OS respect:
  Read SystemParameters.ClientAreaAnimation once at startup and on SystemParameters changes; expose
  a global bool Motion.Enabled. When false, every Storyboard is skipped and the end state is applied
  directly. Settings > Appearance > 'Reduce motion' overrides it manually. This must be honoured by
  the score ring too (it should snap, with the number still correct).

**False positives:** Animating a SolidColorBrush that came from a ResourceDictionary will either throw InvalidOperationException (if frozen, which the perf guidance requires) or animate the shared instance and recolour every control using that token at once. The symptom — 'hovering one row highlights all of them' — looks like a binding bug and is actually this. Always animate a brush declared inside the ControlTemplate, or animate Opacity on a separate overlay Border instead.

### [high] MOTION — Choreography per component, and the virtualisation trap
Where motion is applied, and the two places it must be suppressed. The virtualisation interaction is the most damaging motion bug available in WPF and is worth calling out explicitly because the naive implementation looks correct on a short list.

**How:** SCORE RING (change):  DoubleAnimation on Value, 700ms, Ease.Value. Number is driven off the same
  DP through a converter so it counts in lockstep. Stroke colour crossfades 400ms Ease.Standard.
  First appearance only: sweep from 0. Subsequent updates animate from the current value.

NAV RAIL (expand/collapse): the rail's Width changes in ONE step (no animation — it is a layout
  property). What animates: label Opacity 0->1 over Motion.Fast, and the content canvas's
  TranslateX from -168 to 0 over Motion.Base with Ease.Standard, so the movement is perceived
  without a per-frame layout pass. Selected-indicator pill: Height 0->20 over 200ms Ease.Decelerate.

SCREEN CHANGE: outgoing Opacity 1->0 over 120ms Ease.Accelerate; incoming Opacity 0->1 plus
  TranslateY 8->0 over Motion.Slow Ease.Decelerate, starting 60ms after the outgoing begins.
  Never slide horizontally between screens — it implies a spatial relationship the nav rail does not have.

LIST ITEM ENTRANCE: stagger the FIRST 3 items only, 40ms apart, Opacity 0->1 + TranslateY 8->0,
  Motion.Base, Ease.Decelerate. Items 4+ appear with no animation.

  THE TRAP: do NOT trigger this from an EventTrigger on FrameworkElement.Loaded inside the
  ItemContainerStyle. With VirtualizationMode="Recycling", containers raise Loaded every time they
  are recycled during scrolling, so every row re-fades on every scroll and the list appears to
  flicker and stutter under the cursor. Instead: run the entrance ONCE from the view-model /
  code-behind after the ItemsSource is first assigned, targeting only the realised containers, and
  set a bool 'hasAnimated' on the view so navigation back does not re-run it.

LIVE TABLE: new row fades in (Opacity only, 140ms). Departing row holds 3s at 0.5 opacity then
  is removed. Row REORDER is never animated — animated reordering in a 1Hz table is nauseating and
  makes rows unclickable. Sort is frozen while the pointer is over the list (see Activity screen).

CARD EXPAND: the card's Height changes in one step; the revealed block animates Opacity 0->1 and
  TranslateY -6->0 over Motion.Base Ease.Decelerate. The chevron rotates 0->180deg over Motion.Fast.

BUTTON PRESS: ScaleTransform 1.0 -> 0.97 over Motion.Instant on press, back over Motion.Fast on
  release. Applies to Primary and Secondary only, never to table rows or nav items.

TOAST: see the toast component.

SPINNER: a 20px arc RotateTransform 0->360 over 900ms, RepeatBehavior=Forever, linear (no easing).
  Only shown after a 400ms delay, so fast operations never flash a spinner.

FRAME BUDGET: the app must hold 60fps with the Activity table scrolling. Verify with
  Application.Current.MainWindow's CompositionTarget.Rendering wired to a frame-time counter in a
  DEBUG-only overlay, or run under WPF Performance Suite / dotnet-counters. Any single frame over
  16.6ms during scroll is a bug. Set Timeline.DesiredFrameRate only as a last resort — lowering it
  to 30 for background sparklines is legitimate; raising it above 60 never is.

**False positives:** A stagger animation driven from Loaded looks perfect during development because the test list fits on one screen and never scrolls, so containers are never recycled. It fails only with real data. If list rows flicker during fast scrolling, this is the cause — not a virtualisation setting.

### [high] WPF — ResourceDictionary architecture and runtime theme swapping
With no third-party UI library, the ResourceDictionary layout IS the design system. Getting the layering right is what makes a theme swap a two-line operation instead of an app-wide refactor, and what keeps XAML parse time (which is startup time for a tray app that must launch fast) under control.

**How:** File layout under /Themes:
  Tokens.Dark.xaml      Color + SolidColorBrush ONLY. No styles. Keys identical to Tokens.Light.xaml.
  Tokens.Light.xaml     Same key set, light values.
  Motion.xaml           Duration, KeySpline, EasingFunction resources.
  Typography.xaml       FontFamily resources + the 13 named TextBlock styles.
  Icons.xaml            Glyph string resources (x:String of the Segoe Fluent code points) and any
                        PathGeometry for custom marks. Freeze every geometry.
  Primitives.xaml       Button, ToggleButton, TextBox, CheckBox, RadioButton, ComboBox, Slider,
                        ScrollBar, ScrollViewer, ToolTip, ContextMenu, MenuItem, Separator.
  Components.Nav.xaml   rail ListBox/ListBoxItem, segmented control, command palette.
  Components.Data.xaml  table header, row ListBoxItem, pill, chip, sparkline, score ring.
  Components.Cards.xaml card, incident card, stat tile, empty state, toast.
  Theme.xaml            merges all of the above in exactly the order listed.

App.xaml merges ONLY Theme.xaml, and MergedDictionaries[0] of Theme.xaml is reserved for the
token dictionary. Runtime swap:

  var themes = Application.Current.Resources.MergedDictionaries[0].MergedDictionaries;
  themes[0] = new ResourceDictionary { Source = new Uri("/Themes/Tokens.Dark.xaml", UriKind.Relative) };

BRUSH REFERENCE RULE:
  Use {DynamicResource} for every brush that must retheme — in Styles, ControlTemplates and
  page-level XAML. This is the default.
  EXCEPTION: inside a DataTemplate used by a virtualised list expected to exceed ~500 items, use
  {StaticResource}. Each DynamicResource sets up a resource-reference listener per element per
  container; on a recycling list this measurably increases scroll cost. Those templates are
  re-created on theme change by clearing and reassigning ItemsSource, which is instant and
  happens at most a handful of times in a session.

Freeze everything freezable. Add the presentation-options namespace and mark brushes and geometries:
  xmlns:po="http://schemas.microsoft.com/winfx/2006/xaml/presentation/options"
  <SolidColorBrush x:Key="Surface.Raised" Color="#161A20" po:Freeze="True"/>
Frozen brushes are cheaper to render and thread-safe; the theme swap still works because the whole
dictionary instance is replaced.

Naming convention, used consistently: Category.Role.State
  Surface.Raised, Border.Default, Text.Secondary, Accent.Fill.Hover, Sev.Critical.Pill.Bg,
  Type.Body.Sm, Motion.Base, Ease.Decelerate, Btn.Primary, Card.Base.

Startup cost: a tray app must not take 2s to first paint. Keep Theme.xaml's total under ~3000 lines,
avoid x:Static references into large static classes at parse time, and consider deferring
Components.Data.xaml until the first data screen is navigated to.

**False positives:** If a control reverts to its default Windows look after a theme swap, the cause is almost always a {StaticResource} brush reference inside a Style that was resolved at parse time against the old dictionary — the style still applies but the brush is stale or null, and a null Background renders as the system default. Audit by grepping the theme files for StaticResource on any key starting with Surface., Border., Text., Accent. or Sev. outside of item DataTemplates.

### [critical] WPF — Erasing the default Windows look: control restyling mandates
Six stock controls will destroy the premium impression on sight. The default WPF ScrollBar and ListView/GridView chrome are the worst offenders — they still carry Aero-era gradients, 17px-wide troughs with stepper arrows, and a header with a bevel — and they are non-negotiable rewrites. Every restyle follows the same pattern: OverridesDefaultStyle, a ControlTemplate that is a single Border plus a ContentPresenter, and a hand-drawn focus ring.

**How:** UNIVERSAL PATTERN for every restyled control:
  <Style TargetType="{x:Type Button}">
    <Setter Property="OverridesDefaultStyle" Value="True"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>       <!-- then draw your own -->
    <Setter Property="SnapsToDevicePixels" Value="True"/>
    <Setter Property="UseLayoutRounding" Value="True"/>
    <Setter Property="Template">... Border > ContentPresenter ...</Setter>
  </Style>
Draw the focus ring inside the template as a second Border with Opacity 0, made visible by a
Trigger on IsKeyboardFocused. Never leave FocusVisualStyle null with no replacement.

SCROLLBAR — MANDATORY REWRITE. Target an overlay scrollbar:
  Track Background = Transparent (no trough fill).
  RepeatButtons (line up / line down / page up / page down): retemplate to an EMPTY ControlTemplate
  and set Height/Width = 0. Do not merely set Visibility=Collapsed on the stock template; the
  arrows' 17px reservation persists and leaves a gap.
  Thumb: width 4 at rest, 8 on hover, CornerRadius 4, Fill Border.Strong #3D4650 at rest ->
  #4E5866 on hover -> #5C6674 on drag. Width transition 140ms (animate ScaleX on a fixed-width
  8px thumb rather than Width, per the motion rules).
  Total ScrollBar Width 10 (thumb + 3px padding each side), Background Transparent, so content
  scrolls beneath it.
  Horizontal variant mirrors this with Height.
  Set ScrollViewer's Style to place the ScrollBar in a Grid CELL SHARED with the content (same
  Grid.Column) so it overlays instead of consuming layout width.

LISTVIEW / GRIDVIEW — DO NOT USE. GridViewColumnHeader's default template carries a gradient and
  a bevel that cannot be cleanly overridden without a full retemplate of six parts. Replace with
  the header-Grid + virtualised ListBox pattern from the data table component. If ListView is
  unavoidable for an existing binding, retemplate GridViewColumnHeader completely (including
  PART_HeaderGripper, PART_FloatingHeaderCanvas) and set
  ListView.Template to a bare ScrollViewer.

TABCONTROL — DO NOT USE for primary navigation (use the rail) or for in-page tabs (use a segmented
  control). Stock TabItem draws a 3D-ish tab shape with a notch that is unfixable at the design
  level. Segmented control = a horizontal ListBox, Surface.Inset background, radius 8, padding 2,
  with the selected ListBoxItem drawing a Surface.Raised pill (radius 6) behind it. The selection
  pill slides between items via a TranslateTransform animation over Motion.Fast, Ease.Standard.

TEXTBOX: height 32, radius 8, Surface.Inset bg, 1px Border.Strong, 10px horizontal padding,
  Body.Sm. Focus: border -> Accent.Fill plus the 2px focus ring. Placeholder via a TextBlock
  behind the TextBox, collapsed when Text is non-empty (WPF has no placeholder).
  Selection: SelectionBrush = Accent.Fill @ 0.35, SelectionTextBrush = Text.Primary,
  CaretBrush = Accent.Text.

TOGGLESWITCH: WPF has none. Build from ToggleButton: 36x20 track, radius 10, Surface.Track ->
  Accent.Fill when checked; 16px thumb, radius 8, #FFFFFF, TranslateX 0->16 over Motion.Fast
  Ease.Standard.

CONTEXTMENU / TOOLTIP: retemplate to Surface.Overlay, 1px Border.Default, radius 8, padding 4.
  Set Popup.AllowsTransparency="True" (Popups are separate HWNDs; this is safe here, unlike on the
  main window) and remove the default drop shadow via HasDropShadow="False", then apply your own.
  ToolTip: Caption 12/400, max width 320, 6px/10px padding, InitialShowDelay 400ms.

COMBOBOX: retemplate both the ToggleButton part and the Popup; the default ComboBox is the
  second-most dated control after ScrollBar. Chevron glyph E70D, 10px, Text.Tertiary.

**False positives:** Setting OverridesDefaultStyle="True" without supplying a complete Template produces an invisible control, which developers then 'fix' by removing OverridesDefaultStyle — silently reintroducing the stock chrome underneath their partial styling. If a control looks 90% right but has an unexplained 1px bevel, a gradient edge, or a mouse-over glow, OverridesDefaultStyle is missing. Also note that a ScrollBar restyle applied only in the page's own Resources will not reach ScrollBars created inside a ListBox's default template — the style must be an implicit (unkeyed) TargetType style in Primitives.xaml.

### [critical] WPF — Shadows, rounded cards and virtualisation performance
The two ways a hand-built WPF app dies performance-wise: DropShadowEffect applied per-card, and virtualisation silently disabled. Both look fine with test data. The design deliberately uses borders rather than shadows for cards, which is both the modern aesthetic (Linear, Vercel, GitHub Primer all do this) and free.

**How:** SHADOWS — hard rules:
  1. Cards, tiles, rows, list containers and headers get NO shadow. Elevation is Surface.Raised +
     1px Border.Default + radius 12. This is the primary elevation mechanism.
  2. DropShadowEffect is permitted on exactly three things, and only ever one to three instances
     on screen at once: flyouts/popups, dialogs, and toasts.
  3. When used:
       <DropShadowEffect Color="#000000" Opacity="0.45" BlurRadius="24" ShadowDepth="6"
                         Direction="270" RenderingBias="Performance"/>
     Never BlurRadius > 32. RenderingBias="Performance" is required.
  4. NEVER put an Effect on an element that contains a virtualised list, animates, or contains text
     you care about — any Effect forces the subtree into an intermediate render target, which both
     costs a full-surface re-render per frame AND disables ClearType, making all text in that
     subtree visibly softer.
  5. Never use BitmapEffect (the pre-.NET-3.5 API). It is software-rendered and will destroy
     framerate outright.

ROUNDED CORNERS:
  Border.CornerRadius is free. To clip CHILD content to a rounded parent, do not use OpacityMask
  or a VisualBrush — set the child's own CornerRadius to match, or wrap in a Border with
  ClipToBounds and matching radius. If real clipping is unavoidable (e.g. an image in a rounded
  card), use a RectangleGeometry Clip with RadiusX/RadiusY, which is cheap; an OpacityMask with a
  VisualBrush is an intermediate surface and costs the same as an Effect.
  Always pair CornerRadius with UseLayoutRounding="True" and SnapsToDevicePixels="True" on the
  Border, or the 1px stroke will render as a 2px blur at fractional DPI scaling.

VIRTUALISATION CHECKLIST (verify each on every long list):
  ScrollViewer.CanContentScroll = True                (False disables item virtualisation entirely)
  VirtualizingPanel.IsVirtualizing = True
  VirtualizingPanel.VirtualizationMode = Recycling    (Standard re-creates containers; recycling is required)
  VirtualizingPanel.ScrollUnit = Pixel                (smooth scrolling WITHOUT losing virtualisation)
  VirtualizingPanel.CacheLength = 1,1 / CacheLengthUnit = Page
  ItemsPanelTemplate is a VirtualizingStackPanel (a plain StackPanel silently disables everything)
  The ItemsControl is NOT inside a ScrollViewer, StackPanel, or any container that gives it
  infinite vertical space — that is the single most common cause of full realisation.
  No Grid.IsSharedSizeScope / SharedSizeGroup anywhere in the item template.
  Row height uniform and fixed.

BINDING HYGIENE for 1Hz updates:
  Implement INotifyPropertyChanged and mutate existing items; never rebuild the ObservableCollection.
  For bulk changes use a single Reset notification, not N Add notifications.
  Bind with Mode=OneWay and set NotifyOnSourceUpdated=False.
  Marshal engine updates to the UI thread in ONE Dispatcher.InvokeAsync per tick at
  DispatcherPriority.Background — not one per row.
  Set PresentationTraceSources binding-error logging on in DEBUG; every silent binding failure is
  an exception cost per frame.

MEASUREMENT: verify 60fps with the Activity table scrolling and the score ring animating
simultaneously. Use a DEBUG-only CompositionTarget.Rendering frame-time overlay; any frame over
16.6ms during scroll is a defect, not a tuning opportunity.

**False positives:** A list that scrolls smoothly with 50 test rows proves nothing — every virtualisation mistake above is invisible below a few hundred items. Test with a synthetic 5,000-row source before shipping any list. Similarly, the DropShadowEffect cost is invisible at 3 cards and catastrophic at 40: if the Threats screen ever renders a long list of shadowed incident cards, scrolling will drop to single-digit fps on a machine that runs Unreal fine, because the cost is on the WPF render thread, not the GPU the user paid for.

## Risks
- Mica plus opaque content is a compromise that can read as inconsistent. Because ClearType requires opaque surfaces, only the title strip and rail gutter show the backdrop. On a busy or high-contrast wallpaper the translucent strip can look disconnected from the opaque canvas below it. Mitigation: keep the strip's content minimal (title, search, caption buttons), and provide a Settings > Appearance option 'Solid window background' that sets DWMSBT_NONE and paints the strip Surface.Canvas. Some users will prefer it; do not treat Mica as mandatory.
- Building every control by hand is a large amount of XAML with no library to fall back on. Realistically Primitives.xaml alone is 900-1400 lines and is where schedule overruns will occur. Under-scoping this is the main delivery risk. Mitigation: build Button, ScrollBar, TextBox, ToggleButton and the list row FIRST and get them pixel-correct, since they account for roughly 80% of on-screen controls; defer ComboBox, Slider and TreeView until a screen actually needs them.
- The severity palette is tuned for the dark theme and re-derived (not inverted) for light. Light-theme Sev.Medium is a dark olive #7A5A00 rather than a yellow, because no true amber reaches 4.5:1 on white. This is correct but will look 'wrong' to anyone comparing themes side by side, and there is a standing risk that a later visual-polish pass brightens it and silently breaks AA. Mitigation: keep the contrast script in the repo and run it in CI over the token dictionaries.
- The 1Hz Activity screen is the main performance and battery risk for a tray-resident app. Even with correct virtualisation, waking the UI thread every second to update 400 bound rows costs measurable CPU on a machine that should be idle. Mitigation: suspend all per-screen timers when the window is hidden or minimised (the tray is the normal state), drop to 0.2Hz when the window is visible but unfocused, and only run 1Hz when the Activity screen is both visible and focused.
- Returning HTMAXBUTTON from WM_NCHITTEST to enable Snap Layouts means the maximise button permanently stops receiving normal WPF mouse events. Its hover, press and click must all be reimplemented through WM_NCLBUTTONDOWN / WM_NCLBUTTONUP / WM_NCMOUSELEAVE. A partial implementation produces a button that snaps correctly but never highlights, or one that highlights and never un-highlights when the pointer leaves via the window edge. This is fiddly and should be built and tested as a unit early, not at the end.
- The all-clear state is load-bearing for trust and is also the state most likely to lie. If the detection engine dies, crashes, or is blocked by a driver update, the UI will keep rendering a green ring and a reassuring sentence unless the freshness guard is implemented exactly as specified. This is the highest-consequence design detail in the document and it lives entirely in code, not in XAML — it must be a tested code path, with a deliberate fault-injection test that kills the engine and asserts the Overview flips to 'Monitoring may have stopped'.
- The design specifies no column resizing, no reordering, no user-configurable table layout, and no theming beyond dark/light. This is a deliberate trade of flexibility for coherence, and it is the right call for a single-user product with a premium target. But the user is a developer and may well ask for these later; retrofitting column resize will reintroduce the SharedSizeGroup virtualisation trap. If resizing is ever added, implement it by mutating the shared GridLength resources and forcing a container refresh, never by shared-size scopes.

## Implementation notes
ENVIRONMENT VERIFICATION PERFORMED. Everything below was checked on the actual target machine rather than assumed.

1. OS: Windows 11 Pro, build 26200.8313, DisplayVersion 25H2, x64. Confirmed via HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
2. Runtime: Microsoft.WindowsDesktop.App 10.0.11 present (alongside 6.0.36, 8.0.30, 9.0.19). SDK 10.0.303.
3. Fonts: enumerated through Windows.Media.Fonts.SystemFontFamilies. Confirmed present as WPF-resolvable family names: "Segoe UI Variable Display", "Segoe UI Variable Text", "Segoe UI Variable Small", "Segoe Fluent Icons", "Cascadia Mono", "Cascadia Code", "Segoe UI".
4. WEIGHT CONSTRAINT (verified by typeface enumeration, and it changes the type scale): all three Segoe UI Variable optical cuts expose ONLY weights 300, 350, 400, 600, 700. There is no 500/Medium. Cascadia Mono exposes 200, 300, 350, 400, 600, 700 — also no 500. Segoe UI Variable additionally has no true italic faces, only synthesised obliques, so italic must not be used. The type scale in this spec uses only 400/600/700 as a direct consequence.
5. DWM INTEROP: a minimal WPF app was compiled and executed on this machine. All of the following returned HRESULT 0x00000000 (S_OK) against a WindowChrome-hosted, AllowsTransparency=False window with Background=Transparent and GlassFrameThickness=-1:
     DWMWA_USE_IMMERSIVE_DARK_MODE (20) = 1
     DWMWA_WINDOW_CORNER_PREFERENCE (33) = 2 (DWMWCP_ROUND)
     DWMWA_SYSTEMBACKDROP_TYPE (38) = 2 (Mica), = 3 (Acrylic), = 4 (Mica Alt) — all three accepted
     DWMWA_BORDER_COLOR (34)
     DwmExtendFrameIntoClientArea(-1,-1,-1,-1)
   HwndSource.CompositionTarget.BackgroundColor read back as #00FFFFFF, confirming the composition surface is genuinely transparent and the backdrop can reach the client area. The P/Invoke signatures in this spec are the exact ones that were executed.
6. BUILD GOTCHA (hit during verification, will hit the implementer): <TargetFramework>net10.0-windows</TargetFramework> combined with <SupportedOSPlatformVersion>10.0.22621.0</SupportedOSPlatformVersion> fails with "error NETSDK1135: SupportedOSPlatformVersion 10.0.22621.0 cannot be higher than TargetPlatformVersion 7.0". The working TFM is net10.0-windows10.0.26100.0. Use the csproj given verbatim in the project-configuration item.
7. VIRTUALISATION API: confirmed present in .NET 10 by reflection over System.Windows.Controls.VirtualizingPanel — IsVirtualizingProperty, VirtualizationModeProperty, ScrollUnitProperty, CacheLengthProperty, CacheLengthUnitProperty, IsContainerVirtualizableProperty. ScrollUnit enum = {Pixel, Item}; VirtualizationCacheLengthUnit = {Pixel, Item, Page}. The settings prescribed in this spec are all valid.
8. CONTRAST: 172 automated WCAG checks across both themes, 0 failures. The method was the WCAG 2.x relative-luminance formula (sRGB linearisation at the 0.03928 threshold, coefficients 0.2126/0.7152/0.0722, ratio (L1+0.05)/(L2+0.05)), applied to every text role against every one of the eight surface states per theme, every semantic colour on every surface it renders on, all filled-button/white-text pairs, all ten pill fg/bg pairs, monospace on inset, and all non-text graphics at 3:1. Six of the eight failures found during iteration were on hover/pressed/selected surfaces, not resting ones — keep the verification script in the repo and run it against the token dictionaries in CI so any future colour edit is re-checked against interactive states, not just resting ones.

ORDERING CONSTRAINTS FOR THE BUILD

Phase 1 (must be first, nothing else works without it): csproj + app.manifest with PerMonitorV2; Tokens.Dark.xaml + Tokens.Light.xaml; Typography.xaml; Motion.xaml; the shell window with WindowChrome, the DWM interop class, and the WndProc hook for WM_NCHITTEST + WM_GETMINMAXINFO. Get the caption buttons and Snap Layouts working before any screen content — retrofitting the HTMAXBUTTON hook after the title bar is populated is much harder.

Phase 2: Primitives.xaml, in this order — ScrollBar (everything else contains one), Button, TextBox, ToggleButton/ToggleSwitch, ListBoxItem, ContextMenu, ToolTip. Do not start screens until the ScrollBar is done; a stock ScrollBar appearing inside an otherwise-finished screen is demoralising and easy to miss in screenshots.

Phase 3: the nav rail + routing shell, then Overview (score ring, stat tiles, sparklines, incident card, all-clear state). Overview exercises almost every signature component, so building it second-to-last among screens is wasteful — build it first and the remaining screens are assembly.

Phase 4: Activity (the virtualised table pattern), then Threats, Persistence, Quarantine, Timeline, Maintenance, Settings.

Phase 5: tray icon, toasts, command palette.

STANDING RULES THE IMPLEMENTER MUST NOT DEVIATE FROM
- AllowsTransparency stays False. Rounded corners come from DWM, never from WPF transparency.
- Every text-bearing surface has an explicit opaque Background, or its text loses ClearType.
- No DropShadowEffect on cards, rows or anything containing a list. Borders only.
- No Grid.IsSharedSizeScope or SharedSizeGroup inside any virtualised item template.
- No animation of Width, Height, Margin, Padding, GridLength or CornerRadius, ever.
- No FontWeight 500 and no italics.
- No red backgrounds at region scale; severity colour is confined to pills and 3px rails.
- Every reassuring string is bound to a real freshness timestamp and flips to a warning state when stale.

ADMIN / PRIVILEGE NOTES
Nothing in this design layer requires elevation. The DWM calls, font access and WPF rendering are all per-user. Elevation is a Guardian-engine concern (process termination, service enumeration, ETW sessions), and the UI should be designed to run unelevated with the engine in a separate elevated service — which means every action button needs a defined disabled state and an explanatory tooltip for when the engine is unavailable. Reserve a 32px inline banner slot at the top of the content canvas for "The protection service is not running" with a [Start] action; it is far cheaper to design that slot now than to retrofit it.

SCRATCH ARTEFACTS (verification only, safe to delete, not part of the deliverable)
C:\Users\finla\AppData\Local\Temp\claude\D--My-projects\a6d7918b-0315-41b5-8d82-d4025862d88a\scratchpad\verify-final.ps1 — the 172-check contrast script; worth copying into the Warden repo as a CI check.
C:\Users\finla\AppData\Local\Temp\claude\D--My-projects\a6d7918b-0315-41b5-8d82-d4025862d88a\scratchpad\MicaTest\ — the compiled DWM probe whose Program.cs contains the verified interop code.
C:\Users\finla\AppData\Local\Temp\claude\D--My-projects\a6d7918b-0315-41b5-8d82-d4025862d88a\scratchpad\mica-probe.txt — the recorded S_OK results.

## ADVERSARIAL CRITIQUE
### Corrections (14)
- **Claim:** The ArcShape posture-ring code is presented as verified, ready ~60 lines: `double r = (Math.Min(RenderSize.Width, RenderSize.Height) - StrokeThickness) / 2;` inside `DefiningGeometry`.
  - **Why wrong:** I compiled and ran this exact class on the target machine (net10.0-windows, .NET 10). It throws on the FIRST measure pass: `System.ArgumentException: Width and Height must be non-negative.` Shape.MeasureOverride evaluates DefiningGeometry while RenderSize is still (0,0), so r = (0 - 12) / 2 = -6 and `new Size(-6,-6)` throws. The app's hero component crashes before it ever paints. AffectsRender is correct; the RenderSize dependency is not.
  - **Fix:** Guard the degenerate case: `if (r <= 0) return Geometry.Empty;` immediately after computing r (verified: with that one line the same class measures/arranges cleanly, DesiredSize 176x176, RenderedGeometry bounds 5.99,6 -> 164x164). Also note the shape only ever sizes correctly with explicit Width/Height — with r derived from RenderSize its DesiredSize is 0 if you let it auto-size. Consider deriving r from the measure constraint instead.
- **Claim:** "Verified-good csproj ... <TargetFramework>net10.0-windows10.0.26100.0</TargetFramework> ... this exact file built clean", justified by NETSDK1135.
  - **Why wrong:** It builds, but it silently violates the project's own "ZERO external NuGet packages" rule and bloats the deliverable. `Microsoft.Windows.SDK.NET.Ref` is NOT installed under C:\Program Files\dotnet\packs on this machine — it is restored from NuGet (I confirmed both entries in the probe's own project.assets.json), so the build now requires network/feed access. And the output directory of the spec author's own MicaTest project contains `Microsoft.Windows.SDK.NET.dll` at 25.12 MB plus `WinRT.Runtime.dll` at 0.5 MB, copied into every build and every publish, for a design that uses zero WinRT APIs — only hand-written P/Invoke.
  - **Fix:** Keep `<TargetFramework>net10.0-windows</TargetFramework>` and simply omit SupportedOSPlatformVersion (see the next item — it costs nothing). That leaves TargetPlatformVersion at 7.0, pulls no Windows SDK projection, restores nothing from NuGet, and drops ~25.6 MB from the output. Only take the 10.0.26100.0 TFM if you later genuinely need a WinRT API.
- **Claim:** "Do not 'fix' NETSDK1135 by deleting SupportedOSPlatformVersion ... CA1416 platform-compatibility analysis then produces misleading warnings on every DWM call site."
  - **Why wrong:** Empirically false. I built a project with `net10.0-windows`, no SupportedOSPlatformVersion, `<EnableNETAnalyzers>true</EnableNETAnalyzers>` and `<AnalysisLevel>latest-all</AnalysisLevel>` (the most aggressive setting), containing a `DwmSetWindowAttribute` DllImport and a call to it. Result: 5 warnings, none of them CA1416 (CA1515, CA1721, CA5392, CA1050, CA1031). CA1416 only fires on APIs carrying [SupportedOSPlatform] annotations; a P/Invoke you declare yourself has none, so there is nothing for it to flag. Separately, SupportedOSPlatformVersion does not gate whether the binary launches on 21H2/22H2 — that claim is also wrong; it is an analyzer/manifest hint only.
  - **Fix:** Delete SupportedOSPlatformVersion, keep net10.0-windows. If you want a real minimum-OS gate, enforce it at startup (check Environment.OSVersion.Build and degrade the DWM calls), not via an SDK property.
- **Claim:** "172 automated checks, 0 failures ... Coverage: ... and all non-text graphics (focus ring, ring segments, sparkline, borders) at the 3:1 threshold."
  - **Why wrong:** The borders were never checked. I read verify-final.ps1 (105 lines) in the author's own scratchpad: its non-text block covers exactly the focus ring (3 surfaces), four ring/track pairs and the sparkline. No Border.* token appears in any check. Recomputing with the spec's own WCAG formula: Border.Strong #3D4650 — the declared outline for text inputs and the resting scrollbar thumb, both UI components under 1.4.11 — is 1.99:1 on Surface.Inset, 1.94:1 on Surface.Base, 1.82:1 on Surface.Raised, and 2.14:1 in light theme (#A9B2BF on white). All fail 3:1. Border.Default is 1.36:1 / 1.27:1 dark and 1.35:1 on white, and in light theme it is the ONLY thing separating a card from its ground because Surface.Raised == Surface.Base. Worst of all, the ToggleSwitch off-state track (Surface.Track #232A33 on Surface.Raised) is 1.21:1 — the master "Protection" switch is close to invisible in exactly the state where it means the machine is unprotected.
  - **Fix:** Add every Border.* x Surface.* pair and every control-state fill to the script before making any conformance claim. Lighten Border.Strong to about #606A78 (verified: 3.48:1 on Surface.Inset, 3.18:1 on Surface.Raised) for input outlines and scrollbar thumbs. Give the toggle an off-state that passes 3:1 against its card, and never encode on/off by fill colour alone — add a thumb position plus a text state. Card borders can stay decorative but then stop claiming 3:1 for them.
- **Claim:** The Segoe Fluent Icons code points: E9D9 (Shield), E7C4 (Anchor/Startup), E7B8 (Lock), E9F5 (Broom/Disk), E9D2 (Processes/Net), EA80, E968.
  - **Why wrong:** I rendered all of them at 44px from the installed SegoeIcons.ttf (image sent to the user). Every code point exists, so nothing fails loudly — they just draw the wrong picture. E9D9 is a heartbeat/pulse in a rounded square, not a shield: that is the app's primary identity glyph, the Overview nav icon AND the 40px all-clear hero. E7B8 is a bin/canister with a minus, not a padlock — a trash-can icon on the Quarantine rail directly contradicts the copy "never deleted, always restorable". E7C4 is TaskView (two overlapping rectangles), not an anchor. E9F5 is a pair of gears, which sits two rows above E713 (a single gear, Settings) in the same rail — two gear icons in one nav list. E9D2 is a line/area chart. EA80 is a lightbulb ("tip"), used for "No open incidents". E968 is a PC/tower, used for "No unexplained connections". The canonical padlock is E72E (confirmed in the same render).
  - **Fix:** Re-pick every glyph against the actual font, not from memory. The verification is cheap and repeatable — render the candidate code points to a sheet and look at them. Keep E7BA (warning), E81C (history), E713 (settings), E921/E922/E923/E8BB (caption), E70D/E70E (chevrons), E8C8 (copy), E721 (search), E895 (sync); those are correct.
- **Claim:** "EXCEPTION: inside a DataTemplate used by a virtualised list ... use {StaticResource}. Those templates are re-created on theme change by clearing and reassigning ItemsSource, which is instant."
  - **Why wrong:** Reassigning ItemsSource re-instantiates containers from the SAME FrameworkTemplate. WPF resolves and caches StaticResource values when the template content is loaded, not per instantiation, so new containers get the OLD theme's brushes. The list will keep dark-theme colours after a switch to light and look like a binding bug.
  - **Fix:** Either reload the ResourceDictionary that contains those DataTemplates on theme change, or (better and cheaper) stop putting brushes in the row template at all: set Foreground/Background once on the ListBox with DynamicResource and let property inheritance carry them into rows — zero per-row resource listeners AND correct rethemeing. Keep DynamicResource for the small number of per-state brushes in the ItemContainerStyle.
- **Claim:** The "VIRTUALISATION CHECKLIST (verify each on every long list)" is presented as complete.
  - **Why wrong:** It omits the one setting that matters for three of the spec's own screens. Threats groups by severity with sticky headers, Persistence groups by autorun category, Timeline groups by day. In WPF, applying GroupDescriptions turns virtualisation OFF unless `VirtualizingPanel.IsVirtualizingWhenGrouping="True"` is set explicitly (it defaults to false). Every checklist item can be correct and a 1,000-row grouped Persistence list will still realise all containers.
  - **Fix:** Add IsVirtualizingWhenGrouping="True" to the checklist and to the grouped lists. Also note WPF has no built-in sticky group header — the spec's 32px sticky severity/day headers need a custom ScrollViewer overlay or a header-pinning behaviour, which is real work that is currently unscoped.
- **Claim:** "Every mono value is rendered in a TextBox with IsReadOnly=True ... NOT a TextBlock — so it is selectable." Applied to table cells (PIDs, addresses, ports, paths).
  - **Why wrong:** This contradicts the spec's own "target under 12 visual elements per row" budget. The Processes table has 4 mono columns and the Network table has 6; a TextBox is one of the most expensive WPF controls (template + TextBoxView + ScrollViewer per instance), so a 400-row live table would carry 1,600-2,400 TextBoxes through recycling. It also breaks the list itself: a TextBox swallows clicks and arrow keys, so row selection and keyboard navigation stop working in the columns the user most wants to select.
  - **Fix:** Use TextBlock in table cells and provide selection at the row level — copy-on-hover glyph, Ctrl+C on the selected row, and full selectable mono values in the detail pane and the expanded incident card only. That is where the spec's own "copy the FULL untruncated value" affordance belongs.
- **Claim:** "CONTEXTMENU / TOOLTIP: ... Set Popup.AllowsTransparency=True ... Apply DWMWA_SYSTEMBACKDROP_TYPE=3 (Acrylic) and DWMWCP_ROUNDSMALL to the menu's HWND." Plus "Ctrl+K opens a centred 640x420 Acrylic flyout over a 40%-black scrim."
  - **Why wrong:** Two incompatible things at once. A WPF Popup with AllowsTransparency=True is a WS_EX_LAYERED, frameless WS_POPUP window; DWM system backdrops and corner preferences act on a window's frame, so both calls will return S_OK and do nothing visible. And the Ctrl+K palette is described as an in-window overlay (it sits over a scrim inside the app), where acrylic is impossible by definition — the only way to blur the app's own content is a BlurEffect, which the spec bans outright (Effects force an intermediate render target and kill ClearType).
  - **Fix:** Pick one per surface. Either make menus/palette real top-level windows with AllowsTransparency=False so DWM acrylic and rounding apply, or accept opaque Surface.Overlay + 1px border + one DropShadowEffect (already permitted for exactly these three cases) and delete every "Acrylic" reference for in-window surfaces.
- **Claim:** "ENVIRONMENT VERIFICATION PERFORMED ... All of the following returned HRESULT 0x00000000 (S_OK) ... HwndSource.CompositionTarget.BackgroundColor read back as #00FFFFFF, confirming the composition surface is genuinely transparent and the backdrop can reach the client area."
  - **Why wrong:** The probe proves the calls are accepted, not that Mica renders. I read MicaTest\Program.cs: it calls w.Close() inside the SourceInitialized handler, so the window is destroyed before the first frame is ever composed — nobody has seen this window. DwmSetWindowAttribute returns S_OK on Win11 22621+ regardless of whether the backdrop is actually drawn; it is silently inert when the user turns off Settings > Personalization > Colors > Transparency effects, under battery saver, in high contrast, and over RDP. The whole two-zone shell (transparent title strip + rail gutter) is built on an unobserved result. It also reads CompositionTarget.BackgroundColor rather than setting it, so the classic requirement is untested rather than disproved.
  - **Fix:** Re-run the probe with the window shown, take a screenshot over a saturated wallpaper, and confirm visually. Then define the fallback: read HKCU\...\Themes\Personalize\EnableTransparency and auto-switch to the "Solid window background" presentation instead of shipping it only as a manual setting. Strip the word "verified" from anything that was not observed.
- **Claim:** "Monospace is not a stylistic choice; it is a correctness affordance ... because proportional rendering hides homoglyph and padding attacks (rundll32 vs rundll32, l vs I...)."
  - **Why wrong:** Monospace does not defend against homoglyphs at all — a Cyrillic U+043E renders as an identical round 'o' in Cascadia Mono. The spec's own example is literally the same two ASCII strings. Worse, the real filename-display attack is omitted: U+202E RIGHT-TO-LEFT OVERRIDE, which makes `invoice‮fdp.exe` display as `invoicexe.pdf` in any WPF TextBlock/TextBox. Every incident title, path cell, toast body and Timeline entry in this design renders an attacker-controlled string faithfully, which is exactly the wrong behaviour in a security tool.
  - **Fix:** Keep monospace (it is right for column scanning and whitespace), but change the stated rationale and add a display-sanitiser used by every attacker-controlled string: strip/escape bidi controls (U+202A-U+202E, U+2066-U+2069), zero-width and other Cf characters, control chars and newlines; render them as visible \\uXXXX escapes; flag non-ASCII and mixed-script runs with a distinct colour and a tooltip; make trailing whitespace visible. Add the same sanitisation to the [Export] path.
- **Claim:** "'Segoe UI Variable' with no optical suffix is NOT a resolvable family name in WPF and silently falls back to the default UI font."
  - **Why wrong:** Partly wrong. It is true that Fonts.SystemFontFamilies enumerates only the three suffixed families. But `new FontFamily("Segoe UI Variable").GetTypefaces()` on this machine returns 18 real typefaces at weights 300/350/400/600/700/900 with Italic and Oblique styles, versus 14 typefaces at 400/700/900 for a deliberately nonexistent family name — so WPF does resolve it through the typographic family name; it does not fall back to the default UI font. The spec then contradicts itself by listing "Segoe UI Variable" as a live fallback inside the Font.Display chain it just declared dead.
  - **Fix:** Keep the rule (always name an optical cut) but on the correct grounds: the unsuffixed family gives you an unpredictable optical cut and an extra weight (900) that is not in the type scale. Also drop `sans-serif` and `monospace` from the FontFamily strings — those are CSS generic names and resolve to nothing in WPF.
- **Claim:** "At 1280x820 the fold is roughly y=740 inside the content canvas. Above it, exactly three bands" combined with MinHeight=680.
  - **Why wrong:** The arithmetic does not close at the minimum window size. MinHeight 680 - 40px title strip - 24px top - 24px bottom canvas padding = 592 device-independent units of usable content height. The mandated composition is the universal screen header (28/36 + 13/18 + 24 gap ~= 78) + Band 1 (216) + Band 2 (140) + Band 3 at its own specified min-height (180) + two band gaps (24 each) = 662. That is ~70px of overflow, so at MinHeight the posture ring is pushed off or Band 3 is clipped, breaking the stated invariant that the ring and the three stat tiles occupy identical pixel positions in all states.
  - **Fix:** Either raise MinHeight to ~760, or define an explicit compressed Overview (ring 128px, stat tiles stacked, Band 2 collapsed to a single row) that triggers below ~780px of window height and still holds the ring position.
- **Claim:** "Cards, tiles, rows ... get NO shadow. Elevation is Surface.Raised + 1px Border.Default + radius 12. This is the primary elevation mechanism." Combined with light theme Surface.Raised == Surface.Base == #FFFFFF.
  - **Why wrong:** In light theme the sole elevation cue is a 1.35:1 border, which is below the threshold at which many users can see an edge at all, and the spec has already banned the shadow that would otherwise carry it (light theme permits a shadow only at level 2/overlays). A dashboard whose card structure is invisible is a different product from the one in the mockups.
  - **Fix:** In light theme give Surface.Raised a real fill separation from the canvas (e.g. canvas #F2F5F9 with #FFFFFF cards, or cards #FFFFFF on a #EEF1F6 base) so the card reads without depending on the border, and keep Border.Default as reinforcement. Re-run the contrast script over the new pair.

### False-positive risks
- Sustained CPU is treated as a severity signal: the Live sparkline "crosses a threshold -> STROKE colour crossfades to the appropriate Sev graphic colour", and nothing in the spec excludes resource metrics from the posture score. On this machine, normal work is Unreal shader compilation, Blender Cycles renders, `cargo build -j24`, MSBuild across 24 threads and multi-hour slot-math Monte Carlo runs — all of which peg 100% CPU for long stretches and look exactly like a cryptominer heuristic's target. The UI must state that resource metrics are ambient telemetry only and can never move the posture ring, colour a severity indicator, or fire a toast.
- "Unsigned" is presented as a top-of-card incriminating fact (the sample subtitle is literally "svchost32.exe (PID 8814), unsigned") and Persistence maps "Unrecognised" to Sev.High. On a dev machine the unsigned population is enormous and entirely legitimate: the Rust toolchain (rustc/cargo and every binary they emit), every executable the user builds under D:\My projects, Python scripts and venv shims, node-gyp output, Unreal's UnrealEditor build products and ShaderCompileWorker, Blender addons. Signature state needs a third value beyond signed/unsigned — "built on this machine / in a developer path" — and unsigned alone must not reach Sev.High.
- BlueStacks is the sharpest case on this specific machine. Per the user's own setup, HD-Player.exe is a PATCHED signed binary — i.e. a modified executable whose Authenticode signature no longer validates, which is the single strongest tamper heuristic in any RAT detector. On top of that, ReZygisk/LSPosed perform process injection into other processes, and BlueStacks installs kernel drivers, services, scheduled tasks and Run entries. "Auto-kill + quarantine on HIGH-CONFIDENCE detections" would terminate the emulator mid-session and quarantine the patched binary, destroying the root setup the user deliberately built. There must be a first-class, path- and hash-scoped "I did this on purpose" acknowledgement for tampered-but-intentional binaries, and it must exist before any auto-action ships.
- Network detection copy assumes a quiet host. This machine routinely has: local dev servers listening on 0.0.0.0 (a listening socket from an unsigned self-built binary is textbook RAT-listener shape), Docker's vEthernet stack, ADB talking to 127.0.0.1:5555 for BlueStacks, Unreal's DDC and Epic telemetry, npm/cargo/pip/winget registry fetches, and Blender's addon updates. The Activity empty state "12 network peers, all from signed binaries you have run before" and the Overview evidence line "0 unexplained" will essentially never be true here, so the most-viewed screen in the product will sit permanently in its degraded variant and train the user to ignore it.
- The Persistence "New since baseline" default filter will be permanently non-zero on this machine. Every Visual Studio, Unreal, Epic Launcher, NVIDIA, Docker, Node and winget update rewrites Run keys, services, scheduled tasks, COM/CLSID registrations and sometimes IFEO entries; a single dev-tool update day produces dozens of "New" rows, and the nav badge (Sev.Medium) will never clear. Baseline churn needs publisher/updater-aware grouping ("14 changes from the Epic Games Launcher update") and a one-click accept per updater, or the badge becomes wallpaper.
- The first-run state says "Detection stays conservative for the first 24 hours." 24 hours does not cover this machine's normal: a weekly Unreal build, a monthly toolchain update, an occasional BlueStacks reinstall. The baseline needs to be event-aware (detect installer/updater activity and widen tolerance) rather than purely time-boxed, or the first big build after day one produces a wave of false positives at exactly the moment the user's trust is still forming.
- The confidence meter colours anything below 85 with Sev.Low and labels it "Uncertain"/"Possible" — good — but the spec still allows auto-kill + quarantine on "high-confidence" detections without stating where that threshold sits relative to the meter, and the Settings screen exposes a raw "confidence threshold slider showing the numeric cutoff". A user who nudges that slider down has silently authorised autonomous kills at 70% confidence. The slider needs a hard floor, a plain-English consequence line, and the Threats screen should show which incidents WOULD have been auto-actioned at the current setting before the user commits to it.

### Safety objections
- "Run all safe tasks" is scoped wrongly. The spec only excludes Old restore points and Windows Update cache; Temp files, Browser caches and Disk cleanup remain in the bulk run. On this machine %TEMP% holds live MSBuild/NuGet/Roslyn state, Unreal shader-compile intermediates, installer state and this session's scratchpad — deleting it under a running build corrupts the build. Disk Cleanup (cleanmgr) is worse: depending on the sageset profile it can include the Downloads folder and "Previous Windows installation(s)", both irreversible. And "Browser caches" must be defined precisely, because the cache directories sit next to Local Storage/IndexedDB/Service Worker caches, where a dev's local app state and logged-in sessions live. A bulk button that can do any of this is a one-click data-loss event.
- "Package updates (winget)" as a maintenance card is dangerous on this specific machine and contradicts the product's own no-egress default. A `winget upgrade --all` can move Node/Python/Rust/CUDA toolchains out from under pinned projects, and per the user's own documented setup a BlueStacks auto-update reverts the HD-Player patch and kills root. This card must never be part of any bulk action, must list each package with its current->target version, must support a permanent per-package exclusion list (BlueStacks first), and must be labelled as a network operation.
- Deleting old restore points / VSS shadow copies destroys more than restore points — it removes Previous Versions for every user file on the volume and the machine's own rollback path, which is the last line of defence if Warden itself misbehaves. It is currently one [Run] button behind a card. It needs typed confirmation, must never touch the most recent restore point, and should refuse entirely if system protection has been off long enough that the remaining points are the only ones.
- Purging the Windows Update cache (SoftwareDistribution\Download) while wuauserv/BITS are running can wedge Windows Update into a state that needs manual repair, and it can delete a partially downloaded feature update, forcing a multi-GB re-download. If this ships it must stop wuauserv and BITS, delete, restart, and verify — and it must detect and refuse when an update is pending install or reboot.
- "TRIM/Optimise" is safe only on SSDs. This machine has D: (6.7 TB free), E: (1 TB) and F: (584 GB), which are very likely spinning disks; `defrag` on those is a full defragmentation — many hours of continuous I/O on volumes holding Unreal DDC, VM disks and project data. Query MSFT_PhysicalDisk MediaType and only ever issue a retrim on SSDs; skip Storage Spaces, BitLocker-converting, removable and network volumes; and never present this inside a bulk action.
- The 30-day quarantine retention is designed-in permanent data loss. The Threats screen promises an [Undo] that "stays live for the full quarantine retention window" — meaning undo silently expires, and a file quarantined by a false positive is deleted forever on day 30 without the user ever making a decision. This directly contradicts the product constraint that every action is reversible. Default retention should be "keep until I say otherwise", with any purge requiring an explicit review screen listing exactly what will be destroyed.
- The elevated-engine/unelevated-UI split described in the implementation notes has no security design, and it is the highest-severity gap in the document. Every action button becomes an RPC from a medium-integrity process to a SYSTEM service, and "Restore returns the file to its exact original path and ACLs" is an arbitrary-file-write-as-SYSTEM primitive. Any malware running as the user could drive it. This needs to be specified now, not retrofitted: a named pipe with an explicit DACL limited to the interactive user's SID, server-side verification of the client process image and signature, restore paths validated server-side against the vault manifest rather than accepted from the client, and no kill/quarantine target accepted as a raw path or PID (use a server-issued incident ID).
- The quarantine vault's location, ACLs and at-rest format are unspecified while the UI makes strong promises about them ("moved, renamed, stripped of execute permission and stored inert"). Two concrete consequences: if the vault is user-writable, "inert" is false — the owner (or anything running as them) can re-grant execute or swap the contents so a later Restore writes attacker-chosen bytes to a privileged path. And if samples are stored as raw PEs, Microsoft Defender will quarantine Warden's quarantine, silently breaking Restore. Store the vault under %ProgramData% with the interactive user denied, and store samples wrapped (AES or even XOR + a non-executable extension) with the original path, ACL SDDL, timestamps and hash in a signed manifest.
- The example exclusion rule generated by one click of "Allow and remember" is `allow sha256:9f2c... path:D:\My projects\**`. That is a 6.7 TB blanket exclusion covering exactly the directory where build outputs land and where a dropped payload would be most useful. Showing the rule before committing is the right idea; defaulting it to a recursive path wildcard is not. Default to the narrowest rule (hash + exact full path), require an explicit second action to widen scope, cap wildcard depth, and give path-scoped rules an expiry with a review prompt.
- Nothing in the UI spec defines a protected-process state. The Activity detail pane invites navigating to and acting on a parent process, and the incident card offers Quarantine on whatever the engine names — with no disabled visual, no tooltip, and no distinct rendering for critical/PPL/system processes that must never be killed. Given auto-action is on by default, the un-killable set needs to be visible in the UI, not only enforced in the engine, so the user can see that Warden knows the difference.
- [Export] -> JSON or CSV on the Timeline will contain full command lines, and command lines routinely carry secrets (API tokens as arguments, connection strings, --password). The moment the user shares an export to ask for help, those leak. Add redaction on by default for known secret-shaped arguments, a visible "N values redacted" count, and an explicit opt-in to export raw.

### Omissions
- The posture ring has no state for "I don't know". The spec defines four score bands and mandates that the ring occupies identical pixel positions in all states, and it gets the freshness guard right for the all-clear CARD — but the ring itself will keep displaying a stale green 96 while the engine is dead, paused, or still building its baseline. That is the most dangerous single pixel in the product. Define a no-data rendering (track only, dashed, "--" instead of a number, band word "Unknown") and drive it from the same freshness/liveness signal as the card.
- The freshness guard's "2x the configured monitoring interval" will produce a false alarm every time the machine sleeps or hibernates: after an overnight suspend, last-check is 9 hours old and the Overview greets the user with "Monitoring may have stopped" on a perfectly healthy machine. Use a monotonic clock (Environment.TickCount64/Stopwatch, not DateTime.UtcNow), subscribe to SystemEvents.PowerModeChanged, and treat the suspend gap as expected. Also give "paused by the user" its own presentation so it never renders as "may have stopped".
- There are no failure states for any action, and failure is the common case: quarantine of a file held open by a running process (i.e. exactly the live RAT you are trying to neutralise), access denied on a protected path, an operation that needs the elevated service when it is not running, restore when the original directory no longer exists or is now occupied, restore across a volume that has been reformatted. Every action button needs a defined failure presentation with the actual Win32 reason, a retry/alternative (schedule for next boot via PendingFileRenameOperations, kill-then-quarantine), and a Timeline entry. Silent failure in a defence tool is worse than no action.
- The master "Protection" toggle sits at the bottom of the rail with no confirmation, no timer and no auto-resume — one stray click disables the product indefinitely, and the rail gives no persistent indication of that state beyond the switch itself. The tray menu offers timed pause (15 min / 1 hour / until restart) but the in-app toggle does not. Make the in-app control offer the same timed options, require a confirm, and put a persistent Sev.Medium banner across the content canvas for as long as protection is off.
- Tray-app lifecycle is entirely unspecified and every item of it is a visible bug if missed: ShutdownMode must be OnExplicitShutdown or closing the dashboard exits the product; the close button must hide-to-tray (and say so the first time); NotifyIcon must be disposed on exit or a ghost icon lingers; a second launch must focus the existing instance rather than starting a second engine; and window placement/size/monitor must persist and be validated against the current monitor set on restore.
- The autostart mechanism is never specified, and it is not a neutral choice here: Warden's own Run key or scheduled task is a persistence artifact that Warden's own Persistence screen will enumerate, so the baseline and the UI need to recognise and label it explicitly. If the engine is an elevated service, the UI cannot be autostarted elevated from a Run key without a UAC prompt at every logon — that forces a scheduled task with highest privileges, which is itself a more suspicious-looking artifact. Decide and document it, and show Warden's own persistence entries in the UI rather than hiding them.
- No high-contrast story. The token set is entirely hard-coded and there is no SystemColors path, so under Windows High Contrast the app will render its own dark palette over the user's chosen scheme — the one accessibility mode where ignoring the OS is a hard failure. Add a third token dictionary bound to SystemColors keys, triggered by SystemParameters.HighContrast, and disable Mica in that mode.
- No UI Automation story, despite retemplating every control with OverridesDefaultStyle. Icon-only controls (caption buttons, 32x32 icon buttons, the copy glyph, the rail in collapsed mode) will be announced as unlabeled without AutomationProperties.Name; a ListBox used as a data table announces rows as flat list items rather than cells with column headers; the hand-built ToggleSwitch needs its toggle semantics preserved; and returning HTMAXBUTTON from WM_NCHITTEST removes the maximise button from the normal input and automation path entirely, so it needs an explicit peer. This matters commercially too — it is one of the differences between "premium" and "looks premium in a screenshot".
- Two native window behaviours are missing from the custom-chrome list. (a) The system menu: with WindowStyle=None there is no Alt+Space and no right-click-title-bar menu unless you handle WM_NCRBUTTONUP/WM_SYSCOMMAND and call GetSystemMenu/TrackPopupMenu. (b) A maximised WindowChrome window extends past the work area by the resize-border thickness, so the right-aligned caption buttons and the top edge of the title strip get clipped unless the root border compensates when WindowState=Maximized. Also, the supplied hit-test hook calls MaxButton.PointFromScreen on every WM_NCHITTEST — that throws InvalidOperationException if the visual is not yet connected to a PresentationSource, which is a crash inside the message pump; null/IsLoaded-guard it. (I did verify the hook precedence itself works: a hook added in OnSourceInitialized receives WM_NCHITTEST with handled=false and its HTMAXBUTTON return value wins over WindowChrome, so the Snap Layouts approach is sound.)
- The Privacy & Network trust statement "Warden has made 0 outbound network connections this session" will be false as soon as the engine verifies a signature: X509Chain/WinVerifyTrust performs OCSP and CRL fetches by default, so signature checking is itself an egress path, and the Maintenance screen's winget card is another. Either set X509RevocationMode.NoCheck (and say so in the same panel, since that is a real trade-off) or count and attribute those connections honestly. A privacy claim that is trivially falsifiable with Resource Monitor destroys more trust than it builds.
- The posture score is the hero of the product and is never defined — not its inputs, not its bounds, not its hysteresis, not what the user can do to move it. At minimum the spec needs: which signals contribute, an explicit exclusion of resource-usage metrics, hysteresis so a transient event does not swing the ring, and a per-band explanation so the evidence stack under the ring always names the specific reason the score is not 100.
- There is no self-audit surface. A tool that watches everything should show what it is doing: Warden's own CPU/memory, its ETW session count, whether the driver/service is healthy, how many events it dropped, and the exact list of paths and registry roots it monitors. Settings > Advanced is the obvious home. Related: there is no first-run consent screen describing what will be monitored, and no in-app disable/uninstall path — for a tool with an elevated service and autonomous kill authority, both are table stakes.
- po:Freeze is specified without mc:Ignorable. The presentation-options namespace must be declared AND listed in mc:Ignorable on the ResourceDictionary root, otherwise the attribute is a parse-time problem rather than a no-op. Small, but it is in the ResourceDictionary architecture item that the implementer will copy verbatim.
- Toast delivery has a hole for exactly the user this is built for. When the window is hidden (the normal state) the in-app stack is invisible; balloons are capped at one per 60s, suppressed below Sev.Medium, and dropped entirely by Focus Assist and by fullscreen-exclusive apps — i.e. while the user is in Unreal or a game, which is when a burst of auto-kills is most likely to matter. The tray "Acted" dot is the right idea but is not enough: add a durable unacknowledged-actions queue and a digest on next open ("3 actions taken while you were away"), and use SHQueryUserNotificationState to detect QUNS_RUNNING_D3D_FULL_SCREEN / QUNS_QUIET_TIME rather than assuming a balloon was seen.
