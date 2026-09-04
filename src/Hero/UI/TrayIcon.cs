using System.Windows;

namespace Hero;

/// <summary>
/// System-tray presence.
///
/// WPF has no tray control, so this uses the in-box WinForms NotifyIcon (the only reason
/// UseWindowsForms is enabled). The icon is drawn at runtime with GDI+ rather than shipped
/// as a .ico, so it can reflect posture — calm, watching, alerting — without bundling
/// multiple icon assets.
/// </summary>
internal sealed class TrayIcon : IDisposable
{
    internal enum Posture { Clear, Watching, Attention, Critical }

    private readonly WinForms.NotifyIcon _icon;
    private readonly Action _onOpen;
    private Posture _posture = Posture.Clear;
    private Gdi.Icon? _current;

    internal TrayIcon(Action onOpen, Action onExit)
    {
        _onOpen = onOpen;

        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Open HERO", null, (_, _) => onOpen());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => onExit());

        _icon = new WinForms.NotifyIcon
        {
            Text = "HERO — all clear",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _icon.DoubleClick += (_, _) => _onOpen();
        SetPosture(Posture.Clear);
    }

    internal void SetPosture(Posture posture, string? tooltip = null)
    {
        _posture = posture;
        var next = Render(posture);
        _icon.Icon = next;

        // NotifyIcon does not take ownership of the icon handle, so the previous one must
        // be destroyed explicitly or the app leaks a GDI object on every posture change.
        _current?.Dispose();
        _current = next;

        // The tray tooltip is hard-capped at 63 characters by the shell.
        var text = tooltip ?? posture switch
        {
            Posture.Clear => "HERO — all clear",
            Posture.Watching => "HERO — watching",
            Posture.Attention => "HERO — needs your attention",
            Posture.Critical => "HERO — threat contained",
            _ => "HERO",
        };
        _icon.Text = text.Length > 63 ? text[..63] : text;
    }

    /// <summary>
    /// Renders the tray glyph from the same mark as the application icon, tinted by posture.
    ///
    /// Sharing <see cref="UI.HeroMark"/> rather than drawing a second shield here is what keeps
    /// the tray and the taskbar showing the same logo. The previous local drawing had already
    /// drifted into a different shape entirely.
    /// </summary>
    private static Gdi.Icon Render(Posture posture)
    {
        var colour = posture switch
        {
            Posture.Clear => UI.HeroMark.Clear,
            Posture.Watching => UI.HeroMark.Watching,
            Posture.Attention => UI.HeroMark.Attention,
            Posture.Critical => UI.HeroMark.Critical,
            _ => Gdi.Color.Gainsboro,
        };

        // Windows asks for a 16px tray icon on a 100% display and 20-24px at higher scaling.
        // Rendering at 32 and letting the shell downscale keeps it sharp at every DPI.
        using var bmp = UI.HeroMark.Render(32, colour);

        // FromHandle does not own the handle; copy into a managed icon and release the HICON.
        IntPtr hIcon = bmp.GetHicon();
        try
        {
            using var tmp = Gdi.Icon.FromHandle(hIcon);
            return (Gdi.Icon)tmp.Clone();
        }
        finally
        {
            DestroyIcon(hIcon);
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    /// <summary>Balloon notification. Unpackaged WPF apps cannot raise real Win11 toasts
    /// without a registered AppUserModelID, so this is the dependency-free fallback.</summary>
    internal void Notify(string title, string message, bool warning)
    {
        _icon.BalloonTipTitle = title;
        _icon.BalloonTipText = message;
        _icon.BalloonTipIcon = warning ? WinForms.ToolTipIcon.Warning : WinForms.ToolTipIcon.Info;
        _icon.ShowBalloonTip(8000);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        _current?.Dispose();
    }
}
