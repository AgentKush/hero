using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Hero.Interop;

namespace Hero.UI;

/// <summary>
/// Windows 11 window presentation: Mica backdrop, dark title bar, rounded corners.
///
/// These are what separate a window that looks native and current from one that looks like
/// a 2010 utility. All are applied through DwmSetWindowAttribute and all degrade silently
/// on older builds — a failed HRESULT means "this Windows version doesn't support it",
/// never an error worth surfacing.
/// </summary>
internal static class WindowEffects
{
    /// <summary>
    /// Applies dark mode, rounded corners and the Mica backdrop to a window.
    /// Must be called after the HWND exists (SourceInitialized or later).
    /// </summary>
    /// <param name="window">Target window.</param>
    /// <param name="backdrop">
    /// One of Native.DWMSBT_MAINWINDOW (Mica), DWMSBT_TABBEDWINDOW (Mica Alt) or
    /// DWMSBT_TRANSIENTWINDOW (Acrylic, for transient surfaces such as toasts).
    /// </param>
    internal static void Apply(Window window, int backdrop = Native.DWMSBT_MAINWINDOW, bool dark = true)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;

        // Mica composites against the desktop wallpaper, so the WPF window must not paint
        // an opaque background over it. The window's own Background is set to Transparent
        // and each surface layer supplies its own colour.
        int darkFlag = dark ? 1 : 0;
        Native.DwmSetWindowAttribute(hwnd, Native.DWMWA_USE_IMMERSIVE_DARK_MODE, ref darkFlag, sizeof(int));

        int corner = Native.DWMWCP_ROUND;
        Native.DwmSetWindowAttribute(hwnd, Native.DWMWA_WINDOW_CORNER_PREFERENCE, ref corner, sizeof(int));

        int backdropType = backdrop;
        Native.DwmSetWindowAttribute(hwnd, Native.DWMWA_SYSTEMBACKDROP_TYPE, ref backdropType, sizeof(int));
    }

    /// <summary>
    /// Enables Mica by clearing the WPF-side background to transparent.
    /// Without this the backdrop is drawn but completely hidden behind the window's own fill.
    /// </summary>
    internal static void PrepareForBackdrop(Window window)
    {
        window.Background = Brushes.Transparent;
    }

    /// <summary>Sets the DWM border colour (Win11 22H2+). Pass null to restore the default.</summary>
    internal static void SetBorderColor(Window window, Color? color)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;
        // DWM expects 0x00BBGGRR; 0xFFFFFFFE is the documented "no border" sentinel.
        int value = color is { } c ? (c.B << 16) | (c.G << 8) | c.R : unchecked((int)0xFFFFFFFE);
        Native.DwmSetWindowAttribute(hwnd, Native.DWMWA_BORDER_COLOR, ref value, sizeof(int));
    }
}
