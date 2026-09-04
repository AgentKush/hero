using System.Drawing.Drawing2D;

namespace Hero.UI;

/// <summary>
/// HERO's mark, drawn rather than shipped as a bitmap.
///
/// One renderer serves the application icon, the tray icon and any in-app use, so they cannot
/// drift apart. It also means the tray icon can be tinted by posture without maintaining four
/// separate .ico files.
///
/// The design has to survive 16x16, which rules out most detail. What reads at that size is a
/// strong silhouette plus exactly one interior shape: a shield with a tick cut out of it as
/// negative space.
///
/// The interior was originally a letter H, and it did not work. At icon sizes the crossbar came
/// out nearly as thick as the gaps around it, so the four remaining pieces of shield read as eyes
/// and the whole mark looked like a skull. A tick is one continuous stroke with no enclosed
/// counters, which is the shape class that survives downscaling.
/// </summary>
internal static class HeroMark
{
    /// <summary>Posture colours. Deep enough to hold white text on top at small sizes.</summary>
    internal static Gdi.Color Clear => Gdi.Color.FromArgb(0x3F, 0xB9, 0x84);
    internal static Gdi.Color Watching => Gdi.Color.FromArgb(0x4C, 0x8D, 0xFF);
    internal static Gdi.Color Attention => Gdi.Color.FromArgb(0xE0, 0xA5, 0x4B);
    internal static Gdi.Color Critical => Gdi.Color.FromArgb(0xE5, 0x48, 0x4D);

    /// <summary>
    /// Renders the mark into a new 32-bit ARGB bitmap.
    /// </summary>
    /// <param name="size">Edge length in pixels.</param>
    /// <param name="accent">Shield colour.</param>
    /// <param name="flat">
    /// True for a flat fill instead of a gradient. Below about 20px a gradient just muddies the
    /// silhouette, so the small icon sizes use flat colour.
    /// </param>
    internal static Gdi.Bitmap Render(int size, Gdi.Color accent, bool? flat = null)
    {
        bool useFlat = flat ?? size <= 20;

        var bmp = new Gdi.Bitmap(size, size, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using var g = Gdi.Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.Clear(Gdi.Color.Transparent);

        // Work in a 0..1 space and scale, so every size is the same drawing.
        float s = size;
        float inset = size <= 20 ? 0.02f : 0.06f;   // small sizes need the extra pixels
        float left = inset * s, right = (1 - inset) * s;
        float top = inset * s, bottom = (1 - inset) * s;
        float w = right - left, h = bottom - top;

        using var shield = ShieldPath(left, top, w, h);

        // ---- body
        if (useFlat)
        {
            using var brush = new Gdi.SolidBrush(accent);
            g.FillPath(brush, shield);
        }
        else
        {
            // A vertical gradient from a lifted tint to the accent gives the mark depth without
            // any bevel or shadow, both of which disintegrate when scaled down.
            using var brush = new LinearGradientBrush(
                new Gdi.PointF(left, top),
                new Gdi.PointF(left, bottom),
                Lighten(accent, 0.22f),
                Darken(accent, 0.12f));
            g.FillPath(brush, shield);
        }

        // ---- the tick, cut as negative space
        //
        // Punching a hole (rather than drawing a lighter shape on top) keeps the mark legible on
        // any background, because the cut-out takes the colour of whatever is behind it.
        using (var cut = TickPath(left, top, w, h))
        {
            var previous = g.CompositingMode;
            g.CompositingMode = CompositingMode.SourceCopy;
            using var clear = new Gdi.SolidBrush(Gdi.Color.FromArgb(0, 0, 0, 0));
            g.FillPath(clear, cut);
            g.CompositingMode = previous;
        }

        return bmp;
    }

    /// <summary>
    /// A shield: flat shoulders, straight sides, then a curve into a point. Deliberately not a
    /// heraldic shield, which needs detail HERO cannot afford at 16px.
    /// </summary>
    private static GraphicsPath ShieldPath(float x, float y, float w, float h)
    {
        var path = new GraphicsPath();
        float r = w * 0.16f;            // shoulder radius
        float shoulder = y + h * 0.60f; // where the sides start curving in

        path.AddArc(x, y, r * 2, r * 2, 180, 90);                       // top-left
        path.AddArc(x + w - r * 2, y, r * 2, r * 2, 270, 90);           // top-right
        path.AddLine(x + w, y + r, x + w, shoulder);                    // right side
        // Right side sweeping to the tip.
        path.AddBezier(x + w, shoulder,
                       x + w, y + h * 0.82f,
                       x + w * 0.72f, y + h * 0.94f,
                       x + w / 2, y + h);
        // Left side, mirrored.
        path.AddBezier(x + w / 2, y + h,
                       x + w * 0.28f, y + h * 0.94f,
                       x, y + h * 0.82f,
                       x, shoulder);
        path.CloseFigure();
        return path;
    }

    /// <summary>
    /// A tick, cut out of the shield.
    ///
    /// The first attempt at this was a letter H built from three bars. It failed badly: at the
    /// sizes that matter the crossbar was nearly as thick as the gaps around it, so the four
    /// remaining pieces of shield read as eyes and the mark looked like a skull. A tick has one
    /// continuous stroke and no enclosed counters, which is what survives being scaled to 16px.
    ///
    /// Drawn as a widened polyline rather than a filled outline so the stroke thickness stays
    /// constant around the elbow.
    /// </summary>
    private static GraphicsPath TickPath(float x, float y, float w, float h)
    {
        var path = new GraphicsPath();

        // Sits slightly above centre: the shield tapers, so an optically centred mark must be
        // higher than the geometric middle.
        var points = new[]
        {
            new Gdi.PointF(x + w * 0.30f, y + h * 0.47f),
            new Gdi.PointF(x + w * 0.45f, y + h * 0.61f),
            new Gdi.PointF(x + w * 0.71f, y + h * 0.31f),
        };
        path.AddLines(points);

        float stroke = w * 0.145f;
        using var pen = new Gdi.Pen(Gdi.Color.Black, stroke)
        {
            StartCap = LineCap.Round,
            EndCap = LineCap.Round,
            LineJoin = LineJoin.Round,
        };
        path.Widen(pen);
        return path;
    }

    private static Gdi.Color Lighten(Gdi.Color c, float amount) => Gdi.Color.FromArgb(
        c.A,
        (int)Math.Min(255, c.R + (255 - c.R) * amount),
        (int)Math.Min(255, c.G + (255 - c.G) * amount),
        (int)Math.Min(255, c.B + (255 - c.B) * amount));

    private static Gdi.Color Darken(Gdi.Color c, float amount) => Gdi.Color.FromArgb(
        c.A,
        (int)(c.R * (1 - amount)),
        (int)(c.G * (1 - amount)),
        (int)(c.B * (1 - amount)));

    /// <summary>
    /// Builds a multi-resolution .ico.
    ///
    /// Written by hand because System.Drawing cannot save a multi-image icon, and a single-size
    /// icon looks visibly resampled in the places Windows uses the large one (Alt+Tab, the
    /// taskbar on a high-DPI display, the file's own Properties page).
    /// </summary>
    internal static void WriteIco(string path, Gdi.Color accent, params int[] sizes)
    {
        if (sizes.Length == 0) sizes = new[] { 16, 20, 24, 32, 40, 48, 64, 128, 256 };

        var images = new List<byte[]>();
        foreach (var size in sizes)
        {
            using var bmp = Render(size, accent);
            using var ms = new MemoryStream();
            // Every entry is a PNG. Vista and later accept PNG-compressed icon images at any
            // size, and it avoids hand-rolling the DIB + AND-mask layout.
            bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
            images.Add(ms.ToArray());
        }

        using var file = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var w = new BinaryWriter(file);

        w.Write((ushort)0);                 // reserved
        w.Write((ushort)1);                 // type: icon
        w.Write((ushort)sizes.Length);

        int offset = 6 + 16 * sizes.Length;
        for (int i = 0; i < sizes.Length; i++)
        {
            // 256 is encoded as 0 in the directory entry.
            w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
            w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
            w.Write((byte)0);               // palette
            w.Write((byte)0);               // reserved
            w.Write((ushort)1);             // colour planes
            w.Write((ushort)32);            // bits per pixel
            w.Write(images[i].Length);
            w.Write(offset);
            offset += images[i].Length;
        }

        foreach (var image in images) w.Write(image);
    }
}
