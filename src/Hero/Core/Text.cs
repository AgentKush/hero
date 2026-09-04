using System.Text;

namespace Hero.Core;

/// <summary>
/// Text tidying for values that came from the machine rather than from a designer.
///
/// Command lines, registry values and Defender resource strings are not display strings. They
/// contain newlines, tabs, runs of spaces and occasionally control characters, and a UI that
/// renders them verbatim inherits all of it. A single process launched with a here-doc script
/// turned one row of the Overview into thirty and pushed every column out of alignment, because
/// TextTrimming only ellipsises within a line — it does nothing about the line breaks themselves.
/// </summary>
internal static class Text
{
    /// <summary>
    /// Collapses a machine string onto one line: every run of whitespace becomes a single space,
    /// control characters are dropped, and the result is trimmed.
    /// </summary>
    internal static string OneLine(string? value, int maxLength = 0)
    {
        if (string.IsNullOrEmpty(value)) return "";

        var sb = new StringBuilder(value.Length);
        bool pendingSpace = false;

        foreach (char c in value)
        {
            if (char.IsWhiteSpace(c))
            {
                // Remember that a gap existed, but do not emit it until real content follows;
                // that collapses runs and strips leading whitespace in one pass.
                if (sb.Length > 0) pendingSpace = true;
                continue;
            }

            // Control characters have no width but do have effects — a stray  or an ANSI
            // escape would otherwise travel intact into a label.
            if (char.IsControl(c)) continue;

            if (pendingSpace) { sb.Append(' '); pendingSpace = false; }
            sb.Append(c);
        }

        var text = sb.ToString();

        // Truncate with a real ellipsis so a very long command line cannot dominate a layout even
        // where the control has no trimming of its own.
        if (maxLength > 0 && text.Length > maxLength)
            text = text[..Math.Max(1, maxLength - 1)].TrimEnd() + "…";

        return text;
    }

    /// <summary>
    /// A path shortened from the middle, keeping the root and the file name — the two parts that
    /// identify it. Trimming the end of a path hides the very thing the reader is looking for.
    /// </summary>
    internal static string MiddleTrim(string? path, int maxLength)
    {
        var text = OneLine(path);
        if (maxLength <= 3 || text.Length <= maxLength) return text;

        int keepEnd = Math.Max(12, maxLength / 2);
        int keepStart = Math.Max(3, maxLength - keepEnd - 1);
        return text[..keepStart] + "…" + text[^keepEnd..];
    }
}
