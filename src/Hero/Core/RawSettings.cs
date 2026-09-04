using System.Text.Json;
using System.Text.Json.Nodes;

namespace Hero.Core;

/// <summary>
/// Reads and writes single keys in settings.json that are deliberately NOT part of
/// <see cref="HeroSettings"/>.
///
/// The schema in <see cref="HeroSettings"/> is a security-behaviour contract with a version
/// history. Purely cosmetic preferences — whether animations play, whether network peers get
/// reverse-DNS names — do not belong in it, but they do belong in the same file, because "what
/// has HERO stored about me" should have one answer.
///
/// Extracted from the Settings page when the guardian moved into the service: the write half now
/// has to run on whichever side owns the file, so it cannot live in a UI class any more.
/// </summary>
internal static class RawSettings
{
    internal static bool Read(string key, bool fallback)
    {
        try
        {
            if (!File.Exists(HeroPaths.Settings)) return fallback;
            using var doc = JsonDocument.Parse(File.ReadAllText(HeroPaths.Settings));
            if (doc.RootElement.TryGetProperty(key, out var value)
                && value.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                return value.GetBoolean();
            }
        }
        catch { }
        return fallback;
    }

    /// <summary>
    /// Writes one key, preserving everything else in the file. Whole-file rewrite through a
    /// temporary because a half-written settings.json is worse than a stale one.
    /// </summary>
    internal static void Write(string key, bool value)
    {
        try
        {
            HeroPaths.EnsureCreated();

            JsonObject root = File.Exists(HeroPaths.Settings)
                ? JsonNode.Parse(File.ReadAllText(HeroPaths.Settings)) as JsonObject ?? new JsonObject()
                : new JsonObject();

            root[key] = value;

            var temporary = HeroPaths.Settings + ".tmp";
            File.WriteAllText(temporary, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, HeroPaths.Settings, overwrite: true);
        }
        catch { /* a settings write failure must never take the app down */ }
    }
}
