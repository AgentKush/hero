using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Hero.Core;

/// <summary>
/// How much HERO is allowed to do without asking.
///
/// Four discrete levels rather than a slider, because the boundary is a permission boundary and
/// has to be expressible as a hard rule the user can recite back. <see cref="AutoHighConfidence"/>
/// is the default and is what the user chose.
/// </summary>
internal enum AutonomyLevel
{
    /// <summary>Watch and record. HERO never prompts and never acts.</summary>
    Observe = 0,
    /// <summary>Every action, however obvious, waits for a human.</summary>
    AskAlways = 1,
    /// <summary>Act autonomously (and reversibly) on High confidence; prompt on everything else.</summary>
    AutoHighConfidence = 2,
    /// <summary>Act on Medium as well. Offered, but never the default.</summary>
    Autopilot = 3,
}

/// <summary>An entry the user has explicitly declared benign.</summary>
/// <remarks>
/// Allowlisting is by exact full path, never by image name and never by directory. The critique
/// of the platform spec is emphatic about this and it is right: a name-based allowlist protects
/// the impostor, and node/python/dotnet/powershell are the four most common living-off-the-land
/// hosts on this exact machine. Where a hash is recorded the path match alone is not enough.
/// </remarks>
internal sealed record AllowEntry
{
    /// <summary>Full path, publisher subject/thumbprint, endpoint or persistence key.</summary>
    internal required string Value { get; init; }
    /// <summary>Why the user allowed it. Shown back to them; an empty reason ages badly.</summary>
    internal string Reason { get; init; } = "";
    /// <summary>Optional SHA-256 pin. When present the file must still hash to this.</summary>
    internal string? Sha256 { get; init; }
    internal DateTime AddedUtc { get; init; } = DateTime.UtcNow;
    /// <summary>Optional expiry. A temporary "yes, that's fine" should not be permanent.</summary>
    internal DateTime? ExpiresUtc { get; init; }

    internal bool IsLive(DateTime nowUtc) => ExpiresUtc is null || ExpiresUtc > nowUtc;
}

/// <summary>Per-rule "stop telling me about this".</summary>
internal sealed record RuleMute
{
    internal bool Muted { get; init; } = true;
    /// <summary>Null means indefinitely. A dated mute is strongly preferred.</summary>
    internal DateTime? UntilUtc { get; init; }
    internal string Reason { get; init; } = "";

    internal bool IsActive(DateTime nowUtc) => Muted && (UntilUtc is null || UntilUtc > nowUtc);
}

/// <summary>
/// A window during which HERO stays quiet. Prompts are suppressed and queued; whether autonomous
/// action is also suppressed is a separate switch, because "don't interrupt me" and "don't defend
/// me" are different requests.
/// </summary>
internal sealed class QuietHours
{
    internal bool Enabled { get; set; }
    /// <summary>Local time of day. Start &gt; End means the window wraps past midnight.</summary>
    internal TimeSpan Start { get; set; } = TimeSpan.FromHours(22);
    internal TimeSpan End { get; set; } = TimeSpan.FromHours(8);
    /// <summary>Hold prompts until the window ends rather than dropping them.</summary>
    internal bool SuppressPrompts { get; set; } = true;
    /// <summary>Off by default: a reversible auto-action at 03:00 is better than a live intruder.</summary>
    internal bool SuppressAutoAction { get; set; }

    /// <summary>True when <paramref name="localNow"/> falls inside the window.</summary>
    internal bool Contains(DateTime localNow)
    {
        if (!Enabled) return false;
        var t = localNow.TimeOfDay;
        // Equal endpoints would otherwise mean either "always" or "never" depending on the
        // comparison; treat them as "never", which is the harmless reading.
        if (Start == End) return false;
        return Start < End ? t >= Start && t < End : t >= Start || t < End;
    }
}

/// <summary>
/// HERO's settings, persisted as JSON at <see cref="HeroPaths.Settings"/>.
///
/// Three properties this file is built around:
///
/// 1. <b>A corrupt settings file must never stop HERO starting.</b> Every read is individually
///    tolerant: a bad value falls back to the default and the rest of the file still loads. There
///    is no all-or-nothing <c>JsonSerializer.Deserialize</c> call anywhere here, deliberately.
/// 2. <b>Unknown keys survive.</b> Saving re-reads the file on disk and overlays only the keys
///    HERO owns, so a key written by a newer build (or by hand) is not silently destroyed.
/// 3. <b>Writes are atomic.</b> Temp file then replace, so a crash mid-write cannot leave a
///    truncated settings file — which is exactly the file that would then fail to load.
///
/// <c>uiScale</c> is written directly by MainWindow via its own read-modify-write. That key is
/// therefore treated as foreign-owned: it is re-read from disk at save time unless something has
/// explicitly assigned <see cref="UiScale"/> through this object. Without that, HERO saving any
/// unrelated setting would silently revert the user's zoom level.
/// </summary>
internal sealed class HeroSettings
{
    /// <summary>
    /// Bumped when a key changes meaning. Unknown future versions load best-effort.
    ///
    /// 2 — autonomy became functional. No key changed shape; what changed is that the settings on
    /// either side of this line mean different things in practice. Under version 1 the guardian
    /// could not act at all, whatever the user had chosen, because the autonomy level never
    /// reached the engine. An existing install therefore carries an observation window that
    /// expired long ago and a machine HERO has never actually been trusted to act on. Carrying
    /// that forward would arm a guardian the moment it is upgraded, on evidence gathered while
    /// nothing was at stake. See <see cref="NoteStart"/>.
    /// </summary>
    internal const int CurrentSchemaVersion = 2;

    internal const double DefaultUiScale = 1.15;
    private const double MinUiScale = 0.7;
    private const double MaxUiScale = 2.0;

    private static readonly object Gate = new();
    private static HeroSettings? _current;

    /// <summary>The process-wide instance. Loaded once, lazily, and never reloaded implicitly.</summary>
    internal static HeroSettings Current
    {
        get
        {
            lock (Gate) return _current ??= Load();
        }
    }

    // ------------------------------------------------------------------ values

    internal int SchemaVersion { get; set; } = CurrentSchemaVersion;

    /// <summary>Defaults to <see cref="AutonomyLevel.AutoHighConfidence"/> — the user's choice.</summary>
    internal AutonomyLevel Autonomy { get; set; } = AutonomyLevel.AutoHighConfidence;

    private double _uiScale = DefaultUiScale;
    private bool _uiScaleAssigned;

    /// <summary>
    /// Dashboard zoom, 0.7–2.0. Shared with MainWindow, which owns the key day to day.
    /// </summary>
    internal double UiScale
    {
        get => _uiScale;
        set
        {
            _uiScale = Math.Clamp(value, MinUiScale, MaxUiScale);
            _uiScaleAssigned = true;
        }
    }

    /// <summary>Whether HERO registers itself to start at logon. Opt-in; never assumed.</summary>
    internal bool RunAtStartup { get; set; }

    /// <summary>Which logon mechanism to use. See <see cref="StartupRegistration.Recommended"/>.</summary>
    /// <remarks>
    /// Property and type share a name (the "Color Color" case). Legal C#, but the qualified form
    /// is used here and in <see cref="Save"/> so neither reader nor compiler has to think about it.
    /// </remarks>
    internal StartupMethod StartupMethod { get; set; } = Hero.Core.StartupMethod.RegistryRun;

    internal QuietHours QuietHours { get; set; } = new();

    /// <summary>Exact full paths the user has declared benign, optionally hash-pinned.</summary>
    internal List<AllowEntry> AllowedImages { get; } = new();

    /// <summary>Signer subjects or certificate thumbprints treated as trusted publishers.</summary>
    internal List<AllowEntry> AllowedPublishers { get; } = new();

    /// <summary>Remote endpoints (host or address) whose traffic should not be scored.</summary>
    internal List<AllowEntry> AllowedEndpoints { get; } = new();

    /// <summary>PersistenceEntry.Key values the user has accepted.</summary>
    internal List<AllowEntry> AllowedPersistence { get; } = new();

    /// <summary>Rule id -&gt; mute. Keyed by <c>IDetectionRule.Id</c>.</summary>
    internal Dictionary<string, RuleMute> MutedRules { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Auto-action requires at least one hard indicator (unbacked executable memory, a known-bad
    /// hash, a signature-mismatched system binary) and never a score assembled from soft signals
    /// alone. Nine unsigned binaries are running on this machine right now and every one is
    /// benign, so a purely additive score is not a licence to act. Default on; exposed so it can
    /// be turned off deliberately rather than eroded accidentally.
    /// </summary>
    internal bool RequireHardIndicatorForAutoAction { get; set; } = true;

    /// <summary>
    /// Circuit breaker. Beyond this many autonomous actions in a rolling hour HERO stops acting
    /// and starts asking. Five is enough for a genuine multi-file infection while capping the
    /// blast radius of a bad rule at something a human can undo in a couple of minutes.
    /// </summary>
    internal int MaxAutoActionsPerHour { get; set; } = 5;

    /// <summary>
    /// Per-sweep cap. A single sweep implicating more than two subjects is far more likely to be
    /// a broken heuristic than a real multi-stage compromise, so the second is the last free one.
    /// </summary>
    internal int MaxAutoActionsPerSweep { get; set; } = 2;

    /// <summary>
    /// End of the mandatory observation period. Until this passes HERO watches and explains but
    /// never acts, so its first impression of a machine running Unreal, Blender, BlueStacks and
    /// a dozen language toolchains is formed before it is trusted with a kill switch.
    /// Defaults to 72 hours from first run: long enough to cover at least one full build, render
    /// and emulator cycle, short enough that the user has not forgotten HERO is still warming up.
    /// </summary>
    internal DateTime? ObservationEndsUtc { get; set; }

    /// <summary>
    /// Kill switch. While this is in the future HERO takes no autonomous action at all. Set by
    /// the user, and set automatically after an abnormal termination so a crash loop cannot
    /// quarantine the machine one restart at a time.
    /// </summary>
    internal DateTime? AutoActionDisabledUntilUtc { get; set; }

    internal DateTime FirstRunUtc { get; set; } = DateTime.UtcNow;
    internal DateTime? LastStartUtc { get; set; }
    /// <summary>Written on a clean exit. Missing or older than LastStartUtc means we crashed.</summary>
    internal DateTime? LastCleanExitUtc { get; set; }

    // ------------------------------------------------------------- derived API

    /// <summary>True when the previous run did not shut down cleanly.</summary>
    internal bool PreviousRunEndedAbnormally =>
        LastStartUtc is { } start && (LastCleanExitUtc is null || LastCleanExitUtc < start);

    /// <summary>
    /// Whether HERO may act without asking right now, and if not, why not. The reason is written
    /// for the user, not the log: it goes straight into the UI so "HERO did nothing" is never
    /// indistinguishable from "HERO found nothing".
    /// </summary>
    internal bool AutoActionPermitted(DateTime nowUtc, out string reason)
    {
        if (Autonomy is AutonomyLevel.Observe)
        {
            reason = "Autonomy is set to Observe — HERO is watching only.";
            return false;
        }
        if (Autonomy is AutonomyLevel.AskAlways)
        {
            reason = "Autonomy is set to Ask Always — every action waits for you.";
            return false;
        }
        if (AutoActionDisabledUntilUtc is { } until && until > nowUtc)
        {
            reason = $"Autonomous action is paused until {until.ToLocalTime():g}.";
            return false;
        }
        if (ObservationEndsUtc is { } obs && obs > nowUtc)
        {
            reason = $"HERO is still learning this machine until {obs.ToLocalTime():g} and will not act before then.";
            return false;
        }
        if (QuietHours.SuppressAutoAction && QuietHours.Contains(nowUtc.ToLocalTime()))
        {
            reason = "Quiet hours are active and configured to suppress action.";
            return false;
        }
        reason = "";
        return true;
    }

    /// <summary>True when prompts should be held rather than shown.</summary>
    internal bool PromptsSuppressed(DateTime nowUtc) =>
        QuietHours.SuppressPrompts && QuietHours.Contains(nowUtc.ToLocalTime());

    /// <summary>
    /// Exact-path allowlist check. <paramref name="sha256"/> is required to match when the entry
    /// pins one; a pinned entry that cannot be hash-checked is treated as NOT allowed, because
    /// the pin exists precisely to defeat path reuse.
    /// </summary>
    internal bool IsImageAllowed(string? fullPath, string? sha256, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return false;
        foreach (var e in AllowedImages)
        {
            if (!e.IsLive(nowUtc)) continue;
            if (!PathsEqual(e.Value, fullPath)) continue;
            if (e.Sha256 is { Length: > 0 } pin)
                return sha256 is { Length: > 0 } && string.Equals(pin, sha256, StringComparison.OrdinalIgnoreCase);
            return true;
        }
        return false;
    }

    internal bool IsPublisherAllowed(string? subjectOrThumbprint, DateTime nowUtc) =>
        Matches(AllowedPublishers, subjectOrThumbprint, nowUtc);

    internal bool IsEndpointAllowed(string? endpoint, DateTime nowUtc) =>
        Matches(AllowedEndpoints, endpoint, nowUtc);

    internal bool IsPersistenceAllowed(string? persistenceKey, DateTime nowUtc) =>
        Matches(AllowedPersistence, persistenceKey, nowUtc);

    internal bool IsRuleMuted(string ruleId, DateTime nowUtc) =>
        MutedRules.TryGetValue(ruleId, out var m) && m.IsActive(nowUtc);

    /// <summary>Mutes a rule. A null <paramref name="untilUtc"/> means indefinitely.</summary>
    internal void MuteRule(string ruleId, DateTime? untilUtc, string reason)
    {
        if (string.IsNullOrWhiteSpace(ruleId)) return;
        MutedRules[ruleId] = new RuleMute { Muted = true, UntilUtc = untilUtc, Reason = reason };
    }

    internal void UnmuteRule(string ruleId) => MutedRules.Remove(ruleId);

    private static bool Matches(List<AllowEntry> list, string? value, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        foreach (var e in list)
            if (e.IsLive(nowUtc) && string.Equals(e.Value, value, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static bool PathsEqual(string a, string b)
    {
        try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
        catch { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }
    }

    // ------------------------------------------------------------------- load

    /// <summary>
    /// Reads the settings file. Never throws: a missing, unreadable, truncated or nonsense file
    /// yields defaults, and the defaults are written back on the next save.
    /// </summary>
    internal static HeroSettings Load()
    {
        var s = new HeroSettings();
        JsonObject? root = ReadDisk();
        if (root is null)
        {
            s._uiScaleAssigned = false;
            return s;
        }

        // Absent means LEGACY, not current. A settings file written before the key existed is by
        // definition older than the key, and defaulting it to CurrentSchemaVersion would quietly
        // mark every such file as up to date and skip the upgrade handling in NoteStart.
        s.SchemaVersion = GetInt(root, "schemaVersion", 1);
        s.Autonomy = GetEnum(root, "autonomy", AutonomyLevel.AutoHighConfidence);
        s._uiScale = Math.Clamp(GetDouble(root, "uiScale", DefaultUiScale), MinUiScale, MaxUiScale);
        s.RunAtStartup = GetBool(root, "runAtStartup", false);
        s.StartupMethod = GetEnum(root, "startupMethod", StartupMethod.RegistryRun);

        if (root["quietHours"] is JsonObject q)
        {
            s.QuietHours.Enabled = GetBool(q, "enabled", false);
            s.QuietHours.Start = GetTime(q, "start", TimeSpan.FromHours(22));
            s.QuietHours.End = GetTime(q, "end", TimeSpan.FromHours(8));
            s.QuietHours.SuppressPrompts = GetBool(q, "suppressPrompts", true);
            s.QuietHours.SuppressAutoAction = GetBool(q, "suppressAutoAction", false);
        }

        ReadAllowList(root, "allowedImages", s.AllowedImages);
        ReadAllowList(root, "allowedPublishers", s.AllowedPublishers);
        ReadAllowList(root, "allowedEndpoints", s.AllowedEndpoints);
        ReadAllowList(root, "allowedPersistence", s.AllowedPersistence);

        if (root["mutedRules"] is JsonObject mutes)
        {
            foreach (var kv in mutes)
            {
                if (string.IsNullOrWhiteSpace(kv.Key)) continue;
                // Tolerate both shapes: a bare boolean (hand-edited) and the full object.
                if (kv.Value is JsonValue bare && bare.TryGetValue<bool>(out var flag))
                {
                    if (flag) s.MutedRules[kv.Key] = new RuleMute();
                    continue;
                }
                if (kv.Value is not JsonObject mo) continue;
                s.MutedRules[kv.Key] = new RuleMute
                {
                    Muted = GetBool(mo, "muted", true),
                    UntilUtc = GetDateOrNull(mo, "untilUtc"),
                    Reason = GetString(mo, "reason", ""),
                };
            }
        }

        s.RequireHardIndicatorForAutoAction = GetBool(root, "requireHardIndicatorForAutoAction", true);
        // Clamped rather than trusted: a settings file claiming 100000 auto-actions an hour has
        // disabled the circuit breaker, which is the one control that bounds a bad rule.
        s.MaxAutoActionsPerHour = Math.Clamp(GetInt(root, "maxAutoActionsPerHour", 5), 0, 50);
        s.MaxAutoActionsPerSweep = Math.Clamp(GetInt(root, "maxAutoActionsPerSweep", 2), 0, 20);
        s.ObservationEndsUtc = GetDateOrNull(root, "observationEndsUtc");
        s.AutoActionDisabledUntilUtc = GetDateOrNull(root, "autoActionDisabledUntilUtc");
        s.FirstRunUtc = GetDateOrNull(root, "firstRunUtc") ?? DateTime.UtcNow;
        s.LastStartUtc = GetDateOrNull(root, "lastStartUtc");
        s.LastCleanExitUtc = GetDateOrNull(root, "lastCleanExitUtc");

        s._uiScaleAssigned = false;
        return s;
    }

    /// <summary>
    /// Called once at startup. Stamps the run, seeds the observation window on genuine first run,
    /// and latches the kill switch if the previous run died — a HERO that crashed is a HERO whose
    /// judgement has not yet been shown to be sound, so it observes for an hour before acting.
    /// </summary>
    internal void NoteStart(DateTime nowUtc)
    {
        bool firstRun = LastStartUtc is null;
        if (firstRun && ObservationEndsUtc is null)
            ObservationEndsUtc = nowUtc.AddHours(72);

        // Upgrading from a build where the guardian could not act. Its observation window ran, and
        // expired, while the gate downstream of it was wired shut — so the window was never the
        // thing holding HERO back and its expiry proves nothing about whether this machine is
        // understood. Start it again, once, rather than arming a guardian on the strength of a
        // period that cost it nothing to sit through.
        //
        // Deliberately unconditional on the old value: an install that is mid-window loses nothing
        // by restarting, and one whose window expired in April is exactly the case this exists for.
        if (SchemaVersion < 2)
        {
            ObservationEndsUtc = nowUtc.AddHours(72);
            SchemaVersion = CurrentSchemaVersion;
        }

        if (PreviousRunEndedAbnormally)
        {
            var pause = nowUtc.AddHours(1);
            if (AutoActionDisabledUntilUtc is null || AutoActionDisabledUntilUtc < pause)
                AutoActionDisabledUntilUtc = pause;
        }

        LastStartUtc = nowUtc;
        SaveSafe();
    }

    /// <summary>Called from App.OnExit so the next start can tell a clean exit from a crash.</summary>
    internal void NoteCleanExit(DateTime nowUtc)
    {
        LastCleanExitUtc = nowUtc;
        SaveSafe();
    }

    // ------------------------------------------------------------------- save

    /// <summary>Saves, swallowing any failure. Settings are not worth crashing a guardian over.</summary>
    internal void SaveSafe()
    {
        try { Save(); } catch { /* surfaced by the settings screen, never fatal */ }
    }

    /// <summary>
    /// Re-reads the file, overlays the keys HERO owns, and replaces it atomically. Foreign keys
    /// are preserved verbatim.
    /// </summary>
    internal void Save()
    {
        lock (Gate)
        {
            var root = ReadDisk() ?? new JsonObject();

            // The IN-MEMORY version, not the constant. Writing the constant here would mark the
            // file current on any save that happened before NoteStart got to look at it — and a
            // save before startup is not hypothetical, the UI writes uiScale on its own. The
            // upgrade marker has to survive until the code that handles the upgrade has run and
            // bumped it deliberately.
            root["schemaVersion"] = SchemaVersion;
            root["autonomy"] = Autonomy.ToString();
            root["runAtStartup"] = RunAtStartup;
            root["startupMethod"] = this.StartupMethod.ToString();

            // uiScale belongs to MainWindow unless this object was told otherwise. Adopting the
            // on-disk value here is what stops a settings save from undoing a Ctrl+= zoom.
            if (_uiScaleAssigned)
            {
                root["uiScale"] = _uiScale;
            }
            else
            {
                _uiScale = Math.Clamp(GetDouble(root, "uiScale", _uiScale), MinUiScale, MaxUiScale);
                root["uiScale"] = _uiScale;
            }
            _uiScaleAssigned = false;

            root["quietHours"] = new JsonObject
            {
                ["enabled"] = QuietHours.Enabled,
                ["start"] = FormatTime(QuietHours.Start),
                ["end"] = FormatTime(QuietHours.End),
                ["suppressPrompts"] = QuietHours.SuppressPrompts,
                ["suppressAutoAction"] = QuietHours.SuppressAutoAction,
            };

            root["allowedImages"] = WriteAllowList(AllowedImages);
            root["allowedPublishers"] = WriteAllowList(AllowedPublishers);
            root["allowedEndpoints"] = WriteAllowList(AllowedEndpoints);
            root["allowedPersistence"] = WriteAllowList(AllowedPersistence);

            var mutes = new JsonObject();
            foreach (var kv in MutedRules)
            {
                mutes[kv.Key] = new JsonObject
                {
                    ["muted"] = kv.Value.Muted,
                    ["untilUtc"] = Iso(kv.Value.UntilUtc),
                    ["reason"] = kv.Value.Reason,
                };
            }
            root["mutedRules"] = mutes;

            root["requireHardIndicatorForAutoAction"] = RequireHardIndicatorForAutoAction;
            root["maxAutoActionsPerHour"] = MaxAutoActionsPerHour;
            root["maxAutoActionsPerSweep"] = MaxAutoActionsPerSweep;
            root["observationEndsUtc"] = Iso(ObservationEndsUtc);
            root["autoActionDisabledUntilUtc"] = Iso(AutoActionDisabledUntilUtc);
            root["firstRunUtc"] = Iso(FirstRunUtc);
            root["lastStartUtc"] = Iso(LastStartUtc);
            root["lastCleanExitUtc"] = Iso(LastCleanExitUtc);

            WriteAtomic(root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    private static JsonObject? ReadDisk()
    {
        try
        {
            if (!File.Exists(HeroPaths.Settings)) return null;
            var text = File.ReadAllText(HeroPaths.Settings);
            if (string.IsNullOrWhiteSpace(text)) return null;
            return JsonNode.Parse(text) as JsonObject;
        }
        catch
        {
            // Corrupt, locked, or not JSON at all. Defaults win and the next save repairs it;
            // never let this path throw, because it runs before the UI exists to report it.
            return null;
        }
    }

    /// <summary>
    /// Temp file, flush, replace. A half-written settings file is the one thing guaranteed to
    /// fail to parse on the next start, so the window in which one can exist is closed here.
    /// </summary>
    private static void WriteAtomic(string json)
    {
        HeroPaths.EnsureCreated();
        var target = HeroPaths.Settings;
        var tmp = target + ".tmp";

        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var sw = new StreamWriter(fs))
        {
            sw.Write(json);
            sw.Flush();
            fs.Flush(flushToDisk: true);
        }

        if (File.Exists(target))
        {
            try
            {
                // File.Replace is the true atomic swap on NTFS. ignoreMetadataErrors keeps it
                // working when the destination has attributes the temp file does not.
                File.Replace(tmp, target, destinationBackupFileName: null, ignoreMetadataErrors: true);
                return;
            }
            catch (IOException)
            {
                // Falls through to Move, which is still a single MoveFileEx and better than
                // delete-then-write.
            }
            catch (UnauthorizedAccessException) { }
        }

        File.Move(tmp, target, overwrite: true);
    }

    // -------------------------------------------------------- tolerant readers

    private static bool GetBool(JsonObject o, string name, bool fallback)
    {
        try { if (o[name] is JsonValue v && v.TryGetValue<bool>(out var b)) return b; } catch { }
        return fallback;
    }

    private static int GetInt(JsonObject o, string name, int fallback)
    {
        try { if (o[name] is JsonValue v && v.TryGetValue<int>(out var i)) return i; } catch { }
        return fallback;
    }

    private static double GetDouble(JsonObject o, string name, double fallback)
    {
        try { if (o[name] is JsonValue v && v.TryGetValue<double>(out var d) && double.IsFinite(d)) return d; } catch { }
        return fallback;
    }

    private static string GetString(JsonObject o, string name, string fallback)
    {
        try { if (o[name] is JsonValue v && v.TryGetValue<string>(out var s) && s is not null) return s; } catch { }
        return fallback;
    }

    /// <summary>Enums are stored as names so the file stays hand-editable. Unknown names fall back.</summary>
    private static TEnum GetEnum<TEnum>(JsonObject o, string name, TEnum fallback) where TEnum : struct, Enum
    {
        var raw = GetString(o, name, "");
        return raw.Length > 0 && Enum.TryParse<TEnum>(raw, ignoreCase: true, out var parsed) && Enum.IsDefined(parsed)
            ? parsed
            : fallback;
    }

    private static TimeSpan GetTime(JsonObject o, string name, TimeSpan fallback)
    {
        var raw = GetString(o, name, "");
        if (raw.Length > 0 && TimeSpan.TryParse(raw, CultureInfo.InvariantCulture, out var t)
            && t >= TimeSpan.Zero && t < TimeSpan.FromDays(1))
            return t;
        return fallback;
    }

    /// <summary>
    /// Parses a stored timestamp back to UTC.
    ///
    /// The styles are <c>AssumeUniversal | AdjustToUniversal</c>, NOT <c>RoundtripKind</c>:
    /// DateTime.TryParse validates its styles argument and throws ArgumentException for
    /// RoundtripKind combined with AssumeLocal, AssumeUniversal or AdjustToUniversal — it is not a
    /// parse failure that returns false, it is a throw, and it fires for every date key in the
    /// file. AssumeUniversal covers a hand-edited value with no zone; an explicit offset or a
    /// trailing Z is honoured and converted, so every path here yields Kind=Utc.
    /// </summary>
    private static DateTime? GetDateOrNull(JsonObject o, string name)
    {
        var raw = GetString(o, name, "");
        if (raw.Length == 0) return null;
        try
        {
            return DateTime.TryParse(raw, CultureInfo.InvariantCulture,
                       DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)
                ? DateTime.SpecifyKind(d, DateTimeKind.Utc)
                : null;
        }
        catch
        {
            // Belt and braces. Load() promises never to throw, and it runs before there is any UI
            // to report a failure through.
            return null;
        }
    }

    private static void ReadAllowList(JsonObject root, string name, List<AllowEntry> into)
    {
        if (root[name] is not JsonArray arr) return;
        foreach (var node in arr)
        {
            try
            {
                // A bare string is accepted so a user can hand-add a path without ceremony.
                if (node is JsonValue sv && sv.TryGetValue<string>(out var plain) && !string.IsNullOrWhiteSpace(plain))
                {
                    into.Add(new AllowEntry { Value = plain, Reason = "added by hand" });
                    continue;
                }
                if (node is not JsonObject o) continue;
                var value = GetString(o, "value", "");
                if (string.IsNullOrWhiteSpace(value)) continue;
                into.Add(new AllowEntry
                {
                    Value = value,
                    Reason = GetString(o, "reason", ""),
                    Sha256 = GetString(o, "sha256", "") is { Length: > 0 } h ? h : null,
                    AddedUtc = GetDateOrNull(o, "addedUtc") ?? DateTime.UtcNow,
                    ExpiresUtc = GetDateOrNull(o, "expiresUtc"),
                });
            }
            catch { /* one bad entry must not discard the rest of the allowlist */ }
        }
    }

    private static JsonArray WriteAllowList(List<AllowEntry> list)
    {
        var arr = new JsonArray();
        foreach (var e in list)
        {
            arr.Add(new JsonObject
            {
                ["value"] = e.Value,
                ["reason"] = e.Reason,
                ["sha256"] = e.Sha256,
                ["addedUtc"] = Iso(e.AddedUtc),
                ["expiresUtc"] = Iso(e.ExpiresUtc),
            });
        }
        return arr;
    }

    private static string FormatTime(TimeSpan t) =>
        t.ToString(@"hh\:mm", CultureInfo.InvariantCulture);

    private static JsonNode? Iso(DateTime? d) =>
        d is { } v ? JsonValue.Create(v.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)) : null;
}
