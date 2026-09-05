using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Hero.Core;

namespace Hero.Guardian;

/// <summary>
/// What happened after each finding: the user approved it, acted on it, or waved it away.
///
/// This is HERO's memory of its own track record, and the thing that lets it grow into the machine
/// it lives on. It has two jobs, and they are deliberately separate:
///
///   RECORD — every response, attributed to every rule that accused the subject. Worth shipping on
///   its own, because before it a response vanished: a dismissal set a timer, an approval wrote an
///   allowlist entry, and neither left any trace of which RULE had been right or wrong. So HERO
///   could not answer "how often is this check correct here" — the question a person actually wants
///   answered about a security tool that keeps interrupting them.
///
///   INFLUENCE — a per-rule multiplier, derived by replaying the record. See
///   <see cref="InfluenceFor"/> for what earns it and what bounds it.
///
/// AN ADVERSARIAL REVIEW TOOK THE FIRST VERSION APART, and the three findings are recorded here
/// because the current design is shaped entirely by them:
///
///   * The only gesture that could earn a credit was one the product refuses to perform. The
///     dashboard runs unelevated by design; "This is expected" sends AllowScope.Hash, which
///     GuardianCommands refuses without an elevated caller, and the UI then steered the user to
///     "Hide for a week" — a dismissal, worth nothing. The feature would have shipped inert on the
///     only configuration it ships in. FIXED UPSTREAM: the Threats page now offers "HERO is wrong
///     about this" per signal, sending AllowScope.RuleForEntity with the rule id, which is
///     reachable unelevated — and that gesture is now the only thing that earns influence.
///   * A per-rule multiplier applied after the family winner is chosen inverts the score: soften
///     the winner of a family and a file can score LOWER than if that rule had not fired at all,
///     because the softened winner still suppresses its stronger siblings. FIXED IN Scorer: the
///     family representative is chosen on EFFECTIVE weight, so a softened rule stops suppressing
///     a sibling it no longer outweighs.
///   * Rules are pure functions of attributes an attacker controls, so a decoy can be built whose
///     accusing set is a superset of a payload's. Crediting every accusing rule per approval means
///     the cost of softening a whole rule set is one gesture, not one per rule. NOT dissolved by
///     RuleForEntity naming one rule, which is what the first build of this assumed. Record writes
///     a line per accusing SIGNAL, so one approval leaves a crediting line for every rule in the
///     verdict; Corrections() therefore credits an entry only when its rule id matches the one the
///     detail names. Caught by making a real correction on a real finding, not by review.
///
/// WHAT IS DELIBERATELY NOT RECORDED. Only outcomes that resolved a LIVE verdict get a line. A
/// dismissal naming a subject HERO holds no finding for writes nothing at all — dismiss and
/// undismiss are reachable over the IPC pipe without elevation, and an append-per-call on an
/// unauthenticated command is a disk-filling primitive rather than a feature.
/// </summary>
internal static class OutcomeStore
{
    /// <summary>Kinds of response. Strings on disk so an older build reading a newer file degrades.</summary>
    internal const string KindAllow = "allow";
    internal const string KindAct = "act";
    internal const string KindDismiss = "dismiss";
    internal const string KindUndismiss = "undismiss";

    /// <summary>
    /// The user asking HERO to forget what it has concluded.
    ///
    /// A line rather than a deletion, and that is the point: the record of what actually happened is
    /// evidence, and a security tool that erases its own history on request has a feature an attacker
    /// wants. A reset instead draws a line under the record — <see cref="BuildInfluence"/> ignores
    /// everything at or before the newest one — so the conclusions go and the history stays.
    /// </summary>
    internal const string KindReset = "reset";

    /// <summary>
    /// Cap and rotate, the same discipline ServiceLog uses. "Append for ever" on a file any
    /// interactive process can cause writes to is how a security tool fills the disk it protects.
    /// </summary>
    private const long MaxBytes = 4 * 1024 * 1024;

    private static readonly object Gate = new();

    private static string LedgerPath => Path.Combine(HeroPaths.EventsDir, "outcomes.jsonl");
    private static string PreviousPath => Path.Combine(HeroPaths.EventsDir, "outcomes.1.jsonl");

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
    };

    /// <summary>One user response to one finding, attributed to one rule.</summary>
    internal sealed class Entry
    {
        [JsonPropertyName("t")] public string Utc { get; set; } = "";
        [JsonPropertyName("k")] public string Kind { get; set; } = "";
        [JsonPropertyName("r")] public string RuleId { get; set; } = "";
        [JsonPropertyName("s")] public string SubjectKey { get; set; } = "";

        /// <summary>
        /// Stable identity of the PROGRAM, as distinct from the finding.
        ///
        /// The subject key is not usable for this: a process subject is
        /// <c>proc:&lt;pid&gt;:&lt;start ticks&gt;</c>, which is different every time the same
        /// program runs. Counting distinct programs — the thing that makes "you have told me this
        /// five times about five different things" mean anything — needs an identity that survives
        /// a restart.
        /// </summary>
        [JsonPropertyName("ek")] public string EntityKey { get; set; } = "";

        /// <summary>Verdict score at the moment of the response, so a later reader can weight it.</summary>
        [JsonPropertyName("sc")] public double Score { get; set; }
        [JsonPropertyName("cf")] public string Confidence { get; set; } = "";

        /// <summary>Nominal weight of this rule's signal in the verdict being responded to.</summary>
        [JsonPropertyName("w")] public double Weight { get; set; }
        [JsonPropertyName("f")] public string Family { get; set; } = "";

        /// <summary>Whether the caller proved an elevated administrator token.</summary>
        [JsonPropertyName("e")] public bool Elevated { get; set; }

        /// <summary>
        /// Whether the state root was actually closed to the signed-in user when this was written.
        ///
        /// Stamped rather than assumed. LockDownStateDirectory runs from the installer, so on a
        /// machine where HERO was never installed the root inherits %ProgramData%'s ACL and any
        /// unelevated process can write these files. A line that does not carry this is a line no
        /// future consumer may trust, and finding that out later would be worse than recording it
        /// now.
        /// </summary>
        [JsonPropertyName("p")] public bool Protected { get; set; }

        /// <summary>Free text: the action taken, the allow scope, the granted dismissal length.</summary>
        [JsonPropertyName("d")] public string Detail { get; set; } = "";
    }

    /// <summary>What HERO has seen happen to one rule. Derived by replay; never authoritative on disk.</summary>
    internal sealed record RuleTally(string RuleId, int Allows, int Acts, int Dismisses, int Undismisses)
    {
        internal int Total => Allows + Acts + Dismisses + Undismisses;

        /// <summary>
        /// How often a firing of this rule was met with the user doing something about it, rather
        /// than waving it away. Null until there is enough to say anything.
        ///
        /// Not a score and not consumed by anything — a reader for a person. Ten samples is not
        /// statistics, but it is the point below which a percentage is actively misleading.
        /// </summary>
        internal double? ActedFraction => Total >= 10 ? (double)Acts / Total : null;
    }

    // ------------------------------------------------------------------ recording

    /// <summary>
    /// Records one response, one line per rule that accused the subject.
    ///
    /// <paramref name="verdict"/> is required, not optional, and that is the DoS defence: a caller
    /// can only cause a write by naming something HERO independently decided was worth raising.
    /// </summary>
    internal static void Record(string kind, Verdict verdict, bool elevated, string detail = "")
    {
        if (verdict.Signals.Count == 0) return;

        bool protectedRoot;
        try { protectedRoot = !CanUserWriteRoot(); }
        catch { protectedRoot = false; }

        string now = DateTime.UtcNow.ToString("O");

        string entityKey = "";
        try
        {
            if (Baseline.PathOf(verdict.Subject) is { Length: > 0 } path)
                entityKey = PathModel.KeyFor(path);
        }
        catch { }

        var lines = new List<string>(verdict.Signals.Count);
        foreach (var signal in verdict.Signals)
        {
            if (string.IsNullOrEmpty(signal.RuleId)) continue;

            lines.Add(JsonSerializer.Serialize(new Entry
            {
                Utc = now,
                Kind = kind,
                RuleId = signal.RuleId,
                SubjectKey = verdict.Subject.Key,
                EntityKey = entityKey,
                Score = Math.Round(verdict.Score, 2),
                Confidence = verdict.Confidence.ToString(),
                Weight = signal.Weight,
                Family = signal.Family,
                Elevated = elevated,
                Protected = protectedRoot,
                Detail = detail,
            }, Json));
        }

        if (lines.Count == 0) return;

        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(HeroPaths.EventsDir);
                Rotate();
                File.AppendAllLines(LedgerPath, lines, Encoding.UTF8);
                _influence = null;      // the record changed; the conclusions drawn from it must be re-derived
            }
        }
        catch { /* a record of what happened must never break the thing that happened */ }
    }

    /// <summary>
    /// Every entry, oldest first, across the rotated file and the current one.
    ///
    /// A torn final line is ordinary — the process can be killed mid-append — and is skipped rather
    /// than treated as corruption, which is why each line is its own document.
    /// </summary>
    /// <summary>
    /// Rewrites entity keys in both ledger files after a baseline re-key. Returns how many records
    /// were changed.
    ///
    /// These records are the user's own corrections — "you were wrong about this" — and they are
    /// keyed by the same entity key the baseline mints. When that key changes, an untouched ledger
    /// keeps every correction and applies none of them: <see cref="InfluenceFor"/> counts distinct
    /// programs per rule, and a correction filed under a key nothing resolves to counts toward
    /// nothing. The user would have to tell HERO the same thing again.
    ///
    /// Rewritten through JsonNode rather than the Entry record so that any field a newer build
    /// added survives the round trip. Parsing into Entry and re-serialising would silently drop
    /// them, which is the same class of data loss this method exists to prevent.
    ///
    /// Written to a temp file and moved into place, per file, so an interrupted migration leaves
    /// the original ledger intact rather than half-rewritten.
    /// </summary>
    internal static int RemapEntityKeys(IReadOnlyDictionary<string, string> map)
    {
        if (map.Count == 0) return 0;

        int changed = 0;
        lock (Gate)
        {
            foreach (var path in new[] { PreviousPath, LedgerPath })
            {
                if (!File.Exists(path)) continue;

                var rewritten = new List<string>(256);
                bool touched = false;

                try
                {
                    foreach (var line in File.ReadLines(path))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;

                        JsonNode? node;
                        // A torn final line is ordinary here — the process can be killed
                        // mid-append — and is carried through unchanged rather than dropped.
                        try { node = JsonNode.Parse(line); }
                        catch { rewritten.Add(line); continue; }

                        if (node is JsonObject obj
                            && obj["ek"]?.GetValue<string>() is { Length: > 0 } key
                            && map.TryGetValue(key, out var replacement))
                        {
                            obj["ek"] = replacement;
                            rewritten.Add(obj.ToJsonString(Json));
                            touched = true;
                            changed++;
                        }
                        else rewritten.Add(line);
                    }

                    if (!touched) continue;

                    string temp = path + ".migrating";
                    File.WriteAllLines(temp, rewritten, Encoding.UTF8);
                    File.Move(temp, path, overwrite: true);
                }
                catch
                {
                    // The ledger is evidence, not state. A failed rewrite leaves it exactly as it
                    // was, which costs the user's corrections their influence but loses nothing.
                    try { File.Delete(path + ".migrating"); } catch { }
                }
            }

            _influence = null;      // conclusions drawn from the old keys no longer hold
        }

        return changed;
    }

    private static IEnumerable<Entry> ReadAll()
    {
        foreach (var path in new[] { PreviousPath, LedgerPath })
        {
            if (!File.Exists(path)) continue;

            IEnumerable<string> lines;
            try { lines = File.ReadLines(path); }
            catch { continue; }

            foreach (var line in lines)
            {
                if (line.Length == 0) continue;

                Entry? entry = null;
                try { entry = JsonSerializer.Deserialize<Entry>(line, Json); }
                catch { }

                if (entry is not null) yield return entry;
            }
        }
    }

    private static void Rotate()
    {
        try
        {
            var info = new FileInfo(LedgerPath);
            if (!info.Exists || info.Length < MaxBytes) return;

            if (File.Exists(PreviousPath)) File.Delete(PreviousPath);
            File.Move(LedgerPath, PreviousPath);
        }
        catch { }
    }

    /// <summary>
    /// True when the signed-in user can still write the state root, i.e. the lockdown has not run.
    ///
    /// Asks the filesystem rather than inferring from whether the service is installed: the whole
    /// point of the stamp is to be a fact about the file, not an assumption about the deployment.
    /// Cached because the answer cannot change without an elevated action, and this is on the path
    /// of a button press.
    /// </summary>
    private static bool? _userWritable;

    private static bool CanUserWriteRoot()
    {
        if (_userWritable is { } cached) return cached;

        bool writable = false;
        try
        {
            var acl = new DirectoryInfo(HeroPaths.Root).GetAccessControl(
                System.Security.AccessControl.AccessControlSections.Access);

            foreach (System.Security.AccessControl.FileSystemAccessRule rule in
                     acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
            {
                if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                if (rule.IdentityReference is not System.Security.Principal.SecurityIdentifier sid) continue;
                if (!sid.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinUsersSid)) continue;

                const System.Security.AccessControl.FileSystemRights Write =
                    System.Security.AccessControl.FileSystemRights.WriteData |
                    System.Security.AccessControl.FileSystemRights.AppendData |
                    System.Security.AccessControl.FileSystemRights.Delete;

                if ((rule.FileSystemRights & Write) != 0) { writable = true; break; }
            }
        }
        catch { writable = true; }        // cannot tell, so do not claim protection

        _userWritable = writable;
        return writable;
    }

    // ------------------------------------------------------------------ influence

    /// <summary>Distinct programs a rule must be called wrong about before it is softened at all.</summary>
    private const int MinPrograms = 3;

    /// <summary>How much each program beyond the threshold takes off. Small on purpose.</summary>
    private const double StepPerProgram = 0.05;

    /// <summary>
    /// The most a rule can ever be softened. A rule at the floor still contributes four fifths of
    /// its weight — this tunes HERO's noise, it does not switch checks off.
    /// </summary>
    private const double Floor = 0.80;

    /// <summary>Evidence loses half its force every this many days.</summary>
    private const double HalfLifeDays = 60;

    /// <summary>One rule HERO has decided to count for less here, and the evidence behind it.</summary>
    internal sealed record Softening(string RuleId, double Influence, int Programs);

    private static Dictionary<string, Softening>? _influence;

    /// <summary>
    /// How much of its nominal weight a rule keeps on THIS machine, in [0.80, 1.00].
    ///
    /// Earned only by <see cref="AllowScope.RuleForEntity"/> approvals — the user saying "this
    /// check is wrong about this program" — counted once per distinct program and decayed. Nothing
    /// else moves it: dismissals, acts and blanket approvals are recorded and shown, and are worth
    /// nothing here.
    ///
    /// WHY THAT GESTURE AND NOTHING ELSE. It is the only correction that names a rule, so it is the
    /// only one whose meaning is "this check is wrong" rather than "this program is fine" or "not
    /// now". Crediting a dismissal would credit impatience; crediting a blanket approval would let
    /// one click about one file quieten a rule everywhere.
    ///
    /// WHAT KEEPS THIS FROM BEING AN ATTACK SURFACE. The gesture is reachable without elevation, so
    /// an attacker CAN make it — the defences are therefore in what it can achieve, not in who may
    /// perform it:
    ///
    ///   * Decisive signals are exempt, applied by the caller. HERO acts autonomously only on a
    ///     decisive signal, so no amount of this can stop it acting on a hard indicator. That is
    ///     the property that makes the rest of it safe to have.
    ///   * The floor is 0.80. A softened rule still counts for four fifths.
    ///   * Three distinct PROGRAMS are needed before anything moves, and each program counts once
    ///     however many times it is approved — so repeating one gesture achieves nothing.
    ///   * It decays. Evidence is worth half after sixty days, so softening has to be maintained.
    ///   * It is ignored entirely unless the state directory is actually closed to the user. On a
    ///     machine where HERO was never installed, %ProgramData%\HERO inherits an ACL that lets any
    ///     unelevated process author this file directly, and a number read from a file the
    ///     adversary can write is not evidence of anything.
    ///
    /// Cached because Scorer calls this per signal per verdict; invalidated whenever a line is
    /// recorded.
    /// </summary>
    internal static double InfluenceFor(string ruleId)
    {
        if (string.IsNullOrEmpty(ruleId)) return 1.0;

        // The whole table is worthless if the file is not out of reach.
        try { if (CanUserWriteRoot()) return 1.0; }
        catch { return 1.0; }

        return Table().TryGetValue(ruleId, out var s) ? s.Influence : 1.0;
    }

    /// <summary>
    /// Every rule HERO currently counts for less on this machine, strongest softening first.
    ///
    /// Empty when the state root is writable by the user, for the same reason
    /// <see cref="InfluenceFor"/> returns 1.0 there: showing a person conclusions HERO is not
    /// actually applying would be a lie told by the UI rather than a reassurance.
    /// </summary>
    internal static IReadOnlyList<Softening> Softened()
    {
        try { if (CanUserWriteRoot()) return Array.Empty<Softening>(); }
        catch { return Array.Empty<Softening>(); }

        return Table().Values.OrderBy(s => s.Influence).ThenBy(s => s.RuleId, StringComparer.Ordinal).ToList();
    }

    /// <summary>True when the ledger is out of the signed-in user's reach, so it can be trusted.</summary>
    internal static bool LedgerIsSealed
    {
        get { try { return !CanUserWriteRoot(); } catch { return false; } }
    }

    private static Dictionary<string, Softening> Table()
    {
        var table = _influence;
        if (table is null)
        {
            table = BuildInfluence();
            _influence = table;
        }
        return table;
    }

    private static Dictionary<string, Softening> BuildInfluence()
    {
        var byRule = Corrections();
        var result = new Dictionary<string, Softening>(StringComparer.Ordinal);
        var now = DateTime.UtcNow;
        foreach (var (rule, entities) in byRule)
        {
            double credits = 0;
            foreach (var when in entities.Values)
            {
                double days = Math.Max(0, (now - when).TotalDays);
                credits += Math.Pow(0.5, days / HalfLifeDays);
            }

            // The THRESHOLD is a plain count of distinct programs; the MAGNITUDE is the decayed sum.
            // Splitting them is not a nicety. Gating on the decayed sum instead would mean three
            // corrections made this morning total 3 - 1e-7 credits — fractionally short of three —
            // and soften nothing at all, so the feature would appear not to work on the exact case
            // it is specified for. Decay still does its job through the magnitude: three corrections
            // a half-life old are worth 1.5 credits, which clamps straight back to 1.00.
            if (entities.Count < MinPrograms) continue;

            double influence = Math.Clamp(1.0 - StepPerProgram * (credits - (MinPrograms - 1)), Floor, 1.0);

            // A rule whose evidence has decayed back to full weight is not a softening, and listing
            // it as "counts x1.00" would tell the user HERO had learned something when it has not.
            if (influence >= 1.0) continue;

            result[rule] = new Softening(rule, influence, entities.Count);
        }

        return result;
    }

    /// <summary>
    /// The corrections that still stand: rule to program to the date it was last corrected.
    ///
    /// Shared by the influence table and the reset, because "is there anything to forget" and
    /// "what have I concluded" must be answers to the same question. A reset draws a line under
    /// everything before it — entries are appended in order, so clearing what has been gathered so
    /// far is the whole implementation.
    /// </summary>
    /// <summary>How <see cref="GuardianService.Allow"/> stamps a scoped correction: "<c>scope:ruleId</c>".</summary>
    private const string RuleForEntityPrefix = nameof(AllowScope.RuleForEntity) + ":";

    private static Dictionary<string, Dictionary<string, DateTime>> Corrections()
    {
        var byRule = new Dictionary<string, Dictionary<string, DateTime>>(StringComparer.Ordinal);

        foreach (var entry in ReadAll())
        {
            if (!DateTime.TryParse(entry.Utc, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var when)) continue;

            if (entry.Kind == KindReset) { byRule.Clear(); continue; }

            if (entry.Kind != KindAllow) continue;
            if (!entry.Protected) continue;                     // written while the root was open
            if (entry.RuleId.Length == 0) continue;
            if (entry.EntityKey.Length == 0) continue;

            // Only the scoped correction counts, AND only for the rule it actually named.
            //
            // The second half is not belt-and-braces. Record writes one line per accusing signal —
            // correct for the tallies, since what else was firing is genuine context — so a single
            // RuleForEntity approval leaves a line for EVERY rule in the verdict, each stamped with
            // the same detail. Crediting all of them would be section 31's fourth objection alive
            // and well: one gesture softening a whole rule set, at a cost of one click rather than
            // one per rule.
            //
            // Found by exercising the feature on a real finding rather than by reading the code.
            // Correcting `evade.service-installed` on a Google Play Games service wrote a crediting
            // line for `persist.unquoted-service-path` too — a rule the user had said nothing about.
            if (entry.Detail != RuleForEntityPrefix + entry.RuleId) continue;

            if (!byRule.TryGetValue(entry.RuleId, out var entities))
                byRule[entry.RuleId] = entities = new Dictionary<string, DateTime>(StringComparer.Ordinal);

            // Most recent wins: a program approved twice is still one program, dated by the last
            // time the user said so.
            if (!entities.TryGetValue(entry.EntityKey, out var existing) || when > existing)
                entities[entry.EntityKey] = when;
        }

        return byRule;
    }

    /// <summary>
    /// Forgets everything HERO has concluded from outcomes, without erasing what happened.
    ///
    /// Ungated, and that is a considered decision rather than an oversight: a reset only ever makes
    /// HERO stricter, so the usual question — what does this let an attacker achieve — has the
    /// answer "nothing they could not achieve by leaving it alone". What it could still be is a way
    /// to make HERO append to a file on demand, so a reset with nothing to forget writes nothing —
    /// which also stops the button reporting that it forgot something when it did not.
    /// </summary>
    /// <returns>True when a line was written, i.e. there was something to forget.</returns>
    internal static bool ResetInfluence()
    {
        try
        {
            lock (Gate)
            {
                if (Corrections().Count == 0) return false;

                Directory.CreateDirectory(HeroPaths.EventsDir);
                Rotate();
                File.AppendAllLines(LedgerPath, new[]
                {
                    JsonSerializer.Serialize(new Entry
                    {
                        Utc = DateTime.UtcNow.ToString("O"),
                        Kind = KindReset,
                        Detail = "user",
                    }, Json),
                }, Encoding.UTF8);

                _influence = null;
                return true;
            }
        }
        catch { return false; }
    }

    // ------------------------------------------------------------------ reading

    /// <summary>
    /// Replays the ledger into per-rule tallies.
    ///
    /// Rebuilt on demand rather than cached on disk. The file is small, this is read by a person
    /// opening a page rather than by the hot path, and a derived value that lives only in memory
    /// cannot drift from the record it claims to summarise.
    /// </summary>
    internal static IReadOnlyList<RuleTally> Tallies()
    {
        var allows = new Dictionary<string, int>(StringComparer.Ordinal);
        var acts = new Dictionary<string, int>(StringComparer.Ordinal);
        var dismisses = new Dictionary<string, int>(StringComparer.Ordinal);
        var undismisses = new Dictionary<string, int>(StringComparer.Ordinal);

        void Bump(Dictionary<string, int> into, string rule)
            => into[rule] = into.TryGetValue(rule, out int n) ? n + 1 : 1;

        foreach (var entry in ReadAll())
        {
            if (entry.RuleId.Length == 0) continue;

            switch (entry.Kind)
            {
                case KindAllow: Bump(allows, entry.RuleId); break;
                case KindAct: Bump(acts, entry.RuleId); break;
                case KindDismiss: Bump(dismisses, entry.RuleId); break;
                case KindUndismiss: Bump(undismisses, entry.RuleId); break;
            }
        }

        var rules = new HashSet<string>(StringComparer.Ordinal);
        foreach (var d in new[] { allows, acts, dismisses, undismisses })
            foreach (var key in d.Keys) rules.Add(key);

        int Get(Dictionary<string, int> d, string r) => d.TryGetValue(r, out int n) ? n : 0;

        return rules
            .Select(r => new RuleTally(r, Get(allows, r), Get(acts, r), Get(dismisses, r), Get(undismisses, r)))
            .OrderByDescending(t => t.Total)
            .ToList();
    }
}
