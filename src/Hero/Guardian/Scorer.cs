using Hero.Interop;

namespace Hero.Guardian;

/// <summary>
/// Every constant the scoring model uses, in one place.
///
/// They live together because they are a MODEL, not scattered magic numbers: the baseline stores
/// raw observations and never a score, so retuning any of these is a code change with no data
/// migration and nothing to re-learn. Bump <see cref="Baseline.CurrentEpoch"/> when they change
/// so cached derived state is recomputed.
///
/// THE ARITHMETIC, in full:
///
///   context terms (each 0..1 except Cs, which reaches 1.35 for a broken signature)
///     R   = rarity from the baseline                          weight 3.0
///     Cs  = 1 - signerTrust                                   weight 3.5
///     Cp  = 1 - pathTrust                                     weight 3.0
///     Cp' = Cp * (1 - 0.4 * R * Cp)                           decorrelation, see below
///     B   = behavioural deviation, noisy-OR combined          weight 4.0
///     S_ctx = 3.0*R + 3.5*Cs + 3.0*Cp' + 4.0*B                max 14.725
///
///   rule terms
///     one signal per family (the strongest), attenuated by the signer:
///     a = signerBlind ? 1.0 : 1 - 0.25 * max(0, Sg)
///     S_rules = SUM over families of weight * a
///
///   the precision gate
///     cap   = min(9.9, 3.5 + 1.6 * S_rules)
///     S     = min(S_ctx, cap) + S_rules + exonerations
///
/// Why the cap is graded rather than a simple "if no rules fired, cap context at 9.9": that form
/// is a cliff. The instant any single rule fires — including the weakest one in any plausible
/// catalogue — the ceiling jumps from 9.9 to the full 14.725, so one 3.5-point rule plus maximum
/// context produces an 18-point HIGH. Graded, the same case lands at 3.5 + min(14.725, 9.1) =
/// 12.6, which is a prompt, not an autonomous action. Worked ceilings:
///     S_rules = 0.0  ->  cap 3.50  ->  S &lt;=  3.50   pure statistics are INFORMATIONAL, full stop
///     S_rules = 3.5  ->  cap 9.10  ->  S &lt;= 12.60   one weak rule can never reach HIGH
///     S_rules = 5.0  ->  cap 9.90  ->  S &lt;= 14.90   one persistence rule can never reach HIGH
///     S_rules = 9.5  ->  cap 9.90  ->  S &lt;= 19.40   one dominant rule CAN, but see the family gate
///
/// Why Cp' is written that way: the obvious decorrelation ("if both R and Cp are high, multiply
/// Cp by 0.6") is non-monotone and inverts the path signal — a binary in %TEMP% (Cp=0.90) would
/// score 0.48 points LOWER than the same binary in %APPDATA% (Cp=0.70), because only the former
/// trips the discount. Cp * (1 - 0.4*R*Cp) has derivative 1 - 0.8*R*Cp >= 0.2 &gt; 0, so it is
/// strictly increasing in Cp for every R: a less trustworthy location always scores higher.
/// </summary>
internal static class ScorerModel
{
    internal const double WeightRarity = 3.0;
    internal const double WeightSigner = 3.5;
    internal const double WeightPath = 3.0;
    internal const double WeightBehaviour = 4.0;

    /// <summary>Absolute ceiling on context. Statistics alone must never reach an actionable tier.</summary>
    internal const double ContextCeiling = 9.9;
    internal const double ContextBase = 3.5;
    internal const double ContextPerRulePoint = 1.6;

    /// <summary>Rule points are attenuated by at most 25% for a fully trusted signer. Never more:
    /// every LOLBin on this machine is Microsoft-signed, and more attenuation is a blind spot.</summary>
    internal const double SignerAttenuation = 0.25;

    /// <summary>Exonerating (negative-weight) signals cannot erase an accusation outright.</summary>
    internal const double MaxExoneration = 6.0;

    /// <summary>
    /// Converts the rule catalogue's weight scale into the scale this model is calibrated for.
    ///
    /// The two were written against different assumptions and did not match. The rules emit
    /// 0..28 (RuleKit.MaxSingleSignalWeight = 28); this model's own worked examples assume rule
    /// totals of roughly 3.5 / 5.0 / 9.5, and its bands are Low 4, Medium 10, High 15,
    /// Critical 22. Two concrete consequences of leaving them mismatched:
    ///
    ///   * The precision gate is cap = min(9.9, 3.5 + 1.6 * ruleScore). An unscaled weight of
    ///     just 4 drives the cap straight to its 9.9 ceiling, so a signal an author deliberately
    ///     damped to "record this, do not alarm" totalled up to 13.9 and landed in Medium, which
    ///     Detection.cs defines as "raises a prompt". Only weight 0 was actually quiet.
    ///   * A single unscaled 28-point signal exceeded CriticalScore on its own, which made the
    ///     rule that no individual signal can outvote the corroboration gates untrue.
    ///
    /// Scaling here rather than editing thirteen rule classes keeps every relative weighting the
    /// authors chose, and puts the arithmetic back where the model documents it. Worked results:
    ///   weight  3 (unquoted service path) -> 1.00 + cap 5.10 -> max  6.10  Low
    ///   weight  4 (damped "just noting")  -> 1.33 + cap 5.63 -> max  6.96  Low
    ///   weight 18 (persistence in %TEMP%) -> 6.00 + cap 9.90 -> max 15.90  High
    ///   weight 28 (exact masquerade)      -> 9.33 + cap 9.90 -> max 19.23  High, below Critical
    /// </summary>
    internal const double RuleWeightScale = 1.0 / 3.0;

    /// <summary>
    /// Minimum SCALED rule weight before a signal may count as decisive.
    ///
    /// Severity and weight are set independently by the rules, and several damp the weight while
    /// leaving Severity.High in place. Without this floor, a signal reduced to "worth noting"
    /// still satisfied the decisive gate purely on its severity label and could authorise
    /// autonomous action on its own.
    /// </summary>
    internal const double DecisiveMinimumWeight = 3.0;

    internal const double LowScore = 4.0;
    internal const double MediumScore = 10.0;
    internal const double HighScore = 15.0;
    internal const double CriticalScore = 22.0;

    /// <summary>Distinct corroborating families required for High. Never fewer than three.</summary>
    internal const int FamiliesForHigh = 3;
    internal const double ConfidenceForHigh = 0.80;

    // Behaviour channel weights for the noisy-OR combination. Noisy-OR is the anti-double-counting
    // device: six correlated network observations saturate toward 1.0 instead of summing to 6.
    internal const double KappaParent = 0.70;
    internal const double KappaParentShell = 0.15;   // shells and build tools: unbounded by nature
    internal const double KappaPeer = 0.55;
    internal const double KappaPort = 0.45;
    internal const double KappaHour = 0.30;
    internal const double KappaThreads = 0.35;

    /// <summary>A channel with less than this much history cannot be surprised by anything.</summary>
    internal const double MinCategoryHistory = 10;

    internal const double ZOffset = 3.0;
    internal const double ZOffsetWatching = 1.5;   // halved thresholds after a risky update
    internal const double ZSpan = 5.0;

    /// <summary>
    /// Families whose signals are never attenuated by signer trust and which alone can make a
    /// verdict decisive. A signal marked Severity.High or above qualifies regardless of its
    /// family name, so a rule author gets this by saying how bad the finding is rather than by
    /// matching a string.
    /// </summary>
    internal static readonly HashSet<string> DecisiveFamilies = new(StringComparer.OrdinalIgnoreCase)
    {
        "credential", "credentials", "injection", "evasion", "tamper", "ransom", "exfiltration",
    };

    /// <summary>
    /// Processes whose parent set churns endlessly on a developer machine. Their parent channel
    /// is down-weighted rather than removed, because "python.exe was started by something new" is
    /// a permanent low-grade hum here, not evidence.
    /// </summary>
    internal static readonly HashSet<string> ShellsAndBuildTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe", "wsl.exe",
        "dotnet.exe", "msbuild.exe", "node.exe", "npm.exe", "npx.exe", "python.exe", "pythonw.exe",
        "uv.exe", "uvx.exe", "cargo.exe", "rustc.exe", "go.exe", "java.exe", "ninja.exe", "cmake.exe",
        "conhost.exe", "windowsterminal.exe", "code.exe", "cursor.exe",
    };

    /// <summary>
    /// Build drivers, for the developer-build suppressor. Deliberately compilers and build
    /// systems only — adding cmd.exe or powershell.exe would turn the suppressor into a universal
    /// bypass, since everything on this machine is ultimately launched from a shell.
    /// </summary>
    internal static readonly HashSet<string> Toolchain = new(StringComparer.OrdinalIgnoreCase)
    {
        "dotnet.exe", "msbuild.exe", "csc.exe", "cl.exe", "link.exe", "cargo.exe", "rustc.exe",
        "node.exe", "python.exe", "ninja.exe", "cmake.exe", "go.exe", "unrealbuildtool.exe",
        "clang.exe", "clang++.exe", "gcc.exe", "g++.exe", "swc.exe", "esbuild.exe", "tsc.exe",
    };
}

/// <summary>One line of the "why did this score what it did" breakdown.</summary>
internal sealed record ScoreTerm(string Name, double Points, string Detail);

/// <summary>
/// The full working of a verdict.
///
/// The breakdown is not optional. An alert nobody can interrogate is an alert the user learns to
/// dismiss, and during the learning period the explanation IS the product.
/// </summary>
internal sealed record ScoreExplanation
{
    internal required Subject Subject { get; init; }
    internal required double Score { get; init; }
    internal required double ContextScore { get; init; }
    /// <summary>
    /// Context before the precision gate caps it. This — not <see cref="Score"/> — is what the
    /// day-one triage inbox should rank by: statistics alone never produce an alert, but they are
    /// exactly the right ordering for "here are the twenty things on this PC most worth a look".
    /// </summary>
    internal double ContextRaw { get; init; }
    internal required double RuleScore { get; init; }
    internal required double ContextCap { get; init; }
    internal required Confidence Confidence { get; init; }
    internal required Severity Severity { get; init; }
    internal required int Families { get; init; }
    internal required double EvidenceQuality { get; init; }
    internal required IReadOnlyList<ScoreTerm> Terms { get; init; }
    internal required IReadOnlyList<Signal> Signals { get; init; }

    internal double Rarity { get; init; }
    internal double SignerTrust { get; init; }
    internal double PathTrust { get; init; }
    internal double Behaviour { get; init; }

    /// <summary>True when a user approval held this back. The score still says what it found.</summary>
    internal bool Suppressed { get; init; }
    internal string SuppressedBy { get; init; } = "";
    internal bool Bootstrapping { get; init; }

    internal Verdict ToVerdict() => new()
    {
        Subject = Subject,
        Signals = Signals,
        Score = Math.Round(Score, 2),
        Confidence = Confidence,
        Severity = Severity,
    };
}

/// <summary>Whether an alert may reach the user, and which incident it belongs to.</summary>
internal sealed record NotificationDecision(
    bool Notify, string Reason, string IncidentId, int Occurrences, bool Deferred);

/// <summary>Outcome of a user approval request. Approvals can be refused, and refusals explain.</summary>
internal sealed record AllowResult(bool Accepted, AllowlistEntry? Entry, string Reason);

/// <summary>
/// Turns signals into a verdict, and decides whether the user ever hears about it.
///
/// The two hard guarantees, both enforced here rather than by convention:
///   1. No single signal can reach High confidence. High requires three distinct corroborating
///      signal families AND a decisive one AND enough evidence quality. Persistence plus network
///      is NOT enough — that pair is the normal signature of every per-user auto-updating app on
///      Windows (Discord, VS Code, Slack, Cursor, Teams, Spotify), and a gate that accepts it
///      quarantines a legitimate application the day the user installs it.
///   2. Context alone — novel, unsigned, in a user-writable directory, behaving unusually — is
///      capped below the alerting tier. Nine unsigned binaries are running on this machine right
///      now and every one is benign developer tooling.
/// </summary>
internal sealed class Scorer
{
    private readonly Baseline _baseline;
    private readonly object _gate = new();

    // Alert budgeting state. Deliberately monotonic (Stopwatch) rather than wall-clock: every
    // rate limit driven by DateTime.UtcNow is reset by moving the system clock backwards, which
    // is a one-line defeat of the entire alert budget.
    private readonly Dictionary<string, DedupRecord> _dedup = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IncidentRecord> _incidents = new(StringComparer.Ordinal);
    private readonly TokenBucket _highBucket = new(4, 1.0 / (15 * 60));    // 4, refill 1 per 15 min
    private readonly TokenBucket _mediumBucket = new(3, 1.0 / (60 * 60));  // 3, refill 1 per hour
    private readonly TokenBucket _hourCeiling = new(6, 6.0 / 3600);        // 6 per rolling hour
    private readonly TokenBucket _dayCeiling = new(20, 20.0 / 86400);      // 20 per rolling day
    private readonly TokenBucket _actionHour = new(2, 2.0 / 3600);
    private readonly TokenBucket _actionDay = new(4, 4.0 / 86400);
    private bool _actionsSuspended;

    internal Scorer(Baseline baseline) => _baseline = baseline;

    /// <summary>
    /// Observe-only. HERO scores, explains and shows "this is what I would have done", but takes
    /// no autonomous action. This is the shipping default and it stays the default until a replay
    /// of a captured fortnight of real work produces zero autonomous actions: a single wrongly
    /// quarantined build artefact, debugger or anti-cheat component destroys trust permanently,
    /// and there is no way to earn it back.
    /// </summary>
    internal bool ObserveOnly { get; set; } = true;

    /// <summary>True once the action circuit breaker has tripped. Requires an explicit re-arm.</summary>
    internal bool ActionsSuspended { get { lock (_gate) return _actionsSuspended; } }

    private sealed class DedupRecord
    {
        internal double FirstSeconds;
        internal double LastSeconds;
        internal int Count;
    }

    private sealed class IncidentRecord
    {
        internal string Id = "";
        internal double FirstSeconds;
        internal double LastSeconds;
        internal int Members;
        internal readonly List<double> AlertTimes = new();
    }

    /// <summary>Leaky bucket over a monotonic clock.</summary>
    private sealed class TokenBucket
    {
        private readonly double _capacity;
        private readonly double _refillPerSecond;
        private double _tokens;
        private double _last = -1;

        internal TokenBucket(double capacity, double refillPerSecond)
        {
            _capacity = capacity;
            _refillPerSecond = refillPerSecond;
            _tokens = capacity;
        }

        internal bool TryTake(double now)
        {
            if (_last < 0) _last = now;
            _tokens = Math.Min(_capacity, _tokens + (now - _last) * _refillPerSecond);
            _last = now;
            if (_tokens < 1) return false;
            _tokens -= 1;
            return true;
        }
    }

    private static double Monotonic => Stopwatch.GetTimestamp() / (double)Stopwatch.Frequency;

    // ---------------------------------------------------------------- scoring

    /// <summary>Combines signals into a verdict. The required entry point.</summary>
    internal Verdict Score(Subject subject, IReadOnlyList<Signal> signals, Baseline baseline, DetectionContext context)
        => Explain(subject, signals, baseline, context).ToVerdict();

    /// <summary>Scores and returns the whole working, term by term.</summary>
    internal ScoreExplanation Explain(Subject subject, IReadOnlyList<Signal> signals,
                                      Baseline baseline, DetectionContext context)
    {
        var now = context.Snapshot.TakenUtc == default ? DateTime.UtcNow : context.Snapshot.TakenUtc;
        var terms = new List<ScoreTerm>(10);

        string? path = Baseline.PathOf(subject);
        var entity = baseline.Find(path);
        var signature = path is null ? null : context.Signature(path);
        bool bootstrapping = baseline.IsBootstrapping;

        // ---- allowlist, evaluated first so rule-scoped approvals can drop signals, but applied
        // last so a suppressed detection still records what it found. An approval that leaves no
        // trace is how allowlists rot into invisible holes.
        var (blanket, allowedRules, stale) = MatchAllowlist(baseline, path, signature);

        var normalised = new List<Signal>(signals.Count + 2);
        foreach (var s in signals)
        {
            // A signal with no family is its own family, keyed by rule id. Lumping every
            // family-less signal together would suppress unrelated evidence; leaving them
            // family-less would let one rule stack with itself.
            var sig = string.IsNullOrEmpty(s.Family) ? s with { Family = s.RuleId } : s;
            if (allowedRules.Contains(sig.RuleId)) continue;
            normalised.Add(sig);
        }
        if (stale is not null) normalised.Add(stale);

        // ---- context
        double sg = entity is not null && signature is null
            ? baseline.SignerTrust(entity)
            : baseline.SignerTrust(signature);
        double pt = baseline.PathTrust(path);
        double r = baseline.Novelty(entity, now);

        // Developer-build suppressor. This machine compiles binaries constantly; without it every
        // build output is an unsigned zero-history executable in a user-writable path and produces
        // a permanent stream of noise. It only ever touches CONTEXT — a compiled binary that then
        // reads credentials still scores exactly as it should.
        if (IsDeveloperBuild(subject, context, baseline, path))
        {
            r *= 0.4;
            pt = Math.Min(0.80, pt + 0.25);
            terms.Add(new ScoreTerm("developer build", 0,
                "written moments ago by a known toolchain in a directory HERO already trusts"));
        }

        double cs = 1 - sg;
        double cp = 1 - pt;
        double cpAdjusted = cp * (1 - 0.4 * r * cp);
        double b = bootstrapping ? 0 : Behaviour(entity, subject, context, baseline, now, terms);

        double ctxRarity = ScorerModel.WeightRarity * r;
        double ctxSigner = ScorerModel.WeightSigner * cs;
        double ctxPath = ScorerModel.WeightPath * cpAdjusted;
        double ctxBehaviour = ScorerModel.WeightBehaviour * b;
        double contextRaw = ctxRarity + ctxSigner + ctxPath + ctxBehaviour;

        terms.Add(new ScoreTerm("novelty", ctxRarity, DescribeNovelty(entity, r, bootstrapping)));
        terms.Add(new ScoreTerm("signer", ctxSigner, signature?.Describe() ?? (entity is null ? "not yet verified" : "unverified")));
        terms.Add(new ScoreTerm("location", ctxPath, $"path trust {pt:0.00}"));
        if (ctxBehaviour > 0) terms.Add(new ScoreTerm("behaviour", ctxBehaviour, $"deviation {b:0.00}"));

        // ---- rules: strongest accusation per family, strongest exoneration per family
        // How much of its nominal weight this rule keeps on this machine, from the user's own
        // corrections. Decisive signals are exempt, exactly as they are exempt from signer
        // attenuation below: HERO acts autonomously only on a decisive signal, so nothing learned
        // from feedback may ever weaken one. That single exemption is what makes the rest of this
        // safe to have at all.
        double Influence(Signal s) => IsDecisive(s) ? 1.0 : OutcomeStore.InfluenceFor(s.RuleId);

        var accusations = new Dictionary<string, Signal>(StringComparer.OrdinalIgnoreCase);
        var exonerations = new Dictionary<string, Signal>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in normalised)
        {
            if (s.Weight > 0)
            {
                // Compared on EFFECTIVE weight, not nominal, and that detail is load-bearing.
                // Only the strongest signal in a family counts, so if the family winner were still
                // chosen on nominal weight, softening the winner would make a subject score LOWER
                // than if that rule had not fired at all — the softened winner would keep
                // suppressing its stronger siblings. Concretely: unsigned-image (16) softened to
                // 0.80 contributes 4.27, while volatile-location (14) unsoftened would have
                // contributed 4.67. Carrying one more true accusation must never reduce a score.
                if (!accusations.TryGetValue(s.Family, out var best)
                    || s.Weight * Influence(s) > best.Weight * Influence(best))
                {
                    accusations[s.Family] = s;
                }
            }
            else if (s.Weight < 0)
            {
                if (!exonerations.TryGetValue(s.Family, out var worst) || s.Weight < worst.Weight)
                    exonerations[s.Family] = s;
            }
        }

        double ruleScore = 0;
        foreach (var s in accusations.Values)
        {
            double attenuation = IsDecisive(s) ? 1.0 : 1 - ScorerModel.SignerAttenuation * Math.Max(0, sg);
            double influence = Influence(s);
            // Rule weights are on the catalogue's 0..28 scale; this model is calibrated for
            // totals around 3.5..9.5. See ScorerModel.RuleWeightScale for why and for the
            // worked numbers.
            double points = s.Weight * ScorerModel.RuleWeightScale * attenuation * influence;
            ruleScore += points;

            // Both adjustments are named in the explanation. A score the user cannot account for is
            // the thing this whole model exists to avoid, and "HERO counts this rule for less here
            // because you corrected it" is precisely the kind of thing that must not be silent.
            string note = s.Title;
            if (attenuation < 1) note += $" (signer attenuation x{attenuation:0.00})";
            if (influence < 1) note += $" (you have corrected this check before, so it counts x{influence:0.00} here)";
            terms.Add(new ScoreTerm(s.RuleId, points, note));
        }

        double exonerationTotal = Math.Max(-ScorerModel.MaxExoneration, exonerations.Values.Sum(s => s.Weight));
        foreach (var s in exonerations.Values) terms.Add(new ScoreTerm(s.RuleId, s.Weight, s.Title));

        // ---- the precision gate
        double cap = Math.Min(ScorerModel.ContextCeiling,
                              ScorerModel.ContextBase + ScorerModel.ContextPerRulePoint * ruleScore);
        double contextScore = Math.Min(contextRaw, cap);
        if (contextScore < contextRaw)
            terms.Add(new ScoreTerm("context cap", contextScore - contextRaw,
                $"statistics capped at {cap:0.00} without corroborating rules"));

        double score = Math.Max(0, contextScore + ruleScore + exonerationTotal);

        // ---- confidence and severity
        int families = accusations.Count;
        bool decisive = accusations.Values.Any(IsDecisive);
        double quality = EvidenceQuality(subject, signature, baseline, families);
        var confidence = MapConfidence(score, families, decisive, quality, bootstrapping,
                                       accusations.Values, out string confidenceNote);
        var severity = MapSeverity(score, normalised);

        if (confidenceNote.Length > 0) terms.Add(new ScoreTerm("confidence", 0, confidenceNote));

        // ---- suppression, applied last
        bool suppressed = false;
        if (blanket is { } approval)
        {
            suppressed = true;
            normalised.Add(Meta("hero.allow.suppressed", "Suppressed by your approval",
                $"You approved this on {approval.CreatedUtc.ToLocalTime():d}. It would otherwise have scored {score:0.0}.",
                $"scope={approval.Scope}"));
            confidence = Confidence.Informational;
            severity = Severity.Safe;
            approval.Hits++;
            approval.LastHitUtc = DateTime.UtcNow;
            baseline.MarkDirty();
        }

        normalised.Sort((x, y) => y.Weight.CompareTo(x.Weight));

        return new ScoreExplanation
        {
            Subject = subject,
            Score = score,
            ContextScore = contextScore,
            ContextRaw = contextRaw,
            RuleScore = ruleScore,
            ContextCap = cap,
            Confidence = confidence,
            Severity = severity,
            Families = families,
            EvidenceQuality = quality,
            Terms = terms,
            Signals = normalised,
            Rarity = r,
            SignerTrust = sg,
            PathTrust = pt,
            Behaviour = b,
            Suppressed = suppressed,
            SuppressedBy = blanket is null ? "" : blanket.Id,
            Bootstrapping = bootstrapping,
        };
    }

    private static string DescribeNovelty(BaselineEntity? entity, double r, bool bootstrapping)
    {
        if (entity is null) return bootstrapping ? "never seen (still learning this PC)" : "never seen before";
        if (r <= 0) return "recently updated — novelty suppressed";
        return $"seen {entity.Count:0.#} times over {entity.DistinctDays} days";
    }

    /// <summary>
    /// A signal that must not be discounted for being signed, and that alone can make a verdict
    /// decisive. Severity carries this as well as family, because every LOLBin abuse case involves
    /// a validly signed Microsoft binary and attenuating those findings is a blind spot.
    /// </summary>
    private static bool IsDecisive(Signal s)
        // A severity label alone is not enough. Rules set Severity and Weight independently, and
        // several damp the weight for a benign-looking case while leaving Severity.High in place;
        // without the weight floor, such a signal still cleared the decisive gate on its label.
        => s.Weight * ScorerModel.RuleWeightScale >= ScorerModel.DecisiveMinimumWeight
           && (s.Severity >= Severity.High || ScorerModel.DecisiveFamilies.Contains(s.Family));

    /// <summary>
    /// The hard rule, in one place.
    ///
    /// High confidence — the only tier permitted to act without asking — requires ALL of:
    ///   * a score at or above 15.0
    ///   * three distinct corroborating signal families, so one strong signal can never suffice
    ///   * at least one decisive finding (a credential/injection/evasion-class signal, or anything
    ///     a rule marked Severity.High or above). Persistence + Network + Provenance is three
    ///     families, and it is also exactly what a legitimate per-user auto-updater looks like.
    ///   * evidence quality of 0.80, which is unreachable in the first few days by construction
    ///   * not during the bootstrap window, unless the finding is Critical
    /// Anything that clears the score but fails a gate becomes Medium: HERO asks.
    /// </summary>
    private static Confidence MapConfidence(double score, int families, bool decisive, double quality,
                                            bool bootstrapping, IEnumerable<Signal> accusations,
                                            out string note)
    {
        note = "";
        if (score < ScorerModel.LowScore) return Confidence.Informational;
        if (score < ScorerModel.MediumScore) return Confidence.Low;
        if (score < ScorerModel.HighScore) return Confidence.Medium;

        if (families < ScorerModel.FamiliesForHigh)
        {
            note = $"{families} independent signal families — three are required before HERO acts alone";
            return Confidence.Medium;
        }
        if (!decisive)
        {
            note = "no decisive finding — corroborating evidence only, so HERO asks first";
            return Confidence.Medium;
        }
        if (quality < ScorerModel.ConfidenceForHigh)
        {
            note = $"evidence quality {quality:0.00} — below {ScorerModel.ConfidenceForHigh:0.00}, so HERO asks first";
            return Confidence.Medium;
        }
        if (bootstrapping && !accusations.Any(s => s.Severity >= Severity.Critical))
        {
            note = "still learning this PC — only a critical finding acts during the first days";
            return Confidence.Medium;
        }
        return Confidence.High;
    }

    /// <summary>
    /// Severity is how bad this would be if true; confidence is how sure HERO is. They are
    /// deliberately independent, so the strongest accusation sets severity even when the
    /// corroboration is thin.
    /// </summary>
    private static Severity MapSeverity(double score, List<Signal> signals)
    {
        var fromScore = score switch
        {
            < ScorerModel.LowScore => Severity.Safe,
            < ScorerModel.MediumScore => Severity.Low,
            < ScorerModel.HighScore => Severity.Medium,
            < ScorerModel.CriticalScore => Severity.High,
            _ => Severity.Critical,
        };
        var worst = fromScore;
        foreach (var s in signals)
            if (s.Weight > 0 && s.Severity > worst) worst = s.Severity;
        return worst;
    }

    /// <summary>
    /// C = 0.35*identity + 0.30*sensor + 0.20*history + 0.15*corroboration.
    ///
    /// The sensor term is capped at 0.7 and always will be: HERO is a one-second poller with no
    /// ETW session, so it can miss a process that lives and dies between two polls. Claiming
    /// otherwise would be the dishonest kind of confidence. The practical consequence is that a
    /// verdict needs full corroboration AND about a fortnight of history to clear 0.80 — which is
    /// exactly the "do not act in the first week" property that matters most.
    /// </summary>
    private static double EvidenceQuality(Subject subject, SignatureInfo? signature, Baseline baseline, int families)
    {
        double identity = subject switch
        {
            ProcessSubject p when p.Process.PathUnavailable => 0.3,
            ProcessSubject when signature is not null && signature.State != SignatureState.Unknown => 1.0,
            ProcessSubject => 0.6,
            PersistenceSubject e when string.IsNullOrEmpty(e.Entry.ImagePath) => 0.4,
            _ => 0.6,
        };
        double sensor = subject is PersistenceSubject ? 0.5 : 0.7;
        double history = Math.Min(1, baseline.HistoryDays / 14.0);
        double corroboration = families >= 3 ? 1.0 : families == 2 ? 0.6 : families == 1 ? 0.3 : 0.0;

        return Math.Clamp(0.35 * identity + 0.30 * sensor + 0.20 * history + 0.15 * corroboration, 0, 1);
    }

    // ---------------------------------------------------------------- behaviour term

    /// <summary>
    /// Behavioural deviation in [0,1], combined by noisy-OR so correlated observations saturate
    /// instead of summing. Every channel is gated on having enough history to be surprised by
    /// anything at all — the classic "new process does something for the first time" false
    /// positive is entirely a failure to apply that gate.
    /// </summary>
    private static double Behaviour(BaselineEntity? entity, Subject subject, DetectionContext context,
                                    Baseline baseline, DateTime now, List<ScoreTerm> terms)
    {
        if (entity is null) return 0;
        if (subject is not ProcessSubject ps) return 0;

        bool watching = now < entity.WatchUntilUtc;
        double product = 1.0;

        void Combine(double deviation, double kappa, string name, string detail)
        {
            if (deviation <= 0) return;
            product *= 1 - Math.Clamp(deviation, 0, 1) * kappa;
            terms.Add(new ScoreTerm("behaviour." + name, 0, detail));
        }

        // Parent. The strongest categorical channel on any machine: software has a small, stable
        // set of things that start it, right up until something else does.
        var parent = context.Snapshot.Ancestry(ps.Process, 1).FirstOrDefault();
        if (parent is not null)
        {
            string parentName = parent.FileName.ToLowerInvariant();
            double surprise = CategorySurprise(baseline, entity.Parents, parentName);
            double kappa = ScorerModel.ShellsAndBuildTools.Contains(entity.Name)
                ? ScorerModel.KappaParentShell
                : ScorerModel.KappaParent;
            Combine(surprise, kappa, "parent", $"started by {parentName}, not seen before for this program");
        }

        // Network. Only genuinely external peers: a developer machine chatters to localhost and
        // the LAN constantly, and bucketing to /16 keeps a CDN from looking like a new endpoint
        // every time it rotates an address.
        foreach (var c in context.Snapshot.Connections)
        {
            if (c.Pid != ps.Process.Pid || !c.IsExternal) continue;
            double peerSurprise = CategorySurprise(baseline, entity.Peers, PathModel.PeerPrefix(c.RemoteAddress));
            Combine(peerSurprise, ScorerModel.KappaPeer, "peer", $"new network neighbourhood {c.RemoteAddress}");
            double portSurprise = CategorySurprise(baseline, entity.Ports,
                c.RemotePort.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Combine(portSurprise, ScorerModel.KappaPort, "port", $"new outbound port {c.RemotePort}");
            break;   // one representative connection: the rest are restatements of the same fact
        }

        // Hour of day. Weak by design, and gated hard: plenty of software runs at odd hours
        // legitimately, and this user does too.
        if (entity.Count >= 20)
        {
            int hour = now.ToLocalTime().Hour;
            if (entity.Hours[hour] < 0.5)
                Combine(0.6, ScorerModel.KappaHour, "hour", $"first time this has run at {hour:00}:00");
        }

        // Threads: the only continuous channel HERO currently samples.
        //
        // The freshness gate is not optional. Baseline.Observe is the ONLY thing feeding this
        // envelope today, and it is called exclusively for delta.StartedProcesses — so every
        // stored sample is a thread count from the first second of a process's life. Node,
        // Unreal, Blender, Docker and every browser start with a handful of threads and grow to
        // dozens within a minute, so scoring a long-running process against a distribution of
        // just-started ones compares two different quantities and yields a permanent multi-sigma
        // excursion for exactly the software this machine runs all day. Until a sampler feeds
        // ObserveResources for RUNNING processes, this channel may only speak about a process
        // young enough to be comparable with what was learned.
        var age = now - ps.Process.StartTimeUtc;
        bool comparable = ps.Process.StartTimeUtc != default
                          && age >= TimeSpan.Zero && age <= TimeSpan.FromSeconds(30);

        if (comparable && entity.Threads.N >= 12 && ps.Process.ThreadCount > 0)
        {
            double z = entity.Threads.ZScore(ps.Process.ThreadCount, Baseline.SigmaFloors[2]);
            double offset = watching ? ScorerModel.ZOffsetWatching : ScorerModel.ZOffset;
            double threadDeviation = Math.Clamp((z - offset) / ScorerModel.ZSpan, 0, 1);
            Combine(threadDeviation, ScorerModel.KappaThreads, "threads",
                $"{ps.Process.ThreadCount} threads, z={z:0.0} against its own history");
        }

        return 1 - product;
    }

    /// <summary>
    /// Good–Turing style surprise: the probability that the next observation is a category never
    /// seen before is d/(n+d), so seeing one is 1 - that.
    ///
    /// Worked, and this is why it needs no per-application tuning: a browser that has visited 40
    /// distinct network neighbourhoods across 100 observations has p_new = 40/140 = 0.29, so a
    /// 41st is only 0.71 surprising. A service that has contacted exactly one neighbourhood in
    /// 200 observations has p_new = 1/201 = 0.005, so a new one is 0.995 surprising.
    /// </summary>
    private static double CategorySurprise(Baseline baseline, Dictionary<string, double> channel, string category)
    {
        if (string.IsNullOrEmpty(category)) return 0;

        var (total, distinct, known) = baseline.ChannelStats(channel, category);
        if (known || distinct == 0) return 0;
        if (total < ScorerModel.MinCategoryHistory) return 0;   // too little history to be surprised

        double pNew = distinct / (total + distinct);
        return Math.Clamp(1 - pNew, 0, 1);
    }

    /// <summary>
    /// True when this looks like something the user just compiled.
    ///
    /// Bound to toolchain entities the baseline already knows and that live in a trusted location:
    /// without that clause, dropping a file named MSBuild.exe into a temp folder would be a
    /// universal suppression bypass.
    /// </summary>
    private static bool IsDeveloperBuild(Subject subject, DetectionContext context, Baseline baseline, string? path)
    {
        if (subject is not ProcessSubject ps || path is null) return false;

        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return false;
            if ((DateTime.UtcNow - fi.LastWriteTimeUtc).TotalMinutes > 10) return false;
        }
        catch { return false; }

        foreach (var ancestor in context.Snapshot.Ancestry(ps.Process, 4))
        {
            if (ancestor.PathUnavailable) continue;
            if (!ScorerModel.Toolchain.Contains(ancestor.FileName)) continue;

            var entity = baseline.Find(ancestor.ImagePath);
            if (entity is null || entity.State < EntityState.Familiar) continue;
            if (baseline.PathTrust(ancestor.ImagePath) < 0.55) continue;
            return true;
        }
        return false;
    }

    // ---------------------------------------------------------------- allowlist

    /// <summary>
    /// Finds an approval that covers this subject, re-proving it rather than trusting that it
    /// exists. Returns a blanket suppression (if any), the rule ids the user has silenced for
    /// this entity, and an explanatory signal when an approval had to be revoked.
    /// </summary>
    private static (AllowlistEntry? Blanket, HashSet<string> Rules, Signal? Stale) MatchAllowlist(
        Baseline baseline, string? path, SignatureInfo? signature)
    {
        var rules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (path is null) return (null, rules, null);

        string key = PathModel.KeyFor(path);
        var entries = baseline.AllowlistFor(key);
        if (entries.Count == 0) return (null, rules, null);

        var stamp = ContentIdentity.For(path).Token;
        AllowlistEntry? blanket = null;
        Signal? stale = null;

        foreach (var entry in entries)
        {
            bool identityHeld = string.Equals(entry.Stamp, stamp, StringComparison.Ordinal);

            if (!identityHeld && entry.Identity.StartsWith("h:", StringComparison.Ordinal))
            {
                // The cheap stamp changed. Re-hash before concluding anything: a file restored
                // from backup, or touched by a sync client, has a new mtime and identical bytes.
                var hash = ContentIdentity.TryHash(path);
                if (hash is not null && string.Equals("h:" + hash, entry.Identity, StringComparison.OrdinalIgnoreCase))
                {
                    entry.Stamp = stamp;
                    baseline.MarkDirty();
                    identityHeld = true;
                }
            }

            switch (entry.Scope)
            {
                case AllowScope.Hash when !identityHeld:
                    // The direct answer to path substitution. An approval that survives the file
                    // being replaced is not an approval, it is a persistence primitive.
                    baseline.RevokeAllowlist(entry, "the approved file changed");
                    stale ??= Meta("hero.allow.stale", "An application you approved has changed",
                        "The file at this path is not the one you approved, so that approval no longer applies.",
                        path, Severity.Medium);
                    continue;

                case AllowScope.PathAndSigner:
                    // Deliberately survives updates — that is the entire point of the scope — but
                    // the signature is re-verified on every use, and a different certificate from
                    // the same publisher name does not match.
                    if (signature is null || signature.State != SignatureState.Valid ||
                        !string.Equals(signature.Signer, entry.Signer, StringComparison.OrdinalIgnoreCase))
                    {
                        baseline.RevokeAllowlist(entry, "the publisher changed or the signature no longer verifies");
                        stale ??= Meta("hero.allow.signerbreak", "An approved application's publisher changed",
                            "You approved this publisher at this location; it is now signed by someone else, or not validly signed.",
                            path, Severity.Medium);
                        continue;
                    }
                    break;

                case AllowScope.RuleForEntity when !identityHeld:
                    baseline.RevokeAllowlist(entry, "the file changed after the rule was silenced");
                    continue;
            }

            if (entry.Scope == AllowScope.RuleForEntity) rules.Add(entry.RuleId);
            else blanket ??= entry;
        }

        return (blanket, rules, stale);
    }

    /// <summary>
    /// Records a user approval.
    ///
    /// There is no auto-allow anywhere in HERO, and there never will be: ageing into "known"
    /// lowers a score, it does not create an approval. Approvals only ever come from here.
    /// </summary>
    internal AllowResult Allow(Subject subject, AllowScope scope, string? ruleId = null,
                               SignatureInfo? signature = null, TimeSpan? lifetime = null)
    {
        string? path = Baseline.PathOf(subject);
        if (path is null)
            return new AllowResult(false, null, "HERO cannot see this program's file, so it cannot scope an approval to it.");

        if (scope == AllowScope.RuleForEntity && string.IsNullOrWhiteSpace(ruleId))
            return new AllowResult(false, null, "Silencing a single finding needs to know which finding.");

        if (scope == AllowScope.PathAndSigner &&
            (signature is null || signature.State != SignatureState.Valid || signature.Signer.Length == 0))
            return new AllowResult(false, null,
                "Trusting a publisher requires a valid signature to pin. This file does not have one.");

        // Trust rate limits. The pattern this defeats is spraying prompts until one is approved by
        // reflex; five an hour is far above honest use and far below a spray.
        if (_baseline.AllowlistCreatedSince(TimeSpan.FromHours(1)) >= 5)
            return new AllowResult(false, null, "Too many approvals in the last hour. Try again shortly.");
        if (_baseline.AllowlistCreatedSince(TimeSpan.FromDays(1)) >= 20)
            return new AllowResult(false, null, "Too many approvals today.");

        var identity = ContentIdentity.For(path);
        string stamp = identity.Token;
        string commitment = stamp;
        string caveat = "";

        if (scope == AllowScope.Hash)
        {
            var hash = ContentIdentity.TryHash(path);
            if (hash is not null) commitment = "h:" + hash;
            else caveat = " (the file is too large to fingerprint fully, so this approval is pinned to its size and timestamp)";
        }

        var now = DateTime.UtcNow;
        var entry = new AllowlistEntry
        {
            Id = "al_" + Guid.NewGuid().ToString("n")[..12],
            Scope = scope,
            EntityKey = PathModel.KeyFor(path),
            Path = path,
            Identity = commitment,
            Stamp = stamp,
            Signer = signature?.Signer ?? "",
            SignerState = (int)(signature?.State ?? SignatureState.Unknown),
            RuleId = ruleId ?? "",
            CreatedUtc = now,
            // Expiry differs by scope on purpose: a publisher pin is absolute and cannot be
            // renewed by use, because "I have been using this for a year" is not evidence that the
            // publisher should still be trusted at that location.
            ExpiresUtc = now + (lifetime ?? scope switch
            {
                AllowScope.Hash => TimeSpan.FromDays(365),
                AllowScope.PathAndSigner => TimeSpan.FromDays(365),
                _ => TimeSpan.FromDays(180),
            }),
        };

        _baseline.AddAllowlistEntry(entry);

        var entity = _baseline.Find(path);
        if (entity is not null && scope != AllowScope.RuleForEntity) _baseline.MarkUserAllowed(entity);

        return new AllowResult(true, entry, DescribeScope(scope, ruleId) + caveat);
    }

    private static string DescribeScope(AllowScope scope, string? ruleId) => scope switch
    {
        AllowScope.Hash => "Approved — exactly these bytes at this location. If the file changes, HERO will ask again.",
        AllowScope.PathAndSigner => "Approved — this publisher at this location. Updates are fine; a change of publisher is not.",
        _ => $"Silenced '{ruleId}' for this program only. Every other finding still applies.",
    };

    /// <summary>
    /// Records a kill verdict: blocks the entity, strikes its provisional training data so an
    /// attacker's dwell time does not survive as learned "normal", and revokes its approvals.
    /// </summary>
    internal void Deny(Subject subject)
    {
        string? path = Baseline.PathOf(subject);
        if (path is null) return;

        var entity = _baseline.Find(path);
        if (entity is not null) _baseline.MarkUserDenied(entity);

        foreach (var entry in _baseline.AllowlistFor(PathModel.KeyFor(path)))
            _baseline.RevokeAllowlist(entry, "you asked HERO to remove this program");
    }

    private static Signal Meta(string ruleId, string title, string explanation, string evidence,
                               Severity severity = Severity.Low)
        => new()
        {
            RuleId = ruleId,
            Title = title,
            Explanation = explanation,
            Weight = 0,
            Severity = severity,
            Evidence = evidence,
            // Empty family on purpose: a note about HERO's own state is not corroborating
            // evidence and must never count toward the three families High requires.
            Family = "",
        };

    // ---------------------------------------------------------------- alert budget

    /// <summary>
    /// Decides whether a verdict may interrupt the user, and which incident it belongs to.
    ///
    /// Target: fewer than two notifications a day. If the first fortnight produces more than that,
    /// the thresholds are wrong, not the user — which is why every suppression is counted and
    /// reported rather than silently discarded.
    /// </summary>
    internal NotificationDecision Decide(Verdict verdict)
    {
        double now = Monotonic;
        string entityKey = PathModel.KeyFor(Baseline.PathOf(verdict.Subject));
        if (entityKey.Length == 0) entityKey = verdict.Subject.Key;

        string dedupKey = entityKey + "|" + string.Join(',',
            verdict.Signals.Where(s => s.Weight > 0).Select(s => s.RuleId).OrderBy(x => x, StringComparer.Ordinal));

        // An informational verdict never opens or extends an incident. Letting it would keep one
        // incident per entity alive forever on a one-second poll loop, and "members: 14000" is not
        // a timeline anybody can read.
        if (verdict.Confidence == Confidence.Informational)
            return new NotificationDecision(false, "informational", "", 0, false);

        lock (_gate)
        {
            // A repeat does not count as a new incident member. Without that, a single standing
            // Low or Medium finding on a one-second poll loop reports "members: 14000" after four
            // hours, which is precisely the unreadable timeline the Informational early-return
            // above exists to prevent.
            _dedup.TryGetValue(dedupKey, out var seen);
            bool duplicate = seen is not null && now - seen.LastSeconds < 6 * 3600;
            var incident = JoinIncident(entityKey, now, countMember: !duplicate);

            // Repeat suppression. The badge count still moves; the toast does not.
            if (duplicate && seen is not null)
            {
                seen.LastSeconds = now;
                seen.Count++;
                return new NotificationDecision(false, "already reported in the last 6 hours",
                                                incident.Id, seen.Count, true);
            }
            _dedup[dedupKey] = new DedupRecord { FirstSeconds = now, LastSeconds = now, Count = 1 };
            PruneDedup(now);

            if (verdict.Confidence == Confidence.Low)
                return new NotificationDecision(false, "low confidence — dashboard only, never a toast",
                                                incident.Id, 1, false);

            // Per-entity budget: one program may interrupt three times a day, no matter how many
            // distinct things it does. Everything beyond that joins the open incident.
            incident.AlertTimes.RemoveAll(t => now - t > 86400);
            if (incident.AlertTimes.Count >= 3)
                return new NotificationDecision(false, "this program has already raised three alerts today",
                                                incident.Id, incident.Members, true);

            var tier = verdict.Confidence == Confidence.High ? _highBucket : _mediumBucket;
            if (!tier.TryTake(now))
                return new NotificationDecision(false, "notification budget for this tier is spent",
                                                incident.Id, incident.Members, true);
            if (!_hourCeiling.TryTake(now) || !_dayCeiling.TryTake(now))
                return new NotificationDecision(false, "hourly or daily notification ceiling reached",
                                                incident.Id, incident.Members, true);

            incident.AlertTimes.Add(now);
            return new NotificationDecision(true, "", incident.Id, incident.Members, false);
        }
    }

    /// <summary>
    /// Groups related findings. A compromised program produces one incident, not twenty rows:
    /// events join an open incident for the same entity within ten minutes of its last member,
    /// extended by each new member and capped at four hours so an incident cannot live forever.
    /// </summary>
    private IncidentRecord JoinIncident(string entityKey, double now, bool countMember)
    {
        if (_incidents.TryGetValue(entityKey, out var incident) &&
            now - incident.LastSeconds <= 600 && now - incident.FirstSeconds <= 4 * 3600)
        {
            // A repeat still holds the incident open — it is the same thing still happening — but
            // it is not another member of it.
            incident.LastSeconds = now;
            if (countMember) incident.Members++;
            return incident;
        }

        incident = new IncidentRecord
        {
            Id = "inc_" + Guid.NewGuid().ToString("n")[..10],
            FirstSeconds = now,
            LastSeconds = now,
            Members = 1,
        };
        _incidents[entityKey] = incident;

        if (_incidents.Count > 512)
        {
            var stale = _incidents.Where(kv => now - kv.Value.LastSeconds > 4 * 3600).Select(kv => kv.Key).ToList();
            foreach (var k in stale) _incidents.Remove(k);
        }
        return incident;
    }

    private void PruneDedup(double now)
    {
        if (_dedup.Count < 2000) return;
        var stale = _dedup.Where(kv => now - kv.Value.LastSeconds > 24 * 3600).Select(kv => kv.Key).ToList();
        foreach (var k in stale) _dedup.Remove(k);
    }

    /// <summary>
    /// The circuit breaker on autonomous action.
    ///
    /// Actions are rate-limited even though notifications about them are budgeted separately, and
    /// this is the more important of the two limits. A systematic false positive — a rule
    /// misfiring on every Electron app after a Windows update — could otherwise quarantine dozens
    /// of applications while the user sees a single collapsed "N detections" toast. On the third
    /// action in an hour HERO stops acting entirely and says so.
    /// </summary>
    internal bool TryReserveAutonomousAction(Verdict verdict, out string reason)
    {
        if (ObserveOnly)
        {
            reason = "HERO is in observe-only mode and is showing what it would have done.";
            return false;
        }
        if (verdict.Confidence != Confidence.High)
        {
            reason = "Not confident enough to act without asking.";
            return false;
        }

        double now = Monotonic;
        lock (_gate)
        {
            if (_actionsSuspended)
            {
                reason = "HERO has acted unusually often and has switched itself to asking first.";
                return false;
            }
            if (!_actionHour.TryTake(now) || !_actionDay.TryTake(now))
            {
                _actionsSuspended = true;
                reason = "HERO has acted unusually often and has switched itself to asking first.";
                return false;
            }
            reason = "";
            return true;
        }
    }

    /// <summary>Clears the circuit breaker. Only ever called from an explicit user action.</summary>
    internal void RearmAutonomousActions()
    {
        lock (_gate) _actionsSuspended = false;
    }
}
