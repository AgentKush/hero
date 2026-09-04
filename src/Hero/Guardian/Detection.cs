using Hero.Interop;

namespace Hero.Guardian;

/// <summary>
/// Confidence tiers. These map directly onto what HERO is permitted to DO, which is why there
/// are four and not a continuous score: the user chose "auto-act on high confidence, ask on the
/// rest", and that decision has to be expressible as a hard boundary.
/// </summary>
internal enum Confidence
{
    /// <summary>Recorded for context and timeline only. Never surfaces as an alert.</summary>
    Informational,
    /// <summary>Visible in the UI, contributes to scoring, never prompts on its own.</summary>
    Low,
    /// <summary>Raises a prompt. HERO does not act without the user.</summary>
    Medium,
    /// <summary>Corroborated well enough to act autonomously, reversibly.</summary>
    High,
}

internal enum Severity { Safe, Low, Medium, High, Critical }

/// <summary>
/// A single piece of evidence produced by one rule about one subject.
///
/// Signals are deliberately small and additive. Nothing in HERO decides guilt from one signal;
/// the scorer combines them, and the empirically-grounded rule is that no single signal may
/// reach High on its own. On this machine nine unsigned binaries are running right now and every
/// one is benign developer tooling, so "unsigned" alone must never be sufficient.
/// </summary>
internal sealed record Signal
{
    /// <summary>Stable rule identifier, e.g. "proc.unsigned-in-user-writable".</summary>
    internal required string RuleId { get; init; }
    internal required string Title { get; init; }
    /// <summary>One sentence a non-expert can act on. No jargon without expansion.</summary>
    internal required string Explanation { get; init; }
    /// <summary>Points contributed to the subject's score. Positive accuses, negative exonerates.</summary>
    internal required double Weight { get; init; }
    internal Severity Severity { get; init; } = Severity.Low;
    /// <summary>Literal evidence: the command line, the registry value, the remote endpoint.</summary>
    internal string Evidence { get; init; } = "";

    /// <summary>
    /// Signals sharing a family are correlated, so the scorer counts only the strongest of each
    /// family rather than summing them. Without this, five restatements of "this file is in
    /// AppData" would stack into a false High.
    /// </summary>
    internal string Family { get; init; } = "";
}

/// <summary>
/// What a set of signals is about.
///
/// POLYMORPHIC ON THE WIRE, and it has to be. Verdicts cross the IPC pipe inside StateReply, and
/// an abstract property type is something System.Text.Json will neither write nor read without
/// being told how: it serialised every subject as <c>{}</c> and then threw
/// <c>NotSupportedException: Deserialization of interface or abstract types is not supported</c>
/// on the way back in.
///
/// That failure took the WHOLE reply with it, not just the subject. Verdicts is one property of
/// StateReply, so one unreadable subject meant no snapshot, no processes, no connections, no
/// persistence — every page in the dashboard blank, with the score ring stuck on its initial
/// zero. And because the guardian holds no verdicts on a quiet machine, it looked fine right up
/// until the moment it had something to say: HERO raised its first finding
/// (<c>evade.service-start-type</c>) and the dashboard went dark in the same second. A security
/// tool that works only while it has nothing to report is worse than no tool, because the blank
/// screen reads as "all clear".
///
/// The discriminator is written as "kind" rather than the default "$type" because this shape is
/// read by hand during debugging often enough for that to matter.
/// </summary>
[System.Text.Json.Serialization.JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[System.Text.Json.Serialization.JsonDerivedType(typeof(ProcessSubject), "process")]
[System.Text.Json.Serialization.JsonDerivedType(typeof(PersistenceSubject), "persistence")]
internal abstract record Subject
{
    internal abstract string Key { get; }
    internal abstract string Display { get; }
}

internal sealed record ProcessSubject(ProcessRecord Process) : Subject
{
    // Identity must include start time: Windows recycles PIDs aggressively, and on a machine
    // that spawns hundreds of short-lived build processes a pid-only key would merge unrelated
    // programs into one verdict.
    internal override string Key => $"proc:{Process.Pid}:{Process.StartTimeUtc.Ticks}";
    internal override string Display => Process.FileName;
}

internal sealed record PersistenceSubject(PersistenceEntry Entry) : Subject
{
    internal override string Key => "persist:" + Entry.Key;
    internal override string Display => Entry.Name;
}

/// <summary>The combined judgement about one subject.</summary>
internal sealed record Verdict
{
    internal required Subject Subject { get; init; }
    internal required IReadOnlyList<Signal> Signals { get; init; }
    internal required double Score { get; init; }
    internal required Confidence Confidence { get; init; }
    internal required Severity Severity { get; init; }
    internal DateTime RaisedUtc { get; init; } = DateTime.UtcNow;

    /// <summary>Distinct signal families present. The scorer requires several to reach High.</summary>
    internal int CorroboratingFamilies => Signals.Select(s => s.Family).Where(f => f.Length > 0).Distinct().Count();

    /// <summary>The single most important reason, for headline display.</summary>
    internal Signal? Headline => Signals.OrderByDescending(s => s.Weight).FirstOrDefault();
}

/// <summary>
/// Context handed to every rule. Rules are pure functions of this: given the same context they
/// must produce the same signals, so a verdict can be replayed and explained after the fact.
/// </summary>
internal sealed class DetectionContext
{
    internal required Snapshot Snapshot { get; init; }
    internal required SnapshotDelta? Delta { get; init; }
    internal required SignatureVerifier Verifier { get; init; }

    /// <summary>Signature for a path, using only the cache. Rules must never block on disk I/O.</summary>
    internal SignatureInfo? Signature(string path) => Verifier.TryGetCached(path);
}

/// <summary>
/// One detection rule.
///
/// Rules never act and never mutate state. They observe and accuse. Everything about what
/// happens next belongs to the scorer and the response engine, so that the entire detection
/// surface can be unit-tested without a machine to break.
/// </summary>
internal interface IDetectionRule
{
    /// <summary>Stable id, used for allowlisting and for the user's "don't tell me again".</summary>
    string Id { get; }
    string Description { get; }
    IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context);
}
