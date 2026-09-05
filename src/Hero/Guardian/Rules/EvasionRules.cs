using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using Hero.Interop;

namespace Hero.Guardian.Rules;

/// <summary>How much of a channel HERO can actually see. Never rendered as "clean".</summary>
internal enum ChannelState { Unknown, Available, AccessDenied, NotPresent, Failed }

/// <summary>One relevant record lifted out of a Windows event log.</summary>
internal sealed record SecurityEvent(
    string Channel,
    int EventId,
    DateTime TimeUtc,
    string Summary,
    string ServiceName,
    string ImagePath,
    string Detail,

    /// <summary>
    /// For 7040 only: the start type the service was changed TO, taken from the event's own data
    /// rather than from its rendered sentence.
    ///
    /// Carried separately because the direction of the change is the whole finding, and the
    /// sentence cannot supply it — "changed from disabled to auto start" and "changed from auto
    /// start to disabled" contain the same words. Empty for every other event id.
    /// </summary>
    string NewStartType = "");

/// <summary>
/// The event-log plane.
///
/// Reads three channels on a throttled poll rather than through EventLogWatcher subscriptions.
/// That is a deliberate trade: a watcher delivers events with no latency but loses everything in
/// the gap across a restart unless bookmarks are persisted, and it dies silently — with no
/// exception — when the Event Log service recycles. A poll that remembers the last record id it
/// saw per channel survives both, at the cost of up to <see cref="RefreshIntervalMs"/> of delay.
///
/// Verified on this machine, unelevated:
///   Microsoft-Windows-Windows Defender/Operational — readable, 9309 records.
///   System — readable (7040 service start-type changes, 7045 service installs, 104 log cleared).
///   Security — NOT readable without elevation, so 1102 (log cleared) is recorded as a blind spot
///   rather than as an absence of events. HERO must never render "no events" as "nothing happened".
///
/// Microsoft-Windows-TaskScheduler/Operational is deliberately not subscribed to: it is disabled
/// by default on Windows 11 and verified disabled here, so a subscription would attach and never
/// deliver while the dashboard showed the plane as healthy.
/// </summary>
internal static class WindowsEventFeed
{
    internal const string DefenderChannel = "Microsoft-Windows-Windows Defender/Operational";
    internal const string SystemChannel = "System";
    internal const string SecurityChannel = "Security";

    private const int RefreshIntervalMs = 20_000;
    private const int MaxEventsPerRefresh = 120;
    private const int MaxRetained = 400;
    private static readonly TimeSpan Retention = TimeSpan.FromHours(12);

    private sealed record ChannelSpec(string Name, string Query);

    private static readonly ChannelSpec[] Channels =
    {
        // Six hours of lookback on the first read, so a HERO restart does not blind it to what
        // happened while it was down.
        new(DefenderChannel,
            "*[System[(EventID=5001 or EventID=5004 or EventID=5007 or EventID=5010 or EventID=5012 or EventID=5013) " +
            "and TimeCreated[timediff(@SystemTime) <= 21600000]]]"),
        new(SystemChannel,
            "*[System[(EventID=7040 or EventID=7045 or EventID=104) " +
            "and TimeCreated[timediff(@SystemTime) <= 21600000]]]"),
        new(SecurityChannel,
            "*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime) <= 21600000]]]"),
    };

    private static readonly object Gate = new();
    private static readonly List<SecurityEvent> Events = new();
    private static readonly Dictionary<string, ChannelState> States = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, long> LastRecordIds = new(StringComparer.OrdinalIgnoreCase);

    private static long _lastRefreshTicks;
    private static int _refreshing;
    private static DateTime _newestEventUtc = DateTime.MinValue;

    /// <summary>
    /// An O(1) "has anything happened at all" test.
    ///
    /// Every evasion rule calls this before touching the event list. The common case on a healthy
    /// machine is that nothing has happened for hours, and without this each of ~360 process
    /// subjects would filter a 400-entry list on every one-second poll — roughly 150,000 pointless
    /// comparisons per second inside a budget of about one percent of a core.
    /// </summary>
    internal static bool AnyRecent(TimeSpan within)
    {
        KickRefresh();
        lock (Gate) { return _newestEventUtc >= DateTime.UtcNow - within; }
    }

    /// <summary>
    /// Events seen within <paramref name="within"/>. Returns immediately from the in-memory cache
    /// and starts a background refresh if the cache is stale — a rule must never block the
    /// observation loop on a log read.
    /// </summary>
    internal static IReadOnlyList<SecurityEvent> Recent(TimeSpan within)
    {
        KickRefresh();
        var cutoff = DateTime.UtcNow - within;
        lock (Gate)
        {
            return Events.Where(e => e.TimeUtc >= cutoff).ToList();
        }
    }

    internal static ChannelState StateOf(string channel)
    {
        lock (Gate)
        {
            return States.TryGetValue(channel, out var s) ? s : ChannelState.Unknown;
        }
    }

    /// <summary>
    /// What HERO cannot see, in the user's words. Rendered in the coverage panel so a green tick
    /// is never mistaken for proof of cleanliness.
    /// </summary>
    internal static IReadOnlyList<string> CoverageNotes()
    {
        KickRefresh();
        var notes = new List<string>();

        if (StateOf(SecurityChannel) != ChannelState.Available)
            notes.Add("Security log: not readable without administrator rights. HERO cannot see " +
                      "account creation, group changes, or a cleared Security log.");

        if (StateOf(DefenderChannel) != ChannelState.Available)
            notes.Add("Windows Defender log: unavailable. HERO cannot tell you if Defender was " +
                      "switched off or given an exclusion.");

        if (StateOf(SystemChannel) != ChannelState.Available)
            notes.Add("System log: unavailable. HERO cannot see new services or service changes.");

        notes.Add("Scheduled-task events are not collected: the Task Scheduler operational log is " +
                  "switched off by default on this PC, so subscribing to it would report nothing " +
                  "while appearing to work.");

        return notes;
    }

    private static void KickRefresh()
    {
        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _lastRefreshTicks) < RefreshIntervalMs) return;
        if (Interlocked.Exchange(ref _refreshing, 1) == 1) return;

        Interlocked.Exchange(ref _lastRefreshTicks, now);
        _ = Task.Run(() =>
        {
            try { Refresh(); }
            catch { /* a log read must never take the guardian down */ }
            finally { Interlocked.Exchange(ref _refreshing, 0); }
        });
    }

    private static void Refresh()
    {
        foreach (var spec in Channels)
        {
            long lastSeen;
            lock (Gate) { LastRecordIds.TryGetValue(spec.Name, out lastSeen); }

            var harvested = new List<SecurityEvent>();
            var state = ChannelState.Available;
            long newest = lastSeen;

            try
            {
                var query = new EventLogQuery(spec.Name, PathType.LogName, spec.Query) { ReverseDirection = true };
                using var reader = new EventLogReader(query);

                for (int i = 0; i < MaxEventsPerRefresh; i++)
                {
                    EventRecord? record;
                    try { record = reader.ReadEvent(); }
                    catch (EventLogException) { break; }

                    if (record is null) break;
                    using (record)
                    {
                        long id = record.RecordId ?? 0;
                        if (id != 0 && id <= lastSeen) break;   // reverse order: everything older follows
                        if (id > newest) newest = id;

                        var parsed = Parse(spec.Name, record);
                        if (parsed is not null) harvested.Add(parsed);
                    }
                }
            }
            catch (EventLogNotFoundException) { state = ChannelState.NotPresent; }
            catch (UnauthorizedAccessException) { state = ChannelState.AccessDenied; }
            catch (EventLogException) { state = ChannelState.AccessDenied; }
            catch { state = ChannelState.Failed; }

            lock (Gate)
            {
                States[spec.Name] = state;
                if (state == ChannelState.Available) LastRecordIds[spec.Name] = newest;
                Events.AddRange(harvested);
                foreach (var harvest in harvested)
                    if (harvest.TimeUtc > _newestEventUtc) _newestEventUtc = harvest.TimeUtc;

                var cutoff = DateTime.UtcNow - Retention;
                Events.RemoveAll(e => e.TimeUtc < cutoff);
                if (Events.Count > MaxRetained) Events.RemoveRange(0, Events.Count - MaxRetained);
            }
        }
    }

    private static readonly Regex NewValue =
        new(@"New value:\s*(.+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static SecurityEvent? Parse(string channel, EventRecord record)
    {
        var time = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;

        string description = "";
        try { description = record.FormatDescription() ?? ""; } catch { /* provider metadata missing */ }

        string serviceName = "", imagePath = "", newStartType = "";
        var properties = ReadProperties(record);

        switch (record.Id)
        {
            case 7045:   // service installed
                if (properties.Count > 0) serviceName = properties[0];
                if (properties.Count > 1) imagePath = properties[1];
                break;

            case 7040:   // service start type changed
                // Property 0 is the display name and property 3 the short name; both are useful
                // and neither is guaranteed, so whichever is present is taken.
                if (properties.Count > 3 && properties[3].Length > 0) serviceName = properties[3];
                else if (properties.Count > 0) serviceName = properties[0];

                // Property 1 is the old start type and 2 the new one. Verified against live
                // records on this machine: ["Claude", "auto start", "disabled", "CoworkVMService"]
                // and the same event in reverse, ["Claude", "disabled", "auto start", ...].
                if (properties.Count > 2) newStartType = properties[2];
                break;
        }

        // 5007 carries the interesting part in its "New value:" line — typically a registry path
        // ending in Exclusions\Paths\<something>. The rest of the description is boilerplate.
        string detail = description;
        if (record.Id == 5007)
        {
            var m = NewValue.Match(description);
            if (m.Success) detail = m.Groups[1].Value;
        }

        return new SecurityEvent(
            channel,
            record.Id,
            time,
            KnownSoftware.Sanitise(Summarise(record.Id), 120),
            KnownSoftware.Sanitise(serviceName, 120),
            KnownSoftware.Sanitise(imagePath, 300),
            KnownSoftware.Sanitise(detail, 400),
            KnownSoftware.Sanitise(newStartType, 60));
    }

    private static List<string> ReadProperties(EventRecord record)
    {
        var values = new List<string>(6);
        try
        {
            foreach (var property in record.Properties)
                values.Add(property.Value?.ToString() ?? "");
        }
        catch { /* some providers refuse property access */ }
        return values;
    }

    private static string Summarise(int id) => id switch
    {
        5001 => "Defender real-time protection was turned off",
        5004 => "Defender real-time protection configuration changed",
        5007 => "Defender configuration changed",
        5010 => "Defender spyware scanning was turned off",
        5012 => "Defender virus scanning was turned off",
        5013 => "Defender blocked a change to its own settings",
        7040 => "A service start type was changed",
        7045 => "A new service was installed",
        104 => "An event log was cleared",
        1102 => "The Security log was cleared",
        _ => "Security-relevant system event",
    };
}

/// <summary>
/// HERO's maintenance half legitimately clears logs, disables startup items and changes settings.
/// Without a way to say "that was us", the app detects itself as an attacker the first time the
/// user runs a cleanup.
///
/// The maintenance code calls <see cref="NoteOwnAction"/> immediately before performing one of
/// these actions; the evasion rules consult <see cref="IsOurs"/> before scoring a matching event.
/// The window is short on purpose — a suppression that lasts is a suppression an attacker can
/// hide behind.
/// </summary>
internal static class MaintenanceSelfExclusion
{
    internal const string ClearedEventLog = "cleared-event-log";
    internal const string ChangedServiceStartType = "changed-service-start-type";
    internal const string ChangedDefenderSetting = "changed-defender-setting";

    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
    private static readonly ConcurrentDictionary<string, DateTime> Actions = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Called by HERO's own maintenance code just before it does the thing.</summary>
    internal static void NoteOwnAction(string kind) => Actions[kind] = DateTime.UtcNow;

    internal static bool IsOurs(string kind, DateTime eventUtc) =>
        Actions.TryGetValue(kind, out var when) && (eventUtc - when).Duration() <= Window;
}

/// <summary>
/// Interference with Microsoft Defender.
///
/// This rule is the SOLE owner of every Defender observation, command lines included. The
/// alternative — one rule scoring the Add-MpPreference command line and another scoring the
/// resulting 5007 event — would let a single deliberate keystroke sequence produce two signals in
/// two families, which is exactly the corroboration requirement being defeated by one action. The
/// user adding D:\My projects or a cargo target directory as an exclusion is a real and common
/// developer action on this machine.
///
/// Attribution is honest about its limits: Windows does not say which process changed the setting,
/// so HERO only attaches the event to a process that independently shows a Defender command line
/// or is named in the changed value. Everything else is reported machine-wide by
/// <see cref="EvasionRules.MachineSignals"/> with the process recorded as unknown.
/// </summary>
internal sealed class DefenderTamperRule : IDetectionRule
{
    public string Id => "evade.defender-tampering";
    public string Description => "Microsoft Defender was switched off or told to ignore something";

    private static readonly TimeSpan Lookback = TimeSpan.FromMinutes(30);

    internal static readonly Regex DefenderCmdlet = new(
        @"(?:Add|Set|Remove)-MpPreference|Set-MpComputerStatus|MpCmdRun(?:\.exe)?\s+-RemoveDefinitions|" +
        @"-DisableRealtimeMonitoring|-ExclusionPath|-ExclusionProcess|-ExclusionExtension|" +
        @"DisableAntiSpyware|DisableAntiVirus",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        bool commandLineMatches = p.CommandLine.Length > 0 && DefenderCmdlet.IsMatch(p.CommandLine);

        // Cheapest possible exit for the overwhelmingly common case: nothing has happened and this
        // process is not touching Defender.
        if (!commandLineMatches && !WindowsEventFeed.AnyRecent(Lookback)) yield break;

        var events = WindowsEventFeed.Recent(Lookback)
            .Where(e => e.Channel == WindowsEventFeed.DefenderChannel)
            .Where(e => !MaintenanceSelfExclusion.IsOurs(MaintenanceSelfExclusion.ChangedDefenderSetting, e.TimeUtc))
            .Where(e => commandLineMatches || NamesThisProcess(e, p))
            .ToList();

        // A command line that is trying to change Defender right now, before any event has landed.
        if (commandLineMatches && events.Count == 0)
        {
            double pending = RuleKit.UserIsAtThisProcess(p, context) ? 5 : 12;
            yield return RuleKit.Emit(Id, "Something is changing Defender's settings",
                $"{p.FileName} is running a command that turns off Defender or adds an exclusion to " +
                "it. Excluding your build folders is a normal thing to do deliberately; having it " +
                "happen without you is how malware clears the way for itself.",
                pending, RuleKit.Families.Evasion, Severity.High,
                KnownSoftware.Sanitise(p.CommandLine, 240));
            yield break;
        }

        foreach (var e in events)
        {
            double weight = e.EventId switch
            {
                5001 => 26,                                       // real-time protection off
                5010 or 5012 => 22,                               // scanning off
                5007 when MentionsExclusion(e) => 20,
                5013 => 10,                                       // an attempt Defender itself blocked
                5007 => 8,
                _ => 6,
            };

            // Evidence that the user is present may only move this toward "ask", never below it.
            if (RuleKit.UserIsAtThisProcess(p, context)) weight = Math.Min(weight, 12);

            yield return RuleKit.Emit(Id, e.Summary,
                e.EventId == 5001
                    ? "Defender's real-time protection was switched off. Almost nothing legitimate " +
                      "does this without telling you, and it leaves this PC unprotected until it is " +
                      "switched back on."
                    : MentionsExclusion(e)
                        ? "Defender was told to stop scanning something. Developers exclude build " +
                          "folders on purpose for speed; if you did not just do that, something has " +
                          "made itself invisible to your antivirus."
                        : "Defender's configuration changed. HERO records these so a change you did " +
                          "not make does not go unnoticed.",
                weight, RuleKit.Families.Evasion,
                weight >= 20 ? Severity.Critical : Severity.Medium,
                e.Detail);
        }
    }

    private static bool MentionsExclusion(SecurityEvent e) =>
        e.Detail.Contains("Exclusions", StringComparison.OrdinalIgnoreCase);

    private static bool NamesThisProcess(SecurityEvent e, ProcessRecord p)
    {
        if (e.Detail.Length == 0 || p.ImagePath.Length == 0) return false;
        if (e.Detail.Contains(p.ImagePath, StringComparison.OrdinalIgnoreCase)) return true;
        var dir = p.Directory;
        return dir is { Length: > 3 } && e.Detail.Contains(dir, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// An event log was cleared.
///
/// Nothing on a healthy workstation clears the Security or System log. The realistic false
/// positive is the user running a "debloat" or cleanup script — including HERO's own maintenance
/// half, which is why <see cref="MaintenanceSelfExclusion"/> exists and is consulted first.
/// </summary>
internal sealed class EventLogClearedRule : IDetectionRule
{
    public string Id => "evade.event-log-cleared";
    public string Description => "A Windows event log was wiped";

    private static readonly TimeSpan Lookback = TimeSpan.FromMinutes(30);

    private static readonly Regex ClearCommand = new(
        @"wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|Clear-EventLog\b|Remove-EventLog\b|ClearEventlog\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        var p = RuleKit.ProcessOf(subject);
        if (p is null) yield break;

        // Without the Security log HERO cannot attribute a clear to an account, so a clear event is
        // only ever attached to a process that is independently running a clear command. The
        // unattributed half is reported machine-wide by EvasionRules.MachineSignals instead.
        if (p.CommandLine.Length == 0 || !ClearCommand.IsMatch(p.CommandLine)) yield break;

        var cleared = WindowsEventFeed.Recent(Lookback)
            .Where(e => e.EventId is 104 or 1102)
            .Where(e => !MaintenanceSelfExclusion.IsOurs(MaintenanceSelfExclusion.ClearedEventLog, e.TimeUtc))
            .ToList();

        double weight = cleared.Count > 0 ? 20 : 14;
        if (RuleKit.UserIsAtThisProcess(p, context)) weight = Math.Min(weight, 10);

        yield return RuleKit.Emit(Id, "Windows event logs are being cleared",
            $"{p.FileName} is clearing Windows event logs. Those logs are the record of what happened " +
            "on this PC; cleanup scripts sometimes wipe them, and so does anything that would rather " +
            "you could not look back.",
            weight, RuleKit.Families.Evasion, Severity.High,
            KnownSoftware.Sanitise(p.CommandLine, 240));
    }
}

/// <summary>
/// A service's start type changed (System 7040).
///
/// Windows Update and servicing do this legitimately, and developers deliberately disable Windows
/// Search, SysMain and Windows Update for performance — so the ordinary case scores almost
/// nothing. Only the security services carry real weight.
/// </summary>
internal sealed class ServiceStartTypeRule : IDetectionRule
{
    public string Id => "evade.service-start-type";
    public string Description => "A service was set to start differently, or not at all";

    private static readonly TimeSpan Lookback = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Services whose start type only changes for a security-relevant reason.
    ///
    /// BITS and wuauserv are deliberately NOT here. Verified live on this machine: System 7040
    /// records "The start type of the Background Intelligent Transfer Service service was changed
    /// from demand start to auto start", which Windows Update and Delivery Optimization do several
    /// times a day — it was the single highest-scoring finding the whole catalogue produced against
    /// a clean machine, at 22 points and Critical severity. Windows Update is also the service this
    /// user is most likely to have disabled on purpose.
    /// </summary>
    private static readonly IReadOnlySet<string> SecurityServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "WinDefend", "WdNisSvc", "WdFilter", "WdBoot", "MDCoreSvc", "Sense", "wscsvc",
        "SecurityHealthService", "MpsSvc", "EventLog", "SgrmBroker", "VSS",
    };

    private static readonly Regex ServiceCommand = new(
        @"sc(?:\.exe)?\s+(?:config|stop|delete)\b|Set-Service\b|Stop-Service\b|" +
        @"-StartupType\s+Disabled|net(?:\.exe)?\s+stop\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        // A service subject attributes the change to the exact service it happened to.
        if (RuleKit.PersistenceOf(subject) is { Category: PersistenceCategory.Service } entry)
        {
            if (!WindowsEventFeed.AnyRecent(Lookback)) yield break;

            var events = WindowsEventFeed.Recent(Lookback)
                .Where(e => e.EventId == 7040)
                .Where(e => !MaintenanceSelfExclusion.IsOurs(MaintenanceSelfExclusion.ChangedServiceStartType, e.TimeUtc))
                .Where(e => Matches(e, entry.Name))
                .ToList();

            foreach (var e in events)
            {
                // Only a transition INTO disabled is evasion. A security service being ENABLED, or
                // moved between demand and auto start, is servicing — and 7040 reports both
                // directions with the same event id.
                //
                // THE COMMENT SAID THAT AND THE CODE DID NOT DO IT. The test was
                // e.Detail.Contains("disabled"), and 7040 renders as "...was changed from <old> to
                // <new>.", so the word appears whichever way the change went. Measured on this
                // machine: "The start type of the Claude service was changed from disabled to auto
                // start" — a service being switched ON — matched. For anything in SecurityServices
                // that is 22 points at Critical, so RE-ENABLING Windows Defender was reported as
                // evasion, and with autonomy live that is a finding HERO could act on.
                //
                // The direction is in the event's own data rather than its sentence: property 2 is
                // the new start type, 1 is the old one. The strings are localised but the INDEX is
                // not, which makes this correct on a non-English Windows where a sentence test
                // never could be. The remaining language dependence is the word "disabled" itself,
                // and it still fails the safe way — unrecognised means the ordinary tier, not the
                // critical one.
                bool disabled = e.NewStartType.Contains("disabled", StringComparison.OrdinalIgnoreCase);
                bool security = disabled && SecurityServices.Contains(entry.Name);
                yield return RuleKit.Emit(Id,
                    security ? "A security service was reconfigured" : "A service start type changed",
                    security
                        ? $"The {entry.Name} service — part of this PC's protection — had its startup " +
                          "setting changed. Turning these off is normally the first step in making " +
                          "everything else invisible."
                        : $"The {entry.Name} service had its startup setting changed. Updates and your " +
                          "own tuning both do this; it is recorded so a change you did not make stands out.",
                    security ? 22 : 5, RuleKit.Families.Evasion,
                    security ? Severity.Critical : Severity.Low, e.Detail);
            }
            yield break;
        }

        // Otherwise attribute to a process visibly running a service-control command.
        var p = RuleKit.ProcessOf(subject);
        if (p is null || p.CommandLine.Length == 0 || !ServiceCommand.IsMatch(p.CommandLine)) yield break;

        bool touchesSecurity = SecurityServices.Any(s => p.CommandLine.Contains(s, StringComparison.OrdinalIgnoreCase));
        double weight = touchesSecurity ? 20 : 4;
        if (RuleKit.UserIsAtThisProcess(p, context)) weight = Math.Min(weight, 10);

        yield return RuleKit.Emit(Id,
            touchesSecurity ? "Something is stopping a security service" : "A service is being reconfigured",
            touchesSecurity
                ? $"{p.FileName} is stopping or disabling a Windows security service. If that was not " +
                  "you, this PC is being prepared for something."
                : $"{p.FileName} is changing a Windows service. Recorded for context.",
            weight, RuleKit.Families.Evasion,
            touchesSecurity ? Severity.Critical : Severity.Low,
            KnownSoftware.Sanitise(p.CommandLine, 240));
    }

    private static bool Matches(SecurityEvent e, string serviceName) =>
        e.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase)
        || e.Detail.Contains(serviceName, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// A new service was installed (System 7045).
///
/// This fires legitimately on every GPU driver update, every Docker or WSL update and every
/// anti-cheat install, so the bare event is worth almost nothing. What carries the signal is where
/// the service's program lives.
///
/// The driver case is scored on path alone, deliberately and against the obvious intuition:
/// Driver Signature Enforcement means an unsigned .sys simply cannot load on 64-bit Windows 11, so
/// "unsigned driver" is the case that cannot happen. Real bring-your-own-vulnerable-driver attacks
/// use a validly signed driver dropped somewhere it does not belong.
/// </summary>
internal sealed class ServiceInstalledRule : IDetectionRule
{
    public string Id => "evade.service-installed";
    public string Description => "A new Windows service or driver was installed";

    private static readonly TimeSpan Lookback = TimeSpan.FromMinutes(30);

    public IEnumerable<Signal> Evaluate(Subject subject, DetectionContext context)
    {
        if (!WindowsEventFeed.AnyRecent(Lookback)) yield break;

        // PERSISTENCE SUBJECTS ONLY. There used to be a process arm here, matching a running process
        // whose image equalled the newly-installed service's. It is gone because it could not do its
        // job: a process's command line identifies a binary, and a binary is not a registration, so
        // the arm attributed one service install to every running instance of its executable —
        // including HERO's own dashboard, measured at score 5.33. A service install is a persistence
        // fact and the persistence inventory holds every auto-start service, so the finding belongs
        // on the entry that was created and nowhere else.
        //
        // Known gap, unchanged by this: PersistenceScanner skips services with Start > 2, so a
        // trigger-started service has no subject and its 7045 cannot be attributed to anything.
        var entry = RuleKit.PersistenceOf(subject);
        if (entry is null) yield break;

        var events = WindowsEventFeed.Recent(Lookback).Where(e => e.EventId == 7045).ToList();
        if (events.Count == 0) yield break;

        foreach (var e in events)
        {
            // MATCH ON IDENTITY, NOT ON A BINARY. This rule has been wrong in both directions and
            // both were measured, so the reasoning is recorded rather than the conclusion alone.
            //
            //   UNDER-MATCHING. The first version compared the event's raw ImagePath property — a
            //   COMMAND LINE, quoted and with arguments — against the entry's already-extracted
            //   executable. Only 44 of 780 services on this machine have a registry value that
            //   survives normalisation unchanged, so a rule in the EVASION family was reachable
            //   almost exclusively by services doing the wrong thing, which is precisely what
            //   persist.unquoted-service-path exists to complain about. Quoting your path hid you.
            //
            //   OVER-MATCHING. Extracting both sides and comparing executables fixes that and
            //   introduces a worse fault, because an executable is not a registration. Measured on
            //   this machine: 41 services share `svchost.exe -k netsvcs -p`, 21 share
            //   `-k LocalService -p`, six share `lsass.exe`, `tcpip.sys` backs both Tcpip and
            //   Tcpip6, and edgeupdate/edgeupdatem are one binary differing only in /svc versus
            //   /medsvc. One install would have raised a finding against every sibling. It also
            //   matched any running PROCESS of the image: HERO scored 5.33 against its own
            //   dashboard for the installation of its own guardian service.
            //
            // Normalising the whole command line instead of the executable narrows it but does not
            // fix it — the collisions above are collisions of the full command line too.
            //
            // So: the NAME identifies the registration and the IMAGE confirms it. 7045 reports the
            // DisplayName, the registry is keyed by the short name, and the scanner now carries
            // both. Neither half is sufficient alone and each covers the other's blind spot —
            // checked against all 780 services on this machine:
            //
            //   name alone  is ambiguous for SerCx and SerCx2, two in-box drivers both called
            //               "Serial UART Support Library" but running different .sys files;
            //   image alone is ambiguous for 10 groups, one of 251 services behind svchost.exe.
            //
            // Together they are unique for every service present. See PersistenceEntry.DisplayName
            // for the case this still cannot reach.
            string eventImage = e.ImagePath.Length > 0
                ? PersistenceScanner.ServiceExecutable(e.ImagePath)
                : "";

            // BOTH SIDES THROUGH THE SAME RESOLVER, for the reason section 34 records about paths:
            // normalising one side only is how a comparison quietly stops being true. A service's
            // display name is usually an indirect string, and USUALLY the SCM resolves it before
            // reporting it — but not always. Tcpip6 on this machine is registered as
            // "@todo.dll,-100;Microsoft IPv6 Protocol Driver", a placeholder Windows itself cannot
            // resolve, so the SCM reports the raw text and an event would too. Running the event's
            // name through the same function makes the two agree whichever form arrives.
            string eventName = PersistenceScanner.ResolveDisplayName(e.ServiceName).Trim();

            bool named = entry is { Category: PersistenceCategory.Service }
                && (entry.Name.Equals(eventName, StringComparison.OrdinalIgnoreCase)
                    || (entry.DisplayName.Length > 0
                        && entry.DisplayName.Trim().Equals(eventName, StringComparison.OrdinalIgnoreCase)));

            // Confirmation is skipped when the event carried no image, rather than treated as a
            // mismatch: the name is still evidence, and an absent property is not a contradiction.
            bool imageAgrees = eventImage.Length == 0
                || entry!.ImagePath.Length == 0
                || entry.ImagePath.Equals(eventImage, StringComparison.OrdinalIgnoreCase);

            if (!named || !imageAgrees) continue;

            if (eventImage.Length == 0) eventImage = entry!.ImagePath;

            // Classifying the raw property left every quoted path in PathClass.Unknown — which
            // IsUserWritable treats as writable — and stopped ".sys" ever matching. Verified against
            // the WSL and Google Play Games service installs recorded on this machine.
            var imagePath = eventImage.Length > 0 ? eventImage : entry?.ImagePath ?? "";
            var location = KnownSoftware.ClassifyPath(imagePath);
            bool isDriver = imagePath.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);

            // A validly signed driver inside a vendor's own Program Files installation is what a
            // GPU driver, an anti-cheat and BlueStacks all look like — and BlueStacks reinstalls
            // C:\Program Files\BlueStacks_nxt\BstkDrv_nxt.sys on every auto-update on this machine.
            // Bring-your-own-vulnerable-driver drops the .sys somewhere the user can write, so the
            // full weight is kept for exactly that case.
            bool vendorDriver = isDriver
                && location == PathClass.ProgramFiles
                && context.Signature(imagePath) is { State: SignatureState.Valid };

            double weight;
            string explanation;

            bool inBoxDriver = isDriver && location is PathClass.SystemProtected or PathClass.DriverStore;

            if (isDriver && !inBoxDriver && !vendorDriver)
            {
                weight = 24;
                explanation = $"A kernel driver was installed as the service {e.ServiceName}, and it " +
                              "does not live in the Windows driver folder. Drivers run with complete " +
                              "control of this PC, and dropping a signed-but-vulnerable one somewhere " +
                              "unusual is how modern attacks disable security software.";
            }
            else if (vendorDriver)
            {
                weight = 6;
                explanation = $"A kernel driver was installed as the service {e.ServiceName}. It is " +
                              "properly signed and lives inside its own installation, which is what a " +
                              "graphics driver, an emulator or an anti-cheat update looks like.";
            }
            else if (!isDriver && KnownSoftware.IsUserWritable(location) && !KnownSoftware.IsVolatile(location))
            {
                weight = 10;
                explanation = $"The service {e.ServiceName} was installed and runs a program from a " +
                              "folder you can write to. Windows Defender itself does this, so it is not " +
                              "damning on its own.";
            }
            else if (KnownSoftware.IsVolatile(location))
            {
                weight = 18;
                explanation = $"The service {e.ServiceName} was installed and runs a program from a " +
                              "temporary folder. Services are meant to be permanent; their programs " +
                              "should not live somewhere that gets emptied.";
            }
            else
            {
                weight = 4;
                explanation = $"The service {e.ServiceName} was installed. Driver and application " +
                              "updates do this routinely; it is recorded so you can see what changed.";
            }

            yield return RuleKit.Emit(Id,
                isDriver ? "A new kernel driver was installed" : "A new service was installed",
                explanation, weight, RuleKit.Families.Evasion,
                weight >= 18 ? Severity.Critical : Severity.Low,
                $"{e.ServiceName} · {KnownSoftware.Sanitise(imagePath, 240)}");
        }
    }
}

/// <summary>
/// The evasion family's machine-level surface.
///
/// Some of what this family observes has no process to blame. Windows does not record which
/// process added a Defender exclusion or cleared a log, and HERO refuses to guess — a wrong
/// attribution is worse than an unattributed fact, because it puts an innocent program on a list
/// the response engine can act on.
///
/// The integrator wires <see cref="MachineSignals"/> into the machine timeline and
/// <see cref="CoverageNotes"/> into the coverage panel. Nothing here is attached to a subject, so
/// nothing here can contribute to a per-process score, which is the intended safety property.
/// </summary>
internal static class EvasionRules
{
    private static readonly TimeSpan Lookback = TimeSpan.FromHours(6);

    /// <summary>Security-relevant events that could not be attributed to any process.</summary>
    internal static IReadOnlyList<Signal> MachineSignals()
    {
        var signals = new List<Signal>();

        foreach (var e in WindowsEventFeed.Recent(Lookback))
        {
            var severity = e.EventId switch
            {
                5001 or 1102 or 104 => Severity.High,
                5010 or 5012 or 5007 => Severity.Medium,
                _ => Severity.Low,
            };

            signals.Add(RuleKit.Emit("evade.machine-event", e.Summary,
                $"{e.Summary}. HERO cannot tell which program did this — Windows does not record it — " +
                "so it is shown as a change to the PC rather than blamed on anything.",
                0, RuleKit.Families.Context, severity,
                $"{e.Channel} · event {e.EventId} · {e.TimeUtc:u} · {e.Detail}"));
        }

        return signals;
    }

    /// <summary>What HERO cannot see. Shown to the user verbatim.</summary>
    internal static IReadOnlyList<string> CoverageNotes() => WindowsEventFeed.CoverageNotes();
}
