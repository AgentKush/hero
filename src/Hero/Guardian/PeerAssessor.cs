using System.Collections.Concurrent;
using System.Net;
using Hero.Interop;

namespace Hero.Guardian;

internal enum PeerVerdict
{
    /// <summary>Loopback, this LAN, or a listener. Not a peer at all.</summary>
    Local,
    /// <summary>
    /// Not judged yet, because the owning program's signature has not been verified.
    ///
    /// This exists because the alternative is worse. Verification is a background job at roughly
    /// 22ms per unseen image, so for the first seconds a connection's owner is simply unknown —
    /// and an unknown signature previously fell through to <see cref="Unusual"/>, which labelled
    /// 49 of 54 connections "worth a look" while giving the reason "Nothing notable". Not knowing
    /// something is not evidence against it.
    /// </summary>
    Unknown,
    /// <summary>This program has talked to this endpoint before and nothing has changed.</summary>
    Familiar,
    /// <summary>A signed program doing something ordinary on an ordinary port.</summary>
    Ordinary,
    /// <summary>Nothing damning, but at least one thing here is not typical.</summary>
    Unusual,
    /// <summary>Several things line up badly. Worth looking at.</summary>
    Suspicious,
}

internal sealed record PeerAssessment(
    PeerVerdict Verdict,
    string Host,
    string Reason,
    Severity Severity);

/// <summary>
/// Judges an individual network connection.
///
/// There is no threat-intelligence feed behind this and deliberately so: sending the list of
/// every address this machine talks to to a third party would be a far larger privacy cost than
/// the judgement is worth. Everything below is derived from evidence already on the machine:
///
///   * who owns the socket, and whether that program is signed and by whom;
///   * whether HERO has seen this program use this endpoint before (the learned baseline);
///   * what the port conventionally means;
///   * whether the address is even outside this network.
///
/// Hostnames come from a reverse DNS lookup, which asks the machine's own configured resolver —
/// the same resolver that performed the original forward lookup a moment earlier, so it learns
/// nothing it did not already know. It is still a network request, so it is a setting, and it is
/// stated plainly rather than buried.
/// </summary>
internal sealed class PeerAssessor
{
    private readonly ConcurrentDictionary<string, string> _hostnames = new();
    private readonly ConcurrentDictionary<string, byte> _pending = new();

    /// <summary>Reverse DNS is the only thing in HERO that touches the network.</summary>
    internal bool ResolveHostnames { get; set; } = true;

    /// <summary>
    /// Ports that are ordinary for almost any program. Everything else is not condemned, merely
    /// not automatically excused.
    /// </summary>
    private static readonly HashSet<int> OrdinaryPorts = new()
    {
        80, 443, 8080, 8443,      // web
        53, 853,                  // DNS, DNS over TLS
        123,                      // NTP
        993, 995, 587, 465, 25,   // mail
        22,                       // ssh
        3478, 5349,               // STUN/TURN, used by every voice chat
        5228, 5229, 5230,         // Google services push
        1935,                     // RTMP
    };

    /// <summary>
    /// Ports conventionally used by mining pools and by the default configuration of common
    /// remote-access tooling. Presence is a prompt to look, not a conviction: plenty of ordinary
    /// software picks high ports, and stratum ports are not reserved.
    /// </summary>
    private static readonly HashSet<int> NotableOutboundPorts = new()
    {
        3333, 4444, 5555, 6666, 7777, 8888, 9999,   // common stratum / default C2 ports
        14444, 45700,                                // monero pools
        1337, 31337,                                 // traditional backdoor ports
        5938,                                        // TeamViewer
        6568,                                        // AnyDesk
    };

    /// <summary>
    /// Verdicts computed by the guardian service, keyed by connection. Non-empty only when the
    /// dashboard is reading over IPC.
    /// </summary>
    private volatile Dictionary<string, PeerAssessment>? _remote;

    /// <summary>Publishes the service's assessments so <see cref="Assess"/> can return them.</summary>
    internal void AcceptRemote(Dictionary<string, PeerAssessment> verdicts) => _remote = verdicts;

    internal PeerAssessment Assess(Connection connection, ProcessRecord? owner,
                                   SignatureInfo? signature, Baseline baseline)
    {
        // When the guardian runs in the service, it has already judged this connection against
        // the real learned baseline. Re-deriving it here would need that entire baseline shipped
        // across the pipe, and would quietly disagree with the service whenever the two drifted.
        if (_remote is { } remote
            && remote.TryGetValue(Service.Ipc.GuardianProtocol.ConnectionKey(connection), out var known))
        {
            return known;
        }

        if (!connection.IsExternal)
        {
            // Host must stay an address or a name. Putting prose in it made the Peer column read
            // "this machine or this network" for eighty rows, which is not a peer.
            string local = connection.IsListening
                ? $"{connection.LocalAddress}:{connection.LocalPort}"
                : connection.RemoteAddress?.ToString() ?? "";

            return new PeerAssessment(PeerVerdict.Local, local,
                connection.IsListening
                    ? "Listening for incoming connections. Not reaching out anywhere."
                    : "Loopback or a private address on your own network.",
                Severity.Safe);
        }

        string host = HostnameFor(connection.RemoteAddress);
        var reasons = new List<string>();
        int concern = 0;

        // ---- who owns the socket
        bool signed = signature is { State: SignatureState.Valid };
        bool expired = signature is { State: SignatureState.Expired };
        bool broken = signature is { State: SignatureState.Invalid };
        bool unsigned = signature is { State: SignatureState.Unsigned };

        if (broken) { concern += 3; reasons.Add("the program's signature is present but invalid"); }
        else if (unsigned) { concern += 1; reasons.Add("the program is unsigned"); }
        else if (signed) reasons.Add($"signed by {signature!.Signer}");
        else if (expired) reasons.Add($"signed by {signature!.Signer}, certificate expired");

        // ---- has this pairing happened before
        bool familiar = false;
        if (owner is not null && !owner.PathUnavailable)
        {
            var entity = baseline.Find(owner.ImagePath);
            if (entity is not null && entity.Peers.Count > 0)
            {
                var key = connection.RemoteAddress?.ToString() ?? "";
                familiar = entity.Peers.Keys.Any(k => k.StartsWith(key, StringComparison.OrdinalIgnoreCase));
                if (familiar) reasons.Add("this program has used this endpoint before");
            }
        }

        // ---- what the port conventionally means
        if (NotableOutboundPorts.Contains(connection.RemotePort))
        {
            concern += 2;
            reasons.Add($"port {connection.RemotePort} is conventionally used by mining pools or remote-access tools");
        }
        // Port 0 is not a port: it is how Windows reports "no remote endpoint" for a listener.
        else if (connection.RemotePort is > 0 and < 1024 && !OrdinaryPorts.Contains(connection.RemotePort))
        {
            concern += 1;
            reasons.Add($"port {connection.RemotePort} is an unusual privileged port");
        }

        // ---- an unsigned program reaching the internet is the combination that matters
        if (unsigned && !familiar) concern += 1;

        // An owner whose signature has not been checked yet is UNKNOWN, never Unusual. The only
        // way to reach Unusual or Suspicious is to have accumulated actual concern.
        bool signatureKnown = signature is not null && signature.State != SignatureState.Unknown;

        var verdict = concern switch
        {
            >= 4 => PeerVerdict.Suspicious,
            >= 2 => PeerVerdict.Unusual,
            _ when familiar => PeerVerdict.Familiar,
            _ when signed || expired => PeerVerdict.Ordinary,
            _ when !signatureKnown => PeerVerdict.Unknown,
            _ => PeerVerdict.Ordinary,
        };

        if (verdict == PeerVerdict.Unknown)
            reasons.Add("still checking the program that owns this connection");

        var severity = verdict switch
        {
            PeerVerdict.Suspicious => Severity.High,
            PeerVerdict.Unusual => Severity.Medium,
            PeerVerdict.Unknown => Severity.Safe,
            PeerVerdict.Familiar => Severity.Safe,
            PeerVerdict.Ordinary => Severity.Safe,
            _ => Severity.Safe,
        };

        string reason = reasons.Count > 0
            ? char.ToUpperInvariant(reasons[0][0]) + reasons[0][1..] +
              (reasons.Count > 1 ? "; " + string.Join("; ", reasons.Skip(1)) + "." : ".")
            : "Nothing notable.";

        return new PeerAssessment(verdict, host, reason, severity);
    }

    /// <summary>
    /// Hostname for an address, from cache. Never blocks: an unknown address returns its literal
    /// form and a background lookup fills the cache for the next refresh. A synchronous reverse
    /// lookup on the UI thread would stall the whole table on a single unreachable resolver.
    /// </summary>
    private string HostnameFor(IPAddress? address)
    {
        if (address is null) return "";
        string key = address.ToString();

        if (_hostnames.TryGetValue(key, out var known)) return known;
        if (!ResolveHostnames) return key;
        if (!_pending.TryAdd(key, 0)) return key;

        _ = Task.Run(async () =>
        {
            // THE LOOKUP IS HELD IN A LOCAL, AND ITS FAULT IS OBSERVED SEPARATELY, because
            // WaitAsync does not cancel what it stops waiting for. On timeout the proxy faults with
            // TimeoutException — which the catch below handles — while the real DNS task carries on
            // and faults a moment later with nobody listening. A faulted task nobody observes is
            // rethrown on the finalizer thread, so every one of them arrived as
            // "*** UNHANDLED EXCEPTION (unobserved task) ***" in service.log, complete with a stack
            // trace, for what is simply an address with no PTR record.
            //
            // Measured on this machine after the guardian moved into the service: roughly twenty a
            // minute against 165 live sockets, 188 of them in the first nine minutes of uptime. It
            // reads as a service in trouble and it is nothing of the kind.
            var lookup = Dns.GetHostEntryAsync(address);
            _ = lookup.ContinueWith(static t => _ = t.Exception,
                                    TaskContinuationOptions.OnlyOnFaulted |
                                    TaskContinuationOptions.ExecuteSynchronously);
            try
            {
                var entry = await lookup.WaitAsync(TimeSpan.FromSeconds(3));
                _hostnames[key] = string.IsNullOrWhiteSpace(entry.HostName) ? key : entry.HostName;
            }
            catch
            {
                // No PTR record is the common case for cloud addresses; cache the failure so the
                // same address is not looked up again every refresh.
                _hostnames[key] = key;
            }
            finally { _pending.TryRemove(key, out _); }
        });

        return key;
    }
}
