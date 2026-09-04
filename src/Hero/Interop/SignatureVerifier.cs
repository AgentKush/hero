using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Hero.Interop;

internal enum SignatureState
{
    /// <summary>Not yet checked.</summary>
    Unknown,
    /// <summary>Signature chains to a trusted root and the digest matches.</summary>
    Valid,
    /// <summary>No embedded signature and no catalog entry.</summary>
    Unsigned,
    /// <summary>Signed but the signature failed validation (tampered, untrusted root, revoked).</summary>
    Invalid,
    /// <summary>
    /// Correctly signed, but the signing certificate is outside its validity period.
    ///
    /// This is deliberately NOT <see cref="Invalid"/>. Verified on this machine: Git for Windows
    /// ships bash.exe and sh.exe signed by a certificate that expired on 5 June 2026, and Windows
    /// itself reports them this way. Nothing has been tampered with — a certificate simply aged
    /// out. Treating that as equivalent to a broken digest would flag ordinary, correctly-signed
    /// software as malicious, which is precisely the false positive HERO exists to avoid.
    /// </summary>
    Expired,
    /// <summary>The file could not be read (locked, deleted, access denied).</summary>
    Unreadable,
}

internal enum SignatureKind { None, Embedded, Catalog }

internal sealed record SignatureInfo(
    SignatureState State,
    SignatureKind Kind,
    string Signer,
    string CatalogFile,
    int HResult)
{
    internal static readonly SignatureInfo Unreadable =
        new(SignatureState.Unreadable, SignatureKind.None, "", "", 0);

    /// <summary>True only for a signature that fully validated.</summary>
    internal bool IsTrusted => State == SignatureState.Valid;

    /// <summary>
    /// A signature that exists but failed validation is materially worse than no signature at
    /// all — it means tampering, revocation or an untrusted issuer. An expired certificate is
    /// explicitly excluded: that is ageing, not tampering.
    /// </summary>
    internal bool IsBroken => State == SignatureState.Invalid;

    /// <summary>True when a real publisher identity was established, expiry notwithstanding.</summary>
    internal bool HasKnownPublisher => State is SignatureState.Valid or SignatureState.Expired
                                       && Signer.Length > 0;

    internal string Describe() => State switch
    {
        SignatureState.Valid when Kind == SignatureKind.Catalog => $"Catalog-signed · {Signer}",
        SignatureState.Valid => $"Signed · {Signer}",
        SignatureState.Unsigned => "Unsigned",
        SignatureState.Expired => $"Signed · {Signer} (certificate expired)",
        SignatureState.Invalid => $"Invalid signature (0x{HResult:X8})",
        SignatureState.Unreadable => "Unreadable",
        _ => "Unknown",
    };
}

/// <summary>
/// Authenticode verification with catalog fallback.
///
/// This exists because the naive approach is badly wrong. Verified on this machine:
/// notepad.exe and powershell.exe carry NO embedded signature — they are catalog-signed
/// through Microsoft-Windows-*.cat. An implementation that only checks embedded
/// signatures reports large parts of Windows as "unsigned", which would make an
/// unsigned-binary heuristic fire on the operating system itself.
///
/// Measured cost: ~43ms per unique image (61 images in 2.6s). Far too slow for a
/// per-second monitor loop, hence the cache keyed on path + size + last-write time,
/// which also invalidates automatically when a binary is replaced on disk.
/// </summary>
internal sealed class SignatureVerifier
{
    private readonly record struct CacheKey(string Path, long Length, long WriteTicks);

    private readonly ConcurrentDictionary<CacheKey, SignatureInfo> _cache = new();

    /// <summary>
    /// Images that could not even be stat'd, and when that was decided.
    ///
    /// Separate from <see cref="_cache"/> out of necessity: the normal cache key is (path, length,
    /// write time), and a file that cannot be stat'd has no length and no write time to key on.
    ///
    /// This exists because "cannot read it" was previously returned WITHOUT being recorded, and an
    /// unrecorded answer is indistinguishable from no answer. <see cref="TryGetCached"/> kept
    /// saying null, the service kept leaving the path out of its signature table, the dashboard
    /// kept counting the image as unverified, and the refresh loop kept asking again — so the
    /// posture line sat at "Still checking signatures: 265 of 344" indefinitely. The service's own
    /// log shows the same shortfall in every session it ever ran: ~350 processes, ~282 signatures.
    ///
    /// Roughly 140 processes on this machine expose no readable image path to anything short of
    /// LocalSystem, and a handful (System, Secure System, Registry, Memory Compression) have no
    /// backing file at all, at any privilege. For those, "unreadable" is the true and final answer
    /// and belongs in the cache like any other.
    /// </summary>
    private readonly ConcurrentDictionary<string, (SignatureInfo Info, DateTime AtUtc)> _unreadable =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// How long an "unreadable" verdict stands before it is retried.
    ///
    /// Not permanent, because the failure is not always about the file: an image mid-write, a
    /// volume not yet mounted or a path briefly locked would otherwise be branded unreadable for
    /// the life of the process. Not short either, or the retry storm this fixes simply returns.
    /// </summary>
    private static readonly TimeSpan UnreadableRetryAfter = TimeSpan.FromMinutes(5);

    /// <summary>Number of distinct images verified since start (diagnostics).</summary>
    internal int VerifiedCount { get; private set; }

    internal SignatureInfo Verify(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return SignatureInfo.Unreadable;

        CacheKey key;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return NoteUnreadable(path);
            key = new CacheKey(path, fi.Length, fi.LastWriteTimeUtc.Ticks);
        }
        catch
        {
            return NoteUnreadable(path);
        }

        // It is stat-able now, so drop any standing "unreadable" verdict rather than waiting out
        // the retry window: the file came back.
        if (!_unreadable.IsEmpty) _unreadable.TryRemove(path, out _);

        if (_cache.TryGetValue(key, out var hit)) return hit;

        var result = VerifyUncached(path);
        _cache[key] = result;
        VerifiedCount++;
        return result;
    }

    /// <summary>
    /// Records a definitive "could not read this image" so it stops being asked about.
    /// The timestamp is refreshed on every attempt, so the retry window runs from the last try.
    /// </summary>
    private SignatureInfo NoteUnreadable(string path)
    {
        if (!_unreadable.ContainsKey(path)) VerifiedCount++;
        _unreadable[path] = (SignatureInfo.Unreadable, DateTime.UtcNow);
        return SignatureInfo.Unreadable;
    }

    /// <summary>
    /// Verifies many files concurrently.
    ///
    /// Verification is dominated by cold disk reads and per-file crypto, not by lock
    /// contention: a serial pass over the 356 executables referenced by this machine's
    /// persistence entries took 193 seconds (~540ms each, far worse than the ~22ms for
    /// already-resident images). Each call builds its own WINTRUST_DATA and its own catalog
    /// admin context, so the work parallelises cleanly.
    ///
    /// Parallelism is capped rather than unbounded so a background scan cannot saturate every
    /// core and make the machine feel worse than the threat would have.
    /// </summary>
    internal void VerifyMany(IEnumerable<string> paths, CancellationToken ct = default, int? maxParallel = null)
    {
        var distinct = paths
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (distinct.Count == 0) return;

        int workers = maxParallel ?? Math.Max(2, Math.Min(Environment.ProcessorCount / 2, 12));

        Parallel.ForEach(distinct,
            new ParallelOptions { MaxDegreeOfParallelism = workers, CancellationToken = ct },
            path => { try { Verify(path); } catch { /* one bad file must not abort the batch */ } });
    }

    /// <summary>
    /// Signatures verified by the guardian service, keyed by image path. Non-empty only when the
    /// dashboard is reading over IPC.
    /// </summary>
    private volatile Dictionary<string, SignatureInfo>? _remote;

    /// <summary>
    /// Publishes the service's verified signatures.
    ///
    /// Keyed on path alone, unlike the local cache, which also keys on length and modification
    /// time. The service already did that check when it verified the file; repeating it here would
    /// mean a second stat of every image on every refresh, on the UI thread, to re-derive an
    /// answer that has already been made. A file that changes underneath is caught by the service
    /// on its next verification pass, which is where that check belongs.
    /// </summary>
    /// <remarks>
    /// Rebuilt case-insensitively rather than used as received. Windows paths are case-insensitive
    /// but a JSON dictionary is not, and the snapshot genuinely contains both
    /// <c>C:\Windows\System32\svchost.exe</c> and <c>C:\WINDOWS\system32\svchost.exe</c> — the two
    /// spellings come from different APIs for the same file. Keyed ordinally, every lookup using
    /// the other spelling missed, and the UI reported "still checking" for signatures it already
    /// had. Duplicates are assigned rather than added, since by definition they collide.
    /// </remarks>
    internal void AcceptRemote(Dictionary<string, SignatureInfo> signatures)
    {
        var insensitive = new Dictionary<string, SignatureInfo>(
            signatures.Count, StringComparer.OrdinalIgnoreCase);

        foreach (var (path, signature) in signatures) insensitive[path] = signature;

        _remote = insensitive;
    }

    /// <summary>Cached answer only; never touches disk. Used on the hot monitor path.</summary>
    internal SignatureInfo? TryGetCached(string path)
    {
        if (_remote is { } remote)
            return remote.TryGetValue(path, out var known) ? known : null;

        // Checked before the stat, not after, because the whole point of this entry is that the
        // stat is what fails.
        if (_unreadable.TryGetValue(path, out var negative) &&
            DateTime.UtcNow - negative.AtUtc < UnreadableRetryAfter)
        {
            return negative.Info;
        }

        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return null;
            return _cache.TryGetValue(new CacheKey(path, fi.Length, fi.LastWriteTimeUtc.Ticks), out var v) ? v : null;
        }
        catch { return null; }
    }

    private static SignatureInfo VerifyUncached(string path)
    {
        int hr = VerifyEmbedded(path);
        if (hr == 0)
            return new SignatureInfo(SignatureState.Valid, SignatureKind.Embedded, ReadSigner(path), "", 0);

        // Only "there is no signature here" justifies falling through to catalogs.
        // A present-but-bad signature must stay bad.
        if (hr is Native.TRUST_E_NOSIGNATURE or Native.TRUST_E_SUBJECT_FORM_UNKNOWN or Native.TRUST_E_PROVIDER_UNKNOWN)
        {
            var cat = VerifyCatalog(path);
            if (cat is not null) return cat;
            return new SignatureInfo(SignatureState.Unsigned, SignatureKind.None, "", "", hr);
        }

        return new SignatureInfo(Classify(hr), SignatureKind.Embedded, ReadSigner(path), "", hr);
    }

    /// <summary>
    /// Maps a WinVerifyTrust failure to a state. Only expiry is separated out; every other
    /// failure means the signature cannot be relied on to identify the publisher.
    /// </summary>
    private static SignatureState Classify(int hr) => hr switch
    {
        Native.CERT_E_EXPIRED => SignatureState.Expired,
        // CERT_E_VALIDITYPERIODNESTING: the signature is inside a countersignature whose validity
        // period does not nest correctly. In practice this is the same ageing problem.
        unchecked((int)0x800B0102) => SignatureState.Expired,
        _ => SignatureState.Invalid,
    };

    private static int VerifyEmbedded(string path)
    {
        var fileInfo = new Native.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<Native.WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            return RunWinVerifyTrust(Native.WTD_CHOICE_FILE, pFile);
        }
        finally
        {
            Marshal.DestroyStructure<Native.WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    private static SignatureInfo? VerifyCatalog(string path)
    {
        IntPtr hCatAdmin = IntPtr.Zero, hFile = IntPtr.Zero, hCatInfo = IntPtr.Zero;
        try
        {
            if (!Native.CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                return null;

            hFile = Native.CreateFile(path, Native.GENERIC_READ,
                Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
                IntPtr.Zero, Native.OPEN_EXISTING, Native.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (hFile == Native.INVALID_HANDLE_VALUE) return null;

            uint cbHash = 0;
            Native.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, null, 0);
            if (cbHash == 0) return null;

            var hash = new byte[cbHash];
            if (!Native.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, hash, 0))
                return null;

            // The catalog member tag is the uppercase hex of the file hash.
            string memberTag = Convert.ToHexString(hash);

            IntPtr prev = IntPtr.Zero;
            hCatInfo = Native.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cbHash, 0, ref prev);
            if (hCatInfo == IntPtr.Zero) return null;   // genuinely not in any catalog

            var ci = new Native.CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<Native.CATALOG_INFO>(),
                wszCatalogFile = string.Empty,
            };
            if (!Native.CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) return null;

            var catalogInfo = new Native.WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = ci.wszCatalogFile,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = path,
                hMemberFile = hFile,
                pbCalculatedFileHash = IntPtr.Zero,
                cbCalculatedFileHash = 0,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = hCatAdmin,
            };

            IntPtr pCat = Marshal.AllocHGlobal(Marshal.SizeOf<Native.WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.StructureToPtr(catalogInfo, pCat, false);
                int hr = RunWinVerifyTrust(Native.WTD_CHOICE_CATALOG, pCat);
                string signer = ReadSigner(ci.wszCatalogFile);
                return new SignatureInfo(
                    hr == 0 ? SignatureState.Valid : Classify(hr),
                    SignatureKind.Catalog,
                    signer,
                    Path.GetFileName(ci.wszCatalogFile),
                    hr);
            }
            finally
            {
                Marshal.DestroyStructure<Native.WINTRUST_CATALOG_INFO>(pCat);
                Marshal.FreeHGlobal(pCat);
            }
        }
        catch
        {
            return null;
        }
        finally
        {
            if (hCatInfo != IntPtr.Zero) Native.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hFile != IntPtr.Zero && hFile != Native.INVALID_HANDLE_VALUE) Native.CloseHandle(hFile);
            if (hCatAdmin != IntPtr.Zero) Native.CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static int RunWinVerifyTrust(uint unionChoice, IntPtr pInfo)
    {
        var data = new Native.WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_DATA>(),
            dwUIChoice = Native.WTD_UI_NONE,
            fdwRevocationChecks = Native.WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pInfoStruct = pInfo,
            dwStateAction = Native.WTD_STATEACTION_VERIFY,
            // Revocation checking is deliberately disabled: it performs network I/O to CRL/OCSP
            // endpoints, which would both stall the scan and leak which binaries are on this
            // machine to third parties. HERO makes no network requests by default.
            dwProvFlags = Native.WTD_SAFER_FLAG | Native.WTD_CACHE_ONLY_URL_RETRIEVAL | Native.WTD_REVOCATION_CHECK_NONE,
        };

        var action = Native.WINTRUST_ACTION_GENERIC_VERIFY_V2;
        int hr = Native.WinVerifyTrust(IntPtr.Zero, ref action, ref data);

        // WinVerifyTrust allocates state that must be released with a second call,
        // otherwise every verification leaks a handle.
        data.dwStateAction = Native.WTD_STATEACTION_CLOSE;
        Native.WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        return hr;
    }

    /// <summary>Extracts the signer common name. Returns empty string when unavailable.</summary>
    private static string ReadSigner(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the only in-box way to read an Authenticode signer.
            var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return ExtractCommonName(cert.Subject);
        }
        catch
        {
            return "";
        }
    }

    private static string ExtractCommonName(string subject)
    {
        int i = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
        if (i < 0) return subject;
        var rest = subject[(i + 3)..];
        // Handle quoted CNs containing commas, e.g. CN="Acme, Inc."
        if (rest.StartsWith('"'))
        {
            int close = rest.IndexOf('"', 1);
            return close > 0 ? rest[1..close] : rest.Trim('"');
        }
        int comma = rest.IndexOf(',');
        return (comma > 0 ? rest[..comma] : rest).Trim();
    }
}
