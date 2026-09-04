using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Hero.Core;

namespace Hero.Guardian;

/// <summary>
/// Everything needed to put a quarantined file back exactly as it was.
/// Written before the file is touched; if this cannot be written, nothing is quarantined.
/// </summary>
internal sealed record QuarantineManifest
{
    public required string Id { get; init; }
    public required string OriginalPath { get; init; }
    public required long Length { get; init; }
    public required DateTime QuarantinedUtc { get; init; }
    public required string Reason { get; init; }

    public DateTime OriginalCreatedUtc { get; init; }
    public DateTime OriginalModifiedUtc { get; init; }
    public DateTime OriginalAccessedUtc { get; init; }
    public FileAttributes OriginalAttributes { get; init; }

    /// <summary>Security descriptor in SDDL form, so ACLs survive the round trip.</summary>
    public string OriginalSddl { get; init; } = "";

    /// <summary>SHA-256 of the original bytes, or empty when the file could not be read.</summary>
    public string Sha256 { get; init; } = "";

    /// <summary>
    /// False when HERO could not read the file to encode it — most often because antivirus
    /// is already blocking access. The file is still moved and made non-executable, but its
    /// bytes are stored verbatim.
    /// </summary>
    public bool ContentEncoded { get; init; }

    /// <summary>Why encoding was skipped, when it was.</summary>
    public string EncodingNote { get; init; } = "";

    [JsonIgnore] public string VaultFileName => Id + ".quarantined";
}

internal sealed record QuarantineResult(bool Success, string Message, QuarantineManifest? Manifest);

/// <summary>
/// The quarantine vault.
///
/// Deletion is never HERO's first response. Anything it removes is moved here with a manifest
/// complete enough to put it back byte-for-byte, including timestamps and ACLs. That is what
/// makes autonomous action defensible: a false positive costs the user one click, not a file.
///
/// Neutralisation is deliberately layered, because any single measure can fail:
///   1. the file is moved out of its original location, so nothing referencing that path runs it;
///   2. the extension is replaced with .quarantined, so shell and double-click execution fail;
///   3. the bytes are XOR-masked, so an on-disk scanner does not re-detect the vault copy and
///      the file cannot execute even if renamed back by accident;
///   4. ACLs are rewritten to deny execute to Everyone.
///
/// The XOR mask is obfuscation, not cryptography, and is documented as such. Its job is to stop
/// accidental execution and duplicate AV detections, not to resist an attacker who already has
/// the user's token — such an attacker could simply read the manifest.
/// </summary>
internal sealed class QuarantineVault
{
    /// <summary>Fixed mask. Not a secret and not intended to be one.</summary>
    private static readonly byte[] Mask = "HERO-quarantine-v1"u8.ToArray();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    internal string VaultDirectory => HeroPaths.VaultDir;

    /// <summary>Moves a file into the vault. Returns a failure result rather than throwing.</summary>
    internal QuarantineResult Quarantine(string path, string reason)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return new(false, "No path supplied.", null);

            var info = new FileInfo(path);
            if (!info.Exists) return new(false, $"File no longer exists: {path}", null);

            // Refuse to quarantine HERO's own files or anything under Windows. The protected-set
            // check belongs to the response engine, but the vault enforces a floor of its own so
            // a bug upstream cannot make it eat the operating system.
            //
            // Canonicalised first. Both tests below compared the caller's string as given, so
            // C:\ProgramData\HERO\..\..\Windows\System32\x reached neither branch.
            string canonical;
            try { canonical = Path.GetFullPath(path); }
            catch { return new(false, $"Path could not be resolved: {path}", null); }

            // The WIDE check here, deliberately, unlike the detection sites. This is a floor, and a
            // floor is conservative by definition: quarantining moves a file into the vault and
            // XOR-masks it, so the narrow check would let HERO swallow its own legacy baseline, its
            // own legacy ledger and its own live diagnostic logs under %LOCALAPPDATA%\HERO. That
            // detection is now allowed to LOOK there (a user-writable folder is a hiding place, and
            // pretending otherwise was the bug) does not mean containment should be allowed to eat
            // what it finds there. HERO can still report it, kill it and firewall it.
            if (HeroPaths.IsOwnStateOrDiagnostics(canonical))
                return new(false, "Refusing to quarantine HERO's own files.", null);

            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (canonical.StartsWith(windows + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || canonical.Equals(windows, StringComparison.OrdinalIgnoreCase))
            {
                return new(false, "Refusing to quarantine a file inside the Windows directory.", null);
            }

            Directory.CreateDirectory(VaultDirectory);

            string id = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("n")[..8]}";

            // Capture metadata BEFORE touching anything.
            string sddl = "";
            try { sddl = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All); }
            catch { /* ACL capture is best-effort */ }

            // Hashing reads the file, which antivirus may block. That is not a failure: record
            // it and continue, because a file AV refuses to hand over is one we especially want
            // moved out of the way.
            string sha = "";
            string note = "";
            bool encoded = false;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                sha = Convert.ToHexString(SHA256.HashData(fs));
            }
            catch (Exception ex)
            {
                note = $"Could not read file to hash ({ex.GetType().Name}: {ex.Message.Split('.')[0]}).";
            }

            var manifest = new QuarantineManifest
            {
                Id = id,
                OriginalPath = info.FullName,
                Length = info.Length,
                QuarantinedUtc = DateTime.UtcNow,
                Reason = reason,
                OriginalCreatedUtc = info.CreationTimeUtc,
                OriginalModifiedUtc = info.LastWriteTimeUtc,
                OriginalAccessedUtc = info.LastAccessTimeUtc,
                OriginalAttributes = info.Attributes,
                OriginalSddl = sddl,
                Sha256 = sha,
                ContentEncoded = false,
                EncodingNote = note,
            };

            string vaultPath = Path.Combine(VaultDirectory, manifest.VaultFileName);
            string manifestPath = Path.Combine(VaultDirectory, id + ".json");

            // Write the manifest FIRST. If the process dies mid-operation, an orphan manifest is
            // recoverable; an orphan file with no manifest is not.
            File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, JsonOpts));

            // Clear read-only/hidden/system so the move cannot be refused on attributes alone.
            try { File.SetAttributes(path, FileAttributes.Normal); } catch { }

            try
            {
                File.Move(path, vaultPath);
            }
            catch (Exception ex)
            {
                try { File.Delete(manifestPath); } catch { }

                // Windows returns ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED when antivirus is
                // actively blocking the file. This is NOT a HERO failure and must not be
                // reported as one: it means Defender has already contained the file and is
                // refusing every handle to it, including the one a move needs. Verified against
                // a real detection on this machine — File.Move on a Defender-blocked binary
                // throws exactly this.
                //
                // The right response is to defer to the AV that already won, not to fight it.
                if (IsAntivirusBlock(ex))
                {
                    return new(false,
                        "Already contained by antivirus. Windows is blocking every handle to this " +
                        "file, including the one a move needs, so it cannot execute and does not " +
                        "need quarantining by HERO. Remove it with a targeted Defender scan of its " +
                        "folder, or from Defender's own Protection History.",
                        null);
                }

                // Same-volume moves are a rename and normally succeed even when the content is
                // unreadable. A cross-volume move copies, which AV can also block.
                return new(false, $"Could not move file into the vault: {ex.Message}", null);
            }

            // Try to mask the bytes in place. If AV blocks reading, the move alone plus the
            // extension change and ACL denial is the containment, and the manifest says so.
            try
            {
                MaskInPlace(vaultPath);
                encoded = true;
            }
            catch (Exception ex)
            {
                note = string.IsNullOrEmpty(note)
                    ? $"Content left verbatim ({ex.GetType().Name}). File is still moved, renamed and execute-denied."
                    : note + " Content left verbatim for the same reason.";
            }

            DenyExecute(vaultPath);

            // Close the payload to non-administrators outright, rather than relying on a deny-ACE
            // alone. The vault sits inside a state root that grants Users read so a person can read
            // their own evidence; without this, that read reaches the sample itself. The manifest
            // beside it stays readable, which is the part worth reading.
            Core.HeroPaths.ProtectQuarantinedPayload(vaultPath);

            manifest = manifest with { ContentEncoded = encoded, EncodingNote = note };
            File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, JsonOpts));

            return new(true,
                $"Quarantined to {manifest.VaultFileName}" + (encoded ? " (content masked)." : " (content left verbatim)."),
                manifest);
        }
        catch (Exception ex)
        {
            return new(false, $"{ex.GetType().Name}: {ex.Message}", null);
        }
    }

    /// <summary>Puts a quarantined file back exactly where it was.</summary>
    internal QuarantineResult Restore(string id, bool overwrite = false)
    {
        // See HeroPaths.IsSafeStateId. Without this, a rooted id makes Path.Combine ignore
        // VaultDirectory, and an attacker-authored manifest then drives File.Move as SYSTEM with
        // both source and destination of their choosing.
        if (!Core.HeroPaths.IsSafeStateId(id)) return new(false, "That is not a valid vault id.", null);

        try
        {
            string manifestPath = Path.Combine(VaultDirectory, id + ".json");
            if (!File.Exists(manifestPath)) return new(false, $"No manifest for {id}.", null);

            var manifest = JsonSerializer.Deserialize<QuarantineManifest>(File.ReadAllText(manifestPath), JsonOpts);
            if (manifest is null) return new(false, "Manifest could not be parsed.", null);

            string vaultPath = Path.Combine(VaultDirectory, manifest.VaultFileName);
            if (!File.Exists(vaultPath)) return new(false, "Quarantined payload is missing.", null);

            if (File.Exists(manifest.OriginalPath) && !overwrite)
                return new(false, $"Something already exists at {manifest.OriginalPath}.", manifest);

            // Undo the mask before moving back, otherwise the restored file is corrupt.
            if (manifest.ContentEncoded) MaskInPlace(vaultPath);

            var dir = Path.GetDirectoryName(manifest.OriginalPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            File.Move(vaultPath, manifest.OriginalPath, overwrite);

            // Restore metadata. Timestamps matter: forensic timelines and incremental backups
            // both key off them.
            try
            {
                File.SetCreationTimeUtc(manifest.OriginalPath, manifest.OriginalCreatedUtc);
                File.SetLastWriteTimeUtc(manifest.OriginalPath, manifest.OriginalModifiedUtc);
                File.SetLastAccessTimeUtc(manifest.OriginalPath, manifest.OriginalAccessedUtc);
                File.SetAttributes(manifest.OriginalPath, manifest.OriginalAttributes);
            }
            catch { }

            // The security descriptor has to be dealt with in BOTH directions, and getting only the
            // happy path right leaves the file unusable.
            //
            // A same-volume File.Move is a rename, and NTFS does not recompute inherited ACEs on a
            // rename — so the payload carries the VAULT's descriptor to its destination: protected,
            // SYSTEM and Administrators only, plus an explicit deny on execute. Restoring a
            // false positive would put the file back exactly where it belonged and leave it
            // unreadable and unrunnable, while reporting "Restored to ...".
            //
            // So: put back the captured descriptor when there is one, and otherwise hand the file
            // to its new parent's inheritance. Never leave the vault's.
            try
            {
                var fi = new FileInfo(manifest.OriginalPath);

                if (!string.IsNullOrEmpty(manifest.OriginalSddl))
                {
                    var sec = new FileSecurity();
                    sec.SetSecurityDescriptorSddlForm(manifest.OriginalSddl);
                    fi.SetAccessControl(sec);
                }
                else
                {
                    // Capture is best-effort at quarantine time and can legitimately have failed.
                    // Re-enabling inheritance and dropping every explicit rule gives the file the
                    // same descriptor a freshly created file at that path would have — which is
                    // both usable and not a guess at what the original was.
                    var sec = fi.GetAccessControl();
                    foreach (FileSystemAccessRule rule in
                             sec.GetAccessRules(includeExplicit: true, includeInherited: false,
                                 typeof(System.Security.Principal.SecurityIdentifier)))
                    {
                        sec.RemoveAccessRuleSpecific(rule);
                    }
                    sec.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
                    fi.SetAccessControl(sec);
                }
            }
            catch { /* the file is back; an imperfect ACL beats refusing to restore it */ }

            File.Delete(manifestPath);
            return new(true, $"Restored to {manifest.OriginalPath}", manifest);
        }
        catch (Exception ex)
        {
            return new(false, $"{ex.GetType().Name}: {ex.Message}", null);
        }
    }

    /// <summary>
    /// Permanently destroys a quarantined item and its manifest.
    ///
    /// This is the only operation in HERO that actually loses data, so it exists behind an
    /// explicit user action and nothing calls it automatically. The payload is overwritten with
    /// zeroes before unlinking: a quarantined file is by definition something the user wanted
    /// gone, and leaving recoverable malware in free space is a poor way to honour that.
    /// </summary>
    internal QuarantineResult Delete(string id)
    {
        // The most dangerous of the three. Unvalidated, a rooted id turns this into "SYSTEM deletes
        // any .json or .quarantined file on the machine on request" — including
        // %ProgramData%\HERO\integrity.json, the manifest whose entire purpose is to be
        // untamperable. Its DACL does not help when SYSTEM is doing the deleting on request.
        if (!Core.HeroPaths.IsSafeStateId(id)) return new(false, "That is not a valid vault id.", null);

        try
        {
            string manifestPath = Path.Combine(VaultDirectory, id + ".json");
            string payloadPath = Path.Combine(VaultDirectory, id + ".quarantined");

            if (!File.Exists(manifestPath) && !File.Exists(payloadPath))
                return new(false, $"Nothing in the vault with id {id}.", null);

            if (File.Exists(payloadPath))
            {
                try
                {
                    using (var fs = new FileStream(payloadPath, FileMode.Open, FileAccess.Write, FileShare.None))
                    {
                        var zeroes = new byte[64 * 1024];
                        long remaining = fs.Length;
                        while (remaining > 0)
                        {
                            int chunk = (int)Math.Min(zeroes.Length, remaining);
                            fs.Write(zeroes, 0, chunk);
                            remaining -= chunk;
                        }
                        fs.Flush(true);
                    }
                }
                catch { /* overwrite is best-effort; the unlink below is what matters */ }

                File.Delete(payloadPath);
            }

            if (File.Exists(manifestPath)) File.Delete(manifestPath);
            return new(true, "Permanently deleted.", null);
        }
        catch (Exception ex)
        {
            return new(false, $"{ex.GetType().Name}: {ex.Message}", null);
        }
    }

    internal List<QuarantineManifest> List()
    {
        var result = new List<QuarantineManifest>();
        try
        {
            if (!Directory.Exists(VaultDirectory)) return result;
            foreach (var f in Directory.EnumerateFiles(VaultDirectory, "*.json"))
            {
                try
                {
                    if (JsonSerializer.Deserialize<QuarantineManifest>(File.ReadAllText(f), JsonOpts) is { } m)
                        result.Add(m);
                }
                catch { }
            }
        }
        catch { }
        return result.OrderByDescending(m => m.QuarantinedUtc).ToList();
    }

    private const int ERROR_VIRUS_INFECTED = unchecked((int)0x800700E1);
    private const int ERROR_VIRUS_DELETED = unchecked((int)0x800700E2);

    /// <summary>
    /// True when the OS refused the operation because antivirus flagged the file.
    /// Matched on HRESULT rather than message text so it survives localisation.
    /// </summary>
    private static bool IsAntivirusBlock(Exception ex) =>
        ex.HResult is ERROR_VIRUS_INFECTED or ERROR_VIRUS_DELETED;

    /// <summary>
    /// XOR the file with a repeating mask, in place. Self-inverse, so the same call restores it.
    /// Streamed in chunks so a large file does not have to fit in memory.
    /// </summary>
    private static void MaskInPlace(string path)
    {
        const int ChunkSize = 1 << 20;
        using var fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var buffer = new byte[ChunkSize];
        long offset = 0;
        int read;
        while ((read = fs.Read(buffer, 0, ChunkSize)) > 0)
        {
            for (int i = 0; i < read; i++)
                buffer[i] ^= Mask[(int)((offset + i) % Mask.Length)];

            fs.Position = offset;
            fs.Write(buffer, 0, read);
            fs.Flush();
            offset += read;
            fs.Position = offset;
        }
    }

    /// <summary>Adds an explicit deny-execute ACE for Everyone.</summary>
    private static void DenyExecute(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl();
            var everyone = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.WorldSid, null);
            sec.AddAccessRule(new FileSystemAccessRule(
                everyone, FileSystemRights.ExecuteFile, AccessControlType.Deny));
            fi.SetAccessControl(sec);
        }
        catch { /* the move and rename remain the primary containment */ }
    }
}
