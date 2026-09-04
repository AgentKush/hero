namespace Hero.Core;

/// <summary>
/// Every location HERO writes to. Centralised so that "what does this app touch on my disk"
/// has exactly one answer, and so an uninstall can be complete.
///
/// WHY %ProgramData% AND NOT %LOCALAPPDATA%
///
/// HERO's guardian is moving into a LocalSystem service. A service's "local application data" is
/// <c>C:\Windows\System32\config\systemprofile\AppData\Local</c> — a different directory from the
/// signed-in user's, which the user cannot browse to and would never think to look in. Leaving
/// state under %LOCALAPPDATA% would give HERO two brains: two baselines, two hash-chained
/// ledgers, two vaults. A hash chain with two writers is not a hash chain.
///
/// %ProgramData% is the one location both identities resolve to identically. The trade is that it
/// is a shared root rather than a per-user one, so the ACL matters — and that flip has now
/// happened. The service is the sole writer, the interactive app's write access is gone
/// (<see cref="LockDownStateDirectory"/>), and the app's own diagnostics live per-user instead
/// (<see cref="UserLogDir"/>).
///
/// Measured on this machine before and after that change: an unelevated process went from being
/// able to create files in every subdirectory and append to baseline.json, settings.json,
/// dismissed.json and events\ledger.jsonl, to none of them — while still being able to read all
/// six, which is the point. The record is about the user; they may read every byte of it and
/// change none.
/// </summary>
internal static class HeroPaths
{
    /// <summary>Root of all HERO state: %ProgramData%\HERO</summary>
    internal static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "HERO");

    /// <summary>
    /// Where state lived before the service existed: %LOCALAPPDATA%\HERO. Retained so that a
    /// machine upgrading to the service build keeps its learned baseline and its ledger instead
    /// of starting again from nothing — the baseline is the product of days of observation and
    /// silently discarding it would be the worst kind of upgrade.
    /// </summary>
    internal static string LegacyRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HERO");

    /// <summary>Learned behavioural baseline for this machine.</summary>
    internal static string Baseline => Path.Combine(Root, "baseline.json");

    /// <summary>User settings, including autonomy level and allowlists.</summary>
    internal static string Settings => Path.Combine(Root, "settings.json");

    /// <summary>Append-only incident and action history.</summary>
    internal static string EventsDir => Path.Combine(Root, "events");

    /// <summary>Quarantined files plus their restore manifests.</summary>
    internal static string VaultDir => Path.Combine(Root, "vault");

    /// <summary>Undo records for persistence removals and firewall rules.</summary>
    internal static string UndoDir => Path.Combine(Root, "undo");

    // There is deliberately no LogDir under Root any more. Every log that lived there was written
    // by the interactive app and has moved to UserLogDir; the service's own log is service.log at
    // the root (see ServiceLog). Leaving an unused, official-looking state path behind is how this
    // whole problem started — one diagnostic write into the guardian's directory was the reason
    // that directory had to stay open to the signed-in user.
    //
    // Existing installs keep their old %ProgramData%\HERO\logs folder and its contents. It is not
    // deleted: those are the user's diagnostics to read, and after the lockdown they are read-only
    // rather than a liability.

    /// <summary>
    /// Diagnostic logs written by the interactive app: %LOCALAPPDATA%\HERO\logs.
    ///
    /// These moved out of %ProgramData% so that directory could be closed to the signed-in user.
    /// While the app logged there, the state root had to grant BUILTIN\Users write access, and that
    /// grant is inherited — measured on this machine, an unelevated process could append to
    /// baseline.json, settings.json, dismissed.json and events\ledger.jsonl. The ledger is
    /// hash-chained specifically so that editing it is detectable; leaving it writable so that a
    /// UI animation counter had somewhere to go was the wrong trade.
    ///
    /// Per-user rather than a second shared directory because these are per-user diagnostics: two
    /// people signed into one machine each get their own, and neither needs write access to
    /// anything the guardian owns. Diagnostics are the ONLY thing that lives here — no state, no
    /// baseline, no ledger — so this does not reintroduce the "two brains" problem that put state
    /// in %ProgramData% in the first place.
    /// </summary>
    internal static string UserLogDir => Path.Combine(LegacyRoot, "logs");

    /// <summary>
    /// Appends one line to a per-user diagnostic log, creating the directory on demand.
    ///
    /// Every caller of this is a diagnostic that must never affect the app, so a failure here is
    /// swallowed exactly as it was when these logs lived in %ProgramData%.
    /// </summary>
    internal static void WriteUserLog(string fileName, string line)
    {
        try
        {
            Directory.CreateDirectory(UserLogDir);
            File.AppendAllText(Path.Combine(UserLogDir, fileName), line);
        }
        catch { /* diagnostics must never break the thing they are diagnosing */ }
    }

    /// <summary>Stamped into the old root once its contents have been copied across.</summary>
    private const string MigrationMarker = "moved-to-programdata.txt";

    /// <summary>
    /// True when THIS process could actually persist guardian state.
    ///
    /// Asks the filesystem rather than inferring from identity or from whether the service is
    /// installed, because the question is precisely "will the writes silently fail". Every write
    /// in the guardian is wrapped in a catch that swallows — that is right for a security tool
    /// which must not die because one file was locked, but it means a directory this process
    /// cannot write looks exactly like one where nothing happened to need writing.
    ///
    /// Called before falling back to an in-process guardian: see App.OnStartup.
    /// </summary>
    internal static bool CanPersistState()
    {
        try
        {
            Directory.CreateDirectory(Root);
            string probe = Path.Combine(Root, $".write-probe-{Environment.ProcessId}");
            File.WriteAllBytes(probe, Array.Empty<byte>());
            File.Delete(probe);
            return true;
        }
        catch { return false; }
    }

    /// <summary>Creates the directory tree and migrates old state. Safe to call repeatedly.</summary>
    internal static void EnsureCreated()
    {
        foreach (var d in new[] { Root, EventsDir, VaultDir, UndoDir })
        {
            try { Directory.CreateDirectory(d); } catch { /* surfaced by the first real write */ }
        }

        try { MigrateFromLegacy(); } catch { /* never block startup on a migration */ }
    }

    /// <summary>
    /// Copies %LOCALAPPDATA%\HERO into %ProgramData%\HERO once.
    ///
    /// Deliberately a copy, not a move: if anything about the new location turns out to be wrong,
    /// the original state is still there to fall back to. The old directory is marked rather than
    /// deleted for the same reason. Existing files at the destination are never overwritten, so
    /// running an older build afterwards cannot clobber newer state.
    /// </summary>
    private static void MigrateFromLegacy()
    {
        if (!Directory.Exists(LegacyRoot)) return;
        if (string.Equals(LegacyRoot, Root, StringComparison.OrdinalIgnoreCase)) return;
        if (File.Exists(Path.Combine(LegacyRoot, MigrationMarker))) return;

        // "Already there" and "could not be copied" are not the same outcome and must not share a
        // counter. They did, and the marker below was written regardless — so once the state root
        // was closed to the signed-in user, every File.Copy was denied, counted as a skip, and the
        // legacy directory was then stamped with a note saying it "is no longer read... safe to
        // remove by hand". The user's learned baseline and hash-chained ledger would have been
        // orphaned, with a message inviting them to delete the only remaining copy.
        int copied = 0, alreadyPresent = 0, failed = 0;

        foreach (var source in Directory.EnumerateFiles(LegacyRoot, "*", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(LegacyRoot, source);

            // The legacy root is also where the app now writes its own per-user diagnostics, so
            // this migration would otherwise copy today's logs INTO the directory they were just
            // moved out of. They are diagnostics, not state: there was never a reason to migrate
            // them even when this was purely a one-way upgrade path.
            if (relative.StartsWith("logs" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || relative.StartsWith("logs" + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string destination = Path.Combine(Root, relative);

            try
            {
                if (File.Exists(destination)) { alreadyPresent++; continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(source, destination);
                copied++;
            }
            catch { failed++; }
        }

        if (failed > 0)
        {
            // Say so, and do NOT stamp the marker — leaving it unstamped is what keeps the legacy
            // state reachable by a later run that can actually write the destination (the elevated
            // installer, or a build where the service performs the migration).
            LegacyStateUnmigrated = failed;
            WriteUserLog("app.log",
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} Legacy state migration incomplete: {failed} " +
                $"file(s) from {LegacyRoot} could not be copied to {Root}. The old directory is " +
                $"being kept and is NOT marked as migrated.{Environment.NewLine}");
            return;
        }

        try
        {
            File.WriteAllText(Path.Combine(LegacyRoot, MigrationMarker),
                $"HERO state moved to {Root} on {DateTime.UtcNow:u}.{Environment.NewLine}" +
                $"{copied} file(s) copied, {alreadyPresent} already present.{Environment.NewLine}" +
                "This directory is no longer read. It is kept rather than deleted so the old " +
                "state can be recovered if needed; it is safe to remove by hand." + Environment.NewLine);
        }
        catch { /* the marker is an optimisation; a repeated no-op copy is harmless */ }
    }

    /// <summary>
    /// How many legacy state files could not be migrated on this run. Zero in every ordinary case.
    ///
    /// Non-zero means the old %LOCALAPPDATA%\HERO still holds state this process could not copy
    /// into the locked root — worth telling someone about rather than discovering later that a
    /// learned baseline vanished at upgrade.
    /// </summary>
    internal static int LegacyStateUnmigrated { get; private set; }

    /// <summary>
    /// Closes the state directory to the signed-in user: SYSTEM and Administrators may write, the
    /// user may only read. Requires elevation. Safe to run repeatedly.
    ///
    /// This is the other half of <see cref="UserLogDir"/> — the app no longer writes here, so the
    /// grant that let it can go.
    ///
    /// THREE THINGS ARE REQUIRED, and doing only the obvious one leaves the directory open.
    /// Each was measured on a real install rather than reasoned about:
    ///
    /// 1. INHERITANCE MUST BE BROKEN. %ProgramData% itself carries
    ///    <c>BUILTIN\Users: Write (ContainerInherit)</c> and an inherit-only
    ///    <c>CREATOR OWNER: GENERIC_ALL</c>. Merely removing HERO's own explicit Users ACE leaves
    ///    both of those flowing down, and the user can still create files.
    ///
    /// 2. EXISTING FILES MUST BE REWRITTEN, not just the directory. That CREATOR OWNER ACE stamps
    ///    an EXPLICIT full-control entry for the creating user onto every file the app made, and
    ///    <c>File.Move</c> carries that descriptor along when a .tmp is renamed over the target.
    ///    Measured: baseline.json carried an explicit ACE for the signed-in user, and an unelevated
    ///    process could rewrite that file's DACL — i.e. grant itself back anything this method took
    ///    away. A directory-only lockdown is cosmetic while that ACE exists.
    ///
    /// 3. OWNERSHIP MUST BE RESET. An owner holds WRITE_DAC implicitly, so a file the user owns is
    ///    a file the user controls no matter what the ACEs say. logs\ipc.log was owned by the
    ///    signed-in user.
    ///
    /// What this bought, measured before and after on the same machine: an unelevated process went
    /// from being able to create files in every subdirectory and append to baseline.json,
    /// settings.json, dismissed.json and events\ledger.jsonl, to being able to do none of it. The
    /// ledger is hash-chained so that tampering is detectable; this makes it also difficult.
    /// </summary>
    /// <param name="directory">
    /// Defaults to <see cref="Root"/>. Parameterised so the lockdown can be rehearsed against a
    /// throwaway copy and the result measured, rather than first being applied to the only copy of
    /// a machine's learned baseline and its hash-chained ledger.
    /// </param>
    internal static void LockDownStateDirectory(string? directory = null)
    {
        string target = string.IsNullOrWhiteSpace(directory) ? Root : directory!;

        var system = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
        var admins = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
        var users = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);

        try
        {
            var root = new DirectoryInfo(target);
            if (!root.Exists) return;

            var security = new System.Security.AccessControl.DirectorySecurity();

            // Protected, and NOT preserving what was inherited: the inherited set is precisely the
            // Users:Write and CREATOR OWNER entries this is here to shed.
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            const System.Security.AccessControl.InheritanceFlags Both =
                System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                System.Security.AccessControl.InheritanceFlags.ObjectInherit;

            void Allow(System.Security.Principal.SecurityIdentifier who,
                       System.Security.AccessControl.FileSystemRights rights)
            {
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    who, rights, Both, System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));
            }

            Allow(system, System.Security.AccessControl.FileSystemRights.FullControl);
            Allow(admins, System.Security.AccessControl.FileSystemRights.FullControl);

            // The user may READ every byte of their own security evidence — the vault, the ledger,
            // the settings, the baseline. Withholding it would be the wrong kind of secure: this is
            // the user's machine and the record is about them. They simply may not rewrite it.
            //
            // Deliberately no CREATOR OWNER entry. Reintroducing it would re-stamp per-user full
            // control on every file created here, which is defect (2) above.
            Allow(users, System.Security.AccessControl.FileSystemRights.ReadAndExecute);

            root.SetAccessControl(security);
        }
        catch
        {
            // Needs elevation. The caller is the installer, which has it. Failing here leaves the
            // previous, looser ACL rather than a half-applied one, because the descriptor is built
            // whole and applied in a single call.
            return;
        }

        // ---- now the existing contents, which the directory's ACL alone does not reach
        //
        // Subdirectories as well as files. A subdirectory the user owns is one they can still
        // create and delete inside, whatever the root above it says.

        foreach (var (path, isDirectory) in SafeEnumerate(target))
        {
            try
            {
                const System.Security.AccessControl.AccessControlSections Sections =
                    System.Security.AccessControl.AccessControlSections.Access |
                    System.Security.AccessControl.AccessControlSections.Owner;

                System.Security.AccessControl.FileSystemSecurity acl = isDirectory
                    ? new DirectoryInfo(path).GetAccessControl(Sections)
                    : new FileInfo(path).GetAccessControl(Sections);

                // Ownership first: while the signed-in user owns an entry, they can undo whatever
                // is done to its DACL next. Administrators is the target rather than SYSTEM because
                // a member of that group may set it without holding SeRestorePrivilege.
                acl.SetOwner(admins);

                // Every entry is normalised, with NO exemption for entries that already carry a
                // protected DACL.
                //
                // Exempting them was a hole, not a courtesy. The reasoning was "integrity.json and
                // service.log are deliberately stricter than this sweep, so leave them alone" — but
                // the test was a property of the file, not a statement about which file it is. The
                // state root inherits %ProgramData%'s ACL until this method first runs, and that
                // ACL lets any user create files there. So a user could pre-create
                // baseline.json with `icacls /inheritance:r /grant %USERNAME%:(F)`, and the sweep
                // would see AreAccessRulesProtected and preserve their full control forever —
                // reintroducing exactly the stamped-ACE defect this method exists to remove.
                //
                // Everything is stripped, and the genuinely-stricter files are re-protected
                // afterwards by name. Deterministic beats deferential.
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in
                         acl.GetAccessRules(includeExplicit: true, includeInherited: false,
                             typeof(System.Security.Principal.SecurityIdentifier)))
                {
                    acl.RemoveAccessRuleSpecific(rule);
                }

                acl.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);

                if (isDirectory) new DirectoryInfo(path).SetAccessControl((System.Security.AccessControl.DirectorySecurity)acl);
                else new FileInfo(path).SetAccessControl((System.Security.AccessControl.FileSecurity)acl);
            }
            catch { /* one stubborn entry must not abandon the rest of the sweep */ }
        }

        // ---- re-protect, by name, the entries that must be stricter than the root
        //
        // This pass is not optional decoration: the sweep above deliberately strips EVERY explicit
        // rule, which includes the ones that were protecting something.

        ProtectServiceOwnedFile(Path.Combine(target, "integrity.json"));
        ProtectServiceOwnedFile(Path.Combine(target, "service.log"));

        // Quarantined payloads. The root grants Users ReadAndExecute so a person can read their own
        // evidence, and inheriting that onto quarantined malware was a mistake with two halves,
        // both measured on this machine after the first lockdown ran:
        //
        //   - the explicit "Deny Everyone: ExecuteFile" that QuarantineVault stamps on every
        //     payload was stripped by the sweep, because a Deny rule is a FileSystemAccessRule like
        //     any other and the strip did not discriminate;
        //   - the inherited Users:ReadAndExecute then granted FILE_READ_DATA *and* FILE_EXECUTE on
        //     it to every local account.
        //
        // Net effect: quarantining a file made it MORE available than leaving it alone. "The user
        // may read every byte of their own evidence" is a good argument for the manifests beside
        // the payload; it is not an argument for handing out runnable malware.
        try
        {
            string vault = Path.Combine(target, "vault");
            if (Directory.Exists(vault))
            {
                foreach (var payload in Directory.GetFiles(vault, "*" + QuarantineSuffix))
                    ProtectQuarantinedPayload(payload);
            }
        }
        catch { /* the vault may not exist yet on a fresh install */ }
    }

    /// <summary>Extension the quarantine vault gives a neutralised payload.</summary>
    internal const string QuarantineSuffix = ".quarantined";

    /// <summary>
    /// True when <paramref name="id"/> is safe to concatenate into a path under this directory.
    ///
    /// Anything arriving over the IPC pipe that ends up in a <see cref="Path.Combine"/> must pass
    /// through here first, because Path.Combine DISCARDS its earlier arguments the moment a later
    /// one is rooted: <c>Path.Combine(UndoDir, @"C:\Users\me\forged" + ".json")</c> is simply
    /// <c>C:\Users\me\forged.json</c>. Relative traversal works too, since Path.Combine does not
    /// normalise. The pipe grants the Interactive SID read/write and the service runs as
    /// LocalSystem, so an unvalidated id is that user choosing a file for SYSTEM to act on.
    ///
    /// Whitelist rather than blacklist, and deliberately narrower than NTFS allows: every id HERO
    /// mints is timestamp-and-hex (see ResponseEngine.NewId and QuarantineVault), so nothing
    /// legitimate needs a dot, a colon, a separator or a space.
    /// </summary>
    internal static bool IsSafeStateId(string? id)
    {
        if (string.IsNullOrEmpty(id) || id.Length > 128) return false;

        foreach (char c in id)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_') return false;
        }

        // Belt and braces: even having banned every separator above, confirm the platform agrees
        // this is one plain segment.
        return Path.GetFileName(id) == id;
    }

    /// <summary>
    /// Closes one quarantined payload to everyone but SYSTEM and Administrators.
    ///
    /// Stricter than <see cref="ProtectServiceOwnedFile"/>, which deliberately leaves Users a read:
    /// the manifest beside the payload carries the original path, the hash and the reason, and that
    /// is the part a person needs to read. The payload itself is the sample. It is XOR-masked
    /// rather than encrypted — the vault says so plainly and does not pretend otherwise — so the
    /// ACL is the only thing actually keeping it out of reach.
    ///
    /// The Deny is kept as well as the omission. Belt and braces on the one file in the product
    /// whose whole purpose is to be inert.
    /// </summary>
    internal static void ProtectQuarantinedPayload(string path)
    {
        try
        {
            if (!File.Exists(path)) return;

            var file = new FileInfo(path);
            var security = new System.Security.AccessControl.FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            void Allow(System.Security.Principal.WellKnownSidType who)
            {
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(who, null),
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));
            }

            Allow(System.Security.Principal.WellKnownSidType.LocalSystemSid);
            Allow(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid);

            // No Users entry at all — not even read.
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.WorldSid, null),
                System.Security.AccessControl.FileSystemRights.ExecuteFile,
                System.Security.AccessControl.AccessControlType.Deny));

            file.SetAccessControl(security);
        }
        catch { /* the move and rename remain the primary containment */ }
    }

    /// <summary>
    /// Every file and subdirectory under <paramref name="root"/>, skipping anything that cannot be
    /// listed. Hand-rolled because <c>Directory.EnumerateFiles(..., AllDirectories)</c> throws
    /// part-way through on the first unreadable subdirectory and discards what it had already
    /// found — on a directory this method is in the middle of re-permissioning, that is a real
    /// possibility rather than a theoretical one.
    /// </summary>
    private static IEnumerable<(string Path, bool IsDirectory)> SafeEnumerate(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            string current = pending.Pop();

            string[] files;
            try { files = Directory.GetFiles(current); }
            catch { continue; }

            foreach (var f in files) yield return (f, false);

            string[] directories;
            try { directories = Directory.GetDirectories(current); }
            catch { continue; }

            foreach (var d in directories)
            {
                yield return (d, true);
                pending.Push(d);
            }
        }
    }

    // GrantInteractiveWriteAccess used to live here. It granted BUILTIN\Users Modify on the whole
    // state root, and it was honest about being a transitional weakening: while the guardian ran
    // inside the tray application, the interactive user WAS the writer of the baseline, the ledger
    // and the vault, and without that ACE the app silently failed to save anything at all.
    //
    // It is deleted rather than left unused. Both halves of its premise are now false — the service
    // is the writer, and the app's only remaining writes go to UserLogDir — so all the method could
    // do is undo LockDownStateDirectory. A method whose sole remaining effect is to re-open the
    // directory this one closes has no business being one call away.

    /// <summary>
    /// Locks one file down to SYSTEM and Administrators, breaking inheritance.
    ///
    /// Written when the root still granted Users Modify and that ACE inherited — which silently
    /// un-protected the integrity manifest. Measured at the time: before the grant, writing
    /// integrity.json was DENIED; after it, WRITABLE. A manifest a user-level process can rewrite
    /// is not evidence of anything, because the first thing that tampers with HERO's binaries would
    /// rewrite it to match.
    ///
    /// <see cref="LockDownStateDirectory"/> has since closed the root, so this is no longer the
    /// only thing standing between the manifest and the user. It is kept because it is still
    /// stricter than the root — these files are not merely unwritable, they are unwritable with
    /// inheritance switched off, so they cannot be re-opened by a later change to the directory
    /// above them. Defence in depth on the one file whose whole purpose is to be trustworthy.
    ///
    /// So the few files the SERVICE owns are protected individually rather than relying on the
    /// directory's ACL. Inheritance is switched off explicitly: leaving it on and merely adding a
    /// deny ACE would be undone the next time the directory ACL changed.
    /// </summary>
    internal static void ProtectServiceOwnedFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return;

            var file = new FileInfo(path);
            var security = file.GetAccessControl();

            // Drop inherited rules rather than copying them: the inherited set is exactly what
            // grants Users write here, so preserving it would defeat the whole call.
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            foreach (System.Security.AccessControl.FileSystemAccessRule existing in
                     security.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier)))
            {
                security.RemoveAccessRuleSpecific(existing);
            }

            void Allow(System.Security.Principal.WellKnownSidType who,
                       System.Security.AccessControl.FileSystemRights rights)
            {
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(who, null), rights,
                    System.Security.AccessControl.AccessControlType.Allow));
            }

            Allow(System.Security.Principal.WellKnownSidType.LocalSystemSid,
                  System.Security.AccessControl.FileSystemRights.FullControl);
            Allow(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,
                  System.Security.AccessControl.FileSystemRights.FullControl);
            // The user may READ the evidence. That is the point of it.
            Allow(System.Security.Principal.WellKnownSidType.BuiltinUsersSid,
                  System.Security.AccessControl.FileSystemRights.Read);

            file.SetAccessControl(security);
        }
        catch
        {
            // Needs ownership or elevation. Both callers have it; failure leaves the file merely
            // as protected as the directory, which is the pre-existing behaviour.
        }
    }

    /// <summary>
    /// True when <paramref name="path"/> is inside the guardian's state directory.
    ///
    /// This is the DETECTION answer, and it is deliberately narrow: only <see cref="Root"/>, which
    /// nothing but SYSTEM and Administrators can write. Use it to stop the engine analysing,
    /// scoring, quarantining or acting on its own state — a self-monitoring security tool that eats
    /// itself is a classic own-goal.
    ///
    /// It used to include <see cref="LegacyRoot"/> as well, and that became dangerous the moment
    /// <see cref="UserLogDir"/> was put under LegacyRoot: eight call sites consult this, seven of
    /// them detection, and together they say HERO will never accuse a process from here, never
    /// score an autostart pointing here, never learn about it, never list it in recent starts,
    /// never firewall it and never quarantine it. Pointing that guarantee at a directory the
    /// signed-in user can write turns HERO's own diagnostics folder into the best hiding place on
    /// the machine. For refusing to DELETE something, the wider answer is still right — see
    /// <see cref="IsOwnStateOrDiagnostics"/>.
    /// </summary>
    internal static bool IsOwnState(string path) => IsUnder(path, Root);

    /// <summary>
    /// True when <paramref name="path"/> is anything HERO put on disk: the guardian's state, the
    /// legacy root, and the per-user diagnostics inside it.
    ///
    /// The CLEANUP answer. HERO offering to free up space by deleting its own baseline, its own
    /// ledger or its own logs is the own-goal this was originally written to prevent, and that
    /// argument does apply to every directory HERO writes — unlike the detection one.
    /// </summary>
    internal static bool IsOwnStateOrDiagnostics(string path)
        => IsUnder(path, Root) || IsUnder(path, LegacyRoot);

    /// <summary>
    /// Segment-aware containment. <c>C:\X</c> contains <c>C:\X\y</c> and is itself a match; it does
    /// NOT contain <c>C:\XY</c>.
    ///
    /// The bare <c>StartsWith</c> this replaces had no separator check, so %LOCALAPPDATA%\HEROIC\,
    /// %LOCALAPPDATA%\HEROx\ and %ProgramData%\HERO-evil\ all counted as HERO's own — an exclusion
    /// an attacker claims by choosing a folder name.
    /// </summary>
    private static bool IsUnder(string path, string root)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(root)) return false;
        try
        {
            // GetFullPath on both sides so that a relative path, a trailing separator or an 8.3
            // short name is compared in the same form as the root it is tested against.
            string full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
            string bound = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);

            if (full.Equals(bound, StringComparison.OrdinalIgnoreCase)) return true;
            return full.StartsWith(bound + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
