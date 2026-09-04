using System.Text.RegularExpressions;

namespace Hero.Maintenance;

/// <summary>What HERO is willing to do with an available upgrade.</summary>
internal enum UpgradeDisposition
{
    /// <summary>Offerable. Still requires a click; nothing here is ever applied unattended.</summary>
    Available,
    /// <summary>A toolchain or an ambiguous version. Needs a deliberate, per-package decision.</summary>
    NeedsReview,
    /// <summary>Never offered, for the reason attached.</summary>
    Excluded,
}

/// <summary>One row of winget's upgrade table, after parsing and classification.</summary>
internal sealed record PackageUpgrade(
    string Name, string Id, string InstalledVersion, string AvailableVersion, string Source,
    UpgradeDisposition Disposition, string Reason)
{
    /// <summary>winget prints "&lt; 13.6.0.438" when it only knows an upper bound for what is
    /// installed. The upgrade may already be applied.</summary>
    internal bool VersionIsBounded => InstalledVersion.StartsWith("<", StringComparison.Ordinal);

    /// <summary>A literal "Unknown" installed version. These frequently reinstall rather than
    /// upgrade, and sometimes leave a duplicate entry behind.</summary>
    internal bool InstalledVersionUnknown =>
        InstalledVersion.Equals("Unknown", StringComparison.OrdinalIgnoreCase);

    /// <summary>winget truncated a field to fit the console width, so the value is not the
    /// package's real name or id and must not be used to address it.</summary>
    internal bool Truncated => Name.Contains('…') || Id.Contains('…');
}

internal sealed record UpgradeInventory(
    AccessState Access,
    IReadOnlyList<PackageUpgrade> Packages,
    IReadOnlyList<string> Pinned,
    IReadOnlyList<string> UnparseableLines,
    string Note)
{
    internal IEnumerable<PackageUpgrade> Offerable => Packages.Where(p => p.Disposition == UpgradeDisposition.Available);
    internal IEnumerable<PackageUpgrade> Review => Packages.Where(p => p.Disposition == UpgradeDisposition.NeedsReview);
    internal IEnumerable<PackageUpgrade> Excluded => Packages.Where(p => p.Disposition == UpgradeDisposition.Excluded);
}

internal sealed record UpgradeResult(string Id, bool Attempted, int ExitCode, string Outcome, string Detail)
{
    internal bool Succeeded => Attempted && ExitCode == 0;
}

/// <summary>
/// The winget half: inventory what could be updated, and apply individual upgrades on request.
///
/// Parsing is the hard part and the reason this file exists at all. winget has NO JSON output
/// for `upgrade` — verified against its own --help, which offers only --source,
/// --accept-source-agreements, --header, --include-pinned and --ignore-warnings. The WinRT
/// package-manager API would avoid parsing entirely but is not part of the Windows SDK
/// projection set; it needs winget's own metadata and a projection build step, i.e. an external
/// dependency this project does not take.
///
/// So the table is parsed, carefully. Naive whitespace splitting fails on every one of these
/// real rows from this machine: "&lt; 13.6.0.438" (a bounded version, two tokens),
/// "Microsoft Build of OpenJDK  17.0.17+10 (x64)" (a name containing a double space and
/// parentheses), literal "Unknown" versions, and version-scheme jumps such as 26.8.237.1 to
/// 152.0.7933.0. Two independent strategies are used and cross-checked, and any row that
/// survives neither is reported as unparsed rather than guessed at.
/// </summary>
internal static class UpdateSweep
{
    /// <summary>
    /// winget package ids: dotted, no whitespace, ASCII. Also the allowlist for anything HERO
    /// puts on a command line. An id comes from parsed console output, so it is untrusted input
    /// and is validated against this before it is ever passed to a process.
    /// </summary>
    private static readonly Regex IdPattern = new(@"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$", RegexOptions.Compiled);

    /// <summary>
    /// Never updated through winget, unconditionally, regardless of what the user selects.
    ///
    /// winget's driver packages are repackaged vendor installers with no knowledge of the
    /// specific hardware or OEM variant, and installing a generic GPU or chipset driver over an
    /// OEM-customised one can black-screen the machine. That would violate the project's
    /// must-never-brick-the-machine constraint directly, so the denylist errs towards
    /// over-blocking. Drivers come from Windows Update or the vendor's own utility.
    /// </summary>
    private static readonly string[] DriverIdFragments =
        { "driver", "chipset", "graphics.driver", "geforce.driver", "radeon.software" };

    private static readonly string[] DriverUpdaterIds =
    {
        "IObit.DriverBooster", "IObit.DriverBoosterPro", "Snappy.DriverInstaller",
        "DriverEasy.DriverEasy", "Glarysoft.DriverUpdate",
    };

    /// <summary>
    /// Products that manage their own updates and fight winget when it tries.
    ///
    /// Prefixes, because these all ship several package ids. Visual Studio is here because the
    /// VS Installer owns servicing for it, the download is multi-gigabyte, and an upgrade
    /// mid-project can change the toolset under a build. Game launchers are here because they
    /// patch themselves on launch and winget's copy immediately goes stale.
    /// </summary>
    private static readonly string[] SelfManagedPrefixes =
    {
        "Microsoft.VisualStudio.", "EpicGames.", "Ubisoft.", "Roblox.", "DigitalExtremes.",
        "Valve.Steam", "ElectronicArts.", "Blizzard.", "Discord.Discord",
    };

    /// <summary>
    /// Toolchains. Not excluded — the user may well want them — but never offered as a routine
    /// upgrade, because changing Git, Python, CMake or a JDK under a project in flight is the
    /// classic way a maintenance tool ruins a developer's day.
    /// </summary>
    private static readonly string[] ToolchainPrefixes =
    {
        "Git.Git", "Python.Python", "Kitware.CMake", "GitHub.cli", "Microsoft.OpenJDK",
        "Rustlang.", "astral-sh.uv", "OpenJS.NodeJS", "Microsoft.DotNet", "Microsoft.VisualStudioCode",
        "Microsoft.WSL", "Gyan.FFmpeg", "LLVM.LLVM", "Ninja-build.Ninja", "Docker.DockerDesktop",
        "Oracle.JDK", "GoLang.Go", "Microsoft.PowerShell", "JetBrains.",
    };

    /// <summary>Processes whose presence means a toolchain upgrade would land mid-use.</summary>
    private static readonly string[] ToolchainProcesses =
        { "devenv", "Code", "python", "node", "cargo", "MSBuild", "dotnet", "java" };

    // ------------------------------------------------------------------ inventory

    /// <summary>
    /// Everything winget reports as upgradable, classified. Read-only: nothing is installed here.
    /// </summary>
    internal static UpgradeInventory Inventory(CancellationToken ct = default)
    {
        var pins = Pins();

        // --disable-interactivity stops winget prompting; --include-unknown surfaces packages
        // whose installed version it cannot determine, which is where several of this machine's
        // pending upgrades live. Output is captured as UTF-8 (see Shell) because winget emits
        // box-drawing characters and non-ASCII package names that the console default mangles.
        var result = Shell.Run("winget",
            "upgrade --include-unknown --disable-interactivity --accept-source-agreements", 120000);

        if (!result.Launched)
            return new UpgradeInventory(AccessState.NotPresent, Array.Empty<PackageUpgrade>(), pins,
                Array.Empty<string>(),
                "winget is not available on this machine, so HERO cannot inventory updates.");

        var (rows, unparsed) = ParseTables(result.StandardOutput);
        var packages = new List<PackageUpgrade>();

        foreach (var row in rows)
        {
            var classified = Classify(row, pins);
            packages.Add(classified);
        }

        string note = unparsed.Count == 0
            ? $"{packages.Count} upgrades reported by winget."
            : $"{packages.Count} upgrades reported by winget; {unparsed.Count} lines of its output " +
              "could not be parsed and are listed verbatim rather than guessed at.";

        return new UpgradeInventory(AccessState.Measured, packages, pins, unparsed, note);
    }

    /// <summary>Package ids the user has pinned. Pinned packages are excluded unless the user
    /// explicitly overrides, which is what a pin means.</summary>
    internal static IReadOnlyList<string> Pins()
    {
        var result = Shell.Run("winget", "pin list --disable-interactivity", 30000);
        if (!result.Launched) return Array.Empty<string>();

        var (rows, _) = ParseTables(result.StandardOutput);
        return rows.Select(r => r.Id).Where(id => id.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ------------------------------------------------------------------- parsing

    /// <summary>A row extracted from a winget table, before classification.</summary>
    internal readonly record struct RawRow(string Name, string Id, string Installed, string Available, string Source);

    /// <summary>
    /// Parses every table in winget's output.
    ///
    /// There can be more than one: winget prints a second table headed "the following packages
    /// have an upgrade available, but require explicit targeting", and dropping it would silently
    /// under-report. Tables are located by their separator rule — a long run of dashes — rather
    /// than by header text, because the headers are localised and HERO must not assume English.
    ///
    /// Column offsets come from the HEADER line, not from the separator: winget's separator is
    /// one unbroken run of dashes spanning the whole table, so it carries no column information
    /// at all. The header's tokens are left-aligned at exactly the offsets the data uses.
    /// </summary>
    internal static (List<RawRow> Rows, List<string> Unparsed) ParseTables(string output)
    {
        var rows = new List<RawRow>();
        var unparsed = new List<string>();

        var lines = output.Replace("\r", "").Split('\n');

        for (int i = 1; i < lines.Length; i++)
        {
            if (!IsSeparator(lines[i])) continue;

            var offsets = HeaderOffsets(lines[i - 1]);
            if (offsets.Count < 3) continue;

            // Rows run until a blank line, the next table's separator, or the end of the output.
            // Trailing summary text ("34 upgrades available.") fails both parse strategies and is
            // discarded by LooksLikeData rather than being reported as an unparsed row.
            for (int j = i + 1; j < lines.Length && !IsSeparator(lines[j]); j++)
            {
                string line = lines[j];
                if (string.IsNullOrWhiteSpace(line)) break;

                if (TryParseRow(line, offsets, out var row)) rows.Add(row);
                else if (LooksLikeData(line)) unparsed.Add(line.Trim());
            }
        }

        // A package can appear in both the main table and the explicit-targeting table.
        var deduped = rows.GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
                          .Select(g => g.First())
                          .ToList();

        return (deduped, unparsed);
    }

    /// <summary>A rule line: dashes, nothing else, and long enough to be a table.</summary>
    private static bool IsSeparator(string line)
    {
        var trimmed = line.Trim();
        if (trimmed.Length < 20) return false;
        foreach (var c in trimmed)
            if (c != '-' && c != '─' && c != '—') return false;
        return true;
    }

    /// <summary>Start index of each column, taken from where the header's tokens begin.</summary>
    private static List<int> HeaderOffsets(string header)
    {
        var offsets = new List<int>();
        bool inGap = true;
        for (int i = 0; i < header.Length; i++)
        {
            if (char.IsWhiteSpace(header[i])) { inGap = true; continue; }
            if (inGap) { offsets.Add(i); inGap = false; }
        }
        return offsets;
    }

    private static bool LooksLikeData(string line) =>
        line.Length > 0 && !char.IsWhiteSpace(line[0]) && line.Contains("  ", StringComparison.Ordinal);

    /// <summary>
    /// Slices a row by the header offsets, then validates it. Validation is what makes the
    /// column trick safe: an id containing whitespace means the offsets did not line up — which
    /// happens whenever a name contains double-width CJK characters, since those occupy two
    /// terminal cells but one string index and shift every later column left. In that case the
    /// row is re-parsed by anchoring on the id instead.
    /// </summary>
    private static bool TryParseRow(string line, List<int> offsets, out RawRow row)
    {
        row = default;

        var fields = new string[offsets.Count];
        for (int c = 0; c < offsets.Count; c++)
        {
            int start = Math.Min(offsets[c], line.Length);
            int end = c + 1 < offsets.Count ? Math.Min(offsets[c + 1], line.Length) : line.Length;
            fields[c] = end > start ? line[start..end].Trim() : "";
        }

        // Expected layout: Name, Id, Version, Available, Source. A shorter table (winget pin
        // list) has no Available column, which the anchor path below handles.
        if (fields.Length >= 5 && IsPlausibleId(fields[1]) &&
            fields[2].Length > 0 && fields[3].Length > 0)
        {
            row = new RawRow(fields[0], fields[1], fields[2], fields[3], fields[4]);
            return true;
        }

        return TryParseByAnchor(line, out row);
    }

    /// <summary>
    /// Fallback parse that anchors on the package id.
    ///
    /// winget ids never contain whitespace, so once the id token is located the row decomposes:
    /// everything before it is the name (double spaces and parentheses included), the last token
    /// is the source, and what remains is the installed and available versions — with a lone "&lt;"
    /// re-attached to the token it belongs to, which is the specific shape that defeats naive
    /// splitting on this machine's real output.
    /// </summary>
    private static bool TryParseByAnchor(string line, out RawRow row)
    {
        row = default;
        var tokens = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length < 4) return false;

        int idIndex = -1;
        for (int i = 1; i < tokens.Length - 2; i++)
        {
            if (!IsPlausibleId(tokens[i])) continue;
            // A dotted id, or a Store product code, which is upper-case alphanumeric.
            if (tokens[i].Contains('.') || (tokens[i].Length >= 10 && tokens[i].All(char.IsLetterOrDigit)))
            {
                idIndex = i;
                break;
            }
        }
        if (idIndex < 0) return false;

        string name = string.Join(' ', tokens[..idIndex]);
        string id = tokens[idIndex];

        var rest = new List<string>();
        for (int i = idIndex + 1; i < tokens.Length; i++)
        {
            // Re-attach a bounded-version marker to the number it qualifies.
            if (rest.Count > 0 && rest[^1] == "<") rest[^1] = "< " + tokens[i];
            else rest.Add(tokens[i]);
        }

        string source = "";
        if (rest.Count > 0 && (rest[^1].Equals("winget", StringComparison.OrdinalIgnoreCase) ||
                               rest[^1].Equals("msstore", StringComparison.OrdinalIgnoreCase)))
        {
            source = rest[^1];
            rest.RemoveAt(rest.Count - 1);
        }

        if (rest.Count < 2) return false;

        row = new RawRow(name, id, rest[0], rest[1], source);
        return true;
    }

    private static bool IsPlausibleId(string candidate) =>
        candidate.Length > 0 && !candidate.Contains(' ') && IdPattern.IsMatch(candidate);

    // -------------------------------------------------------------- classification

    private static PackageUpgrade Classify(RawRow row, IReadOnlyList<string> pins)
    {
        var package = new PackageUpgrade(row.Name, row.Id, row.Installed, row.Available, row.Source,
                                         UpgradeDisposition.Available, "");

        if (package.Truncated)
            return package with
            {
                Disposition = UpgradeDisposition.Excluded,
                Reason = "winget truncated this row to fit the console, so the id shown is not the " +
                         "real one and HERO will not act on it.",
            };

        if (!IsPlausibleId(row.Id))
            return package with
            {
                Disposition = UpgradeDisposition.Excluded,
                Reason = "The package id did not parse cleanly, so HERO will not put it on a command line.",
            };

        foreach (var fragment in DriverIdFragments)
            if (row.Id.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return package with
                {
                    Disposition = UpgradeDisposition.Excluded,
                    Reason = "Driver package. winget ships repackaged vendor installers that know " +
                             "nothing about this machine's OEM variant, and a generic GPU or " +
                             "chipset driver over an OEM-customised one can black-screen the PC. " +
                             "Get drivers from Windows Update or the vendor's own utility.",
                };

        foreach (var updater in DriverUpdaterIds)
            if (row.Id.Equals(updater, StringComparison.OrdinalIgnoreCase))
                return package with
                {
                    Disposition = UpgradeDisposition.Excluded,
                    Reason = "This is a third-party driver updater. HERO will not update it and " +
                             "does not use it: this class of tool commonly causes the problems it " +
                             "claims to fix. It was installed deliberately, so HERO reports it and " +
                             "leaves the decision to you.",
                };

        if (pins.Any(p => p.Equals(row.Id, StringComparison.OrdinalIgnoreCase)))
            return package with
            {
                Disposition = UpgradeDisposition.Excluded,
                Reason = "Pinned. A pin is an explicit instruction not to upgrade, so HERO honours " +
                         "it rather than passing --include-pinned.",
            };

        foreach (var prefix in SelfManagedPrefixes)
            if (row.Id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return package with
                {
                    Disposition = UpgradeDisposition.Excluded,
                    Reason = "Self-managed. This product services itself and fights winget when " +
                             "winget tries — the result is usually a stale entry rather than an " +
                             "upgrade.",
                };

        if (package.InstalledVersionUnknown)
            return package with
            {
                Disposition = UpgradeDisposition.NeedsReview,
                Reason = "winget does not know which version is installed. Upgrading these often " +
                         "reinstalls rather than upgrades, and can leave a duplicate entry behind.",
            };

        if (package.VersionIsBounded)
            return package with
            {
                Disposition = UpgradeDisposition.NeedsReview,
                Reason = $"winget only knows an upper bound for what is installed ({row.Installed}), " +
                         "so the upgrade may already be applied.",
            };

        foreach (var prefix in ToolchainPrefixes)
        {
            if (!row.Id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;

            string running = MaintenanceGuards.AnyRunning(ToolchainProcesses)
                ? " Something that uses a toolchain is running right now, so this would land mid-work."
                : "";

            return package with
            {
                Disposition = UpgradeDisposition.NeedsReview,
                Reason = "Toolchain. Compilers, runtimes and SDKs change behaviour across versions, " +
                         "so this needs a deliberate decision rather than a routine update." + running,
            };
        }

        return package;
    }

    // ---------------------------------------------------------------- applying

    /// <summary>
    /// Applies ONE upgrade. There is no bulk path and deliberately no wrapper around
    /// `winget upgrade --all`: applying everything unattended is how a toolchain change lands in
    /// the middle of a build.
    /// </summary>
    /// <param name="package">A package from <see cref="Inventory"/>.</param>
    /// <param name="overrideDisposition">
    /// Set only when the user has explicitly chosen a package HERO put in the review bucket.
    /// An <see cref="UpgradeDisposition.Excluded"/> package can never be applied this way —
    /// exclusion covers drivers and self-managed products, and neither becomes safe because a
    /// checkbox was ticked.
    /// </param>
    internal static UpgradeResult Apply(PackageUpgrade package, bool overrideDisposition = false,
                                        CancellationToken ct = default)
    {
        if (package.Disposition == UpgradeDisposition.Excluded)
            return new UpgradeResult(package.Id, false, -1, "refused", package.Reason);

        if (package.Disposition == UpgradeDisposition.NeedsReview && !overrideDisposition)
            return new UpgradeResult(package.Id, false, -1, "needs review", package.Reason);

        // The id came from parsed console output. Re-validating it here rather than trusting the
        // classification step is the same discipline the file deleter applies to paths: never put
        // something on a command line because an earlier stage said it was fine.
        if (!IsPlausibleId(package.Id))
            return new UpgradeResult(package.Id, false, -1, "refused",
                "The package id contains characters HERO will not pass to a process.");

        if (ct.IsCancellationRequested)
            return new UpgradeResult(package.Id, false, -1, "cancelled", "Cancelled before starting.");

        var result = Shell.Run("winget",
            $"upgrade --id {package.Id} --exact --silent --accept-package-agreements " +
            "--accept-source-agreements --disable-interactivity",
            timeoutMs: 30 * 60 * 1000);

        if (!result.Launched)
            return new UpgradeResult(package.Id, false, -1, "failed", result.StandardError);

        return new UpgradeResult(package.Id, true, result.ExitCode,
            result.ExitCode == 0 ? "upgraded" : "failed",
            DescribeExitCode(result.ExitCode, result.StandardOutput, result.StandardError));
    }

    /// <summary>
    /// winget's exit codes carry real information, so they are surfaced rather than collapsed
    /// into "it failed". Only codes whose meaning is documented are named; anything else is
    /// reported as its raw value with winget's own output, because inventing an explanation for
    /// an unknown code is worse than admitting the code is unknown.
    /// </summary>
    private static string DescribeExitCode(int exitCode, string stdout, string stderr)
    {
        string tail = (stdout + " " + stderr).Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (tail.Length > 400) tail = tail[..400] + "...";

        return unchecked((uint)exitCode) switch
        {
            0 => "Upgrade completed.",
            0x8A150011 => "No installer in the package applies to this machine. " + tail,
            0x8A15010B => "winget found no applicable update after all. " + tail,
            _ => exitCode == 0 ? tail : $"winget exited with 0x{exitCode:X8}. {tail}",
        };
    }

    /// <summary>
    /// A short, honest summary for the weekly report's updates section: what was applied, what
    /// needs a decision, and what was excluded with the reason. The last group is the important
    /// one — a tool that explains its restraint is trusted more than one that maximises the
    /// number of things it claims to have done.
    /// </summary>
    internal static string Summarise(UpgradeInventory inventory)
    {
        if (inventory.Access != AccessState.Measured) return inventory.Note;

        int offerable = inventory.Offerable.Count();
        int review = inventory.Review.Count();
        int excluded = inventory.Excluded.Count();

        var lines = new List<string>
        {
            $"{inventory.Packages.Count} upgrades available: {offerable} straightforward, " +
            $"{review} needing a decision, {excluded} excluded.",
        };

        foreach (var group in inventory.Excluded.GroupBy(p => p.Reason))
            lines.Add($"  excluded ({group.Count()}): {string.Join(", ", group.Select(p => p.Id).Take(6))}" +
                      (group.Count() > 6 ? ", ..." : "") + " — " + group.Key);

        if (inventory.UnparseableLines.Count > 0)
            lines.Add($"  {inventory.UnparseableLines.Count} lines of winget output could not be " +
                      "parsed and were not guessed at.");

        return string.Join(Environment.NewLine, lines);
    }
}
