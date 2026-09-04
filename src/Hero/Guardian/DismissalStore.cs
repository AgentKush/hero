using System.Text.Json;
using Hero.Core;

namespace Hero.Guardian;

/// <summary>
/// Findings the user has told HERO to stop showing, and until when.
///
/// This is distinct from the allowlist on purpose, and the distinction matters:
///
///   * The <b>allowlist</b> is a statement about the software — "these exact bytes are fine" —
///     and it is pinned to content, so it evaporates the moment the file changes.
///   * A <b>dismissal</b> is a statement about the user's attention — "I have seen this, stop
///     telling me for now". It says nothing about whether the thing is safe.
///
/// Conflating them would be the worst of both: either the user's "not now" silently becomes a
/// permanent trust decision, or it is forgotten immediately and the finding returns on the next
/// scan. The second is what HERO did before this existed, and it made the Dismiss button useless:
/// persistence is re-inventoried every ten minutes, so a dismissed entry came straight back.
///
/// Dismissals expire. A threat the user waved away a month ago should be raised again, because
/// their reasons for ignoring it may no longer hold.
/// </summary>
internal sealed class DismissalStore
{
    private sealed record Record(string Key, DateTime UntilUtc, string Note);

    private readonly Dictionary<string, Record> _records = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly string _path = Path.Combine(HeroPaths.Root, "dismissed.json");

    internal DismissalStore() => Load();

    /// <summary>True when this finding is currently suppressed.</summary>
    internal bool IsDismissed(string subjectKey)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(subjectKey, out var record)) return false;
            if (record.UntilUtc <= DateTime.UtcNow)
            {
                _records.Remove(subjectKey);
                SaveLocked();
                return false;
            }
            return true;
        }
    }

    internal void Dismiss(string subjectKey, TimeSpan duration, string note = "")
    {
        lock (_gate)
        {
            _records[subjectKey] = new Record(subjectKey, DateTime.UtcNow + duration, note);
            SaveLocked();
        }
    }

    internal void Restore(string subjectKey)
    {
        lock (_gate)
        {
            if (_records.Remove(subjectKey)) SaveLocked();
        }
    }

    internal int Count
    {
        get { lock (_gate) return _records.Count(r => r.Value.UntilUtc > DateTime.UtcNow); }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var records = JsonSerializer.Deserialize<List<Record>>(File.ReadAllText(_path));
            if (records is null) return;

            lock (_gate)
            {
                foreach (var r in records.Where(r => r.UntilUtc > DateTime.UtcNow))
                    _records[r.Key] = r;
            }
        }
        catch { /* a corrupt dismissal file just means nothing is suppressed */ }
    }

    private void SaveLocked()
    {
        try
        {
            HeroPaths.EnsureCreated();
            var live = _records.Values.Where(r => r.UntilUtc > DateTime.UtcNow).ToList();

            // Write-and-rename: a half-written file here would silently un-dismiss everything.
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(live, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, _path, overwrite: true);
        }
        catch { }
    }
}
