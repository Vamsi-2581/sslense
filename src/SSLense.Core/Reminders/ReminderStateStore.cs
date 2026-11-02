using System.Text.Json;
using SSLense.Core.Config;

namespace SSLense.Core.Reminders;

/// <param name="LastDigestDate">The server-local day the daily digest was last handled (sent, or nothing was due).</param>
/// <param name="LastWeeklySummaryDate">The day the weekly summary was last sent.</param>
/// <param name="CheckFailures">Consecutive days each proactive check has failed, by check and site.</param>
/// <param name="LastChecksDate">The day failures were last counted, so a retried digest does not count a day twice.</param>
public sealed record ReminderState(
    DateOnly? LastDigestDate = null,
    DateOnly? LastWeeklySummaryDate = null,
    int SchemaVersion = StateSchema.ReminderState,
    IReadOnlyDictionary<string, int>? CheckFailures = null,
    DateOnly? LastChecksDate = null);

public interface IReminderStateStore
{
    Task<ReminderState> GetAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads the state, applies <paramref name="change"/> and writes the result, under a lock shared by the service, the
    /// GUI and the CLI, so one writer does not overwrite what another just recorded.
    /// </summary>
    Task UpdateAsync(Func<ReminderState, Task<ReminderState>> change, CancellationToken cancellationToken = default);
}

/// <summary>Kept apart from the certificates so a service restart does not send the same day's digest twice.</summary>
internal sealed class JsonReminderStateStore : IReminderStateStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _path;
    private readonly string _lockPath;

    public JsonReminderStateStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.ReminderStateFile, AppPaths.ReminderStateLockFile)
    {
    }

    internal JsonReminderStateStore(IFileSystem fileSystem, string path, string lockPath)
    {
        _fileSystem = fileSystem;
        _path = path;
        _lockPath = lockPath;
    }

    public async Task<ReminderState> GetAsync(CancellationToken cancellationToken = default)
    {
        if (!_fileSystem.FileExists(_path))
        {
            return new ReminderState();
        }

        try
        {
            var state = JsonSerializer.Deserialize<ReminderState>(
                await _fileSystem.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false),
                SerializerOptions) ?? new ReminderState();
            StateSchema.EnsureSupported(state.SchemaVersion, StateSchema.ReminderState, _path);
            return state;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Reminder state '{_path}' contains invalid JSON.", exception);
        }
    }

    // The service writes this file, and saving reminder settings clears the digest date; the atomic replace keeps a crash
    // from leaving it half written, so reading needs no lock.
    public async Task UpdateAsync(Func<ReminderState, Task<ReminderState>> change, CancellationToken cancellationToken = default)
    {
        await using var fileLock = await _fileSystem.AcquireExclusiveFileLockAsync(_lockPath, cancellationToken).ConfigureAwait(false);
        var state = await change(await GetAsync(cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        await _fileSystem.WriteAllTextAtomicAsync(
                _path,
                JsonSerializer.Serialize(state with { SchemaVersion = StateSchema.ReminderState }, SerializerOptions),
                cancellationToken)
            .ConfigureAwait(false);
    }
}
