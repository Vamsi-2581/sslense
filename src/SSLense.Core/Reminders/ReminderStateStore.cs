using System.Text.Json;
using SSLense.Core.Config;

namespace SSLense.Core.Reminders;

/// <param name="LastDigestDate">The server-local day the daily digest was last handled (sent, or nothing was due).</param>
/// <param name="LastWeeklySummaryDate">The day the weekly summary was last sent.</param>
public sealed record ReminderState(
    DateOnly? LastDigestDate = null,
    DateOnly? LastWeeklySummaryDate = null,
    int SchemaVersion = StateSchema.ReminderState);

public interface IReminderStateStore
{
    Task<ReminderState> GetAsync(CancellationToken cancellationToken = default);

    Task SaveAsync(ReminderState state, CancellationToken cancellationToken = default);
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

    public JsonReminderStateStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.ReminderStateFile)
    {
    }

    internal JsonReminderStateStore(IFileSystem fileSystem, string path)
    {
        _fileSystem = fileSystem;
        _path = path;
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

    // Only the service writes this file; the atomic replace keeps a crash from leaving it half written.
    public Task SaveAsync(ReminderState state, CancellationToken cancellationToken = default) =>
        _fileSystem.WriteAllTextAtomicAsync(
            _path,
            JsonSerializer.Serialize(state with { SchemaVersion = StateSchema.ReminderState }, SerializerOptions),
            cancellationToken);
}
