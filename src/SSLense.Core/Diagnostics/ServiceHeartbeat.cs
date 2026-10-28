using System.Text.Json;
using SSLense.Core.Config;

namespace SSLense.Core.Diagnostics;

/// <summary>Written by the renewal service so the health check can tell whether it is actually working.</summary>
public sealed record ServiceHeartbeat(
    string Version,
    DateTimeOffset ProcessStartedAt,
    DateTimeOffset? LastCycleStartedAt = null,
    DateTimeOffset? LastCycleCompletedAt = null,
    bool? LastCycleSucceeded = null,
    string? LastCycleMessage = null,
    int SchemaVersion = StateSchema.ServiceHeartbeat);

public interface IServiceHeartbeatStore
{
    Task<ServiceHeartbeat?> GetAsync(CancellationToken cancellationToken = default);

    Task SaveAsync(ServiceHeartbeat heartbeat, CancellationToken cancellationToken = default);
}

internal sealed class JsonServiceHeartbeatStore : IServiceHeartbeatStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _path;

    public JsonServiceHeartbeatStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.ServiceHeartbeatFile)
    {
    }

    internal JsonServiceHeartbeatStore(IFileSystem fileSystem, string path)
    {
        _fileSystem = fileSystem;
        _path = path;
    }

    public async Task<ServiceHeartbeat?> GetAsync(CancellationToken cancellationToken = default)
    {
        if (!_fileSystem.FileExists(_path))
        {
            return null;
        }

        try
        {
            var heartbeat = JsonSerializer.Deserialize<ServiceHeartbeat>(
                await _fileSystem.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false),
                SerializerOptions);
            if (heartbeat is not null)
            {
                StateSchema.EnsureSupported(heartbeat.SchemaVersion, StateSchema.ServiceHeartbeat, _path);
            }

            return heartbeat;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Service heartbeat '{_path}' contains invalid JSON.", exception);
        }
    }

    // Only the service writes this file, and the atomic replace keeps readers from seeing a partial write.
    public Task SaveAsync(ServiceHeartbeat heartbeat, CancellationToken cancellationToken = default) =>
        _fileSystem.WriteAllTextAtomicAsync(
            _path,
            JsonSerializer.Serialize(heartbeat with { SchemaVersion = StateSchema.ServiceHeartbeat }, SerializerOptions),
            cancellationToken);
}
