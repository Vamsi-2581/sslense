using System.Text.Json;

namespace SSLense.Core.Config;

public sealed class JsonConfigStore : IConfigStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _configPath;
    private readonly string _lockPath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public JsonConfigStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.ConfigFile, AppPaths.ConfigLockFile)
    {
    }

    public JsonConfigStore(IFileSystem fileSystem, string configPath)
        : this(fileSystem, configPath, $"{configPath}.lock")
    {
    }

    public JsonConfigStore(IFileSystem fileSystem, string configPath, string lockPath)
    {
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        _configPath = string.IsNullOrWhiteSpace(configPath)
            ? throw new ArgumentException("A config path is required.", nameof(configPath))
            : configPath;
        _lockPath = string.IsNullOrWhiteSpace(lockPath)
            ? throw new ArgumentException("A lock path is required.", nameof(lockPath))
            : lockPath;
    }

    public async Task<AppConfig> LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var fileLock = await _fileSystem
                .AcquireExclusiveFileLockAsync(_lockPath, cancellationToken)
                .ConfigureAwait(false);
            if (!_fileSystem.FileExists(_configPath))
            {
                return new AppConfig();
            }

            var json = await _fileSystem.ReadAllTextAsync(_configPath, cancellationToken)
                .ConfigureAwait(false);
            var config = JsonSerializer.Deserialize<AppConfig>(json, SerializerOptions)
                ?? throw new InvalidDataException($"Configuration file '{_configPath}' is empty.");
            StateSchema.EnsureSupported(config.SchemaVersion, StateSchema.Config, _configPath);
            config = config.Notifications is null
                ? config with { Notifications = new NotificationConfig() }
                : config with { Notifications = config.Notifications with { Chat = config.Notifications.Chat ?? [] } };
            config = config with { CertificateAuthorities = config.CertificateAuthorities ?? [] };

            // Migrated in memory; the file is rewritten (after a backup) the next time settings are saved.
            return ConfigMigrations.Migrate(config);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Configuration file '{_configPath}' contains invalid JSON.",
                exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(AppConfig config, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var fileLock = await _fileSystem
                .AcquireExclusiveFileLockAsync(_lockPath, cancellationToken)
                .ConfigureAwait(false);
            var existingVersion = await ReadExistingVersionAsync(cancellationToken).ConfigureAwait(false);
            if (existingVersion is { } version)
            {
                StateSchema.EnsureSupported(version, StateSchema.Config, _configPath);
                if (version < StateSchema.Config)
                {
                    await StateSchema.BackupBeforeMigrationAsync(_fileSystem, _configPath, version, cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            var json = JsonSerializer.Serialize(config with { SchemaVersion = StateSchema.Config }, SerializerOptions);
            await _fileSystem.WriteAllTextAtomicAsync(_configPath, json, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Configuration file '{_configPath}' contains invalid JSON and was not overwritten.",
                exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<int?> ReadExistingVersionAsync(CancellationToken cancellationToken)
    {
        if (!_fileSystem.FileExists(_configPath))
        {
            return null;
        }

        using var document = JsonDocument.Parse(
            await _fileSystem.ReadAllTextAsync(_configPath, cancellationToken).ConfigureAwait(false));
        return document.RootElement.TryGetProperty("schemaVersion", out var value) && value.TryGetInt32(out var version)
            ? version
            : 0;
    }
}
