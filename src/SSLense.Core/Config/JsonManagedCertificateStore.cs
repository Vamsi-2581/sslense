using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SSLense.Core.Config;

public sealed class JsonManagedCertificateStore : IManagedCertificateStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _statePath;
    private readonly string _lockPath;

    public JsonManagedCertificateStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.ManagedCertificatesFile, AppPaths.ManagedCertificatesLockFile)
    {
    }

    public JsonManagedCertificateStore(IFileSystem fileSystem, string statePath, string lockPath)
    {
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        _statePath = statePath;
        _lockPath = lockPath;
    }

    public async Task<IReadOnlyList<ManagedCertificate>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        await using var fileLock = await _fileSystem
            .AcquireExclusiveFileLockAsync(_lockPath, cancellationToken)
            .ConfigureAwait(false);
        return (await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false)).Records;
    }

    public async Task UpsertAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        await UpdateAsync(
                records =>
                {
                    var existing = records.FindIndex(value => IsSite(value, certificate.SiteName));
                    var id = certificate.Id != Guid.Empty
                        ? certificate.Id
                        : existing >= 0 ? records[existing].Id : Guid.NewGuid();
                    var record = certificate with { Id = id };
                    if (existing >= 0)
                    {
                        record = WithReminderState(record, records[existing]);
                        records.RemoveAt(existing);
                    }

                    records.Add(record);
                    return true;
                },
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ManagedCertificate?> RecordRenewalFailureAsync(
        string siteName,
        DateTimeOffset attemptedAt,
        string message,
        DateTimeOffset nextRetryAt,
        CancellationToken cancellationToken = default)
    {
        ManagedCertificate? updated = null;
        await UpdateAsync(
                records =>
                {
                    var index = records.FindIndex(value => IsSite(value, siteName));
                    if (index < 0)
                    {
                        return false;
                    }

                    updated = records[index] = records[index] with
                    {
                        LastRenewalAttempt = attemptedAt,
                        LastRenewalSucceeded = false,
                        LastRenewalMessage = message,
                        ConsecutiveFailures = records[index].ConsecutiveFailures + 1,
                        NextRetryAt = nextRetryAt
                    };
                    return true;
                },
                cancellationToken)
            .ConfigureAwait(false);
        return updated;
    }

    public Task RecordRemindersAsync(
        IReadOnlyList<ReminderRecord> sent,
        DateTimeOffset sentAt,
        CancellationToken cancellationToken = default) =>
        UpdateAsync(
            records =>
            {
                var changed = false;
                foreach (var entry in sent)
                {
                    var index = records.FindIndex(value => IsSite(value, entry.SiteName));
                    if (index < 0 ||
                        !string.Equals(records[index].Thumbprint, entry.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    records[index] = records[index] with
                    {
                        LastRemindedAt = entry.Reminded ? sentAt : records[index].LastRemindedAt,
                        UpcomingNoticeSent = records[index].UpcomingNoticeSent || entry.NoticeSent
                    };
                    changed = true;
                }

                return changed;
            },
            cancellationToken);

    /// <summary>
    /// Reminder state belongs to the site's record: an install or renewal keeps it, and a new certificate starts its
    /// reminders afresh, except when the administrator turned them off permanently.
    /// </summary>
    private static ManagedCertificate WithReminderState(ManagedCertificate incoming, ManagedCertificate existing)
    {
        if (string.Equals(incoming.Thumbprint, existing.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            return incoming with
            {
                Reminders = existing.Reminders,
                SnoozedUntil = existing.SnoozedUntil,
                LastRemindedAt = existing.LastRemindedAt,
                UpcomingNoticeSent = existing.UpcomingNoticeSent
            };
        }

        return incoming with
        {
            Reminders = existing.Reminders == ReminderMode.Off ? ReminderMode.Off : ReminderMode.On,
            SnoozedUntil = null,
            LastRemindedAt = null,
            UpcomingNoticeSent = false
        };
    }

    public async Task RemoveAsync(string siteName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        await UpdateAsync(
                records =>
                {
                    records.RemoveAll(value => IsSite(value, siteName));
                    return true;
                },
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal static Guid CreateMigratedId(string siteName)
    {
        // Deterministic, so a legacy file read repeatedly before its first rewrite yields the same IDs.
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"sslense-v0:{siteName.Trim().ToUpperInvariant()}"));
        return new Guid(hash.AsSpan(0, 16));
    }

    private async Task UpdateAsync(Func<List<ManagedCertificate>, bool> mutate, CancellationToken cancellationToken)
    {
        await using var fileLock = await _fileSystem
            .AcquireExclusiveFileLockAsync(_lockPath, cancellationToken)
            .ConfigureAwait(false);
        var (records, version) = await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false);
        var list = records.ToList();
        if (!mutate(list))
        {
            return;
        }

        if (version < StateSchema.ManagedCertificates)
        {
            await StateSchema.BackupBeforeMigrationAsync(_fileSystem, _statePath, version, cancellationToken)
                .ConfigureAwait(false);
        }

        await _fileSystem.WriteAllTextAtomicAsync(
                _statePath,
                JsonSerializer.Serialize(new StateDocument(StateSchema.ManagedCertificates, list), SerializerOptions),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<(IReadOnlyList<ManagedCertificate> Records, int Version)> ReadUnsafeAsync(
        CancellationToken cancellationToken)
    {
        if (!_fileSystem.FileExists(_statePath))
        {
            return ([], StateSchema.ManagedCertificates);
        }

        var json = await _fileSystem.ReadAllTextAsync(_statePath, cancellationToken).ConfigureAwait(false);
        int version;
        List<ManagedCertificate>? records;
        try
        {
            // Read as a tree first, so older records can be upgraded before they are bound to the current type.
            var root = JsonNode.Parse(json)
                ?? throw new InvalidDataException($"Managed certificate state '{_statePath}' is empty.");
            JsonArray? array;
            if (root is JsonArray bareArray)
            {
                version = 0;
                array = bareArray;
            }
            else
            {
                version = root["schemaVersion"]?.GetValue<int>() ?? 0;
                StateSchema.EnsureSupported(version, StateSchema.ManagedCertificates, _statePath);
                array = root["certificates"] as JsonArray;
            }

            if (array is not null && version < 2)
            {
                ManagedCertificateMigrations.UpgradeRecords(array);
            }

            records = array?.Deserialize<List<ManagedCertificate>>(SerializerOptions);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Managed certificate state '{_statePath}' contains invalid JSON.",
                exception);
        }

        if (records is null)
        {
            throw new InvalidDataException($"Managed certificate state '{_statePath}' is empty.");
        }

        return (
            records
                .Select(record => record.Id == Guid.Empty
                    ? record with { Id = CreateMigratedId(record.SiteName) }
                    : record)
                .ToArray(),
            version);
    }

    private static bool IsSite(ManagedCertificate record, string siteName) =>
        string.Equals(record.SiteName, siteName, StringComparison.OrdinalIgnoreCase);

    private sealed record StateDocument(int SchemaVersion, List<ManagedCertificate>? Certificates);
}
