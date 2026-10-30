using System.Text.Json;
using System.Text.Json.Nodes;
using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

internal sealed class JsonCertificateTransactionJournal : ICertificateTransactionJournal
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };
    private readonly IFileSystem _fileSystem;
    private readonly string _directory;

    public JsonCertificateTransactionJournal(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.TransactionDirectory)
    {
    }

    internal JsonCertificateTransactionJournal(IFileSystem fileSystem, string directory)
    {
        _fileSystem = fileSystem;
        _directory = directory;
    }

    public async Task<CertificateTransaction> BeginAsync(
        ManagedCertificate certificate,
        string? previousThumbprint,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var transaction = new CertificateTransaction(
            Guid.NewGuid(),
            certificate,
            previousThumbprint,
            CertificateTransactionStage.Prepared,
            DateTimeOffset.UtcNow);
        await WriteAsync(transaction, cancellationToken).ConfigureAwait(false);
        return transaction;
    }

    public async Task UpdateStageAsync(
        Guid id,
        CertificateTransactionStage stage,
        CancellationToken cancellationToken = default)
    {
        var transaction = await GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Certificate transaction '{id}' was not found.");
        await WriteAsync(transaction with { Stage = stage }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<CertificateTransaction?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        var path = GetPath(id);
        if (!_fileSystem.FileExists(path))
        {
            return null;
        }

        return Deserialize(
            await _fileSystem.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false),
            path);
    }

    public async Task<IReadOnlyList<CertificateTransaction>> GetPendingAsync(
        CancellationToken cancellationToken = default)
    {
        var transactions = new List<CertificateTransaction>();
        foreach (var path in _fileSystem.GetFiles(_directory, "*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            transactions.Add(Deserialize(
                await _fileSystem.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false),
                path));
        }

        return transactions.OrderBy(value => value.StartedAt).ToArray();
    }

    public Task CompleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _fileSystem.DeleteFile(GetPath(id));
        _fileSystem.DeleteDirectoryIfEmpty(_directory);
        return Task.CompletedTask;
    }

    private Task WriteAsync(CertificateTransaction transaction, CancellationToken cancellationToken)
    {
        _fileSystem.CreateDirectory(_directory);
        return _fileSystem.WriteAllTextAtomicAsync(
            GetPath(transaction.Id),
            JsonSerializer.Serialize(transaction, SerializerOptions),
            cancellationToken);
    }

    private static CertificateTransaction Deserialize(string json, string path)
    {
        try
        {
            var node = JsonNode.Parse(json) as JsonObject
                ?? throw new InvalidDataException($"Certificate transaction '{path}' is empty.");

            // Entries written before schema 2 hold a schema 1 certificate snapshot. Upgrading it here keeps an
            // interrupted production operation from being recovered as staging after an upgrade.
            if ((node["schemaVersion"]?.GetValue<int>() ?? 0) < 2 && node["certificate"] is JsonObject certificate)
            {
                ManagedCertificateMigrations.UpgradeRecord(certificate);
                node["schemaVersion"] = 2;
            }

            return node.Deserialize<CertificateTransaction>(SerializerOptions)
                ?? throw new InvalidDataException($"Certificate transaction '{path}' is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Certificate transaction '{path}' contains invalid JSON.",
                exception);
        }
    }

    private string GetPath(Guid id) => Path.Combine(_directory, $"{id:N}.json");
}
