using System.Text.Json;
using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

/// <summary>A certificate request (CSR) waiting for the certificate authority to issue its certificate.</summary>
/// <param name="KeyName">Name of the persisted, non-exportable key in the Windows key store.</param>
/// <param name="KeyType">One of <see cref="PrivateKeyTypes"/>.</param>
/// <param name="CsrPem">The request itself; public information, kept so it can be shown again.</param>
public sealed record PendingCertificateRequest(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string KeyName,
    string KeyType,
    string CsrPem,
    DateTimeOffset CreatedAt);

public interface IPendingRequestStore
{
    Task<IReadOnlyList<PendingCertificateRequest>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<PendingCertificateRequest?> GetAsync(string siteName, CancellationToken cancellationToken = default);

    /// <summary>Saves the site's request, returning the one it replaces so its key can be deleted.</summary>
    Task<PendingCertificateRequest?> SaveAsync(PendingCertificateRequest request, CancellationToken cancellationToken = default);

    Task RemoveAsync(string siteName, CancellationToken cancellationToken = default);
}

/// <summary>One pending request per IIS site, in pending-requests.json.</summary>
internal sealed class JsonPendingRequestStore : IPendingRequestStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _path;
    private readonly string _lockPath;

    public JsonPendingRequestStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.PendingRequestsFile, AppPaths.PendingRequestsLockFile)
    {
    }

    internal JsonPendingRequestStore(IFileSystem fileSystem, string path, string lockPath)
    {
        _fileSystem = fileSystem;
        _path = path;
        _lockPath = lockPath;
    }

    public async Task<IReadOnlyList<PendingCertificateRequest>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var fileLock = await _fileSystem.AcquireExclusiveFileLockAsync(_lockPath, cancellationToken).ConfigureAwait(false);
        return await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<PendingCertificateRequest?> GetAsync(string siteName, CancellationToken cancellationToken = default) =>
        (await GetAllAsync(cancellationToken).ConfigureAwait(false)).FirstOrDefault(request => IsSite(request, siteName));

    public async Task<PendingCertificateRequest?> SaveAsync(PendingCertificateRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await using var fileLock = await _fileSystem.AcquireExclusiveFileLockAsync(_lockPath, cancellationToken).ConfigureAwait(false);
        var requests = (await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false)).ToList();
        var replaced = requests.FirstOrDefault(value => IsSite(value, request.SiteName));
        requests.RemoveAll(value => IsSite(value, request.SiteName));
        requests.Add(request);
        await WriteUnsafeAsync(requests, cancellationToken).ConfigureAwait(false);
        return replaced;
    }

    public async Task RemoveAsync(string siteName, CancellationToken cancellationToken = default)
    {
        await using var fileLock = await _fileSystem.AcquireExclusiveFileLockAsync(_lockPath, cancellationToken).ConfigureAwait(false);
        var requests = (await ReadUnsafeAsync(cancellationToken).ConfigureAwait(false)).ToList();
        if (requests.RemoveAll(value => IsSite(value, siteName)) > 0)
        {
            await WriteUnsafeAsync(requests, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<IReadOnlyList<PendingCertificateRequest>> ReadUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!_fileSystem.FileExists(_path))
        {
            return [];
        }

        try
        {
            var document = JsonSerializer.Deserialize<Document>(
                    await _fileSystem.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false),
                    SerializerOptions)
                ?? throw new InvalidDataException($"Pending requests file '{_path}' is empty.");
            StateSchema.EnsureSupported(document.SchemaVersion, StateSchema.PendingRequests, _path);
            return document.Requests ?? [];
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Pending requests file '{_path}' contains invalid JSON.", exception);
        }
    }

    private Task WriteUnsafeAsync(IReadOnlyList<PendingCertificateRequest> requests, CancellationToken cancellationToken) =>
        _fileSystem.WriteAllTextAtomicAsync(
            _path,
            JsonSerializer.Serialize(new Document(StateSchema.PendingRequests, requests), SerializerOptions),
            cancellationToken);

    private static bool IsSite(PendingCertificateRequest request, string siteName) =>
        string.Equals(request.SiteName, siteName, StringComparison.OrdinalIgnoreCase);

    private sealed record Document(int SchemaVersion, IReadOnlyList<PendingCertificateRequest>? Requests);
}
