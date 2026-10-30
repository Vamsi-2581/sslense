using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Config;

namespace SSLense.Core.Acme;

internal sealed class AcmeAccountStore : IAcmeAccountStore
{
    private readonly IFileSystem _fileSystem;
    private readonly ISecretProtector _protector;

    public AcmeAccountStore(IFileSystem fileSystem, ISecretProtector protector)
    {
        _fileSystem = fileSystem;
        _protector = protector;
    }

    public async Task<string?> LoadKeyAsync(string authorityId, CancellationToken cancellationToken)
    {
        var path = AppPaths.GetAccountKeyFile(authorityId);
        if (!_fileSystem.FileExists(path))
        {
            return null;
        }

        var encoded = await _fileSystem.ReadAllTextAsync(path, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var encrypted = Convert.FromBase64String(encoded);
            var plaintext = _protector.Unprotect(encrypted);
            try
            {
                return Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The saved ACME account key is corrupt.", exception);
        }
    }

    public async Task SaveKeyAsync(string authorityId, string accountKeyPem, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountKeyPem);

        var plaintext = Encoding.UTF8.GetBytes(accountKeyPem);
        try
        {
            var encrypted = _protector.Protect(plaintext);
            await _fileSystem.WriteAllTextAtomicAsync(
                    AppPaths.GetAccountKeyFile(authorityId),
                    Convert.ToBase64String(encrypted),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
