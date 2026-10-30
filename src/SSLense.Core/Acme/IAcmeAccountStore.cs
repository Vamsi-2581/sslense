namespace SSLense.Core.Acme;

/// <summary>Stores one DPAPI-protected ACME account key per certificate authority.</summary>
public interface IAcmeAccountStore
{
    Task<string?> LoadKeyAsync(string authorityId, CancellationToken cancellationToken);

    Task SaveKeyAsync(string authorityId, string accountKeyPem, CancellationToken cancellationToken);
}
