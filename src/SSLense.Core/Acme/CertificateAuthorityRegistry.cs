using SSLense.Core.Config;

namespace SSLense.Core.Acme;

public interface ICertificateAuthorityRegistry
{
    /// <summary>Every available profile: the built-in Let's Encrypt profiles first, then configured ones.</summary>
    Task<IReadOnlyList<CertificateAuthority>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>Resolves a profile by ID, or explains how to configure it when it does not exist.</summary>
    Task<CertificateAuthority> GetAsync(string id, CancellationToken cancellationToken = default);
}

internal sealed class CertificateAuthorityRegistry(IConfigStore configStore) : ICertificateAuthorityRegistry
{
    /// <summary>Only the built-in Let's Encrypt profiles; the default where no configuration is involved, such as tests.</summary>
    public static ICertificateAuthorityRegistry BuiltInOnly { get; } = new BuiltInRegistry();

    public async Task<IReadOnlyList<CertificateAuthority>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        return [.. CertificateAuthorities.BuiltIn, .. config.CertificateAuthorities.Where(value => !value.IsBuiltIn)];
    }

    public async Task<CertificateAuthority> GetAsync(string id, CancellationToken cancellationToken = default) =>
        Find(await GetAllAsync(cancellationToken).ConfigureAwait(false), id);

    private static CertificateAuthority Find(IReadOnlyList<CertificateAuthority> authorities, string id) =>
        authorities.FirstOrDefault(value => string.Equals(value.Id, id, StringComparison.OrdinalIgnoreCase))
        ?? throw new InvalidOperationException(
            $"Certificate authority '{id}' is not configured on this server. Available: " +
            string.Join(", ", authorities.Select(value => value.Id)) + ".");

    private sealed class BuiltInRegistry : ICertificateAuthorityRegistry
    {
        public Task<IReadOnlyList<CertificateAuthority>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CertificateAuthorities.BuiltIn);

        public Task<CertificateAuthority> GetAsync(string id, CancellationToken cancellationToken = default) =>
            Task.FromResult(Find(CertificateAuthorities.BuiltIn, id));
    }
}

public static class CertificateAuthorityRegistryExtensions
{
    /// <summary>
    /// How to show where a managed certificate comes from. Never throws: a profile removed since the certificate
    /// was issued is shown by its ID, and an imported certificate by its issuer.
    /// </summary>
    public static async Task<(string Name, bool IsTest)> DescribeAsync(
        this ICertificateAuthorityRegistry registry,
        Config.ManagedCertificate certificate,
        CancellationToken cancellationToken = default)
    {
        if (certificate.Source == Config.CertificateSource.Imported)
        {
            return ($"Imported{(string.IsNullOrWhiteSpace(certificate.Issuer) ? string.Empty : $" ({certificate.Issuer})")}", false);
        }

        var authority = (await registry.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(value => string.Equals(value.Id, certificate.AuthorityId, StringComparison.OrdinalIgnoreCase));
        return authority is null ? (certificate.AuthorityId, false) : (authority.Name, authority.IsTest);
    }
}
