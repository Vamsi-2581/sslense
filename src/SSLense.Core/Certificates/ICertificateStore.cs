using System.Security.Cryptography.X509Certificates;

namespace SSLense.Core.Certificates;

/// <summary>The LocalMachine certificate stores: My for site certificates, CA for intermediates.</summary>
public interface ICertificateStore
{
    Task<InstalledCertificate?> FindByThumbprintAsync(
        string thumbprint,
        CancellationToken cancellationToken = default);

    /// <summary>Opens an installed certificate for inspection; the caller disposes it. Null when not installed.</summary>
    Task<X509Certificate2?> OpenAsync(string thumbprint, CancellationToken cancellationToken = default);

    Task<InstalledCertificate> ImportPfxAsync(
        byte[] pfxBytes,
        string password,
        string friendlyName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Imports the certificate with a private key from a PFX as non-exportable, and adds any intermediate
    /// certificates it contains to the CA store. Root certificates are never added to the trusted roots.
    /// </summary>
    Task<InstalledCertificate> ImportPfxWithChainAsync(
        byte[] pfxBytes,
        string password,
        string friendlyName,
        CancellationToken cancellationToken = default);

    /// <summary>Adds a certificate whose private key is already persisted in the Windows key store.</summary>
    Task<InstalledCertificate> AddAsync(
        X509Certificate2 certificateWithKey,
        string friendlyName,
        CancellationToken cancellationToken = default);

    /// <summary>Adds intermediate CA certificates to LocalMachine\CA. Self-signed roots are skipped.</summary>
    Task AddIntermediatesAsync(
        IReadOnlyList<X509Certificate2> intermediates,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(string thumbprint, CancellationToken cancellationToken = default);
}
