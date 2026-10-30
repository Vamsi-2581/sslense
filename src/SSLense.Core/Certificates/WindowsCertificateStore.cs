using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SSLense.Core.Certificates;

internal sealed class WindowsCertificateStore : ICertificateStore
{
    public Task<InstalledCertificate?> FindByThumbprintAsync(
        string thumbprint,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        var normalizedThumbprint = NormalizeThumbprint(thumbprint);

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            normalizedThumbprint,
            validOnly: false);
        try
        {
            var certificate = matches.OfType<X509Certificate2>().FirstOrDefault();
            return Task.FromResult(certificate is null ? null : Map(certificate));
        }
        finally
        {
            foreach (var certificate in matches.OfType<X509Certificate2>())
            {
                certificate.Dispose();
            }
        }
    }

    public Task<InstalledCertificate> ImportPfxAsync(
        byte[] pfxBytes,
        string password,
        string friendlyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(friendlyName);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();

        try
        {
            using var certificate = X509CertificateLoader.LoadPkcs12(
                pfxBytes,
                password,
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet);
            if (!certificate.HasPrivateKey)
            {
                throw new CryptographicException("The issued PFX does not contain a private key.");
            }

            certificate.FriendlyName = friendlyName;
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
            store.Add(certificate);
            return Task.FromResult(Map(certificate));
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException(
                "The certificate could not be imported into LocalMachine\\My. " +
                "Run SSLense as Administrator and verify the PFX is valid.",
                exception);
        }
    }

    public Task<X509Certificate2?> OpenAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, NormalizeThumbprint(thumbprint), validOnly: false);
        var found = matches.OfType<X509Certificate2>().FirstOrDefault();
        foreach (var certificate in matches.OfType<X509Certificate2>().Where(value => !ReferenceEquals(value, found)))
        {
            certificate.Dispose();
        }

        return Task.FromResult(found);
    }

    public Task<InstalledCertificate> ImportPfxWithChainAsync(
        byte[] pfxBytes,
        string password,
        string friendlyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);
        ArgumentException.ThrowIfNullOrWhiteSpace(friendlyName);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();

        X509Certificate2Collection? collection = null;
        try
        {
            // Without Exportable, the persisted private key cannot be exported again from this server.
            collection = X509CertificateLoader.LoadPkcs12Collection(
                pfxBytes,
                password,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
            var leaf = collection.OfType<X509Certificate2>().SingleOrDefault(value => value.HasPrivateKey)
                ?? throw new CryptographicException("The PFX must contain exactly one certificate with a private key.");
            leaf.FriendlyName = friendlyName;
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                store.Add(leaf);
            }

            AddIntermediates(collection.OfType<X509Certificate2>().Where(value => !ReferenceEquals(value, leaf)));
            return Task.FromResult(Map(leaf));
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException(
                "The PFX could not be imported into LocalMachine\\My. Check the password, and run SSLense as Administrator.",
                exception);
        }
        finally
        {
            foreach (var certificate in collection?.OfType<X509Certificate2>() ?? [])
            {
                certificate.Dispose();
            }
        }
    }

    public Task<InstalledCertificate> AddAsync(
        X509Certificate2 certificateWithKey,
        string friendlyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificateWithKey);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        if (!certificateWithKey.HasPrivateKey)
        {
            throw new InvalidOperationException("The certificate is not linked to its private key.");
        }

        certificateWithKey.FriendlyName = friendlyName;
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
        store.Add(certificateWithKey);
        return Task.FromResult(Map(certificateWithKey));
    }

    public Task AddIntermediatesAsync(
        IReadOnlyList<X509Certificate2> intermediates,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        AddIntermediates(intermediates);
        return Task.CompletedTask;
    }

    private static void AddIntermediates(IEnumerable<X509Certificate2> certificates)
    {
        // Self-signed roots would grant trust; only an administrator should add those, deliberately.
        var intermediates = certificates
            .Where(value => CertificateInspector.IsCertificateAuthority(value) &&
                            !value.SubjectName.RawData.AsSpan().SequenceEqual(value.IssuerName.RawData))
            .ToArray();
        if (intermediates.Length == 0)
        {
            return;
        }

        using var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        foreach (var intermediate in intermediates)
        {
            store.Add(intermediate);
        }
    }

    public Task RemoveAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
        var matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            NormalizeThumbprint(thumbprint),
            validOnly: false);
        try
        {
            foreach (var certificate in matches.OfType<X509Certificate2>())
            {
                store.Remove(certificate);
            }
        }
        finally
        {
            foreach (var certificate in matches.OfType<X509Certificate2>())
            {
                certificate.Dispose();
            }
        }

        return Task.CompletedTask;
    }

    private static InstalledCertificate Map(X509Certificate2 certificate) => new(
        NormalizeThumbprint(certificate.Thumbprint),
        certificate.NotBefore.ToUniversalTime(),
        certificate.NotAfter.ToUniversalTime(),
        certificate.HasPrivateKey,
        certificate.Issuer,
        CertificateInspector.GetDnsNames(certificate),
        certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true));

    private static string NormalizeThumbprint(string thumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);
        return string.Concat(thumbprint.Where(Uri.IsHexDigit)).ToUpperInvariant();
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The LocalMachine certificate store is only available on Windows.");
        }
    }
}
