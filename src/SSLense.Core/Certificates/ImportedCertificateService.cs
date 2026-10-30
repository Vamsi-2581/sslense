using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Iis;

namespace SSLense.Core.Certificates;

/// <summary>An HTTPS binding in IIS and the certificate it uses, for choosing what to adopt.</summary>
public sealed record DiscoveredBinding(
    string SiteName,
    string Host,
    int Port,
    string? Thumbprint,
    string? IssuerName,
    DateTimeOffset? NotAfter,
    bool IsManaged);

/// <param name="Notes">Things the administrator should know, such as a previous certificate left in the store.</param>
public sealed record ImportResult(ManagedCertificate Certificate, IReadOnlyList<string> Notes);

/// <summary>
/// Certificates obtained outside SSLense (bought from a reseller, or issued by another CA): create the request,
/// complete it, import a PFX, or adopt one already bound in IIS. SSLense installs and monitors them but never renews them.
/// </summary>
public interface IImportedCertificateService
{
    Task<IReadOnlyList<DiscoveredBinding>> DiscoverAsync(CancellationToken cancellationToken = default);

    /// <summary>Starts monitoring the certificate already bound to the site, without changing IIS.</summary>
    Task<ManagedCertificate> AdoptAsync(string siteName, string? thumbprint = null, CancellationToken cancellationToken = default);

    /// <summary>Creates a non-exportable key in Windows and a certificate request (CSR) to send to the CA.</summary>
    Task<PendingCertificateRequest> CreateRequestAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string keyType = PrivateKeyTypes.Default,
        CancellationToken cancellationToken = default);

    Task<PendingCertificateRequest?> GetRequestAsync(string siteName, CancellationToken cancellationToken = default);

    Task CancelRequestAsync(string siteName, CancellationToken cancellationToken = default);

    /// <summary>Installs the certificate the CA issued for the site's pending request, with its intermediate bundle.</summary>
    Task<ImportResult> CompleteRequestAsync(
        string siteName,
        byte[] certificateFile,
        byte[]? chainFile,
        bool force = false,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);

    /// <param name="hosts">Hosts to bind; when empty, the site's binding host names that the certificate covers.</param>
    Task<ImportResult> ImportPfxAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        byte[] pfxBytes,
        string password,
        bool force = false,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);
}

internal sealed class ImportedCertificateService(
    IIisService iisService,
    ICertificateStore certificateStore,
    IManagedCertificateStore managedStore,
    IPendingRequestStore pendingRequests,
    IPrivateKeyStore privateKeys,
    ICertificateOperationLock operationLock,
    ICertificateTransactionJournal journal,
    IReadOnlyList<X509Certificate2>? trustedRootsForTesting = null) : IImportedCertificateService
{
    public async Task<IReadOnlyList<DiscoveredBinding>> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var managed = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var certificates = new Dictionary<string, InstalledCertificate?>(StringComparer.OrdinalIgnoreCase);
        var discovered = new List<DiscoveredBinding>();
        foreach (var site in sites)
        {
            foreach (var binding in site.Bindings.Where(value =>
                         string.Equals(value.Protocol, "https", StringComparison.OrdinalIgnoreCase)))
            {
                InstalledCertificate? certificate = null;
                if (binding.CertificateThumbprint is { } thumbprint &&
                    !certificates.TryGetValue(thumbprint, out certificate))
                {
                    certificate = await certificateStore.FindByThumbprintAsync(thumbprint, cancellationToken).ConfigureAwait(false);
                    certificates[thumbprint] = certificate;
                }

                discovered.Add(new DiscoveredBinding(
                    site.Name,
                    binding.HostName,
                    binding.Port,
                    binding.CertificateThumbprint,
                    certificate?.IssuerName,
                    certificate?.NotAfter,
                    managed.Any(record =>
                        string.Equals(record.SiteName, site.Name, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(record.Thumbprint, binding.CertificateThumbprint, StringComparison.OrdinalIgnoreCase))));
            }
        }

        return discovered;
    }

    public async Task<ManagedCertificate> AdoptAsync(
        string siteName,
        string? thumbprint = null,
        CancellationToken cancellationToken = default)
    {
        var site = await FindSiteAsync(siteName, cancellationToken).ConfigureAwait(false);
        await using var siteLock = await operationLock.AcquireAsync(site.Name, cancellationToken).ConfigureAwait(false);
        if (await FindRecordAsync(site.Name, cancellationToken).ConfigureAwait(false) is { } existing)
        {
            throw new InvalidOperationException(
                $"IIS site '{site.Name}' is already managed by SSLense (certificate {existing.Thumbprint}). " +
                "Import a certificate or complete a request to replace it.");
        }

        var bindings = site.Bindings
            .Where(binding => string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                              binding.CertificateThumbprint is not null &&
                              (thumbprint is null || string.Equals(Normalize(binding.CertificateThumbprint), Normalize(thumbprint), StringComparison.Ordinal)))
            .ToArray();
        var thumbprints = bindings.Select(binding => binding.CertificateThumbprint!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (thumbprints.Length == 0)
        {
            throw new InvalidOperationException(thumbprint is null
                ? $"IIS site '{site.Name}' has no HTTPS binding with a certificate to adopt."
                : $"No HTTPS binding of IIS site '{site.Name}' uses certificate {thumbprint}.");
        }

        if (thumbprints.Length > 1)
        {
            throw new InvalidOperationException(
                $"IIS site '{site.Name}' uses several certificates ({string.Join(", ", thumbprints)}). " +
                "Choose which one to adopt (--thumbprint in the CLI); SSLense manages one certificate per site.");
        }

        var certificate = await certificateStore.FindByThumbprintAsync(thumbprints[0], cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Certificate {thumbprints[0]} is bound in IIS but missing from LocalMachine\\My.");
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException($"Certificate {certificate.Thumbprint} has no private key on this server.");
        }

        var hosts = bindings.Select(binding => NormalizeHost(binding.HostName)).Where(host => host.Length > 0).Distinct().ToArray();
        if (hosts.Length == 0)
        {
            throw new InvalidOperationException(
                $"The HTTPS bindings of IIS site '{site.Name}' have no host names. SSLense manages SNI bindings by host name.");
        }

        var record = new ManagedCertificate(
            site.Name,
            hosts,
            string.Empty,
            certificate.Thumbprint,
            certificate.NotBefore,
            certificate.NotAfter,
            LastRenewalMessage: "Existing certificate adopted for monitoring.",
            Source: CertificateSource.Imported,
            Issuer: certificate.IssuerName);
        await managedStore.UpsertAsync(record, CancellationToken.None).ConfigureAwait(false);
        return record;
    }

    public async Task<PendingCertificateRequest> CreateRequestAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string keyType = PrivateKeyTypes.Default,
        CancellationToken cancellationToken = default)
    {
        var site = await FindSiteAsync(siteName, cancellationToken).ConfigureAwait(false);
        var normalizedHosts = NormalizeHosts(hosts);
        if (!PrivateKeyTypes.All.Contains(keyType))
        {
            throw new ArgumentException($"Unknown key type '{keyType}'. Use {string.Join(", ", PrivateKeyTypes.All)}.", nameof(keyType));
        }

        var keyName = $"SSLense-request-{Guid.NewGuid():N}";
        string csr;
        using (var key = privateKeys.Create(keyName, keyType))
        {
            try
            {
                csr = BuildRequest(key, normalizedHosts).CreateSigningRequestPem();
            }
            catch
            {
                privateKeys.Delete(keyName);
                throw;
            }
        }

        var request = new PendingCertificateRequest(site.Name, normalizedHosts, keyName, keyType, csr, DateTimeOffset.UtcNow);
        // Held so a completion of the request being replaced cannot run at the same time.
        IAsyncDisposable siteLock;
        PendingCertificateRequest? replaced;
        try
        {
            siteLock = await operationLock.AcquireAsync(site.Name, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            DeleteKeyQuietly(keyName);
            throw;
        }

        await using (siteLock.ConfigureAwait(false))
        {
            try
            {
                replaced = await pendingRequests.SaveAsync(request, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                DeleteKeyQuietly(keyName);
                throw;
            }

            if (replaced is not null)
            {
                await ReleaseRequestKeyAsync(replaced, CancellationToken.None).ConfigureAwait(false);
            }
        }

        return request;
    }

    public Task<PendingCertificateRequest?> GetRequestAsync(string siteName, CancellationToken cancellationToken = default) =>
        pendingRequests.GetAsync(siteName, cancellationToken);

    public async Task CancelRequestAsync(string siteName, CancellationToken cancellationToken = default)
    {
        // Looked up first so a request can be cancelled even after its IIS site was deleted.
        var found = await pendingRequests.GetAsync(siteName, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"IIS site '{siteName}' has no pending certificate request.");
        await using var siteLock = await operationLock.AcquireAsync(found.SiteName, cancellationToken).ConfigureAwait(false);
        var request = await pendingRequests.GetAsync(found.SiteName, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"IIS site '{siteName}' has no pending certificate request.");
        await pendingRequests.RemoveAsync(request.SiteName, CancellationToken.None).ConfigureAwait(false);
        await ReleaseRequestKeyAsync(request, CancellationToken.None).ConfigureAwait(false);
    }

    public async Task<ImportResult> CompleteRequestAsync(
        string siteName,
        byte[] certificateFile,
        byte[]? chainFile,
        bool force = false,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificateFile);
        var site = await FindSiteAsync(siteName, cancellationToken).ConfigureAwait(false);

        // Held for the whole completion, so the request and its key cannot be replaced or cancelled meanwhile.
        await using var siteLock = await operationLock.AcquireAsync(site.Name, cancellationToken).ConfigureAwait(false);
        var request = await pendingRequests.GetAsync(site.Name, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"IIS site '{siteName}' has no pending certificate request. Create one with 'csr', or use 'import' for a PFX file.");
        var certificates = CertificateInspector.LoadCertificates(certificateFile).ToList();
        if (chainFile is not null)
        {
            certificates.AddRange(CertificateInspector.LoadCertificates(chainFile));
        }

        try
        {
            using var key = privateKeys.Open(request.KeyName)
                ?? throw new InvalidOperationException(
                    "The private key for this request no longer exists on this server. Create a new request with 'csr' " +
                    "and ask the certificate provider to reissue the certificate for it.");
            var publicKey = key.ExportSubjectPublicKeyInfo();
            var leaf = certificates.FirstOrDefault(certificate =>
                    certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(publicKey))
                ?? throw new InvalidOperationException(
                    "None of the certificates in the file belongs to this server's pending request. Check that the " +
                    "provider issued it for the CSR SSLense created, not an older or different request.");
            var intermediates = certificates.Where(value => !ReferenceEquals(value, leaf) && CertificateInspector.IsCertificateAuthority(value)).ToArray();
            ThrowIfInvalid(leaf, request.Hosts, intermediates);

            using var withKey = key switch
            {
                RSA rsa => leaf.CopyWithPrivateKey(rsa),
                ECDsa ecdsa => leaf.CopyWithPrivateKey(ecdsa),
                _ => throw new InvalidOperationException("The pending request uses an unsupported key type.")
            };
            var result = await InstallAsync(
                    site,
                    request.Hosts,
                    leaf,
                    intermediates,
                    token => certificateStore.AddAsync(withKey, FriendlyName(request.Hosts), token),
                    force,
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);

            // The key now belongs to the installed certificate; only the request record goes.
            await pendingRequests.RemoveAsync(request.SiteName, CancellationToken.None).ConfigureAwait(false);
            return result;
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    public async Task<ImportResult> ImportPfxAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        byte[] pfxBytes,
        string password,
        bool force = false,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);
        var site = await FindSiteAsync(siteName, cancellationToken).ConfigureAwait(false);

        // Inspect an in-memory copy first; nothing is written to the key store until validation passes.
        X509Certificate2Collection collection;
        try
        {
            collection = X509CertificateLoader.LoadPkcs12Collection(pfxBytes, password, X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (CryptographicException exception)
        {
            throw await ExplainUnreadablePfxAsync(pfxBytes, exception, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            var leaf = collection.OfType<X509Certificate2>().SingleOrDefault(value => value.HasPrivateKey)
                ?? throw new InvalidOperationException("The PFX must contain exactly one certificate with its private key.");
            var intermediates = collection.OfType<X509Certificate2>()
                .Where(value => !ReferenceEquals(value, leaf) && CertificateInspector.IsCertificateAuthority(value))
                .ToArray();
            var dnsNames = CertificateInspector.GetDnsNames(leaf);
            var targetHosts = hosts.Count > 0
                ? NormalizeHosts(hosts)
                : site.Bindings.Select(binding => NormalizeHost(binding.HostName))
                    .Where(host => host.Length > 0 && CertificateInspector.Covers(dnsNames, host))
                    .Distinct()
                    .ToArray();
            if (targetHosts.Count == 0)
            {
                throw new InvalidOperationException(
                    $"None of IIS site '{site.Name}''s binding host names is covered by the certificate " +
                    $"({string.Join(", ", dnsNames)}). Enter the host names to bind (--hosts in the CLI).");
            }

            ThrowIfInvalid(leaf, targetHosts, intermediates);
            await using var siteLock = await operationLock.AcquireAsync(site.Name, cancellationToken).ConfigureAwait(false);
            return await InstallAsync(
                    site,
                    targetHosts,
                    leaf,
                    intermediates,
                    token => certificateStore.ImportPfxWithChainAsync(pfxBytes, password, FriendlyName(targetHosts), token),
                    force,
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            foreach (var certificate in collection.OfType<X509Certificate2>())
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>
    /// The same safe swap as ACME issuance: journal first, then the store, then IIS with live HTTPS verification and
    /// automatic rollback, then the record. The previous certificate is never deleted, because SSLense did not obtain it.
    /// The caller holds the site's operation lock.
    /// </summary>
    private async Task<ImportResult> InstallAsync(
        IisSite site,
        IReadOnlyList<string> hosts,
        X509Certificate2 leaf,
        IReadOnlyList<X509Certificate2> intermediates,
        Func<CancellationToken, Task<InstalledCertificate>> addToStore,
        bool force,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var existing = await FindRecordAsync(site.Name, cancellationToken).ConfigureAwait(false);
        if (existing?.Source == CertificateSource.Acme && !force)
        {
            throw new InvalidOperationException(
                $"IIS site '{site.Name}' has a certificate that SSLense renews automatically. Importing replaces it with " +
                "one you must renew manually. Confirm the replacement to continue (--force in the CLI).");
        }

        var thumbprint = Normalize(leaf.Thumbprint);
        if (existing is not null && string.Equals(Normalize(existing.Thumbprint), thumbprint, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Certificate {thumbprint} is already installed and bound for IIS site '{site.Name}'.");
        }

        var record = new ManagedCertificate(
            site.Name,
            hosts,
            existing?.Email ?? string.Empty,
            thumbprint,
            leaf.NotBefore.ToUniversalTime(),
            leaf.NotAfter.ToUniversalTime(),
            LastRenewalAttempt: DateTimeOffset.UtcNow,
            LastRenewalSucceeded: true,
            LastRenewalMessage: "Certificate imported and bound successfully.",
            Id: existing?.Id ?? default,
            Source: CertificateSource.Imported,
            Issuer: leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: true));

        // The same certificate may already be installed, for example bound to another site; a rollback must leave it.
        var alreadyInStore = await certificateStore.FindByThumbprintAsync(thumbprint, cancellationToken).ConfigureAwait(false) is not null;
        var transaction = await journal.BeginAsync(record, existing?.Thumbprint, CancellationToken.None).ConfigureAwait(false);
        InstalledCertificate installed;
        try
        {
            progress?.Report(new ProgressEvent("install", "Importing the certificate into LocalMachine\\My with a non-exportable key."));
            await certificateStore.AddIntermediatesAsync(intermediates, cancellationToken).ConfigureAwait(false);
            installed = await addToStore(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Failed before installing: retire the entry, or recovery would find the certificate (possibly one that was
            // already there) and finish an import that was reported as failed.
            if (!alreadyInStore)
            {
                await RemoveQuietlyAsync(thumbprint).ConfigureAwait(false);
            }

            await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        await journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.CertificateImported, CancellationToken.None).ConfigureAwait(false);
        try
        {
            progress?.Report(new ProgressEvent(
                "binding",
                "Creating or updating IIS HTTPS bindings with SNI, then confirming over HTTPS that the new certificate is served."));
            await iisService.ConfigureHttpsBindingsAsync(site.Name, hosts, installed.Thumbprint, "My", cancellationToken).ConfigureAwait(false);
            await journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.BindingsUpdated, CancellationToken.None).ConfigureAwait(false);
        }
        catch (IisBindingException exception) when (exception.PreviousBindingsRestored)
        {
            // The site is back on its previous certificate; the new one is removed only if this import added it. Its key
            // is kept, so a completed request can be retried.
            if (!alreadyInStore)
            {
                await certificateStore.RemoveAsync(installed.Thumbprint, CancellationToken.None).ConfigureAwait(false);
            }

            await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        progress?.Report(new ProgressEvent("state", "Saving the managed certificate record."));
        await managedStore.UpsertAsync(record, CancellationToken.None).ConfigureAwait(false);
        await journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.StateSaved, CancellationToken.None).ConfigureAwait(false);
        await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);

        var notes = new List<string>();
        if (existing is not null)
        {
            notes.Add(
                $"The previous certificate {existing.Thumbprint} was left in LocalMachine\\My, because other software may " +
                "use it. Delete it in certlm.msc when it is no longer needed.");
        }

        if (leaf.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddDays(30))
        {
            notes.Add($"This certificate expires on {leaf.NotAfter.ToUniversalTime():yyyy-MM-dd}; order its replacement soon.");
        }

        return new ImportResult(record, notes);
    }

    private void ThrowIfInvalid(X509Certificate2 leaf, IReadOnlyList<string> hosts, IReadOnlyList<X509Certificate2> intermediates)
    {
        // Production always validates against the machine's trusted roots; tests supply their own test CA.
        var problems = CertificateInspector.Validate(leaf, hosts, intermediates, DateTimeOffset.UtcNow, trustedRootsForTesting);
        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                $"The certificate {CertificateInspector.Describe(leaf)} was not installed: {string.Join(" ", problems)}");
        }
    }

    internal static CertificateRequest BuildRequest(AsymmetricAlgorithm key, IReadOnlyList<string> hosts)
    {
        var subject = new X500DistinguishedName($"CN={hosts[0]}");
        var request = key switch
        {
            RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new ArgumentException("Unsupported key type.", nameof(key))
        };
        var names = new SubjectAlternativeNameBuilder();
        foreach (var host in hosts)
        {
            names.AddDnsName(host);
        }

        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));
        return request;
    }

    /// <summary>
    /// The usual mistake is choosing the provider's .cer or .crt, which has no private key. Say so, and say which
    /// path fits: completing this server's pending request, or exporting a PFX from where the key was created.
    /// </summary>
    private async Task<Exception> ExplainUnreadablePfxAsync(byte[] file, CryptographicException exception, CancellationToken cancellationToken)
    {
        IReadOnlyList<X509Certificate2> certificates;
        try
        {
            certificates = CertificateInspector.LoadCertificates(file);
        }
        catch (InvalidDataException)
        {
            return new InvalidOperationException("The PFX could not be opened. Check the file and its password.", exception);
        }

        try
        {
            foreach (var request in await pendingRequests.GetAllAsync(cancellationToken).ConfigureAwait(false))
            {
                var requestKey = CertificateRequest.LoadSigningRequestPem(request.CsrPem, HashAlgorithmName.SHA256)
                    .PublicKey.ExportSubjectPublicKeyInfo();
                if (certificates.Any(certificate =>
                        certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(requestKey)))
                {
                    return new InvalidOperationException(
                        $"This is the certificate issued for the pending request of IIS site '{request.SiteName}'. It has no " +
                        "private key of its own: the key is already on this server. Install it with 'Complete a request' " +
                        $"(in the CLI: complete --site \"{request.SiteName}\" --certificate <file>).");
                }
            }

            var leaf = certificates.FirstOrDefault(certificate => !CertificateInspector.IsCertificateAuthority(certificate))
                ?? certificates[0];
            return new InvalidOperationException(
                $"This file is a certificate without its private key ({CertificateInspector.Describe(leaf)}), so it cannot be " +
                "imported on its own; a PFX contains both. If SSLense created the request on this server, use 'Complete a " +
                "request'. Otherwise, on the server where the request was created, export the certificate with its private " +
                "key as a PFX (certlm.msc, Personal, Certificates, the certificate, All Tasks, Export, 'Yes, export the " +
                "private key') and import that PFX. If your provider created the key for you, download the PFX or the key " +
                "file from them.");
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    private async Task<IisSite> FindSiteAsync(string siteName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        return sites.FirstOrDefault(site => string.Equals(site.Name, siteName.Trim(), StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException(
                $"IIS site '{siteName}' was not found. Run 'list-sites' to see the site names.");
    }

    private async Task<ManagedCertificate?> FindRecordAsync(string siteName, CancellationToken cancellationToken) =>
        (await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
        .FirstOrDefault(record => string.Equals(record.SiteName, siteName, StringComparison.OrdinalIgnoreCase));

    private static IReadOnlyList<string> NormalizeHosts(IReadOnlyList<string> hosts)
    {
        var normalized = hosts.Select(NormalizeHost).Where(host => host.Length > 0).Distinct().ToArray();
        if (normalized.Length == 0)
        {
            throw new ArgumentException("Specify at least one host name.");
        }

        foreach (var host in normalized)
        {
            if (host.Contains('*') || Uri.CheckHostName(host) != UriHostNameType.Dns)
            {
                throw new ArgumentException($"'{host}' is not a valid DNS host name for an IIS binding.");
            }
        }

        return normalized;
    }

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string Normalize(string thumbprint) => string.Concat(thumbprint.Where(Uri.IsHexDigit)).ToUpperInvariant();

    private static string FriendlyName(IReadOnlyList<string> hosts) => $"SSLense: {hosts[0]} (imported {DateTimeOffset.UtcNow:yyyy-MM-dd})";

    /// <summary>
    /// Deletes a replaced or cancelled request's key, unless an installed certificate uses it. That happens when a
    /// completion was interrupted after installing and recovery finished the binding but not the request cleanup;
    /// deleting the key then would break HTTPS for the site, and the key cannot be restored.
    /// </summary>
    private async Task ReleaseRequestKeyAsync(PendingCertificateRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var requestKey = CertificateRequest.LoadSigningRequestPem(request.CsrPem, HashAlgorithmName.SHA256)
                .PublicKey.ExportSubjectPublicKeyInfo();
            var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
            var managed = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
            var thumbprints = managed.Select(record => record.Thumbprint)
                .Concat(sites.SelectMany(site => site.Bindings).Select(binding => binding.CertificateThumbprint).OfType<string>())
                .Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var thumbprint in thumbprints)
            {
                using var certificate = await certificateStore.OpenAsync(thumbprint, cancellationToken).ConfigureAwait(false);
                if (certificate is not null &&
                    certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(requestKey))
                {
                    return;
                }
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // When in doubt, keep the key: an orphaned key is harmless, a deleted one in use is not.
            return;
        }

        DeleteKeyQuietly(request.KeyName);
    }

    private async Task RemoveQuietlyAsync(string thumbprint)
    {
        try
        {
            await certificateStore.RemoveAsync(thumbprint, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidOperationException)
        {
            // Usually it was never added; anything left is reported by the health check, not worth masking the failure.
        }
    }

    private void DeleteKeyQuietly(string keyName)
    {
        try
        {
            privateKeys.Delete(keyName);
        }
        catch (CryptographicException)
        {
            // An orphaned key is harmless; it cannot be exported and is no longer referenced.
        }
    }
}
