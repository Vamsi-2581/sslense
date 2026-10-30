using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Logs;

namespace SSLense.Core.Certificates;

internal sealed class CertificateManagementService(
    IManagedCertificateStore managedStore,
    ICertificateStore certificateStore,
    IIisService iisService,
    ILogService logService,
    ICertificateAuthorityRegistry? authorities = null) : ICertificateManagementService
{
    private readonly ICertificateAuthorityRegistry _authorities = authorities ?? CertificateAuthorityRegistry.BuiltInOnly;

    public async Task<CertificateDetails> GetDetailsAsync(
        string siteName,
        CancellationToken cancellationToken = default)
    {
        var record = await FindRecordAsync(siteName, cancellationToken).ConfigureAwait(false);
        var installed = await certificateStore.FindByThumbprintAsync(record.Thumbprint, cancellationToken)
            .ConfigureAwait(false);
        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var boundSites = sites.Where(site => site.Bindings.Any(binding =>
                string.Equals(binding.CertificateThumbprint, record.Thumbprint, StringComparison.OrdinalIgnoreCase)))
            .Select(site => site.Name)
            .ToArray();
        var logs = await logService.ReadCurrentAsync("All", 10, cancellationToken).ConfigureAwait(false);
        var authority = await _authorities.DescribeAsync(record, cancellationToken).ConfigureAwait(false);
        return new CertificateDetails(
            record.SiteName,
            record.Hosts,
            record.Thumbprint,
            installed?.Issuer ?? "Unknown",
            installed?.NotBefore ?? record.NotBefore,
            installed?.NotAfter ?? record.NotAfter,
            boundSites,
            logs.Lines,
            record.AuthorityId,
            authority.Name,
            authority.IsTest,
            record.Source);
    }

    public async Task RemoveAsync(string siteName, CancellationToken cancellationToken = default)
    {
        var record = await FindRecordAsync(siteName, cancellationToken).ConfigureAwait(false);
        await iisService.RemoveHttpsBindingsAsync(
                record.SiteName,
                record.Hosts,
                record.Thumbprint,
                cancellationToken)
            .ConfigureAwait(false);

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var stillUsed = sites.SelectMany(site => site.Bindings).Any(binding =>
            string.Equals(binding.CertificateThumbprint, record.Thumbprint, StringComparison.OrdinalIgnoreCase));
        // Only certificates SSLense obtained itself are deleted; an imported one may be used outside IIS.
        if (!stillUsed && record.Source == CertificateSource.Acme)
        {
            await certificateStore.RemoveAsync(record.Thumbprint, cancellationToken).ConfigureAwait(false);
        }

        await managedStore.RemoveAsync(record.SiteName, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ManagedCertificate> FindRecordAsync(
        string siteName,
        CancellationToken cancellationToken)
    {
        var records = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return records.SingleOrDefault(value =>
            string.Equals(value.SiteName, siteName, StringComparison.OrdinalIgnoreCase))
            ?? throw ManagedCertificateNotFound.Create(siteName, records);
    }
}
