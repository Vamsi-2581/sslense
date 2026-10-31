using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Notifications;

namespace SSLense.Core.Reminders;

/// <summary>
/// Notices a certificate from another provider that was renewed outside SSLense, for example a new 123-reg certificate
/// installed through IIS Manager, so reminders about the old one stop (docs/design/expiry-reminders.md, section 4.5).
/// </summary>
public interface IOutsideRenewalDetector
{
    /// <summary>Updates the record of each imported certificate whose site now serves a newer one. Returns what changed.</summary>
    Task<IReadOnlyList<string>> DetectAsync(CancellationToken cancellationToken = default);
}

internal sealed class OutsideRenewalDetector(
    IManagedCertificateStore managedStore,
    IIisService iisService,
    ICertificateStore certificateStore,
    INotifier notifier,
    ICertificateOperationLock operationLock) : IOutsideRenewalDetector
{
    public async Task<IReadOnlyList<string>> DetectAsync(CancellationToken cancellationToken = default)
    {
        var changes = new List<string>();
        var sites = (await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .Where(record => record.Source == CertificateSource.Imported)
            .Select(record => record.SiteName)
            .ToArray();
        foreach (var siteName in sites)
        {
            // An import or completion in progress changes the bindings first and may still roll them back after its
            // HTTPS check; such a site is looked at again at the next hourly check instead of waiting.
            await using var siteLock = operationLock.TryAcquire(siteName);
            if (siteLock is null)
            {
                continue;
            }

            // Read again under the lock: the record and bindings seen before taking it may already be out of date.
            var record = (await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
                .FirstOrDefault(value => string.Equals(value.SiteName, siteName, StringComparison.OrdinalIgnoreCase));
            var site = (await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false))
                .FirstOrDefault(value => string.Equals(value.Name, siteName, StringComparison.OrdinalIgnoreCase));
            if (record is not { Source: CertificateSource.Imported } || site is null ||
                await FindReplacementAsync(record, site, cancellationToken).ConfigureAwait(false) is not { } replacement)
            {
                continue;
            }

            // Upsert resets the reminders for the new certificate, unless they are off permanently.
            await managedStore.UpsertAsync(
                    record with
                    {
                        Thumbprint = replacement.Thumbprint,
                        NotBefore = replacement.NotBefore,
                        NotAfter = replacement.NotAfter,
                        Issuer = replacement.IssuerName ?? record.Issuer,
                        LastRenewalAttempt = DateTimeOffset.UtcNow,
                        LastRenewalSucceeded = true,
                        LastRenewalMessage = "Replaced outside SSLense; the new certificate was found in IIS and is now monitored."
                    },
                    CancellationToken.None)
                .ConfigureAwait(false);
            var change = $"The certificate for '{record.SiteName}' ({string.Join(", ", record.Hosts)}) was replaced outside SSLense. " +
                         $"SSLense now monitors the new one, which expires {replacement.NotAfter:yyyy-MM-dd}.";
            changes.Add(change);
            try
            {
                await notifier.NotifyAsync(
                        new NotificationMessage(NotificationKind.RenewalSuccess, $"SSLense: certificate replaced for {record.SiteName}", change),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                // The record is already updated; the next digest reflects it.
                changes.Add($"Could not send the replacement notice for '{record.SiteName}': {exception.Message}");
            }
        }

        return changes;
    }

    /// <summary>
    /// The certificate every HTTPS binding of the record's hosts on port 443 now uses, when it differs, has its private
    /// key here, covers all the hosts, and expires later: the same checks as adoption. Every binding counts, so a host
    /// bound on several IP addresses is only taken as replaced once none of them still serves the old certificate.
    /// </summary>
    private async Task<InstalledCertificate?> FindReplacementAsync(ManagedCertificate record, IisSite site, CancellationToken cancellationToken)
    {
        var bindings = record.Hosts
            .Select(host => site.Bindings
                .Where(binding =>
                    string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                    binding.Port == 443 &&
                    string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase))
                .ToArray())
            .ToArray();
        if (bindings.Any(forHost => forHost.Length == 0))
        {
            return null;
        }

        var thumbprints = bindings.SelectMany(forHost => forHost).Select(binding => binding.CertificateThumbprint).ToArray();
        if (thumbprints.Any(thumbprint => thumbprint is null) ||
            thumbprints.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 1 ||
            string.Equals(thumbprints[0], record.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var candidate = await certificateStore.FindByThumbprintAsync(thumbprints[0]!, cancellationToken).ConfigureAwait(false);
        return candidate is { HasPrivateKey: true } &&
               candidate.NotAfter > record.NotAfter &&
               candidate.DnsNames is { } names &&
               record.Hosts.All(host => CertificateInspector.Covers(names, host))
            ? candidate
            : null;
    }
}
