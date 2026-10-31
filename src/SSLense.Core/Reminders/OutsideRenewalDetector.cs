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
    INotifier notifier) : IOutsideRenewalDetector
{
    public async Task<IReadOnlyList<string>> DetectAsync(CancellationToken cancellationToken = default)
    {
        var changes = new List<string>();
        var imported = (await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .Where(record => record.Source == CertificateSource.Imported)
            .ToArray();
        if (imported.Length == 0)
        {
            return changes;
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        foreach (var record in imported)
        {
            if (sites.FirstOrDefault(site => string.Equals(site.Name, record.SiteName, StringComparison.OrdinalIgnoreCase)) is not { } site ||
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
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // The record is already updated; the next digest reflects it.
                changes.Add($"Could not send the replacement notice for '{record.SiteName}': {exception.Message}");
            }
        }

        return changes;
    }

    /// <summary>
    /// The certificate every HTTPS binding of the record's hosts on port 443 now uses, when it differs, has its private
    /// key here, covers all the hosts, and expires later: the same checks as adoption.
    /// </summary>
    private async Task<InstalledCertificate?> FindReplacementAsync(ManagedCertificate record, IisSite site, CancellationToken cancellationToken)
    {
        var thumbprints = record.Hosts
            .Select(host => site.Bindings.FirstOrDefault(binding =>
                string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 443 &&
                string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase))?.CertificateThumbprint)
            .ToArray();
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
