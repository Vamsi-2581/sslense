using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Validation;

namespace SSLense.Core.Reminders;

/// <summary>
/// Runs the pre-flight checks ahead of each automatic renewal, so a closed port or a removed binding is found while there
/// is time to fix it (docs/design/proactive-checks.md, section 3). Report-only. The checks run from this server, so a
/// failure means renewal is likely to fail, but a pass does not prove that the CA can reach the site.
/// </summary>
public interface IRenewalReadinessCheck
{
    /// <param name="scheduledRenewals">By site: when each automatic certificate is scheduled to renew.</param>
    Task<ProactiveCheckResult> CheckAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

internal sealed class RenewalReadinessCheck(
    IPreflightService preflight,
    ICertificateOperationLock operationLock) : IRenewalReadinessCheck
{
    /// <summary>Checks start this long before the scheduled renewal, so a certificate far from it causes no daily emails.</summary>
    internal static readonly TimeSpan Window = TimeSpan.FromDays(30);

    public async Task<ProactiveCheckResult> CheckAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        var problems = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var passed = new List<string>();
        var errors = new List<string>();
        foreach (var certificate in certificates.Where(value =>
                     value.Source == CertificateSource.Acme && !ReminderDigestBuilder.IsMuted(value, now)))
        {
            if (!scheduledRenewals.TryGetValue(certificate.SiteName, out var renewalAt) || renewalAt - now > Window)
            {
                continue;
            }

            // An operation in progress changes bindings and challenge files; this site is looked at again tomorrow.
            await using var siteLock = operationLock.TryAcquire(certificate.SiteName);
            if (siteLock is null)
            {
                continue;
            }

            try
            {
                var failed = (await preflight.CheckAsync(certificate.SiteName, certificate.Hosts, cancellationToken).ConfigureAwait(false))
                    .Where(check => !check.Succeeded)
                    .Select(check => $"'{check.Name}' failed: {check.Message}")
                    .ToArray();
                if (failed.Length == 0)
                {
                    passed.Add(certificate.SiteName);
                }
                else
                {
                    problems[certificate.SiteName] = string.Join(" ", failed);
                }
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                errors.Add($"Could not check renewal readiness for '{certificate.SiteName}': {exception.Message}");
            }
        }

        return new ProactiveCheckResult(problems, passed, errors);
    }
}
