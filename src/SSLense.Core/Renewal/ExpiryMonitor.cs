using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Notifications;

namespace SSLense.Core.Renewal;

internal sealed class ExpiryMonitor(
    IManagedCertificateStore managedStore,
    INotifier notifier) : IExpiryMonitor
{
    // Thresholds scale with lifetime so 90-, 64-, 45-, and 6-day certificates all warn in time,
    // capped at the original 14-day and 3-day points for long-lived certificates.
    private static readonly TimeSpan WarningCap = TimeSpan.FromDays(14);
    private static readonly TimeSpan CriticalCap = TimeSpan.FromDays(3);

    public async Task<IReadOnlyList<string>> CheckAsync(CancellationToken cancellationToken = default)
    {
        var sent = new List<string>();
        var now = DateTimeOffset.UtcNow;
        foreach (var certificate in await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var level = GetLevel(certificate, now);
            if (level <= certificate.ExpiryWarningSent)
            {
                continue;
            }

            // Recorded only after delivery, so a failed send is retried on the next check.
            try
            {
                await notifier.NotifyAsync(CreateMessage(certificate, level), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                sent.Add($"Could not send the {level} expiry notification for '{certificate.SiteName}': " +
                    $"{exception.Message} It will be retried on the next check.");
                continue;
            }

            await managedStore.RecordExpiryWarningAsync(
                    certificate.SiteName,
                    certificate.Thumbprint,
                    level,
                    CancellationToken.None)
                .ConfigureAwait(false);
            sent.Add($"Sent {level} expiry notification for '{certificate.SiteName}' " +
                $"(expires {certificate.NotAfter:yyyy-MM-dd HH:mm} UTC).");
        }

        return sent;
    }

    internal static ExpiryWarningLevel GetLevel(ManagedCertificate certificate, DateTimeOffset now)
    {
        var remaining = certificate.NotAfter - now;
        if (remaining <= TimeSpan.Zero)
        {
            return ExpiryWarningLevel.Expired;
        }

        var lifetime = certificate.NotAfter - certificate.NotBefore;
        if (remaining <= Min(CriticalCap, lifetime / 18))
        {
            return ExpiryWarningLevel.Critical;
        }

        return remaining <= Min(WarningCap, lifetime / 6)
            ? ExpiryWarningLevel.Warning
            : ExpiryWarningLevel.None;
    }

    private static NotificationMessage CreateMessage(ManagedCertificate certificate, ExpiryWarningLevel level)
    {
        var hosts = string.Join(", ", certificate.Hosts);
        var environment = certificate.Environment.DisplayName();
        var renewalState = certificate.ConsecutiveFailures > 0
            ? $" The last {certificate.ConsecutiveFailures} renewal attempt(s) failed: {certificate.LastRenewalMessage}"
            : string.Empty;
        return level == ExpiryWarningLevel.Expired
            ? new NotificationMessage(
                NotificationKind.ExpiryWarning,
                $"SSLense certificate EXPIRED: {certificate.SiteName}",
                $"The {environment} certificate for {certificate.SiteName} ({hosts}) expired at " +
                $"{certificate.NotAfter:O}. HTTPS clients now reject it.{renewalState}",
                NotificationSeverity.Error)
            : new NotificationMessage(
                NotificationKind.ExpiryWarning,
                level == ExpiryWarningLevel.Critical
                    ? $"SSLense certificate expires very soon: {certificate.SiteName}"
                    : $"SSLense certificate expires soon: {certificate.SiteName}",
                $"The {environment} certificate for {certificate.SiteName} ({hosts}) expires at " +
                $"{certificate.NotAfter:O} and has not been renewed yet.{renewalState}",
                level == ExpiryWarningLevel.Critical ? NotificationSeverity.Error : NotificationSeverity.Warning);
    }

    private static TimeSpan Min(TimeSpan first, TimeSpan second) => first < second ? first : second;
}
