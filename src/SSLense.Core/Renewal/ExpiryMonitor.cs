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
            if (certificate.Source == CertificateSource.Imported && certificate.NotAfter > now)
            {
                if (await SendImportedReminderAsync(certificate, now, cancellationToken).ConfigureAwait(false) is { } message)
                {
                    sent.Add(message);
                }

                continue;
            }

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

    /// <summary>
    /// Ordering a certificate from a CA takes time, so imported certificates get fixed, earlier reminders than the
    /// lifetime-relative warnings for certificates SSLense renews itself. Each is sent once.
    /// </summary>
    internal static IReadOnlyList<int> ImportedReminderDays { get; } = [30, 14, 7, 1];

    /// <summary>The reminder due now (30, 14, 7, or 1 days), or null when none is due.</summary>
    internal static int? GetImportedReminder(ManagedCertificate certificate, DateTimeOffset now)
    {
        var daysLeft = (certificate.NotAfter - now).TotalDays;
        int? due = ImportedReminderDays.Where(days => daysLeft <= days).Select(days => (int?)days).LastOrDefault();
        return due is { } value && (certificate.ReminderDaysSent is null || value < certificate.ReminderDaysSent)
            ? value
            : null;
    }

    private async Task<string?> SendImportedReminderAsync(
        ManagedCertificate certificate,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (GetImportedReminder(certificate, now) is not { } days)
        {
            return null;
        }

        var daysLeft = Math.Max(0, (int)Math.Floor((certificate.NotAfter - now).TotalDays));
        var issuer = certificate.Issuer is { Length: > 0 } name ? name : "its issuer";
        var message = new NotificationMessage(
            NotificationKind.ExpiryWarning,
            $"SSLense: order a replacement certificate for {certificate.SiteName} ({daysLeft} days left)",
            $"The certificate for {certificate.SiteName} ({string.Join(", ", certificate.Hosts)}) from {issuer} expires at " +
            $"{certificate.NotAfter:O}. SSLense cannot renew it automatically because it was obtained outside SSLense.{Environment.NewLine}" +
            "To replace it: create a certificate request on the Other Providers page of the SSLense app " +
            $"(or run 'SSLense.Cli csr --site \"{certificate.SiteName}\"'), submit it to {issuer}, then complete the request " +
            "with the issued certificate. " +
            "SSLense swaps the binding safely and keeps the current certificate until the new one is confirmed.",
            days <= 7 ? NotificationSeverity.Error : NotificationSeverity.Warning);
        try
        {
            await notifier.NotifyAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return $"Could not send the {days}-day reminder for '{certificate.SiteName}': {exception.Message} " +
                   "It will be retried on the next check.";
        }

        await managedStore.RecordImportedReminderAsync(certificate.SiteName, certificate.Thumbprint, days, CancellationToken.None)
            .ConfigureAwait(false);
        return $"Sent the {days}-day replacement reminder for imported certificate '{certificate.SiteName}'.";
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
        var environment = CertificateAuthorities.Label(certificate.AuthorityId);
        var renewalState = certificate.ConsecutiveFailures > 0
            ? $" The last {certificate.ConsecutiveFailures} renewal attempt(s) failed: {certificate.LastRenewalMessage}"
            : string.Empty;
        return level == ExpiryWarningLevel.Expired
            ? new NotificationMessage(
                NotificationKind.ExpiryWarning,
                $"SSLense certificate EXPIRED: {certificate.SiteName}",
                certificate.Source == CertificateSource.Imported
                    ? $"The certificate for {certificate.SiteName} ({hosts}) from {certificate.Issuer ?? "its issuer"} expired at " +
                      $"{certificate.NotAfter:O}. HTTPS clients now reject it. Order a replacement, then install it with " +
                      $"'SSLense.Cli complete' or 'SSLense.Cli import'."
                    : $"The {environment} certificate for {certificate.SiteName} ({hosts}) expired at " +
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
