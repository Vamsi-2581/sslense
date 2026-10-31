using SSLense.Core.Config;

namespace SSLense.Core.Renewal;

/// <summary>
/// How close a certificate is to expiry, for the health check. Thresholds scale with lifetime so 90-, 64-, 45-, and
/// 6-day certificates are all flagged in time, capped at 14 and 3 days for long-lived certificates.
/// </summary>
internal static class ExpiryLevels
{
    private static readonly TimeSpan WarningCap = TimeSpan.FromDays(14);
    private static readonly TimeSpan CriticalCap = TimeSpan.FromDays(3);

    public static ExpiryWarningLevel GetLevel(ManagedCertificate certificate, DateTimeOffset now)
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

    private static TimeSpan Min(TimeSpan first, TimeSpan second) => first < second ? first : second;
}
