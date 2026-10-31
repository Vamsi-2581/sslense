using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Notifications;

namespace SSLense.Core.Reminders;

public enum ReminderItemKind
{
    /// <summary>The certificate has expired.</summary>
    Expired,

    /// <summary>A certificate from another provider is within the reminder window; it must be ordered again.</summary>
    ManualRenewalDue,

    /// <summary>Automatic renewal is failing.</summary>
    AutomaticRenewalFailing,

    /// <summary>Automatic renewal should have happened more than a day ago.</summary>
    AutomaticRenewalOverdue,

    /// <summary>For information: an automatic certificate entered the window and will be renewed on its own.</summary>
    UpcomingAutomaticRenewal
}

public sealed record ReminderItem(
    ManagedCertificate Certificate,
    ReminderItemKind Kind,
    int DaysLeft,
    DateTimeOffset? ScheduledRenewal);

/// <summary>What one day's reminder email says. Built by <see cref="ReminderDigestBuilder"/>; nothing is sent here.</summary>
/// <param name="All">Every managed certificate, for the weekly summary.</param>
public sealed record ReminderDigest(
    IReadOnlyList<ReminderItem> Items,
    IReadOnlyList<ManagedCertificate> Muted,
    IReadOnlyList<ManagedCertificate> All,
    bool IsWeeklySummary,
    DateTimeOffset BuiltAt)
{
    public IReadOnlyList<ReminderItem> NeedsAttention =>
        Items.Where(item => item.Kind != ReminderItemKind.UpcomingAutomaticRenewal).ToArray();

    public IReadOnlyList<ReminderItem> Upcoming =>
        Items.Where(item => item.Kind == ReminderItemKind.UpcomingAutomaticRenewal).ToArray();

    /// <summary>Whether this digest should be sent: something needs attention, a notice is due, or it is the weekly summary.</summary>
    public bool HasContent => Items.Count > 0 || IsWeeklySummary;

    /// <summary>What to record once the digest was delivered.</summary>
    public IReadOnlyList<ReminderRecord> ToRecords() => Items
        .Select(item => new ReminderRecord(
            item.Certificate.SiteName,
            item.Certificate.Thumbprint,
            Reminded: item.Kind != ReminderItemKind.UpcomingAutomaticRenewal,
            NoticeSent: item.Kind == ReminderItemKind.UpcomingAutomaticRenewal))
        .ToArray();

    public NotificationMessage ToMessage(string serverName, bool sample = false)
    {
        var attention = NeedsAttention;
        var upcoming = Upcoming;
        var subject = attention.Count > 0
            ? $"SSLense: {attention.Count} certificate(s) need attention on {serverName}"
            : upcoming.Count > 0
                ? $"SSLense: upcoming automatic renewals on {serverName}"
                : $"SSLense weekly summary for {serverName}: {All.Count} certificate(s), nothing needs attention";

        var body = new StringBuilder();
        if (sample)
        {
            body.AppendLine("SAMPLE: this is how today's reminder would look. Nothing was recorded, and the real reminders are unchanged.");
            body.AppendLine();
        }

        if (attention.Count > 0)
        {
            body.AppendLine("Needs attention:");
            foreach (var item in attention.OrderBy(item => item.DaysLeft))
            {
                body.AppendLine($"- {Describe(item)}");
            }

            body.AppendLine();
        }

        if (upcoming.Count > 0)
        {
            body.AppendLine("Will renew automatically (no action needed):");
            foreach (var item in upcoming.OrderBy(item => item.DaysLeft))
            {
                body.AppendLine($"- {Describe(item)}");
            }

            body.AppendLine();
        }

        if (IsWeeklySummary)
        {
            body.AppendLine($"Weekly summary: SSLense manages {All.Count} certificate(s) on {serverName}.");
            if (All.OrderBy(certificate => certificate.NotAfter).FirstOrDefault() is { } next)
            {
                body.AppendLine($"Next to expire: {Name(next)} on {Date(next.NotAfter)} ({DaysLeft(next)} days).");
            }

            body.AppendLine();
        }

        if (Muted.Count > 0)
        {
            body.AppendLine("Not reminding (turned off or snoozed in SSLense):");
            foreach (var certificate in Muted.OrderBy(certificate => certificate.NotAfter))
            {
                body.AppendLine($"- {Name(certificate)}: expires {Date(certificate.NotAfter)}, {MuteText(certificate)}.");
            }

            body.AppendLine();
        }

        body.Append("Turn reminders off or snooze them per certificate on the Certificate Details page in SSLense.");
        return new NotificationMessage(NotificationKind.ExpiryWarning, subject, body.ToString(), Severity(attention));
    }

    private string Describe(ReminderItem item)
    {
        var certificate = item.Certificate;
        var name = Name(certificate);
        var source = certificate.Source == CertificateSource.Imported
            ? certificate.Issuer ?? "another provider"
            : certificate.AuthorityId switch
            {
                CertificateAuthorities.LetsEncryptId => "Let's Encrypt",
                CertificateAuthorities.LetsEncryptStagingId => "Let's Encrypt staging",
                var other => other
            };
        return item.Kind switch
        {
            ReminderItemKind.Expired =>
                $"{name} ({source}): EXPIRED on {Date(certificate.NotAfter)}. Browsers now reject this site's certificate. " +
                (certificate.Source == CertificateSource.Imported
                    ? "Order a replacement from the provider and install it on the Other Providers page."
                    : $"Automatic renewal has not succeeded: {certificate.LastRenewalMessage ?? "see the SSLense log"}"),
            ReminderItemKind.ManualRenewalDue =>
                $"{name} ({source}): expires {Date(certificate.NotAfter)}, {item.DaysLeft} days left. Order the renewal from " +
                $"{source}, then on the Other Providers page in SSLense create a request and complete it with the new certificate.",
            ReminderItemKind.AutomaticRenewalFailing =>
                $"{name} ({source}): automatic renewal is failing ({certificate.ConsecutiveFailures} attempt(s)): " +
                $"{certificate.LastRenewalMessage}. Expires {Date(certificate.NotAfter)}, {item.DaysLeft} days left.",
            ReminderItemKind.AutomaticRenewalOverdue =>
                $"{name} ({source}): should have renewed on {Date(item.ScheduledRenewal)} but has not. Expires " +
                $"{Date(certificate.NotAfter)}, {item.DaysLeft} days left. Check that the SSLense service is running.",
            _ =>
                $"{name} ({source}): expires {Date(certificate.NotAfter)}; SSLense will renew it automatically around " +
                $"{Date(item.ScheduledRenewal)}."
        };
    }

    private string MuteText(ManagedCertificate certificate) => certificate.Reminders switch
    {
        ReminderMode.Snoozed when certificate.SnoozedUntil is { } until => $"snoozed until {Date(until)}",
        ReminderMode.Snoozed => "snoozed until it is replaced",
        ReminderMode.OffUntilReplaced => "off until it is replaced",
        _ => "off permanently"
    };

    private static NotificationSeverity Severity(IReadOnlyList<ReminderItem> attention) =>
        attention.Any(item => item.Kind == ReminderItemKind.Expired || item.DaysLeft <= 7)
            ? NotificationSeverity.Error
            : attention.Count > 0 ? NotificationSeverity.Warning : NotificationSeverity.Information;

    private static string Name(ManagedCertificate certificate) =>
        certificate.Hosts.Count == 0 ? certificate.SiteName : $"{certificate.Hosts[0]}{(certificate.Hosts.Count > 1 ? $" (+{certificate.Hosts.Count - 1})" : string.Empty)} on site '{certificate.SiteName}'";

    private string Date(DateTimeOffset? value) => value is { } date ? date.ToOffset(BuiltAt.Offset).ToString("dd MMM yyyy") : "an unknown date";

    private int DaysLeft(ManagedCertificate certificate) => ReminderDigestBuilder.DaysLeft(certificate, BuiltAt);
}

/// <summary>
/// Decides which certificates belong in a day's digest (docs/design/expiry-reminders.md, section 4). Pure: the caller
/// supplies the time, the settings, and each automatic certificate's scheduled renewal.
/// </summary>
public static class ReminderDigestBuilder
{
    /// <summary>In the last days before expiry, reminders are daily whatever the repeat setting says.</summary>
    public const int DailyFinalDays = 7;

    /// <param name="now">The current time in the server's local offset; days are counted in local dates.</param>
    /// <param name="scheduledRenewals">By site name: when each automatic certificate is scheduled to renew, when known.</param>
    public static ReminderDigest Build(
        IReadOnlyList<ManagedCertificate> certificates,
        ReminderConfig settings,
        DateTimeOffset now,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals,
        bool weeklySummary)
    {
        var items = new List<ReminderItem>();
        var muted = new List<ManagedCertificate>();
        foreach (var certificate in certificates)
        {
            if (IsMuted(certificate, now))
            {
                muted.Add(certificate);
                continue;
            }

            if (Classify(certificate, settings, now, scheduledRenewals) is { } item)
            {
                items.Add(item);
            }
        }

        return new ReminderDigest(items, muted, certificates, weeklySummary, now);
    }

    public static bool IsMuted(ManagedCertificate certificate, DateTimeOffset now) => certificate.Reminders switch
    {
        ReminderMode.On => false,
        ReminderMode.Snoozed => certificate.SnoozedUntil is not { } until || until > now,
        _ => true
    };

    /// <summary>Whole days until expiry, rounded down; negative once expired.</summary>
    public static int DaysLeft(ManagedCertificate certificate, DateTimeOffset now) =>
        (int)Math.Floor((certificate.NotAfter - now).TotalDays);

    private static ReminderItem? Classify(
        ManagedCertificate certificate,
        ReminderConfig settings,
        DateTimeOffset now,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals)
    {
        var daysLeft = DaysLeft(certificate, now);
        var remaining = certificate.NotAfter - now;
        var inWindow = remaining <= TimeSpan.FromDays(settings.StartDays);
        DateTimeOffset? scheduled = scheduledRenewals.TryGetValue(certificate.SiteName, out var value) ? value : null;

        if (remaining <= TimeSpan.Zero)
        {
            // Every day until it is replaced: the site is broken.
            return IntervalElapsed(certificate, now, interval: 1)
                ? new ReminderItem(certificate, ReminderItemKind.Expired, daysLeft, scheduled)
                : null;
        }

        var interval = remaining <= TimeSpan.FromDays(DailyFinalDays) ? 1 : settings.RepeatDays;
        if (certificate.Source == CertificateSource.Imported)
        {
            return inWindow && IntervalElapsed(certificate, now, interval)
                ? new ReminderItem(certificate, ReminderItemKind.ManualRenewalDue, daysLeft, null)
                : null;
        }

        // Failures are also sent immediately when they happen; the digest repeats them while they last.
        if (certificate.LastRenewalSucceeded == false && certificate.ConsecutiveFailures > 0)
        {
            return IntervalElapsed(certificate, now, interval)
                ? new ReminderItem(certificate, ReminderItemKind.AutomaticRenewalFailing, daysLeft, scheduled)
                : null;
        }

        if (scheduled is { } renewalAt && now > renewalAt.AddDays(1))
        {
            return IntervalElapsed(certificate, now, interval)
                ? new ReminderItem(certificate, ReminderItemKind.AutomaticRenewalOverdue, daysLeft, scheduled)
                : null;
        }

        return inWindow && settings.UpcomingRenewalNotices && !certificate.UpcomingNoticeSent
            ? new ReminderItem(certificate, ReminderItemKind.UpcomingAutomaticRenewal, daysLeft, scheduled)
            : null;
    }

    /// <summary>Whether at least <paramref name="interval"/> local days passed since this certificate was last reminded.</summary>
    private static bool IntervalElapsed(ManagedCertificate certificate, DateTimeOffset now, int interval)
    {
        if (certificate.LastRemindedAt is not { } last)
        {
            return true;
        }

        var today = DateOnly.FromDateTime(now.DateTime);
        var lastDay = DateOnly.FromDateTime(last.ToOffset(now.Offset).DateTime);
        return today.DayNumber - lastDay.DayNumber >= interval;
    }
}
