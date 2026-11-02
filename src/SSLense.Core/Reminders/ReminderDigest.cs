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

    /// <summary>The daily checks found a problem that is likely to make the coming automatic renewal fail.</summary>
    RenewalNotReady,

    /// <summary>This server does not serve the certificate SSLense expects, or does not answer on port 443.</summary>
    ServedCertificateProblem,

    /// <summary>For information: an automatic certificate entered the window and will be renewed on its own.</summary>
    UpcomingAutomaticRenewal,

    /// <summary>For information: an automatic certificate is still in the window, and repeats were asked for.</summary>
    AutomaticRenewalReminder
}

/// <param name="Detail">What a daily check found, for the kinds that report one.</param>
public sealed record ReminderItem(
    ManagedCertificate Certificate,
    ReminderItemKind Kind,
    int DaysLeft,
    DateTimeOffset? ScheduledRenewal,
    string? Detail = null);

/// <summary>Why a certificate is or is not in a digest, for the service log and the reminder outlook.</summary>
/// <param name="Included">Whether it is listed in the digest built now.</param>
/// <param name="NextReminder">The day it is next expected to be listed; null when nothing more is expected.</param>
public sealed record ReminderDecision(ManagedCertificate Certificate, bool Included, string Reason, DateOnly? NextReminder)
{
    /// <summary>One line for the service log.</summary>
    public string LogLine => $"{ReminderDigest.Name(Certificate)}: {(Included ? "included" : "skipped")}, {Reason}.";

    /// <summary>One line for the reminder outlook.</summary>
    public string OutlookLine =>
        $"{ReminderDigest.Name(Certificate)}: {(NextReminder is { } day ? $"next reminder {day:dd MMM yyyy}" : "no reminder expected")} ({Reason}).";
}

/// <summary>What one day's reminder email says. Built by <see cref="ReminderDigestBuilder"/>; nothing is sent here.</summary>
/// <param name="All">Every managed certificate, for the weekly summary.</param>
/// <param name="Decisions">One for each managed certificate.</param>
public sealed record ReminderDigest(
    IReadOnlyList<ReminderItem> Items,
    IReadOnlyList<ManagedCertificate> Muted,
    IReadOnlyList<ManagedCertificate> All,
    bool IsWeeklySummary,
    DateTimeOffset BuiltAt,
    IReadOnlyList<ReminderDecision> Decisions)
{
    public IReadOnlyList<ReminderItem> NeedsAttention =>
        Items.Where(item => !IsInformational(item.Kind)).ToArray();

    public IReadOnlyList<ReminderItem> Upcoming =>
        Items.Where(item => IsInformational(item.Kind)).ToArray();

    /// <summary>Whether this digest should be sent: something needs attention, a notice is due, or it is the weekly summary.</summary>
    public bool HasContent => Items.Count > 0 || IsWeeklySummary;

    /// <summary>What to record once the digest was delivered.</summary>
    public IReadOnlyList<ReminderRecord> ToRecords() => Items
        .Select(item => new ReminderRecord(
            item.Certificate.SiteName,
            item.Certificate.Thumbprint,
            Reminded: item.Kind != ReminderItemKind.UpcomingAutomaticRenewal,
            NoticeSent: IsInformational(item.Kind)))
        .ToArray();

    private static bool IsInformational(ReminderItemKind kind) =>
        kind is ReminderItemKind.UpcomingAutomaticRenewal or ReminderItemKind.AutomaticRenewalReminder;

    public NotificationMessage ToMessage(string serverName, bool sample = false)
    {
        var attention = NeedsAttention;
        var upcoming = Upcoming;
        var subject = attention.Count > 0
            ? $"SSLense: {attention.Select(item => item.Certificate.SiteName).Distinct(StringComparer.OrdinalIgnoreCase).Count()} certificate(s) need attention on {serverName}"
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
            ReminderItemKind.RenewalNotReady =>
                $"{name} ({source}): renewal is likely to fail. Renewal is due around {Date(item.ScheduledRenewal)}, and a check " +
                $"on this server found a problem. {item.Detail}",
            ReminderItemKind.ServedCertificateProblem =>
                $"{name} ({source}): a check of what this server serves found a problem. {item.Detail}",
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

    internal static string Name(ManagedCertificate certificate) =>
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
    /// <param name="readinessProblems">By site name: what the daily readiness checks found that should be reported.</param>
    /// <param name="servedProblems">By site name: what the daily served-certificate checks found that should be reported.</param>
    public static ReminderDigest Build(
        IReadOnlyList<ManagedCertificate> certificates,
        ReminderConfig settings,
        DateTimeOffset now,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals,
        bool weeklySummary,
        IReadOnlyDictionary<string, string>? readinessProblems = null,
        IReadOnlyDictionary<string, string>? servedProblems = null)
    {
        var items = new List<ReminderItem>();
        var muted = new List<ManagedCertificate>();
        var decisions = new List<ReminderDecision>();
        foreach (var certificate in certificates)
        {
            if (IsMuted(certificate, now))
            {
                muted.Add(certificate);
                decisions.Add(DecideMuted(certificate, settings, now, scheduledRenewals, readinessProblems));
                continue;
            }

            var (item, decision) = Decide(certificate, settings, now, scheduledRenewals, readinessProblems);
            if (item is not null)
            {
                items.Add(item);
            }

            // A line of its own: a certificate can be due for renewal and also not be the one being served.
            if (servedProblems is not null &&
                servedProblems.TryGetValue(certificate.SiteName, out var served) &&
                IntervalElapsed(certificate, now, RepeatInterval(certificate, settings, now)))
            {
                items.Add(new ReminderItem(certificate, ReminderItemKind.ServedCertificateProblem, DaysLeft(certificate, now), null, served));
                const string servedReason = "a check of the served certificate found a problem";
                decision = decision with
                {
                    Included = true,
                    Reason = decision.Included ? $"{decision.Reason}; {servedReason}" : servedReason,
                    NextReminder = Today(now)
                };
            }

            decisions.Add(decision);
        }

        return new ReminderDigest(items, muted, certificates, weeklySummary, now, decisions);
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

    private static (ReminderItem? Item, ReminderDecision Decision) Decide(
        ManagedCertificate certificate,
        ReminderConfig settings,
        DateTimeOffset now,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals,
        IReadOnlyDictionary<string, string>? readinessProblems)
    {
        var daysLeft = DaysLeft(certificate, now);
        var remaining = certificate.NotAfter - now;
        // Whole days, as the Dashboard shows them: a certificate showing 87 days left is in a window that starts at 87.
        var inWindow = daysLeft <= settings.StartDays;
        DateTimeOffset? scheduled = scheduledRenewals.TryGetValue(certificate.SiteName, out var value) ? value : null;
        var renewsAround = scheduled is { } around ? DayText(Today(around.ToOffset(now.Offset))) : "an unknown date";

        (ReminderItem?, ReminderDecision) Listed(ReminderItemKind kind, string reason, DateTimeOffset? renewal, string? detail = null) =>
            (new ReminderItem(certificate, kind, daysLeft, renewal, detail), new ReminderDecision(certificate, true, reason, Today(now)));

        (ReminderItem?, ReminderDecision) Skipped(string reason, DateOnly? next) =>
            (null, new ReminderDecision(certificate, false, reason, next));

        (ReminderItem?, ReminderDecision) Repeating(ReminderItemKind kind, string reason, int interval, DateTimeOffset? renewal, string? detail = null)
        {
            if (IntervalElapsed(certificate, now, interval))
            {
                return Listed(kind, reason, renewal, detail);
            }

            var lastDay = Today(certificate.LastRemindedAt!.Value.ToOffset(now.Offset));
            return Skipped($"{reason}; already reminded on {DayText(lastDay)}", NextRepeat(certificate, settings, lastDay, now));
        }

        if (remaining <= TimeSpan.Zero)
        {
            // Every day until it is replaced: the site is broken.
            return Repeating(ReminderItemKind.Expired, "expired", interval: 1, scheduled);
        }

        var interval = RepeatInterval(certificate, settings, now);
        if (certificate.Source == CertificateSource.Imported)
        {
            if (!inWindow)
            {
                var start = WindowStart(certificate, settings, now);
                return Skipped($"reminders start on {DayText(start)}", start);
            }

            return Repeating(ReminderItemKind.ManualRenewalDue, $"the renewal must be ordered, {daysLeft} days left", interval, null);
        }

        // Failures are also sent immediately when they happen; the digest repeats them while they last.
        if (certificate.LastRenewalSucceeded == false && certificate.ConsecutiveFailures > 0)
        {
            return Repeating(ReminderItemKind.AutomaticRenewalFailing, "automatic renewal is failing", interval, scheduled);
        }

        if (scheduled is { } renewalAt && now > renewalAt.AddDays(1))
        {
            return Repeating(ReminderItemKind.AutomaticRenewalOverdue, "automatic renewal is overdue", interval, scheduled);
        }

        // While a problem is known, the digest must not also say that the certificate will renew on its own.
        if (readinessProblems is not null && readinessProblems.TryGetValue(certificate.SiteName, out var problem))
        {
            return Repeating(ReminderItemKind.RenewalNotReady, "a check found that renewal is likely to fail", interval, scheduled, problem);
        }

        if (inWindow && settings.RepeatAutomaticReminders)
        {
            return Repeating(ReminderItemKind.AutomaticRenewalReminder, $"renews automatically around {renewsAround}", interval, scheduled);
        }

        if (!settings.RepeatAutomaticReminders)
        {
            if (!settings.UpcomingRenewalNotices)
            {
                return Skipped("notices about automatic renewals are off", null);
            }

            if (certificate.UpcomingNoticeSent)
            {
                return Skipped("its one notice was already sent; nothing more unless a problem is found", null);
            }
        }

        if (!inWindow)
        {
            var start = WindowStart(certificate, settings, now);
            return Skipped($"reminders start on {DayText(start)}", start);
        }

        return Listed(ReminderItemKind.UpcomingAutomaticRenewal, $"one notice, renews automatically around {renewsAround}", scheduled);
    }

    private static ReminderDecision DecideMuted(
        ManagedCertificate certificate,
        ReminderConfig settings,
        DateTimeOffset now,
        IReadOnlyDictionary<string, DateTimeOffset> scheduledRenewals,
        IReadOnlyDictionary<string, string>? readinessProblems)
    {
        if (certificate.Reminders == ReminderMode.Snoozed && certificate.SnoozedUntil is { } until)
        {
            // What happens once the snooze ends, as far as can be said today.
            var resumes = Decide(certificate with { Reminders = ReminderMode.On }, settings, until.ToOffset(now.Offset), scheduledRenewals, readinessProblems);
            return new ReminderDecision(certificate, false, $"reminders are snoozed until {DayText(Today(until.ToOffset(now.Offset)))}", resumes.Decision.NextReminder);
        }

        var reason = certificate.Reminders switch
        {
            ReminderMode.Snoozed => "reminders are snoozed until it is replaced",
            ReminderMode.OffUntilReplaced => "reminders are off until it is replaced",
            _ => "reminders are off permanently"
        };
        return new ReminderDecision(certificate, false, reason, null);
    }

    /// <summary>
    /// The first digest inside the window. Whole days left reach the start setting one day earlier than the plain
    /// subtraction suggests, and a window that opens after the send time is first seen by the next day's digest.
    /// </summary>
    private static DateOnly WindowStart(ManagedCertificate certificate, ReminderConfig settings, DateTimeOffset now)
    {
        var opens = certificate.NotAfter.AddDays(-(settings.StartDays + 1)).ToOffset(now.Offset);
        return opens.Hour >= settings.SendAtHour ? Today(opens).AddDays(1) : Today(opens);
    }

    /// <summary>The day the repeat interval next allows a line, counting the daily reminders of the last days.</summary>
    private static DateOnly NextRepeat(ManagedCertificate certificate, ReminderConfig settings, DateOnly lastDay, DateTimeOffset now)
    {
        var dailyFrom = Today(certificate.NotAfter.AddDays(-DailyFinalDays).ToOffset(now.Offset));
        if (dailyFrom <= lastDay)
        {
            return lastDay.AddDays(1);
        }

        var byInterval = lastDay.AddDays(settings.RepeatDays);
        return byInterval < dailyFrom ? byInterval : dailyFrom;
    }

    private static DateOnly Today(DateTimeOffset now) => DateOnly.FromDateTime(now.DateTime);

    private static string DayText(DateOnly day) => day.ToString("dd MMM yyyy");

    private static int RepeatInterval(ManagedCertificate certificate, ReminderConfig settings, DateTimeOffset now) =>
        certificate.NotAfter - now <= TimeSpan.FromDays(DailyFinalDays) ? 1 : settings.RepeatDays;

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
