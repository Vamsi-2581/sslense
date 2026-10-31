using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using SSLense.Core.Reminders;
using Xunit;

namespace SSLense.Tests.Reminders;

public sealed class ReminderDigestBuilderTests
{
    private static readonly DateTimeOffset Now = new(2026, 12, 1, 9, 30, 0, TimeSpan.FromHours(1));
    private static readonly ReminderConfig Settings = new() { StartDays = 30, RepeatDays = 3 };

    [Theory]
    [InlineData(45, null, false)]                // before the window
    [InlineData(29, null, true)]                 // in the window, never reminded
    [InlineData(20, 1, false)]                   // reminded yesterday, repeat every 3 days
    [InlineData(20, 3, true)]                    // three days later
    [InlineData(6, 1, true)]                     // daily in the last seven days, whatever the repeat says
    public void ImportedCertificate_IsRemindedFromTheStartAndRepeatsUntilReplaced(int daysLeft, int? remindedDaysAgo, bool expected)
    {
        var certificate = Imported(daysLeft) with { LastRemindedAt = remindedDaysAgo is { } ago ? Now.AddDays(-ago) : null };

        var digest = Build(certificate);

        Assert.Equal(expected, digest.Items.Any(item => item.Kind == ReminderItemKind.ManualRenewalDue));
    }

    [Fact]
    public void AutomaticCertificate_GetsOneUpcomingNotice_WithItsScheduledRenewal()
    {
        var certificate = Automatic(25);
        var renewsAt = Now.AddDays(2);

        var item = Assert.Single(Build(certificate, renewsAt).Items);
        Assert.Equal(ReminderItemKind.UpcomingAutomaticRenewal, item.Kind);
        Assert.Equal(renewsAt, item.ScheduledRenewal);

        Assert.Empty(Build(certificate with { UpcomingNoticeSent = true }, renewsAt).Items);
        Assert.Empty(ReminderDigestBuilder.Build([certificate], Settings with { UpcomingRenewalNotices = false }, Now,
            new Dictionary<string, DateTimeOffset> { ["Site"] = renewsAt }, weeklySummary: false).Items);
    }

    [Fact]
    public void AutomaticCertificate_FailingOrOverdue_NeedsAttention()
    {
        var failing = Automatic(40) with { LastRenewalSucceeded = false, ConsecutiveFailures = 2, LastRenewalMessage = "HTTP-01 failed" };
        var overdue = Automatic(20);

        Assert.Equal(ReminderItemKind.AutomaticRenewalFailing, Assert.Single(Build(failing).Items).Kind);
        Assert.Equal(ReminderItemKind.AutomaticRenewalOverdue, Assert.Single(Build(overdue, Now.AddDays(-2)).Items).Kind);
        // Due today but not yet a day late: still only the notice.
        Assert.Equal(ReminderItemKind.UpcomingAutomaticRenewal, Assert.Single(Build(overdue, Now.AddHours(-3)).Items).Kind);
    }

    [Fact]
    public void ExpiredCertificate_IsRemindedDaily()
    {
        var expired = Imported(-2) with { LastRemindedAt = Now.AddDays(-1) };

        Assert.Equal(ReminderItemKind.Expired, Assert.Single(Build(expired).Items).Kind);
    }

    [Theory]
    [InlineData(ReminderMode.Off, 0, true)]
    [InlineData(ReminderMode.OffUntilReplaced, 0, true)]
    [InlineData(ReminderMode.Snoozed, 3, true)]
    [InlineData(ReminderMode.Snoozed, -1, false)]
    public void MutedCertificates_AreListedButNeverCauseADigest(ReminderMode mode, int snoozeDays, bool muted)
    {
        var certificate = Imported(5) with { Reminders = mode, SnoozedUntil = Now.AddDays(snoozeDays) };

        var digest = Build(certificate);

        Assert.Equal(muted, digest.Muted.Count == 1);
        Assert.Equal(!muted, digest.HasContent);
    }

    [Fact]
    public void WeeklySummary_IsSentEvenWhenNothingNeedsAttention()
    {
        var digest = ReminderDigestBuilder.Build([Imported(200)], Settings, Now, new Dictionary<string, DateTimeOffset>(), weeklySummary: true);

        Assert.True(digest.HasContent);
        Assert.Contains("nothing needs attention", digest.ToMessage("SERVER01").Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void Message_ListsAttentionFirstAndMarksTheLastWeekAsAnError()
    {
        var digest = ReminderDigestBuilder.Build(
            [Imported(5), Automatic(25), Imported(10) with { SiteName = "Muted", Reminders = ReminderMode.Off }],
            Settings,
            Now,
            new Dictionary<string, DateTimeOffset> { ["Site"] = Now.AddDays(1) },
            weeklySummary: false);

        var message = digest.ToMessage("SERVER01", sample: true);

        Assert.Equal(NotificationKind.ExpiryWarning, message.Kind);
        Assert.Equal(NotificationSeverity.Error, message.EffectiveSeverity);
        Assert.Equal("SSLense: 1 certificate(s) need attention on SERVER01", message.Subject);
        Assert.StartsWith("SAMPLE:", message.Body, StringComparison.Ordinal);
        Assert.True(message.Body.IndexOf("Needs attention", StringComparison.Ordinal) < message.Body.IndexOf("Will renew automatically", StringComparison.Ordinal));
        Assert.Contains("Order the renewal from Sectigo RSA DV", message.Body, StringComparison.Ordinal);
        Assert.Contains("SSLense will renew it automatically around 02 Dec 2026", message.Body, StringComparison.Ordinal);
        Assert.Contains("off permanently", message.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void ToRecords_StartsTheRepeatForRemindersAndMarksNoticesSentOnce()
    {
        var digest = ReminderDigestBuilder.Build(
            [Imported(10), Automatic(25) with { SiteName = "Auto" }],
            Settings,
            Now,
            new Dictionary<string, DateTimeOffset> { ["Auto"] = Now.AddDays(3) },
            weeklySummary: false);

        Assert.Equal(
            [new ReminderRecord("Site", "AABB", Reminded: true, NoticeSent: false), new ReminderRecord("Auto", "AABB", Reminded: false, NoticeSent: true)],
            digest.ToRecords());
    }

    private static ReminderDigest Build(ManagedCertificate certificate, DateTimeOffset? scheduledRenewal = null) =>
        ReminderDigestBuilder.Build(
            [certificate],
            Settings,
            Now,
            scheduledRenewal is { } at ? new Dictionary<string, DateTimeOffset> { [certificate.SiteName] = at } : new Dictionary<string, DateTimeOffset>(),
            weeklySummary: false);

    private static ManagedCertificate Imported(int daysLeft) => new(
        "Site", ["shop.example.com"], "", "AABB", Now.AddDays(daysLeft - 365), Now.AddDays(daysLeft).AddHours(1),
        Source: CertificateSource.Imported, Issuer: "Sectigo RSA DV");

    private static ManagedCertificate Automatic(int daysLeft) => new(
        "Site", ["api.example.com"], "admin@example.com", "AABB", Now.AddDays(daysLeft - 90), Now.AddDays(daysLeft).AddHours(1),
        AuthorityId: CertificateAuthorities.LetsEncryptId, LastRenewalSucceeded: true);
}
