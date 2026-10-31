using Moq;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;
using Xunit;

namespace SSLense.Tests.Reminders;

public sealed class ReminderServiceTests
{
    private readonly InMemoryFileSystem _files = new();
    private readonly JsonManagedCertificateStore _certificates;
    private readonly JsonReminderStateStore _state;
    private readonly Mock<INotifier> _notifier = new(MockBehavior.Strict);
    private readonly List<NotificationMessage> _sent = [];
    private readonly Mock<IOutsideRenewalDetector> _detector = new();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 12, 1, 8, 0, 0, TimeSpan.Zero)); // a Tuesday
    private ReminderConfig _settings = new() { SendAtHour = 9 };

    public ReminderServiceTests()
    {
        _certificates = new JsonManagedCertificateStore(_files, @"C:\data\managed-certificates.json", @"C:\data\managed.lock");
        _state = new JsonReminderStateStore(_files, @"C:\data\reminder-state.json");
        _notifier.Setup(value => value.NotifyAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .Callback<NotificationMessage, CancellationToken>((message, _) => _sent.Add(message))
            .Returns(Task.CompletedTask);
        _detector.Setup(value => value.DetectAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
    }

    [Fact]
    public async Task SetCertificateRemindersAsync_SnoozeStopsTheDigestUntilItEnds()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        var service = CreateService();
        var snoozedAt = _clock.Now;
        await service.SetCertificateRemindersAsync("SHOP", ReminderMode.Snoozed, snoozeDays: 2);
        _clock.Now = _clock.Now.AddHours(1);

        await service.CheckAsync();
        _clock.Now = _clock.Now.AddDays(2);
        await service.CheckAsync();

        Assert.Single(_sent);
        Assert.Equal(snoozedAt.AddDays(2), Assert.Single(await _certificates.GetAllAsync()).SnoozedUntil);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.SetCertificateRemindersAsync("Shop", ReminderMode.Snoozed, 0));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.SetCertificateRemindersAsync("Unknown", ReminderMode.Off));
    }

    [Fact]
    public async Task CheckAsync_ScheduleLookupTimingOut_DoesNotStopTheDigest()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        await _certificates.UpsertAsync(Imported(daysLeft: 40) with { SiteName = "Api", Source = CertificateSource.Acme });
        var renewal = new Mock<IRenewalService>();
        // What HttpClient throws on a timeout, although nobody cancelled the check.
        renewal.Setup(value => value.GetScheduledRenewalAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout."));
        _clock.Now = _clock.Now.AddHours(1);

        await CreateService(renewal.Object).CheckAsync();

        Assert.Contains("1 certificate(s) need attention", Assert.Single(_sent).Subject, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CheckAsync_ScheduleUnavailable_StillReportsALateAutomaticRenewal()
    {
        // A 90-day certificate with 10 days left: the fallback schedule renews it 30 days before expiry, 20 days ago.
        await _certificates.UpsertAsync(new ManagedCertificate(
            "Api", ["api.example.com"], "admin@example.com", "AABB", _clock.Now.AddDays(-80), _clock.Now.AddDays(10),
            LastRenewalSucceeded: true, UpcomingNoticeSent: true));
        var renewal = new Mock<IRenewalService>();
        renewal.Setup(value => value.GetScheduledRenewalAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout."));
        _clock.Now = _clock.Now.AddHours(1);

        await CreateService(renewal.Object).CheckAsync();

        Assert.Contains("should have renewed", Assert.Single(_sent).Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SaveSettingsAsync_RejectsOutOfRangeValues()
    {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.SaveSettingsAsync(new ReminderConfig { StartDays = 0 }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.SaveSettingsAsync(new ReminderConfig { RepeatDays = 31 }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.SaveSettingsAsync(new ReminderConfig { SendAtHour = 24 }));
    }

    [Fact]
    public async Task SendSampleAsync_SendsEvenWhenNothingIsDue_AndRecordsNothing()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 200));

        await CreateService().SendSampleAsync();

        Assert.StartsWith("SAMPLE:", Assert.Single(_sent).Body, StringComparison.Ordinal);
        Assert.Null((await _state.GetAsync()).LastDigestDate);
    }

    [Fact]
    public async Task CheckAsync_ReportsCertificatesReplacedOutsideSslense()
    {
        _detector.Setup(value => value.DetectAsync(It.IsAny<CancellationToken>())).ReturnsAsync(["replaced"]);

        var results = await CreateService().CheckAsync();

        Assert.Equal("replaced", Assert.Single(results).Message);
    }

    [Fact]
    public async Task CheckAsync_SendsOnceADayFromTheConfiguredHour_AndRecordsIt()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        var service = CreateService();

        Assert.Empty(await service.CheckAsync());          // 08:00, before the send time
        _clock.Now = _clock.Now.AddHours(1);
        var sentAt = _clock.Now;
        var result = Assert.Single(await service.CheckAsync());
        _clock.Now = _clock.Now.AddHours(1);
        Assert.Empty(await service.CheckAsync());          // 10:00, already sent today

        Assert.False(result.Failed);
        Assert.Single(_sent);
        Assert.Equal(sentAt, Assert.Single(await _certificates.GetAllAsync()).LastRemindedAt);
    }

    [Fact]
    public async Task CheckAsync_RepeatsTheNextDayUntilTheCertificateIsReplaced()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        var service = CreateService();
        _clock.Now = _clock.Now.AddHours(1);
        await service.CheckAsync();

        _clock.Now = _clock.Now.AddDays(1);
        await service.CheckAsync();
        await _certificates.UpsertAsync(Imported(daysLeft: 385) with { Thumbprint = "RENEWED" });
        _clock.Now = _clock.Now.AddDays(1);
        await service.CheckAsync();

        Assert.Equal(2, _sent.Count);
    }

    [Fact]
    public async Task CheckAsync_NothingDue_SendsNothingAndDoesNotCheckAgainToday()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 200));
        _clock.Now = _clock.Now.AddHours(1);
        var service = CreateService();

        await service.CheckAsync();
        await _certificates.UpsertAsync(Imported(daysLeft: 5) with { SiteName = "Added later" });
        await service.CheckAsync();

        Assert.Empty(_sent);
        Assert.Equal(new DateOnly(2026, 12, 1), (await _state.GetAsync()).LastDigestDate);
    }

    [Fact]
    public async Task CheckAsync_FailedSend_IsNotRecordedSoTheNextCheckRetries()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        _clock.Now = _clock.Now.AddHours(1);
        _notifier.SetupSequence(value => value.NotifyAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("SMTP offline"))
            .Returns(Task.CompletedTask);
        var service = CreateService();

        var failed = Assert.Single(await service.CheckAsync());
        Assert.True(failed.Failed);
        Assert.Contains("SMTP offline", failed.Message, StringComparison.Ordinal);
        Assert.Null(Assert.Single(await _certificates.GetAllAsync()).LastRemindedAt);

        _clock.Now = _clock.Now.AddHours(1);
        Assert.False(Assert.Single(await service.CheckAsync()).Failed);
        Assert.NotNull(Assert.Single(await _certificates.GetAllAsync()).LastRemindedAt);
    }

    [Fact]
    public async Task CheckAsync_WeeklySummaryDay_SendsEvenWhenAllIsWell()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 200));
        _settings = _settings with { WeeklySummaryDay = DayOfWeek.Tuesday };
        _clock.Now = _clock.Now.AddHours(1);

        await CreateService().CheckAsync();

        Assert.Contains("weekly summary", Assert.Single(_sent).Subject, StringComparison.Ordinal);
        Assert.Equal(new DateOnly(2026, 12, 1), (await _state.GetAsync()).LastWeeklySummaryDate);
    }

    [Fact]
    public async Task PreviewAsync_BuildsTodaysDigestWithoutSendingOrRecording()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));

        var digest = await CreateService().PreviewAsync();

        Assert.Single(digest.NeedsAttention);
        Assert.Empty(_sent);
        Assert.Null(Assert.Single(await _certificates.GetAllAsync()).LastRemindedAt);
        Assert.Null((await _state.GetAsync()).LastDigestDate);
    }

    private ReminderService CreateService(IRenewalService? renewal = null)
    {
        var config = new Mock<IConfigStore>(MockBehavior.Strict);
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => new AppConfig { Reminders = _settings });
        return new ReminderService(_certificates, config.Object, renewal ?? Mock.Of<IRenewalService>(), _state, _notifier.Object, _detector.Object, _clock);
    }

    private ManagedCertificate Imported(int daysLeft) => new(
        "Shop", ["shop.example.com"], "", "AABB", _clock.Now.AddDays(daysLeft - 365), _clock.Now.AddDays(daysLeft),
        Source: CertificateSource.Imported, Issuer: "Sectigo RSA DV");

    /// <summary>A settable clock in UTC, so "local" days are predictable on any test machine.</summary>
    private sealed class TestClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;

        public override TimeZoneInfo LocalTimeZone => TimeZoneInfo.Utc;
    }
}
