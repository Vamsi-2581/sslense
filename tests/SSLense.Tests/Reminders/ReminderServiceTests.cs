using Moq;
using SSLense.Core.Config;
using SSLense.Core.Diagnostics;
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
    private readonly Mock<IRenewalReadinessCheck> _readiness = new();
    private readonly Mock<IServedCertificateCheck> _served = new();
    private readonly Mock<IServiceHeartbeatStore> _heartbeat = new();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 12, 1, 8, 0, 0, TimeSpan.Zero)); // a Tuesday
    private ReminderConfig _settings = new() { SendAtHour = 9 };

    public ReminderServiceTests()
    {
        _certificates = new JsonManagedCertificateStore(_files, @"C:\data\managed-certificates.json", @"C:\data\managed.lock");
        _state = new JsonReminderStateStore(_files, @"C:\data\reminder-state.json", @"C:\data\reminder-state.lock");
        _notifier.Setup(value => value.NotifyAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .Callback<NotificationMessage, CancellationToken>((message, _) => _sent.Add(message))
            .Returns(Task.CompletedTask);
        _detector.Setup(value => value.DetectAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        NotReady();
        Served();
    }

    [Fact]
    public async Task CheckAsync_ReadinessProblem_IsReportedOnlyOnTheSecondDayInARow()
    {
        await _certificates.UpsertAsync(Automatic(daysLeft: 40));
        NotReady("Api");
        var service = CreateService();
        _clock.Now = _clock.Now.AddHours(1);

        await service.CheckAsync();
        Assert.Empty(_sent);

        _clock.Now = _clock.Now.AddDays(1);
        await service.CheckAsync();

        var message = Assert.Single(_sent);
        Assert.Contains("renewal is likely to fail", message.Body, StringComparison.Ordinal);
        Assert.Contains("'HTTP binding: api.example.com' failed", message.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CheckAsync_ServedProblem_IsCountedSeparatelyAndReportedOnTheSecondDay()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 200));
        Served("Shop");
        var service = CreateService();
        _clock.Now = _clock.Now.AddHours(1);

        await service.CheckAsync();
        Assert.Empty(_sent);

        _clock.Now = _clock.Now.AddDays(1);
        await service.CheckAsync();

        Assert.Contains("a check of what this server serves found a problem", Assert.Single(_sent).Body, StringComparison.Ordinal);
        Assert.Equal(2, (await _state.GetAsync()).CheckFailures!["served:Shop"]);
    }

    [Fact]
    public async Task CheckAsync_ReadinessPass_ResetsTheCount()
    {
        await _certificates.UpsertAsync(Automatic(daysLeft: 40));
        var service = CreateService();
        _clock.Now = _clock.Now.AddHours(1);

        NotReady("Api");
        await service.CheckAsync();
        _clock.Now = _clock.Now.AddDays(1);
        Ready("Api");
        await service.CheckAsync();
        _clock.Now = _clock.Now.AddDays(1);
        NotReady("Api");
        await service.CheckAsync();

        Assert.Empty(_sent);
    }

    [Fact]
    public async Task CheckAsync_RetryAfterAFailedSend_DoesNotCountTheSameDayTwice()
    {
        await _certificates.UpsertAsync(Automatic(daysLeft: 40));
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        NotReady("Api");
        _notifier.SetupSequence(value => value.NotifyAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("SMTP offline"))
            .Returns(Task.CompletedTask);
        var service = CreateService();
        _clock.Now = _clock.Now.AddHours(1);

        await service.CheckAsync();
        _clock.Now = _clock.Now.AddHours(1);
        await service.CheckAsync();

        var retried = (NotificationMessage)_notifier.Invocations[^1].Arguments[0];
        Assert.DoesNotContain("likely to fail", retried.Body, StringComparison.Ordinal);
        Assert.Equal(new DateOnly(2026, 12, 1), (await _state.GetAsync()).LastDigestDate);
    }

    [Fact]
    public async Task PreviewAsync_ShowsAReadinessProblemStraightAway_AndCountsNothing()
    {
        await _certificates.UpsertAsync(Automatic(daysLeft: 40));
        NotReady("Api");

        var digest = await CreateService().PreviewAsync();

        Assert.Equal(ReminderItemKind.RenewalNotReady, Assert.Single(digest.Items).Kind);
        Assert.Null((await _state.GetAsync()).CheckFailures);
    }

    [Fact]
    public async Task CheckAsync_ChecksTurnedOff_DoesNotRunThem()
    {
        await _certificates.UpsertAsync(Automatic(daysLeft: 40));
        _settings = _settings with { ProactiveChecks = false };
        _clock.Now = _clock.Now.AddHours(1);

        await CreateService().CheckAsync();

        _readiness.Verify(value => value.CheckAsync(
                It.IsAny<IReadOnlyList<ManagedCertificate>>(), It.IsAny<IReadOnlyDictionary<string, DateTimeOffset>>(),
                It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Never());
    }

    [Fact]
    public async Task CheckAsync_ChecksThatCannotRun_StillSendTheDigest()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        _readiness.Setup(value => value.CheckAsync(
                It.IsAny<IReadOnlyList<ManagedCertificate>>(), It.IsAny<IReadOnlyDictionary<string, DateTimeOffset>>(),
                It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("IIS cannot be read"));
        _clock.Now = _clock.Now.AddHours(1);

        var results = await CreateService().CheckAsync();

        Assert.Single(_sent);
        Assert.Contains(results, result => result.Failed && result.Message.Contains("IIS cannot be read", StringComparison.Ordinal));
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
    public async Task SaveSettingsAsync_AfterTodayWasHandled_TheNextCheckLooksAgainAndSendsNothingTwice()
    {
        // 09:00: nothing is due with a window of 30 days, so today is marked as handled.
        await _certificates.UpsertAsync(Imported(daysLeft: 87));
        var saved = new AppConfig { Reminders = _settings };
        var config = new Mock<IConfigStore>();
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => saved);
        config.Setup(value => value.SaveAsync(It.IsAny<AppConfig>(), It.IsAny<CancellationToken>()))
            .Callback<AppConfig, CancellationToken>((value, _) => saved = value)
            .Returns(Task.CompletedTask);
        var service = new ReminderService(_certificates, config.Object, ScheduledInTenDays(), _state, _notifier.Object, _detector.Object, _readiness.Object, _served.Object, _heartbeat.Object, _clock);
        _clock.Now = _clock.Now.AddHours(1);
        await service.CheckAsync();
        Assert.Empty(_sent);

        // Later that day the window is widened.
        await service.SaveSettingsAsync(new ReminderConfig { StartDays = 87 });
        _clock.Now = _clock.Now.AddHours(1);
        await service.CheckAsync();
        Assert.Single(_sent);

        // Saving again the same day does not repeat today's reminder.
        await service.SaveSettingsAsync(new ReminderConfig { StartDays = 87, RepeatDays = 2 });
        _clock.Now = _clock.Now.AddHours(1);
        await service.CheckAsync();
        Assert.Single(_sent);
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

        Assert.Contains(results, result => result.Message == "replaced");
    }

    [Fact]
    public async Task CheckAsync_SendsOnceADayFromTheConfiguredHour_AndRecordsIt()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        var service = CreateService();

        Assert.Contains("not sending yet", Assert.Single(await service.CheckAsync()).Message, StringComparison.Ordinal); // 08:00
        _clock.Now = _clock.Now.AddHours(1);
        var sentAt = _clock.Now;
        var results = await service.CheckAsync();
        _clock.Now = _clock.Now.AddHours(1);
        Assert.Contains("already handled", Assert.Single(await service.CheckAsync()).Message, StringComparison.Ordinal); // 10:00

        Assert.DoesNotContain(results, result => result.Failed);
        Assert.Contains(results, result => result.Message == "Reminder check: shop.example.com on site 'Shop': included, the renewal must be ordered, 19 days left.");
        Assert.Contains(results, result => result.Message.StartsWith("Sent the reminder digest", StringComparison.Ordinal));
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

        var failed = Assert.Single(await service.CheckAsync(), result => result.Failed);
        Assert.True(failed.Failed);
        Assert.Contains("SMTP offline", failed.Message, StringComparison.Ordinal);
        Assert.Null(Assert.Single(await _certificates.GetAllAsync()).LastRemindedAt);

        _clock.Now = _clock.Now.AddHours(1);
        Assert.DoesNotContain(await service.CheckAsync(), result => result.Failed);
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

    [Fact]
    public async Task SaveSettingsAsync_WhileADigestIsBeingSent_IsNotMarkedHandled_AndTheWeeklySummaryIsKept()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        _settings = new ReminderConfig { SendAtHour = 9, WeeklySummaryDay = DayOfWeek.Tuesday };
        var service = CreateServiceWithSavedSettings(Mock.Of<IRenewalService>());
        _notifier.Setup(value => value.NotifyAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .Returns<NotificationMessage, CancellationToken>(async (message, _) =>
            {
                _sent.Add(message);
                await service.SaveSettingsAsync(_settings with { StartDays = 45 });
            });
        _clock.Now = _clock.Now.AddHours(1);

        await service.CheckAsync();

        var state = await _state.GetAsync();
        Assert.Null(state.LastDigestDate);
        Assert.Equal(new DateOnly(2026, 12, 1), state.LastWeeklySummaryDate);

        // The next check looks again under the new settings, and neither the reminder nor the summary is repeated.
        _clock.Now = _clock.Now.AddHours(1);
        await service.CheckAsync();
        Assert.Single(_sent);
        Assert.Equal(new DateOnly(2026, 12, 1), (await _state.GetAsync()).LastDigestDate);
    }

    [Fact]
    public async Task SaveSettingsAsync_WhileADigestIsBeingBuilt_TheNextCheckUsesTheNewSettings()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 87) with { Source = CertificateSource.Acme });
        var renewal = new Mock<IRenewalService>();
        var service = CreateServiceWithSavedSettings(renewal.Object);
        var saved = false;
        renewal.Setup(value => value.GetScheduledRenewalAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                if (!saved)
                {
                    saved = true;
                    await service.SaveSettingsAsync(_settings with { StartDays = 87 });
                }

                return _clock.Now.AddDays(57);
            });
        _clock.Now = _clock.Now.AddHours(1);

        await service.CheckAsync();
        Assert.Empty(_sent);
        Assert.Null((await _state.GetAsync()).LastDigestDate);

        _clock.Now = _clock.Now.AddHours(1);
        await service.CheckAsync();
        Assert.Single(_sent);
    }

    [Fact]
    public async Task GetOutlookAsync_DueToday_IsExpectedAtTheNextCheck_AndNothingIsSentOrRecorded()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        _clock.Now = _clock.Now.AddHours(2); // 10:00
        Checked(_clock.Now.AddMinutes(-40));

        var outlook = await CreateService().GetOutlookAsync();

        Assert.Equal(_clock.Now.AddMinutes(20), outlook.NextCheck);
        Assert.Equal(outlook.NextCheck, outlook.NextEmail);
        Assert.Equal(new DateOnly(2026, 12, 1), Assert.Single(outlook.Certificates).NextReminder);
        Assert.Empty(_sent);
        Assert.Null(Assert.Single(await _certificates.GetAllAsync()).LastRemindedAt);
        Assert.Null((await _state.GetAsync()).LastDigestDate);
    }

    [Fact]
    public async Task GetOutlookAsync_SentToday_ExpectsTheFirstCheckAfterTheSendTimeOnTheRepeatDay()
    {
        _settings = new ReminderConfig { SendAtHour = 9, RepeatDays = 3 };
        await _certificates.UpsertAsync(Imported(daysLeft: 20));
        var service = CreateService();
        _clock.Now = _clock.Now.AddHours(1);
        await service.CheckAsync();
        _clock.Now = _clock.Now.AddMinutes(20); // 09:20
        Checked(_clock.Now.AddMinutes(-20));    // checks run at 09:00, 10:00 and so on

        var outlook = await service.GetOutlookAsync();

        Assert.Equal(new DateOnly(2026, 12, 4), Assert.Single(outlook.Certificates).NextReminder);
        Assert.Equal(new DateTimeOffset(2026, 12, 2, 9, 0, 0, TimeSpan.Zero), outlook.NextDigest);
        Assert.Equal(new DateTimeOffset(2026, 12, 4, 9, 0, 0, TimeSpan.Zero), outlook.NextEmail);
    }

    [Fact]
    public async Task GetOutlookAsync_ServiceNotCheckingOrNothingDue_SaysSo()
    {
        await _certificates.UpsertAsync(Imported(daysLeft: 20) with { Reminders = ReminderMode.Off });
        _clock.Now = _clock.Now.AddHours(1);
        Checked(_clock.Now.AddHours(-3));

        var outlook = await CreateService().GetOutlookAsync();

        Assert.Null(outlook.NextCheck);
        Assert.Null(outlook.NextEmail);
        Assert.Contains(outlook.Lines, line => line.Contains("check that it is running", StringComparison.Ordinal));
        Assert.Contains(outlook.Lines, line => line == "Next email expected: none");
        Assert.Contains(outlook.Lines, line => line.EndsWith("no reminder expected (reminders are off permanently).", StringComparison.Ordinal));
    }

    [Fact]
    public async Task GetOutlookAsync_WeeklySummaryCountsAsTheNextEmail()
    {
        _settings = new ReminderConfig { SendAtHour = 9, WeeklySummaryDay = DayOfWeek.Friday };
        await _certificates.UpsertAsync(Imported(daysLeft: 200));
        Checked(_clock.Now.AddMinutes(-10)); // checks run at 07:50, 08:50 and so on

        var outlook = await CreateService().GetOutlookAsync();

        Assert.Equal(new DateTimeOffset(2026, 12, 4, 9, 50, 0, TimeSpan.Zero), outlook.NextEmail);
    }

    private void Checked(DateTimeOffset at) =>
        _heartbeat.Setup(value => value.GetAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ServiceHeartbeat("test", at, LastCycleStartedAt: at));

    /// <summary>A service whose settings are saved and read back, for tests that change them part way through a check.</summary>
    private ReminderService CreateServiceWithSavedSettings(IRenewalService renewal)
    {
        var saved = new AppConfig { Reminders = _settings };
        var config = new Mock<IConfigStore>();
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => saved);
        config.Setup(value => value.SaveAsync(It.IsAny<AppConfig>(), It.IsAny<CancellationToken>()))
            .Callback<AppConfig, CancellationToken>((value, _) => saved = value)
            .Returns(Task.CompletedTask);
        return new ReminderService(_certificates, config.Object, renewal, _state, _notifier.Object, _detector.Object, _readiness.Object, _served.Object, _heartbeat.Object, _clock);
    }

    private ReminderService CreateService(IRenewalService? renewal = null)
    {
        var config = new Mock<IConfigStore>(MockBehavior.Strict);
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => new AppConfig { Reminders = _settings });
        return new ReminderService(_certificates, config.Object, renewal ?? ScheduledInTenDays(), _state, _notifier.Object, _detector.Object, _readiness.Object, _served.Object, _heartbeat.Object, _clock);
    }

    private IRenewalService ScheduledInTenDays()
    {
        var renewal = new Mock<IRenewalService>();
        renewal.Setup(value => value.GetScheduledRenewalAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => _clock.Now.AddDays(10));
        return renewal.Object;
    }

    /// <param name="problemSites">Sites that do not serve the expected certificate today.</param>
    private void Served(params string[] problemSites) =>
        _served.Setup(value => value.CheckAllAsync(It.IsAny<IReadOnlyList<ManagedCertificate>>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProactiveCheckResult(problemSites.ToDictionary(site => site, _ => "shop.example.com serves a different certificate."), [], []));

    private void NotReady(params string[] sites) => Readiness(new ProactiveCheckResult(
        sites.ToDictionary(site => site, _ => "'HTTP binding: api.example.com' failed: Add an IIS HTTP binding on port 80 for this host."),
        [],
        []));

    private void Ready(params string[] sites) => Readiness(new ProactiveCheckResult(new Dictionary<string, string>(), sites, []));

    private void Readiness(ProactiveCheckResult result) =>
        _readiness.Setup(value => value.CheckAsync(
                It.IsAny<IReadOnlyList<ManagedCertificate>>(), It.IsAny<IReadOnlyDictionary<string, DateTimeOffset>>(),
                It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);

    private ManagedCertificate Automatic(int daysLeft) => new(
        "Api", ["api.example.com"], "admin@example.com", "CCDD", _clock.Now.AddDays(daysLeft - 90), _clock.Now.AddDays(daysLeft),
        LastRenewalSucceeded: true, UpcomingNoticeSent: true);

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
