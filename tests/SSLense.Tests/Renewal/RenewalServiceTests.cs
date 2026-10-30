using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Renewal;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Renewal;

public sealed class RenewalServiceTests
{
    [Fact]
    public async Task RenewAsync_NotDueWithoutForce_SkipsIssuance()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(60))]);
        var config = new Mock<IConfigStore>(MockBehavior.Strict);
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { RenewalThresholdDays = 30 });
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        var service = CreateService(managed, config, acme);

        var results = await service.RenewAsync(new RenewalRequest(All: true));

        var result = Assert.Single(results);
        Assert.False(result.Attempted);
        Assert.True(result.Succeeded);
        acme.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RenewAsync_ImportedCertificate_IsNeverSentToAnAcmeCa()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(2)) with
            {
                Source = CertificateSource.Imported,
                Issuer = "Sectigo RSA DV"
            }]);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        var service = CreateService(managed, MockConfig(), acme);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true, Force: true)));

        Assert.False(result.Attempted);
        Assert.True(result.Succeeded);
        Assert.Contains("Sectigo RSA DV", result.Message, StringComparison.Ordinal);
        acme.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RenewAsync_AriWindowOverridesFallbackSchedule()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        var ari = new Mock<IRenewalInfoProvider>(MockBehavior.Strict);
        ari.Setup(value => value.GetWindowAsync(
                It.IsAny<ManagedCertificate>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RenewalWindow(
                DateTimeOffset.UtcNow.AddDays(2),
                DateTimeOffset.UtcNow.AddDays(3)));
        var service = CreateService(managed, MockConfig(), acme, renewalInfoProvider: ari);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true)));

        Assert.False(result.Attempted);
        Assert.Contains("scheduled", result.Message, StringComparison.OrdinalIgnoreCase);
        acme.VerifyNoOtherCalls();
        ari.VerifyAll();
    }

    [Fact]
    public void SelectTimeInWindow_IsStableAndInsideWindow()
    {
        var window = new RenewalWindow(
            new DateTimeOffset(2026, 10, 28, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 29, 0, 0, 0, TimeSpan.Zero));

        var first = RenewalService.SelectTimeInWindow(window, "AABBCC");
        var second = RenewalService.SelectTimeInWindow(window, "AABBCC");

        Assert.Equal(first, second);
        Assert.InRange(first, window.Start, window.End);
    }

    [Fact]
    public async Task RenewAsync_StateChangedWhileWaiting_IsSuccessfulSkip()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(
                It.IsAny<AcmeIssueRequest>(), null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new CertificateStateChangedException("another process renewed it"));
        var service = CreateService(managed, MockConfig(), acme);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true)));

        Assert.False(result.Attempted);
        Assert.True(result.Succeeded);
        Assert.Contains("Skipped", result.Message, StringComparison.Ordinal);
        managed.Verify(
            value => value.RecordRenewalFailureAsync(
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<string>(),
                It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Never());
    }

    [Fact]
    public async Task RenewAsync_Due_SwapsBindingBeforeRemovingUnusedOldCertificate()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        var config = MockConfig();
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(
                It.Is<AcmeIssueRequest>(request => request.Force && request.SiteName == "My Site"),
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult(
                "certificate.pem",
                "certificate.pfx",
                ["example.com"],
                "NEW"));
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [
                    new IisBinding("https", "*", 443, "example.com", "NEW", "My", true)
                ])
            ]);
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.RemoveAsync("OLD", It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        // Expiry warnings now come from ExpiryMonitor, so renewal sends only the success message.
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalSuccess),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("notification offline"));
        var service = CreateService(managed, config, acme, iis, certificateStore, notifier: notifier);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true)));

        Assert.True(result.Succeeded);
        Assert.Equal("NEW", result.NewThumbprint);
        certificateStore.VerifyAll();
        notifier.VerifyAll();
    }

    [Fact]
    public async Task RenewAsync_OldCertificateStillUsedByIis_DoesNotRemoveIt()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(
                It.IsAny<AcmeIssueRequest>(),
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("pem", "pfx", ["example.com"], "NEW"));
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                new IisSite(2, "Other Site", "Started", null, [
                    new IisBinding("https", "*", 443, "other.example.com", "OLD", "My", true)
                ])
            ]);
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        var service = CreateService(managed, MockConfig(), acme, iis, certificateStore);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true)));

        Assert.True(result.Succeeded);
        Assert.Contains("retained", result.Message, StringComparison.OrdinalIgnoreCase);
        certificateStore.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RenewAsync_Failure_PersistsRetryScheduleInsteadOfWaiting()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        DateTimeOffset? recordedRetry = null;
        managed.Setup(value => value.RecordRenewalFailureAsync(
                "My Site", It.IsAny<DateTimeOffset>(), "ACME unavailable", It.IsAny<DateTimeOffset>(), CancellationToken.None))
            .Callback<string, DateTimeOffset, string, DateTimeOffset, CancellationToken>(
                (_, _, _, retryAt, _) => recordedRetry = retryAt)
            .ReturnsAsync(CreateCertificate(DateTimeOffset.UtcNow.AddDays(5)) with { ConsecutiveFailures = 1 });
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("ACME unavailable"));
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        var service = CreateService(managed, MockConfig(), acme, notifier: notifier);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true, Scheduled: true)));

        Assert.True(result.Attempted);
        Assert.False(result.Succeeded);
        Assert.Contains("Next automatic attempt", result.Message, StringComparison.Ordinal);
        Assert.NotNull(recordedRetry);
        Assert.InRange(recordedRetry.Value - DateTimeOffset.UtcNow, TimeSpan.FromMinutes(59), TimeSpan.FromHours(1));
        acme.Verify(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), null, It.IsAny<CancellationToken>()), Times.Once());

        // The first scheduled failure is retried quietly; escalation starts at the third.
        notifier.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RenewAsync_ScheduledRunInBackoff_SkipsOnlyThatCertificate()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                CreateCertificate(DateTimeOffset.UtcNow.AddDays(5)) with
                {
                    ConsecutiveFailures = 2,
                    NextRetryAt = DateTimeOffset.UtcNow.AddHours(1)
                },
                CreateCertificate(DateTimeOffset.UtcNow.AddDays(5)) with { SiteName = "Healthy Site" }
            ]);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(
                It.Is<AcmeIssueRequest>(request => request.SiteName == "Healthy Site"), null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("pem", "pfx", ["example.com"], "OLD"));
        var service = CreateService(managed, MockConfig(), acme);

        var results = await service.RenewAsync(new RenewalRequest(All: true, Scheduled: true));

        Assert.Collection(
            results,
            result =>
            {
                Assert.False(result.Attempted);
                Assert.Contains("attempt 3", result.Message, StringComparison.Ordinal);
            },
            result => Assert.True(result.Succeeded));
        acme.VerifyAll();
    }

    [Fact]
    public async Task RenewAsync_ManualRunInBackoff_AttemptsImmediately()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5)) with
            {
                ConsecutiveFailures = 1,
                NextRetryAt = DateTimeOffset.UtcNow.AddHours(1)
            }]);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("pem", "pfx", ["example.com"], "OLD"));
        var service = CreateService(managed, MockConfig(), acme);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(SiteName: "My Site")));

        Assert.True(result.Succeeded);
        acme.VerifyAll();
    }

    [Fact]
    public async Task RenewAsync_ThirdScheduledFailure_SendsFailureNotification()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5)) with
            {
                ConsecutiveFailures = 2,
                NextRetryAt = DateTimeOffset.UtcNow.AddMinutes(-1)
            }]);
        managed.Setup(value => value.RecordRenewalFailureAsync(
                "My Site", It.IsAny<DateTimeOffset>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), CancellationToken.None))
            .ReturnsAsync(CreateCertificate(DateTimeOffset.UtcNow.AddDays(5)) with { ConsecutiveFailures = 3 });
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("ACME unavailable"));
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message =>
                    message.Kind == NotificationKind.RenewalFailure &&
                    message.Body.Contains("3 consecutive", StringComparison.Ordinal)),
                CancellationToken.None))
            .Returns(Task.CompletedTask);
        var service = CreateService(managed, MockConfig(), acme, notifier: notifier);

        await service.RenewAsync(new RenewalRequest(All: true, Scheduled: true));

        notifier.VerifyAll();
    }

    [Fact]
    public async Task RenewAsync_RateLimited_WaitsADayAndNotifiesImmediately()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        DateTimeOffset? recordedRetry = null;
        managed.Setup(value => value.RecordRenewalFailureAsync(
                "My Site", It.IsAny<DateTimeOffset>(), "rate limit reached", It.IsAny<DateTimeOffset>(), CancellationToken.None))
            .Callback<string, DateTimeOffset, string, DateTimeOffset, CancellationToken>(
                (_, _, _, retryAt, _) => recordedRetry = retryAt)
            .ReturnsAsync((ManagedCertificate?)null);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new AcmeRateLimitedException("rate limit reached"));
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalFailure),
                CancellationToken.None))
            .Returns(Task.CompletedTask);
        var service = CreateService(managed, MockConfig(), acme, notifier: notifier);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true, Scheduled: true)));

        Assert.False(result.Succeeded);
        Assert.InRange(recordedRetry!.Value - DateTimeOffset.UtcNow, TimeSpan.FromHours(23.9), TimeSpan.FromHours(24));
        notifier.VerifyAll();
    }

    [Theory]
    [InlineData("acme-test.sslense.com", "is a host name of IIS site 'My Site'")]
    [InlineData("Unknown Site", "Managed IIS sites: 'My Site'")]
    public async Task RenewAsync_UnknownSite_SuggestsTheRightSiteName(string siteName, string expectedHint)
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(30)) with { Hosts = ["acme-test.sslense.com"] }]);
        var service = CreateService(managed, MockConfig(), new Mock<IAcmeService>(MockBehavior.Strict));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.RenewAsync(new RenewalRequest(SiteName: siteName, Force: true)));

        Assert.Contains(expectedHint, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1, false, 30, 1)]
    [InlineData(2, false, 30, 2)]
    [InlineData(3, false, 30, 6)]
    [InlineData(9, false, 30, 6)]
    [InlineData(5, false, 1, 1)]
    [InlineData(1, true, 30, 24)]
    [InlineData(1, true, 1, 24)]
    public void GetRetryDelay_BacksOffAndStaysHourlyNearExpiry(
        int failures,
        bool rateLimited,
        int daysRemaining,
        int expectedHours)
    {
        Assert.Equal(
            TimeSpan.FromHours(expectedHours),
            RenewalService.GetRetryDelay(failures, rateLimited, TimeSpan.FromDays(daysRemaining)));
    }

    [Theory]
    [InlineData(1, true, false, false)]
    [InlineData(2, true, false, false)]
    [InlineData(3, true, false, true)]
    [InlineData(4, true, false, false)]
    [InlineData(7, true, false, true)]
    [InlineData(1, true, true, true)]
    [InlineData(1, false, false, true)]
    public void ShouldNotifyFailure_EscalatesAboutDailyForScheduledRuns(
        int failures,
        bool scheduled,
        bool rateLimited,
        bool expected)
    {
        Assert.Equal(expected, RenewalService.ShouldNotifyFailure(failures, scheduled, rateLimited));
    }

    private static RenewalService CreateService(
        Mock<IManagedCertificateStore> managed,
        Mock<IConfigStore> config,
        Mock<IAcmeService> acme,
        Mock<IIisService>? iis = null,
        Mock<ICertificateStore>? certificateStore = null,
        Mock<INotifier>? notifier = null,
        Mock<IRenewalInfoProvider>? renewalInfoProvider = null) =>
        new(
            managed.Object,
            config.Object,
            acme.Object,
            (iis ?? new Mock<IIisService>(MockBehavior.Strict)).Object,
            (certificateStore ?? new Mock<ICertificateStore>(MockBehavior.Strict)).Object,
            (notifier ?? new Mock<INotifier>()).Object,
            renewalInfoProvider?.Object);

    private static Mock<IConfigStore> MockConfig()
    {
        var config = new Mock<IConfigStore>(MockBehavior.Strict);
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { RenewalThresholdDays = 30 });
        return config;
    }

    private static ManagedCertificate CreateCertificate(DateTimeOffset expires) => new(
        "My Site",
        ["example.com"],
        "admin@example.com",
        "OLD",
        DateTimeOffset.UtcNow.AddDays(-60),
        expires);
}
