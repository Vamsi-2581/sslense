using Moq;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using SSLense.Core.Renewal;
using Xunit;

namespace SSLense.Tests.Renewal;

public sealed class ExpiryMonitorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 28, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    // 90-day certificates keep the original 14-day warning and a 3-day critical point.
    [InlineData(90, 15, ExpiryWarningLevel.None)]
    [InlineData(90, 13.9, ExpiryWarningLevel.Warning)]
    [InlineData(90, 2.9, ExpiryWarningLevel.Critical)]
    // 45-day certificates: warning at 7.5 days, critical at 2.5 days.
    [InlineData(45, 8, ExpiryWarningLevel.None)]
    [InlineData(45, 7, ExpiryWarningLevel.Warning)]
    [InlineData(45, 2, ExpiryWarningLevel.Critical)]
    // 6-day certificates: warning at 1 day, critical at 8 hours.
    [InlineData(6, 1.5, ExpiryWarningLevel.None)]
    [InlineData(6, 0.9, ExpiryWarningLevel.Warning)]
    [InlineData(6, 0.3, ExpiryWarningLevel.Critical)]
    [InlineData(90, -0.1, ExpiryWarningLevel.Expired)]
    public void GetLevel_ScalesWithCertificateLifetime(
        double lifetimeDays,
        double remainingDays,
        ExpiryWarningLevel expected)
    {
        var notAfter = Now.AddDays(remainingDays);
        var certificate = CreateCertificate(notAfter.AddDays(-lifetimeDays), notAfter);

        Assert.Equal(expected, ExpiryMonitor.GetLevel(certificate, Now));
    }

    [Fact]
    public async Task CheckAsync_SendsEachNewLevelOnceAndRecordsIt()
    {
        var expiring = CreateCertificate(DateTimeOffset.UtcNow.AddDays(-80), DateTimeOffset.UtcNow.AddDays(10));
        var alreadyWarned = expiring with { SiteName = "Warned Site", ExpiryWarningSent = ExpiryWarningLevel.Warning };
        var healthy = CreateCertificate(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(80))
            with { SiteName = "Healthy Site" };
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([expiring, alreadyWarned, healthy]);
        managed.Setup(value => value.RecordExpiryWarningAsync(
                "My Site", "AABBCC", ExpiryWarningLevel.Warning, CancellationToken.None))
            .Returns(Task.CompletedTask);
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message =>
                    message.Kind == NotificationKind.ExpiryWarning && message.Subject.Contains("My Site")),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var monitor = new ExpiryMonitor(managed.Object, notifier.Object);

        var messages = await monitor.CheckAsync();

        Assert.Single(messages);
        managed.VerifyAll();
        notifier.VerifyAll();
        notifier.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task CheckAsync_FailedSend_IsNotRecordedSoItRetries()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(-89), DateTimeOffset.UtcNow.AddHours(1))]);
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        notifier.Setup(value => value.NotifyAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("SMTP offline"));
        var monitor = new ExpiryMonitor(managed.Object, notifier.Object);

        var message = Assert.Single(await monitor.CheckAsync());

        Assert.Contains("SMTP offline", message, StringComparison.Ordinal);
        managed.Verify(
            value => value.RecordExpiryWarningAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<ExpiryWarningLevel>(), It.IsAny<CancellationToken>()),
            Times.Never());
    }

    [Theory]
    [InlineData(45, null, null)]
    [InlineData(29.5, null, 30)]
    [InlineData(29.5, 30, null)]
    [InlineData(10, 30, 14)]
    // Installed late: only the closest reminder is sent, not every one that was missed.
    [InlineData(5, null, 7)]
    [InlineData(0.5, 7, 1)]
    [InlineData(0.5, 1, null)]
    public void GetImportedReminder_SendsEachThresholdOnce(double remainingDays, int? alreadySent, int? expected)
    {
        var certificate = CreateCertificate(Now.AddDays(-300), Now.AddDays(remainingDays)) with
        {
            Source = CertificateSource.Imported,
            ReminderDaysSent = alreadySent
        };

        Assert.Equal(expected, ExpiryMonitor.GetImportedReminder(certificate, Now));
    }

    [Fact]
    public async Task CheckAsync_ImportedCertificate_RemindsToOrderAReplacementAndRecordsIt()
    {
        var imported = CreateCertificate(DateTimeOffset.UtcNow.AddDays(-355), DateTimeOffset.UtcNow.AddDays(10)) with
        {
            Source = CertificateSource.Imported,
            Issuer = "Sectigo RSA DV",
            ReminderDaysSent = 30
        };
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([imported]);
        managed.Setup(value => value.RecordImportedReminderAsync("My Site", "AABBCC", 14, CancellationToken.None))
            .Returns(Task.CompletedTask);
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message =>
                    message.Severity == NotificationSeverity.Warning &&
                    message.Body.Contains("Sectigo RSA DV", StringComparison.Ordinal) &&
                    message.Body.Contains("SSLense.Cli csr", StringComparison.Ordinal)),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var message = Assert.Single(await new ExpiryMonitor(managed.Object, notifier.Object).CheckAsync());

        Assert.Contains("14-day", message, StringComparison.Ordinal);
        managed.VerifyAll();
        notifier.VerifyAll();
    }

    private static ManagedCertificate CreateCertificate(DateTimeOffset notBefore, DateTimeOffset notAfter) => new(
        "My Site", ["example.com"], "admin@example.com", "AABBCC", notBefore, notAfter);
}
