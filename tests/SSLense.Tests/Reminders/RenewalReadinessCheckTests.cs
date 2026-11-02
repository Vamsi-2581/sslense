using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Reminders;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Reminders;

public sealed class RenewalReadinessCheckTests
{
    private static readonly DateTimeOffset Now = new(2026, 12, 1, 9, 0, 0, TimeSpan.Zero);
    private readonly Mock<IPreflightService> _preflight = new(MockBehavior.Strict);
    private readonly Mock<ICertificateOperationLock> _lock = new();

    public RenewalReadinessCheckTests()
    {
        _lock.Setup(value => value.TryAcquire(It.IsAny<string>())).Returns(Mock.Of<IAsyncDisposable>());
    }

    [Fact]
    public async Task FailedChecks_AreReportedWithWhatFailed()
    {
        Preflight(new PreflightCheck("Administrator", true, "SSLense is elevated."),
            new PreflightCheck("HTTP binding: api.example.com", false, "Add an IIS HTTP binding on port 80 for this host."));

        var result = await Check(Automatic(), renewsInDays: 10);

        Assert.Equal(
            "'HTTP binding: api.example.com' failed: Add an IIS HTTP binding on port 80 for this host.",
            result.Problems["Api"]);
        Assert.Empty(result.Passed);
    }

    [Fact]
    public async Task AllChecksPassing_IsRecordedAsPassed()
    {
        Preflight(new PreflightCheck("Administrator", true, "SSLense is elevated."));

        var result = await Check(Automatic(), renewsInDays: 10);

        Assert.Equal(["Api"], result.Passed);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public async Task CertificateFarFromRenewal_IsNotChecked()
    {
        var result = await Check(Automatic(), renewsInDays: 31);

        Assert.Empty(result.Passed);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public async Task RenewalAlreadyPastDue_IsStillChecked()
    {
        Preflight(new PreflightCheck("Administrator", true, "SSLense is elevated."));

        Assert.Single((await Check(Automatic(), renewsInDays: -2)).Passed);
    }

    [Fact]
    public async Task ImportedAndMutedCertificates_AreNotChecked()
    {
        var imported = Automatic() with { Source = CertificateSource.Imported };
        var muted = Automatic() with { SiteName = "Muted", Reminders = ReminderMode.Off };

        var result = await new RenewalReadinessCheck(_preflight.Object, _lock.Object).CheckAsync(
            [imported, muted],
            new Dictionary<string, DateTimeOffset> { ["Api"] = Now, ["Muted"] = Now },
            Now);

        Assert.Empty(result.Passed);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public async Task SiteWithAnOperationInProgress_IsSkipped()
    {
        _lock.Setup(value => value.TryAcquire("Api")).Returns((IAsyncDisposable?)null);

        var result = await Check(Automatic(), renewsInDays: 10);

        Assert.Empty(result.Passed);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public async Task CheckThatCannotRun_IsAnErrorAndOthersContinue()
    {
        _preflight.Setup(value => value.CheckAsync("Api", It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("IIS cannot be read"));

        var result = await Check(Automatic(), renewsInDays: 10);

        Assert.Contains("IIS cannot be read", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    private Task<RenewalReadinessResult> Check(ManagedCertificate certificate, int renewsInDays) =>
        new RenewalReadinessCheck(_preflight.Object, _lock.Object).CheckAsync(
            [certificate],
            new Dictionary<string, DateTimeOffset> { [certificate.SiteName] = Now.AddDays(renewsInDays) },
            Now);

    private void Preflight(params PreflightCheck[] checks) =>
        _preflight.Setup(value => value.CheckAsync("Api", It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(checks);

    private static ManagedCertificate Automatic() => new(
        "Api", ["api.example.com"], "admin@example.com", "CCDD", Now.AddDays(-50), Now.AddDays(40));
}
