using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Logs;
using Xunit;

namespace SSLense.Tests.Certificates;

public sealed class CertificateManagementServiceTests
{
    [Fact]
    public async Task RemoveAsync_OldCertificateUsedElsewhere_PreservesStoreCertificate()
    {
        var record = new ManagedCertificate(
            "My Site", ["example.com"], "admin@example.com", "OLD",
            DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(60));
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([record]);
        managed.Setup(value => value.RemoveAsync("My Site", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.RemoveHttpsBindingsAsync(
            "My Site", It.IsAny<IReadOnlyList<string>>(), "OLD", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([
            new IisSite(2, "Other", "Started", null, [
                new IisBinding("https", "*", 443, "other.example.com", "OLD", "My", true)])
        ]);
        var certificates = new Mock<ICertificateStore>(MockBehavior.Strict);
        var service = new CertificateManagementService(
            managed.Object, certificates.Object, iis.Object, Mock.Of<ILogService>());

        await service.RemoveAsync("My Site");

        certificates.VerifyNoOtherCalls();
        managed.VerifyAll();
        iis.VerifyAll();
    }

    [Fact]
    public async Task RemoveAsync_ImportedCertificate_StaysInTheStore()
    {
        var record = new ManagedCertificate(
            "My Site", ["example.com"], "", "BOUGHT",
            DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(300),
            Source: CertificateSource.Imported);
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([record]);
        managed.Setup(value => value.RemoveAsync("My Site", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.RemoveHttpsBindingsAsync(
            "My Site", It.IsAny<IReadOnlyList<string>>(), "BOUGHT", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var certificates = new Mock<ICertificateStore>(MockBehavior.Strict);
        var service = new CertificateManagementService(
            managed.Object, certificates.Object, iis.Object, Mock.Of<ILogService>());

        await service.RemoveAsync("My Site");

        certificates.VerifyNoOtherCalls();
        managed.VerifyAll();
    }

    [Fact]
    public async Task GetDetailsAsync_ReturnsIssuerBindingsAndTenLogs()
    {
        var record = new ManagedCertificate(
            "My Site", ["example.com"], "admin@example.com", "ABC",
            DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(60));
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([record]);
        var certificates = new Mock<ICertificateStore>();
        certificates.Setup(value => value.FindByThumbprintAsync("ABC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("ABC", record.NotBefore, record.NotAfter, true, "CN=Issuer"));
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([
            new IisSite(1, "My Site", "Started", null, [
                new IisBinding("https", "*", 443, "example.com", "ABC", "My", true)])
        ]);
        var logs = new Mock<ILogService>();
        logs.Setup(value => value.ReadCurrentAsync("All", 10, It.IsAny<CancellationToken>(), null))
            .ReturnsAsync(new LogSnapshot("log", Enumerable.Range(1, 10).Select(value => $"line {value}").ToArray()));
        var service = new CertificateManagementService(managed.Object, certificates.Object, iis.Object, logs.Object);

        var details = await service.GetDetailsAsync("My Site");

        Assert.Equal("CN=Issuer", details.Issuer);
        Assert.Equal(["My Site"], details.BoundSites);
        Assert.Equal(10, details.RecentLogLines.Count);
    }
}
