using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Notifications;
using SSLense.Core.Reminders;
using Xunit;

namespace SSLense.Tests.Reminders;

public sealed class OutsideRenewalDetectorTests
{
    private static readonly DateTimeOffset OldExpiry = DateTimeOffset.UtcNow.AddDays(10);
    private readonly JsonManagedCertificateStore _certificates =
        new(new InMemoryFileSystem(), @"C:\data\managed-certificates.json", @"C:\data\managed.lock");
    private readonly Mock<ICertificateStore> _store = new();
    private readonly Mock<INotifier> _notifier = new();

    [Fact]
    public async Task NewerCertificateBoundInIis_ReplacesTheRecordAndRestartsReminders()
    {
        await _certificates.UpsertAsync(Imported() with { Reminders = ReminderMode.OffUntilReplaced, LastRemindedAt = DateTimeOffset.UtcNow });
        Installed("NEW", OldExpiry.AddDays(365), hasKey: true, "shop.example.com", "www.shop.example.com");

        var change = Assert.Single(await Detect("NEW"));

        var record = Assert.Single(await _certificates.GetAllAsync());
        Assert.Equal("NEW", record.Thumbprint);
        Assert.Equal(ReminderMode.On, record.Reminders);
        Assert.Null(record.LastRemindedAt);
        Assert.Equal("Sectigo RSA DV", record.Issuer);
        Assert.Contains("replaced outside SSLense", change, StringComparison.Ordinal);
        _notifier.Verify(value => value.NotifyAsync(
            It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalSuccess), It.IsAny<CancellationToken>()));
    }

    [Theory]
    [InlineData(false, 365, "shop.example.com")]   // no private key here
    [InlineData(true, -5, "shop.example.com")]     // not newer
    [InlineData(true, 365, "other.example.com")]   // does not cover the hosts
    public async Task UnsuitableCertificate_IsIgnored(bool hasKey, int extraDays, string dnsName)
    {
        await _certificates.UpsertAsync(Imported());
        Installed("NEW", OldExpiry.AddDays(extraDays), hasKey, dnsName);

        Assert.Empty(await Detect("NEW"));
        Assert.Equal("OLD", Assert.Single(await _certificates.GetAllAsync()).Thumbprint);
    }

    [Fact]
    public async Task AutomaticCertificate_IsLeftToTheHealthCheck()
    {
        await _certificates.UpsertAsync(Imported() with { Source = CertificateSource.Acme });
        Installed("NEW", OldExpiry.AddDays(365), hasKey: true, "shop.example.com", "www.shop.example.com");

        Assert.Empty(await Detect("NEW"));
    }

    private Task<IReadOnlyList<string>> Detect(string boundThumbprint)
    {
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([
            new IisSite(1, "Shop", "Started", null, [
                new IisBinding("https", "*", 443, "shop.example.com", boundThumbprint, "My", true),
                new IisBinding("https", "*", 443, "www.shop.example.com", boundThumbprint, "My", true)
            ])
        ]);
        return new OutsideRenewalDetector(_certificates, iis.Object, _store.Object, _notifier.Object).DetectAsync();
    }

    private void Installed(string thumbprint, DateTimeOffset notAfter, bool hasKey, params string[] dnsNames) =>
        _store.Setup(value => value.FindByThumbprintAsync(thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(thumbprint, notAfter.AddDays(-365), notAfter, hasKey, DnsNames: dnsNames, IssuerName: "Sectigo RSA DV"));

    private static ManagedCertificate Imported() => new(
        "Shop", ["shop.example.com", "www.shop.example.com"], "", "OLD", OldExpiry.AddDays(-355), OldExpiry,
        Source: CertificateSource.Imported, Issuer: "Sectigo RSA DV");
}
