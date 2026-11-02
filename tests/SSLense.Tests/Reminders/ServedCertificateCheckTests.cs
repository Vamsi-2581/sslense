using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Reminders;
using Xunit;

namespace SSLense.Tests.Reminders;

public sealed class ServedCertificateCheckTests
{
    private const string Expected = "AABBCCDDEEFF00112233";
    private const string Other = "11223344556677889900";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private readonly Mock<IIisService> _iis = new();
    private readonly Mock<ITlsBindingProbe> _probe = new(MockBehavior.Strict);
    private readonly Mock<ICertificateStore> _store = new();
    private readonly Mock<ICertificateOperationLock> _lock = new();

    public ServedCertificateCheckTests()
    {
        _lock.Setup(value => value.TryAcquire(It.IsAny<string>())).Returns(Mock.Of<IAsyncDisposable>());
    }

    [Fact]
    public async Task ExpectedCertificate_Passes_IgnoringCaseAndSpaces()
    {
        Site(Binding());
        Serves("aabb ccdd eeff 0011 2233");

        var result = await Check();

        Assert.Equal(["Shop"], result.Passed);
        Assert.Empty(result.Problems);
        _probe.Verify(value => value.GetServedThumbprintAsync("127.0.0.1", "shop.example.com", 443, It.IsAny<CancellationToken>()));
    }

    [Fact]
    public async Task DifferentCertificate_IsReportedWithBothThumbprintsAndItsExpiry()
    {
        Site(Binding());
        Serves(Other);
        var expires = Now.AddDays(90);
        _store.Setup(value => value.FindByThumbprintAsync(Other, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(Other, Now.AddDays(-10), expires, true));

        var problem = (await Check()).Problems["Shop"];

        Assert.Contains("expected AABBCCDD…, served 11223344…", problem, StringComparison.Ordinal);
        Assert.Contains($"It expires on {expires:yyyy-MM-dd}", problem, StringComparison.Ordinal);
        Assert.EndsWith("Check the site's HTTPS binding in IIS.", problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiredOrUnknownServedCertificate_SaysSo()
    {
        Site(Binding());
        Serves(Other);

        Assert.Contains("not in this server's certificate store", (await Check()).Problems["Shop"], StringComparison.Ordinal);

        var expired = Now.AddDays(-3);
        _store.Setup(value => value.FindByThumbprintAsync(Other, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(Other, Now.AddDays(-100), expired, true));

        Assert.Contains($"It expired on {expired:yyyy-MM-dd}", (await Check()).Problems["Shop"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpectedCertificateThatHasExpired_IsReported()
    {
        Site(Binding());
        Serves(Expected);
        var expired = Now.AddDays(-2);

        var result = await Check(Certificate() with { NotAfter = expired });

        Assert.Empty(result.Passed);
        Assert.Contains($"serves the expected certificate, but it expired on {expired:yyyy-MM-dd}", result.Problems["Shop"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoAnswer_OrNoBinding_IsReported()
    {
        Site(Binding());
        _probe.Setup(value => value.GetServedThumbprintAsync(It.IsAny<string>(), It.IsAny<string>(), 443, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("timed out"));
        Assert.Contains("did not answer on port 443 (timed out)", (await Check()).Problems["Shop"], StringComparison.Ordinal);

        Site();
        Assert.Contains("has no HTTPS binding on port 443", (await Check()).Problems["Shop"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task BindingOnAnAddress_IsProbedThere_AndEveryBindingCounts()
    {
        Site(Binding(), Binding("10.0.0.5"));
        _probe.Setup(value => value.GetServedThumbprintAsync("127.0.0.1", "shop.example.com", 443, It.IsAny<CancellationToken>())).ReturnsAsync(Expected);
        _probe.Setup(value => value.GetServedThumbprintAsync("10.0.0.5", "shop.example.com", 443, It.IsAny<CancellationToken>())).ReturnsAsync(Other);

        Assert.Contains("serves a different certificate", (await Check()).Problems["Shop"], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Stopped", false, ReminderMode.On)]
    [InlineData("Unknown", false, ReminderMode.On)]
    [InlineData("Started", true, ReminderMode.On)]
    [InlineData("Started", false, ReminderMode.Off)]
    public async Task StoppedBusyOrMutedSites_AreNotChecked(string state, bool busy, ReminderMode mode)
    {
        Site(state, Binding());
        if (busy)
        {
            _lock.Setup(value => value.TryAcquire("Shop")).Returns((IAsyncDisposable?)null);
        }

        var result = await Check(Certificate() with { Reminders = mode });

        Assert.Empty(result.Passed);
        Assert.Empty(result.Problems);
    }

    private Task<ProactiveCheckResult> Check(ManagedCertificate? certificate = null) =>
        new ServedCertificateCheck(_iis.Object, _probe.Object, _store.Object, _lock.Object)
            .CheckAllAsync([certificate ?? Certificate()], Now);

    private void Serves(string thumbprint) =>
        _probe.Setup(value => value.GetServedThumbprintAsync(It.IsAny<string>(), It.IsAny<string>(), 443, It.IsAny<CancellationToken>()))
            .ReturnsAsync(thumbprint);

    private void Site(params IisBinding[] bindings) => Site("Started", bindings);

    private void Site(string state, params IisBinding[] bindings) =>
        _iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new IisSite(1, "Shop", state, null, bindings)]);

    private static IisBinding Binding(string address = "*") =>
        new("https", address, 443, "shop.example.com", Expected, "My", true);

    private static ManagedCertificate Certificate() => new(
        "Shop", ["shop.example.com"], "", Expected, Now.AddDays(-10), Now.AddDays(200), Source: CertificateSource.Imported);
}
