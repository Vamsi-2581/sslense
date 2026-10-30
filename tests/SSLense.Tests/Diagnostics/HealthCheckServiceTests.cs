using System.Net;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Diagnostics;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using SSLense.Core.WindowsServices;
using Xunit;

namespace SSLense.Tests.Diagnostics;

public sealed class HealthCheckServiceTests
{
    private const string Thumbprint = "6533D7B01A1F3C4BDF85551F375A3EFC4BD45F5F";

    [Fact]
    public async Task RunAsync_HealthyServer_PassesTheCertificateAndServiceChecks()
    {
        var results = await CreateService().RunAsync();

        foreach (var name in new[]
                 {
                     "Configuration", "Managed certificates", "Interrupted operations", "Renewal service",
                     "Service heartbeat", "IIS", "Certificate installed: My Site", "HTTPS bindings: My Site",
                     "Expiry: My Site", "Renewal history: My Site", "DNS: example.com",
                     "HTTP reachability: example.com (My Site)", "Let's Encrypt staging", "Notifications"
                 })
        {
            Assert.Equal(HealthStatus.Pass, Assert.Single(results, result => result.Name == name).Status);
        }

        // Pre-flight's own Administrator check is not repeated.
        Assert.Single(results, result => result.Name.StartsWith("Administrator", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RunAsync_Problems_AreReportedWithFixes()
    {
        var certificate = Certificate() with
        {
            NotBefore = DateTimeOffset.UtcNow.AddDays(-88),
            NotAfter = DateTimeOffset.UtcNow.AddDays(1),
            ConsecutiveFailures = 3,
            LastRenewalMessage = "HTTP-01 validation failed",
            NextRetryAt = DateTimeOffset.UtcNow.AddHours(6)
        };
        var service = CreateService(
            certificate: certificate,
            serviceStatus: WindowsServiceStatus.Stopped,
            heartbeat: new ServiceHeartbeat("0.9.0", DateTimeOffset.UtcNow.AddDays(-2), LastCycleCompletedAt: DateTimeOffset.UtcNow.AddHours(-5)),
            boundThumbprint: "OTHER",
            config: new AppConfig());

        var results = await service.RunAsync();

        AssertStatus(results, "Renewal service", HealthStatus.Fail, "start-service");
        AssertStatus(results, "Service heartbeat", HealthStatus.Warning, "Restart");
        AssertStatus(results, "HTTPS bindings: My Site", HealthStatus.Fail, "renew");
        AssertStatus(results, "Expiry: My Site", HealthStatus.Fail, "renew");
        AssertStatus(results, "Renewal history: My Site", HealthStatus.Fail, "renew");
        AssertStatus(results, "Notifications", HealthStatus.Warning, "SSLense.Cli notifications");
    }

    [Fact]
    public async Task RunAsync_OneCheckThrows_OthersStillRun()
    {
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("IIS management components were not found."));

        var results = await CreateService(iis: iis).RunAsync();

        Assert.Equal(HealthStatus.Fail, Assert.Single(results, result => result.Name == "IIS").Status);
        Assert.Contains(results, result => result.Name == "Notifications");
        Assert.Contains(results, result => result.Name == "Let's Encrypt staging");
    }

    [Fact]
    public async Task RunQuickAsync_RunsOnlyLocalChecks()
    {
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        var resolver = new Mock<IHostResolver>(MockBehavior.Strict);

        var results = await CreateService(iis: iis, resolver: resolver).RunQuickAsync();

        Assert.Equal(
            ["Data folder permissions", "Configuration", "Managed certificates", "Interrupted operations",
             "Renewal service", "Service heartbeat", "Notifications"],
            results.Select(result => result.Name));
        iis.VerifyNoOtherCalls();
        resolver.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RunAsync_DnsAndAcmeFailures_AreFailures()
    {
        var resolver = new Mock<IHostResolver>(MockBehavior.Strict);
        resolver.Setup(value => value.ResolveAsync("example.com", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new System.Net.Sockets.SocketException(11001));

        var results = await CreateService(resolver: resolver, acmeStatus: HttpStatusCode.ServiceUnavailable).RunAsync();

        AssertStatus(results, "DNS: example.com", HealthStatus.Fail, "DNS record");
        AssertStatus(results, "Let's Encrypt staging", HealthStatus.Fail, "status");
    }

    private static void AssertStatus(IReadOnlyList<HealthCheckResult> results, string name, HealthStatus status, string fixContains)
    {
        var result = Assert.Single(results, value => value.Name == name);
        Assert.Equal(status, result.Status);
        Assert.Contains(fixContains, result.Fix, StringComparison.Ordinal);
    }

    private static ManagedCertificate Certificate() => new(
        "My Site", ["example.com"], "admin@example.com", Thumbprint,
        DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(50), LastRenewalSucceeded: true);

    private static HealthCheckService CreateService(
        ManagedCertificate? certificate = null,
        WindowsServiceStatus serviceStatus = WindowsServiceStatus.Running,
        ServiceHeartbeat? heartbeat = null,
        string boundThumbprint = Thumbprint,
        AppConfig? config = null,
        Mock<IIisService>? iis = null,
        Mock<IHostResolver>? resolver = null,
        HttpStatusCode acmeStatus = HttpStatusCode.OK)
    {
        certificate ??= Certificate();
        config ??= new AppConfig
        {
            Notifications = new NotificationConfig { Chat = [new ChatNotificationConfig(ChatFormat.Teams, "protected")] }
        };
        heartbeat ??= new ServiceHeartbeat("0.9.0", DateTimeOffset.UtcNow.AddHours(-3), LastCycleCompletedAt: DateTimeOffset.UtcNow.AddMinutes(-20), LastCycleSucceeded: true);

        var configStore = new Mock<IConfigStore>(MockBehavior.Strict);
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(config);
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([certificate]);
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var serviceManager = new Mock<IWindowsServiceManager>(MockBehavior.Strict);
        serviceManager.Setup(value => value.GetStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(serviceStatus);
        var heartbeatStore = new Mock<IServiceHeartbeatStore>(MockBehavior.Strict);
        heartbeatStore.Setup(value => value.GetAsync(It.IsAny<CancellationToken>())).ReturnsAsync(heartbeat);
        if (iis is null)
        {
            iis = new Mock<IIisService>(MockBehavior.Strict);
            iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync([new IisSite(1, "My Site", "Started", @"C:\inetpub\site", [
                    new IisBinding("http", "*", 80, "example.com", null, null, false),
                    new IisBinding("https", "*", 443, "example.com", boundThumbprint, "My", true)
                ])]);
        }

        var store = new Mock<ICertificateStore>(MockBehavior.Strict);
        store.Setup(value => value.FindByThumbprintAsync(Thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(Thumbprint, certificate.NotBefore, certificate.NotAfter, true));
        var preflight = new Mock<IPreflightService>(MockBehavior.Strict);
        preflight.Setup(value => value.CheckAsync("My Site", It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                new PreflightCheck("Administrator", true, "SSLense is elevated."),
                new PreflightCheck("HTTP reachability: example.com", true, "Host responded with HTTP 404.")
            ]);
        if (resolver is null)
        {
            resolver = new Mock<IHostResolver>(MockBehavior.Strict);
            resolver.Setup(value => value.ResolveAsync("example.com", It.IsAny<CancellationToken>()))
                .ReturnsAsync([IPAddress.Parse("203.0.113.10")]);
        }

        var pending = new Mock<IPendingRequestStore>(MockBehavior.Strict);
        pending.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);

        return new HealthCheckService(
            configStore.Object, managed.Object, journal.Object, serviceManager.Object, heartbeatStore.Object,
            iis.Object, store.Object, preflight.Object, resolver.Object,
            new HttpClient(new StubHandler(acmeStatus)),
            CertificateAuthorityRegistry.BuiltInOnly,
            pending.Object);
    }

    /// <summary>Answers every request locally, so the test never contacts Let's Encrypt.</summary>
    private sealed class StubHandler(HttpStatusCode status) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal(CertificateAuthorities.LetsEncryptStaging.DirectoryUri, request.RequestUri);
            return Task.FromResult(new HttpResponseMessage(status));
        }
    }
}
