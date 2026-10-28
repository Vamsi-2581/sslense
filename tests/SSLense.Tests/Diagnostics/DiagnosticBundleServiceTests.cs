using System.IO.Compression;
using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Diagnostics;
using SSLense.Core.Iis;
using SSLense.Core.WindowsServices;
using Xunit;

namespace SSLense.Tests.Diagnostics;

public sealed class DiagnosticBundleServiceTests : IDisposable
{
    // Realistic secrets planted in every input; none may appear anywhere in the bundle.
    private const string SmtpPassword = "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAProtectedSmtpPasswordBlobValue==";
    private const string WebhookUrl = "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAProtectedWebhookUrlBlobValue12==";
    private const string LoggedPassword = "Hunter2Secret!";
    private const string LoggedWebhookToken = "XXXXWEBHOOKSECRETXXXX";
    private const string LoggedBearer = "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM";
    private const string PrivateKeyBody = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7PrivateKeyBody";
    private const string AccountEmail = "admin@example.com";

    private readonly string _output = Path.Combine(Path.GetTempPath(), $"sslense-bundle-{Guid.NewGuid():N}.zip");

    [Fact]
    public async Task CreateAsync_SeededSecrets_NeverAppearInTheBundle()
    {
        var service = CreateService();

        var result = await service.CreateAsync(new DiagnosticBundleRequest(_output));

        var entries = ReadEntries(result.Path);
        Assert.Contains("README.txt", entries.Keys);
        Assert.Contains("health.json", entries.Keys);
        Assert.Contains("logs/sslense-20261028.log", entries.Keys);
        var everything = string.Join("\n", entries.Values);
        foreach (var secret in new[]
                 {
                     SmtpPassword, WebhookUrl, LoggedPassword, LoggedWebhookToken, LoggedBearer, PrivateKeyBody,
                     AccountEmail, "smtp-user@example.com", "alerts@example.com"
                 })
        {
            Assert.DoesNotContain(secret, everything, StringComparison.Ordinal);
        }

        // Diagnostic value is kept.
        Assert.Contains("acme-test.sslense.com", everything, StringComparison.Ordinal);
        Assert.Contains("6533D7B01A1F3C4BDF85551F375A3EFC4BD45F5F", everything, StringComparison.Ordinal);
        Assert.Contains("smtp.example.com", entries["config.json"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_RedactHosts_ReplacesSiteAndHostNames()
    {
        var service = CreateService();

        var result = await service.CreateAsync(new DiagnosticBundleRequest(_output, RedactHosts: true));

        var everything = string.Join("\n", ReadEntries(result.Path).Values);
        Assert.DoesNotContain("acme-test.sslense.com", everything, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SSLense Test", everything, StringComparison.Ordinal);
        Assert.Contains("host-1.example", everything, StringComparison.Ordinal);
        Assert.Contains("site-1", everything, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_FailingSection_StillWritesTheRestAndExplainsTheGap()
    {
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("IIS management components were not found."));
        var service = CreateService(iis);

        var result = await service.CreateAsync(new DiagnosticBundleRequest(_output));

        var entries = ReadEntries(result.Path);
        Assert.Contains("IIS management components were not found.", entries["iis-sites.json"], StringComparison.Ordinal);
        Assert.Contains("managed-certificates.json", entries.Keys);
        Assert.Contains(result.Notes, note => note.Contains("IIS", StringComparison.Ordinal));
    }

    public void Dispose()
    {
        if (File.Exists(_output))
        {
            File.Delete(_output);
        }
    }

    private static DiagnosticBundleService CreateService(Mock<IIisService>? iis = null)
    {
        var certificate = new ManagedCertificate(
            "SSLense Test", ["acme-test.sslense.com"], AccountEmail, "6533D7B01A1F3C4BDF85551F375A3EFC4BD45F5F",
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(63),
            LastRenewalMessage: $"SMTP failed with password={LoggedPassword}");
        var config = new AppConfig
        {
            DefaultEmail = AccountEmail,
            Notifications = new NotificationConfig
            {
                Smtp = new SmtpNotificationConfig(
                    "smtp.example.com", 587, true, "smtp-user@example.com", SmtpPassword, "alerts@example.com", AccountEmail),
                Webhook = new WebhookNotificationConfig(WebhookUrl)
            }
        };

        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[Path.Combine(AppPaths.LogDirectory, "sslense-20261028.log")] = string.Join("\n",
            "[INF] Issued for acme-test.sslense.com, thumbprint 6533D7B01A1F3C4BDF85551F375A3EFC4BD45F5F",
            $"[ERR] SMTP authentication failed: password={LoggedPassword}",
            $"[ERR] POST https://hooks.slack.com/services/T000/B000/{LoggedWebhookToken} returned 500",
            $"[DBG] Authorization: Bearer {LoggedBearer}",
            "[DBG] -----BEGIN PRIVATE KEY-----",
            PrivateKeyBody,
            "-----END PRIVATE KEY-----",
            $"[INF] Account {AccountEmail} loaded");

        var health = new Mock<IHealthCheckService>(MockBehavior.Strict);
        health.Setup(value => value.RunAsync(It.IsAny<IProgress<SSLense.Core.ProgressEvent>?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([new HealthCheckResult("Expiry: SSLense Test", HealthStatus.Pass, "63 days left.")]);
        var configStore = new Mock<IConfigStore>(MockBehavior.Strict);
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(config);
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([certificate]);
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var heartbeat = new Mock<IServiceHeartbeatStore>(MockBehavior.Strict);
        heartbeat.Setup(value => value.GetAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ServiceHeartbeat("0.9.0", DateTimeOffset.UtcNow.AddHours(-2), LastCycleCompletedAt: DateTimeOffset.UtcNow));
        var serviceManager = new Mock<IWindowsServiceManager>(MockBehavior.Strict);
        serviceManager.Setup(value => value.GetStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(WindowsServiceStatus.Running);
        if (iis is null)
        {
            iis = new Mock<IIisService>(MockBehavior.Strict);
            iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync([new IisSite(1, "SSLense Test", "Started", @"C:\inetpub\sslense", [
                    new IisBinding("https", "*", 443, "acme-test.sslense.com", "6533D7B01A1F3C4BDF85551F375A3EFC4BD45F5F", "My", true)
                ])]);
        }

        return new DiagnosticBundleService(
            health.Object, configStore.Object, managed.Object, journal.Object,
            heartbeat.Object, serviceManager.Object, iis.Object, fileSystem);
    }

    private static Dictionary<string, string> ReadEntries(string path)
    {
        using var archive = ZipFile.OpenRead(path);
        return archive.Entries.ToDictionary(
            entry => entry.FullName,
            entry =>
            {
                using var reader = new StreamReader(entry.Open());
                return reader.ReadToEnd();
            });
    }
}
