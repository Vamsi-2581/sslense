using System.Net;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Renewal;
using SSLense.Core.Validation;
using SSLense.Core.WindowsServices;

namespace SSLense.Core.Diagnostics;

/// <summary>Resolves host names; behind an interface so tests never depend on real DNS.</summary>
public interface IHostResolver
{
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

internal sealed class DnsHostResolver : IHostResolver
{
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
        Dns.GetHostAddressesAsync(host, cancellationToken);
}

internal sealed class HealthCheckService(
    IConfigStore configStore,
    IManagedCertificateStore managedStore,
    ICertificateTransactionJournal journal,
    IWindowsServiceManager serviceManager,
    IServiceHeartbeatStore heartbeatStore,
    IIisService iisService,
    ICertificateStore certificateStore,
    IPreflightService preflightService,
    IHostResolver hostResolver,
    HttpClient httpClient) : IHealthCheckService
{
    // The service checks hourly; three missed cycles means it is stuck or not running its loop.
    private static readonly TimeSpan HeartbeatStaleAfter = TimeSpan.FromHours(3);
    private static readonly TimeSpan NetworkTimeout = TimeSpan.FromSeconds(15);

    public async Task<IReadOnlyList<HealthCheckResult>> RunAsync(
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<HealthCheckResult>();

        async Task Check(string name, Func<Task<HealthCheckResult>> check)
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new ProgressEvent("health", $"Checking {name}."));
            try
            {
                results.Add(await check().ConfigureAwait(false));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                results.Add(new HealthCheckResult(name, HealthStatus.Fail, exception.Message));
            }
        }

        await Check("Administrator", () => Task.FromResult(CheckElevation())).ConfigureAwait(false);
        await Check("Data folder permissions", () => Task.FromResult(CheckPermissions())).ConfigureAwait(false);

        AppConfig? config = null;
        await Check("Configuration", async () =>
        {
            config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            return Pass("Configuration", "config.json is readable.");
        }).ConfigureAwait(false);

        IReadOnlyList<ManagedCertificate> certificates = [];
        await Check("Managed certificates", async () =>
        {
            certificates = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
            return Pass("Managed certificates", $"{certificates.Count} managed certificate(s).");
        }).ConfigureAwait(false);

        await Check("Interrupted operations", () => CheckJournalAsync(cancellationToken)).ConfigureAwait(false);
        await Check("Renewal service", () => CheckServiceAsync(certificates.Count, cancellationToken)).ConfigureAwait(false);
        await Check("Service heartbeat", () => CheckHeartbeatAsync(cancellationToken)).ConfigureAwait(false);

        IReadOnlyList<IisSite> sites = [];
        await Check("IIS", async () =>
        {
            sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
            return Pass("IIS", $"IIS configuration is readable ({sites.Count} site(s)).");
        }).ConfigureAwait(false);

        foreach (var certificate in certificates)
        {
            var site = certificate.SiteName;
            await Check($"Certificate installed: {site}", () => CheckInstalledAsync(certificate, cancellationToken))
                .ConfigureAwait(false);
            await Check($"HTTPS bindings: {site}", () => Task.FromResult(CheckBindings(certificate, sites)))
                .ConfigureAwait(false);
            await Check($"Expiry: {site}", () => Task.FromResult(CheckExpiry(certificate))).ConfigureAwait(false);
            await Check($"Renewal history: {site}", () => Task.FromResult(CheckRenewalHistory(certificate)))
                .ConfigureAwait(false);
            foreach (var host in certificate.Hosts)
            {
                await Check($"DNS: {host}", () => CheckDnsAsync(host, cancellationToken)).ConfigureAwait(false);
            }

            // Port 80 reachability and challenge-folder access, exactly as checked before issuance.
            progress?.Report(new ProgressEvent("health", $"Running pre-flight checks for {site}."));
            try
            {
                var checks = await preflightService.CheckAsync(site, certificate.Hosts, cancellationToken)
                    .ConfigureAwait(false);
                results.AddRange(checks
                    .Where(check => check.Name != "Administrator")
                    .Select(check => new HealthCheckResult(
                        $"{check.Name} ({site})",
                        check.Succeeded ? HealthStatus.Pass : HealthStatus.Fail,
                        check.Message)));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                results.Add(new HealthCheckResult($"Pre-flight ({site})", HealthStatus.Fail, exception.Message));
            }
        }

        var environments = certificates.Select(value => value.Environment).Distinct().ToList();
        if (environments.Count == 0)
        {
            environments.Add(AcmeEnvironment.Staging);
        }

        foreach (var environment in environments)
        {
            await Check(
                    $"Let's Encrypt {environment.DisplayName()}",
                    () => CheckAcmeAsync(environment, cancellationToken))
                .ConfigureAwait(false);
        }

        await Check("Notifications", () => Task.FromResult(CheckNotifications(config))).ConfigureAwait(false);
        return results;
    }

    private static HealthCheckResult CheckElevation() =>
        WindowsElevation.IsAdministrator()
            ? Pass("Administrator", "Running elevated.")
            : new HealthCheckResult(
                "Administrator",
                HealthStatus.Fail,
                "Not running as Administrator; several checks cannot read IIS or SSLense state.",
                "Run SSLense from an elevated terminal.");

    private static HealthCheckResult CheckPermissions()
    {
        var problems = DataDirectorySecurity.Verify();
        return problems.Count == 0
            ? Pass("Data folder permissions", $"'{AppPaths.DataDirectory}' is restricted to Administrators and SYSTEM.")
            : new HealthCheckResult(
                "Data folder permissions",
                HealthStatus.Fail,
                string.Join(" ", problems.Take(3)) + (problems.Count > 3 ? $" (+{problems.Count - 3} more)" : string.Empty),
                "Run 'SSLense.Cli secure-data' from an elevated terminal.");
    }

    private async Task<HealthCheckResult> CheckJournalAsync(CancellationToken cancellationToken)
    {
        var pending = await journal.GetPendingAsync(cancellationToken).ConfigureAwait(false);
        return pending.Count == 0
            ? Pass("Interrupted operations", "No interrupted certificate operations.")
            : new HealthCheckResult(
                "Interrupted operations",
                HealthStatus.Warning,
                $"{pending.Count} interrupted operation(s) for: " +
                string.Join(", ", pending.Select(value => value.Certificate.SiteName).Distinct()) + ".",
                "They are completed or rolled back automatically the next time the service, GUI, or CLI starts.");
    }

    private async Task<HealthCheckResult> CheckServiceAsync(int certificateCount, CancellationToken cancellationToken)
    {
        const string name = "Renewal service";
        return await serviceManager.GetStatusAsync(cancellationToken).ConfigureAwait(false) switch
        {
            WindowsServiceStatus.Running => Pass(name, "The SSLense service is running."),
            WindowsServiceStatus.NotInstalled => new HealthCheckResult(
                name,
                certificateCount > 0 ? HealthStatus.Fail : HealthStatus.Warning,
                "The SSLense service is not installed, so certificates are not renewed automatically.",
                "Install SSLense with the MSI, or run 'SSLense.Cli install-service'."),
            WindowsServiceStatus.Stopped => new HealthCheckResult(
                name,
                certificateCount > 0 ? HealthStatus.Fail : HealthStatus.Warning,
                "The SSLense service is stopped, so certificates are not renewed automatically.",
                "Run 'SSLense.Cli start-service' or start it in services.msc."),
            var status => new HealthCheckResult(
                name,
                HealthStatus.Warning,
                $"The SSLense service state is {status}.",
                "Check it again in a minute, or look in services.msc.")
        };
    }

    private async Task<HealthCheckResult> CheckHeartbeatAsync(CancellationToken cancellationToken)
    {
        const string name = "Service heartbeat";
        var heartbeat = await heartbeatStore.GetAsync(cancellationToken).ConfigureAwait(false);
        if (heartbeat?.LastCycleCompletedAt is not { } completed)
        {
            return new HealthCheckResult(
                name,
                HealthStatus.Warning,
                "The service has not recorded a completed renewal check yet.",
                "If the service has been running for more than an hour, check the log in C:\\ProgramData\\SSLense\\logs.");
        }

        var age = DateTimeOffset.UtcNow - completed;
        var when = $"{completed:yyyy-MM-dd HH:mm} UTC ({FormatAge(age)} ago, version {heartbeat.Version})";
        if (age > HeartbeatStaleAfter)
        {
            return new HealthCheckResult(
                name,
                HealthStatus.Warning,
                $"The last completed renewal check was {when}.",
                "The service checks hourly. Restart it, then check the log in C:\\ProgramData\\SSLense\\logs.");
        }

        return heartbeat.LastCycleSucceeded == false
            ? new HealthCheckResult(
                name,
                HealthStatus.Warning,
                $"The last renewal check ran {when} but reported a problem: {heartbeat.LastCycleMessage}",
                "See the per-certificate results below and the service log.")
            : Pass(name, $"The last renewal check completed {when}.");
    }

    private async Task<HealthCheckResult> CheckInstalledAsync(ManagedCertificate certificate, CancellationToken cancellationToken)
    {
        var name = $"Certificate installed: {certificate.SiteName}";
        var installed = await certificateStore.FindByThumbprintAsync(certificate.Thumbprint, cancellationToken)
            .ConfigureAwait(false);
        if (installed is null)
        {
            return new HealthCheckResult(
                name,
                HealthStatus.Fail,
                $"Certificate {certificate.Thumbprint} is not in LocalMachine\\My.",
                $"Run 'SSLense.Cli renew --site \"{certificate.SiteName}\" --force' to issue and bind a new one.");
        }

        return installed.HasPrivateKey
            ? Pass(name, $"Certificate {certificate.Thumbprint} is installed with its private key.")
            : new HealthCheckResult(
                name,
                HealthStatus.Fail,
                $"Certificate {certificate.Thumbprint} is installed without its private key.",
                $"Run 'SSLense.Cli renew --site \"{certificate.SiteName}\" --force'.");
    }

    private static HealthCheckResult CheckBindings(ManagedCertificate certificate, IReadOnlyList<IisSite> sites)
    {
        var name = $"HTTPS bindings: {certificate.SiteName}";
        var site = sites.FirstOrDefault(value =>
            string.Equals(value.Name, certificate.SiteName, StringComparison.OrdinalIgnoreCase));
        if (site is null)
        {
            return new HealthCheckResult(
                name,
                HealthStatus.Fail,
                $"IIS site '{certificate.SiteName}' no longer exists.",
                $"Remove the managed certificate with 'SSLense.Cli remove --site \"{certificate.SiteName}\" --yes', or recreate the site.");
        }

        var missing = certificate.Hosts
            .Where(host => !site.Bindings.Any(binding =>
                string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 443 &&
                string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(binding.CertificateThumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        return missing.Length == 0
            ? Pass(name, $"Every host is bound on port 443 to certificate {certificate.Thumbprint}.")
            : new HealthCheckResult(
                name,
                HealthStatus.Fail,
                $"No HTTPS binding with the managed certificate for: {string.Join(", ", missing)}.",
                $"Run 'SSLense.Cli renew --site \"{certificate.SiteName}\" --force' to rebind.");
    }

    private static HealthCheckResult CheckExpiry(ManagedCertificate certificate)
    {
        var name = $"Expiry: {certificate.SiteName}";
        var days = (int)Math.Floor((certificate.NotAfter - DateTimeOffset.UtcNow).TotalDays);
        var environment = certificate.Environment.DisplayName();
        var expires = $"{environment} certificate expires {certificate.NotAfter:yyyy-MM-dd HH:mm} UTC";
        return ExpiryMonitor.GetLevel(certificate, DateTimeOffset.UtcNow) switch
        {
            ExpiryWarningLevel.None => Pass(name, $"{expires} ({days} days left)."),
            ExpiryWarningLevel.Warning => new HealthCheckResult(
                name, HealthStatus.Warning, $"{expires} ({days} days left) and has not been renewed yet.",
                "Check the renewal history below; renew manually if it keeps failing."),
            ExpiryWarningLevel.Critical => new HealthCheckResult(
                name, HealthStatus.Fail, $"{expires} ({Math.Max(days, 0)} days left).",
                $"Renew now: 'SSLense.Cli renew --site \"{certificate.SiteName}\" --force'."),
            _ => new HealthCheckResult(
                name, HealthStatus.Fail, $"{environment} certificate expired {certificate.NotAfter:yyyy-MM-dd HH:mm} UTC.",
                $"Renew now: 'SSLense.Cli renew --site \"{certificate.SiteName}\" --force'.")
        };
    }

    private static HealthCheckResult CheckRenewalHistory(ManagedCertificate certificate)
    {
        var name = $"Renewal history: {certificate.SiteName}";
        if (certificate.ConsecutiveFailures == 0)
        {
            return Pass(name, certificate.LastRenewalSucceeded == true
                ? "The last renewal succeeded."
                : "No failed renewal attempts.");
        }

        var next = certificate.NextRetryAt is { } retryAt ? $" Next automatic attempt: {retryAt:yyyy-MM-dd HH:mm} UTC." : string.Empty;
        return new HealthCheckResult(
            name,
            certificate.ConsecutiveFailures >= 3 ? HealthStatus.Fail : HealthStatus.Warning,
            $"{certificate.ConsecutiveFailures} consecutive failed renewal(s). Last error: {certificate.LastRenewalMessage}{next}",
            "Fix the cause shown in the error, then run 'SSLense.Cli renew --site \"" + certificate.SiteName + "\"'.");
    }

    private async Task<HealthCheckResult> CheckDnsAsync(string host, CancellationToken cancellationToken)
    {
        var name = $"DNS: {host}";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(NetworkTimeout);
        try
        {
            var addresses = await hostResolver.ResolveAsync(host, timeout.Token).ConfigureAwait(false);
            return addresses.Length == 0
                ? new HealthCheckResult(name, HealthStatus.Fail, $"'{host}' has no DNS addresses.", "Add an A or AAAA record for the host.")
                : Pass(name, $"Resolves to {string.Join(", ", addresses.Take(4).Select(value => value.ToString()))}.");
        }
        catch (Exception exception) when (exception is System.Net.Sockets.SocketException ||
                                          exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new HealthCheckResult(
                name,
                HealthStatus.Fail,
                $"'{host}' does not resolve: {exception.Message}",
                "Check the DNS record for the host, or the tunnel route that publishes it.");
        }
    }

    private async Task<HealthCheckResult> CheckAcmeAsync(AcmeEnvironment environment, CancellationToken cancellationToken)
    {
        // A directory GET creates nothing and needs no account; it only proves outbound HTTPS works.
        var name = $"Let's Encrypt {environment.DisplayName()}";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(NetworkTimeout);
        try
        {
            using var response = await httpClient.GetAsync(environment.DirectoryUri(), timeout.Token).ConfigureAwait(false);
            return response.IsSuccessStatusCode
                ? Pass(name, $"The ACME directory responded with HTTP {(int)response.StatusCode}.")
                : new HealthCheckResult(
                    name,
                    HealthStatus.Fail,
                    $"The ACME directory responded with HTTP {(int)response.StatusCode}.",
                    "Check https://letsencrypt.status.io for outages, and any outbound proxy.");
        }
        catch (Exception exception) when (exception is HttpRequestException ||
                                          exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new HealthCheckResult(
                name,
                HealthStatus.Fail,
                $"Could not reach {environment.DirectoryUri()}: {exception.Message}",
                "Allow outbound HTTPS (port 443) to Let's Encrypt, and check DNS, proxy, and TLS-inspection settings.");
        }
    }

    private static HealthCheckResult CheckNotifications(AppConfig? config)
    {
        const string name = "Notifications";
        if (config is null)
        {
            return new HealthCheckResult(name, HealthStatus.Warning, "Configuration could not be read.");
        }

        var channels = new List<string>();
        if (config.Notifications.Smtp is not null)
        {
            channels.Add("SMTP email");
        }

        if (config.Notifications.Webhook is not null)
        {
            channels.Add("webhook");
        }

        return channels.Count > 0
            ? Pass(name, $"Configured: {string.Join(" and ", channels)}. Use 'SSLense.Cli notifications test' to send a test.")
            : new HealthCheckResult(
                name,
                HealthStatus.Warning,
                "No notification channel is configured, so renewal failures and expiry warnings reach nobody.",
                "Configure SMTP or a webhook with 'SSLense.Cli notifications configure' or in Settings.");
    }

    private static HealthCheckResult Pass(string name, string message) => new(name, HealthStatus.Pass, message);

    private static string FormatAge(TimeSpan age) =>
        age.TotalMinutes < 90 ? $"{Math.Max(0, (int)age.TotalMinutes)} min" :
        age.TotalHours < 48 ? $"{(int)age.TotalHours} h" :
        $"{(int)age.TotalDays} days";
}
