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
    HttpClient httpClient,
    ICertificateAuthorityRegistry authorities,
    IPendingRequestStore pendingRequests) : IHealthCheckService
{
    // The service checks hourly; three missed cycles means it is stuck or not running its loop.
    private static readonly TimeSpan HeartbeatStaleAfter = TimeSpan.FromHours(3);
    private static readonly TimeSpan NetworkTimeout = TimeSpan.FromSeconds(15);

    public Task<IReadOnlyList<HealthCheckResult>> RunAsync(
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default) =>
        RunCoreAsync(full: true, progress, cancellationToken);

    public Task<IReadOnlyList<HealthCheckResult>> RunQuickAsync(CancellationToken cancellationToken = default) =>
        RunCoreAsync(full: false, progress: null, cancellationToken);

    private async Task<IReadOnlyList<HealthCheckResult>> RunCoreAsync(
        bool full,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
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

        if (full)
        {
            await Check("Administrator", () => Task.FromResult(CheckElevation())).ConfigureAwait(false);
        }

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

        // IIS, per-certificate, DNS, port 80, and network checks are slower and run only in the full check.
        if (full)
        {
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
                if (certificate.Source == CertificateSource.Imported)
                {
                    await Check($"Certificate chain: {site}", () => CheckChainAsync(certificate, cancellationToken))
                        .ConfigureAwait(false);
                }
                else
                {
                    await Check($"Renewal history: {site}", () => Task.FromResult(CheckRenewalHistory(certificate)))
                        .ConfigureAwait(false);
                }

                foreach (var host in certificate.Hosts)
                {
                    await Check($"DNS: {host}", () => CheckDnsAsync(host, cancellationToken)).ConfigureAwait(false);
                }

                // Imported certificates are validated by their CA, not over HTTP on this server.
                if (certificate.Source == CertificateSource.Imported)
                {
                    continue;
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

            await Check("Pending certificate requests", () => CheckPendingRequestsAsync(cancellationToken)).ConfigureAwait(false);

            // Every CA that renews a managed certificate; Let's Encrypt staging when nothing is managed yet.
            var authorityIds = certificates
                .Where(value => value.Source == CertificateSource.Acme)
                .Select(value => value.AuthorityId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .DefaultIfEmpty(CertificateAuthorities.LetsEncryptStagingId);
            foreach (var authorityId in authorityIds)
            {
                await Check(
                        authorityId,
                        async () => await CheckAcmeAsync(
                                await authorities.GetAsync(authorityId, cancellationToken).ConfigureAwait(false),
                                cancellationToken)
                            .ConfigureAwait(false))
                    .ConfigureAwait(false);
            }
        }

        await Check("Notifications", () => Task.FromResult(CheckNotifications(config))).ConfigureAwait(false);
        await Check("Reminders", () => Task.FromResult(CheckReminders(config, certificates))).ConfigureAwait(false);
        return results;
    }

    /// <summary>
    /// Summarises the reminder settings, and warns about a certificate whose reminders are off or snoozed while it
    /// expires within a week: the one case a muted reminder would have mattered.
    /// </summary>
    private static HealthCheckResult CheckReminders(AppConfig? config, IReadOnlyList<ManagedCertificate> certificates)
    {
        const string name = "Reminders";
        if (config is null)
        {
            return new HealthCheckResult(name, HealthStatus.Warning, "Configuration could not be read.");
        }

        var settings = config.Reminders;
        var now = DateTimeOffset.UtcNow;
        var summary = $"Daily digest from {settings.SendAtHour:00}:00, starting {settings.StartDays} days before expiry, " +
                      $"repeating every {settings.RepeatDays} day(s).";
        var mutedSoon = certificates
            .Where(certificate => Reminders.ReminderDigestBuilder.IsMuted(certificate, now) &&
                                  certificate.NotAfter - now <= TimeSpan.FromDays(Reminders.ReminderDigestBuilder.DailyFinalDays))
            .ToArray();
        return mutedSoon.Length == 0
            ? Pass(name, summary)
            : new HealthCheckResult(
                name,
                HealthStatus.Warning,
                $"{summary} Reminders are off or snoozed for {string.Join(", ", mutedSoon.Select(certificate => $"'{certificate.SiteName}' (expires {certificate.NotAfter:yyyy-MM-dd})"))}.",
                "Turn its reminders back on in Certificate Details, or with 'SSLense.Cli reminders site --site <site> --mode on'.");
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
                Reinstall(certificate, $"Run 'SSLense.Cli renew --site \"{certificate.SiteName}\" --force' to issue and bind a new one."));
        }

        return installed.HasPrivateKey
            ? Pass(name, $"Certificate {certificate.Thumbprint} is installed with its private key.")
            : new HealthCheckResult(
                name,
                HealthStatus.Fail,
                $"Certificate {certificate.Thumbprint} is installed without its private key.",
                Reinstall(certificate, $"Run 'SSLense.Cli renew --site \"{certificate.SiteName}\" --force'."));
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
                Reinstall(certificate, $"Run 'SSLense.Cli renew --site \"{certificate.SiteName}\" --force' to rebind."));
    }

    private static HealthCheckResult CheckExpiry(ManagedCertificate certificate)
    {
        var name = $"Expiry: {certificate.SiteName}";
        var days = (int)Math.Floor((certificate.NotAfter - DateTimeOffset.UtcNow).TotalDays);
        if (certificate.Source == CertificateSource.Imported)
        {
            var issued = $"Imported certificate from {certificate.Issuer ?? "an external CA"} expires {certificate.NotAfter:yyyy-MM-dd HH:mm} UTC";
            var replace = $"Order a replacement, then run 'SSLense.Cli csr --site \"{certificate.SiteName}\"' and 'complete', or 'import' a PFX.";
            return days < 0 ? new HealthCheckResult(name, HealthStatus.Fail, $"{issued} and has expired.", replace)
                : days <= 7 ? new HealthCheckResult(name, HealthStatus.Fail, $"{issued} ({days} days left).", replace)
                : days <= 30 ? new HealthCheckResult(name, HealthStatus.Warning, $"{issued} ({days} days left).", replace)
                : Pass(name, $"{issued} ({days} days left). It is renewed manually.");
        }

        var environment = CertificateAuthorities.Label(certificate.AuthorityId);
        var expires = $"{environment} certificate expires {certificate.NotAfter:yyyy-MM-dd HH:mm} UTC";
        return ExpiryLevels.GetLevel(certificate, DateTimeOffset.UtcNow) switch
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

    /// <summary>The fix for a missing or unbound certificate: renew for ACME certificates, reinstall for imported ones.</summary>
    private static string Reinstall(ManagedCertificate certificate, string acmeFix) =>
        certificate.Source == CertificateSource.Imported
            ? $"Reinstall it with 'SSLense.Cli import --site \"{certificate.SiteName}\" --pfx <file>', or create a request with " +
              "'csr' and install the issued certificate with 'complete'."
            : acmeFix;

    private async Task<HealthCheckResult> CheckChainAsync(ManagedCertificate certificate, CancellationToken cancellationToken)
    {
        var name = $"Certificate chain: {certificate.SiteName}";
        using var installed = await certificateStore.OpenAsync(certificate.Thumbprint, cancellationToken).ConfigureAwait(false);
        if (installed is null)
        {
            return new HealthCheckResult(name, HealthStatus.Fail, $"Certificate {certificate.Thumbprint} is not installed.", Reinstall(certificate, string.Empty));
        }

        // Intermediates are looked up in the machine stores, as HTTP.sys does when it sends the chain.
        return CertificateInspector.GetChainProblem(installed, []) is { } problem
            ? new HealthCheckResult(
                name,
                HealthStatus.Fail,
                problem,
                "Without the intermediate certificate, some browsers and most API clients reject the site. Reinstall with the " +
                "bundle: 'SSLense.Cli complete ... --chain <bundle>', or 'import' a PFX that includes the chain.")
            : Pass(name, "The certificate chains to a trusted root.");
    }

    private async Task<HealthCheckResult> CheckPendingRequestsAsync(CancellationToken cancellationToken)
    {
        const string name = "Pending certificate requests";
        var requests = await pendingRequests.GetAllAsync(cancellationToken).ConfigureAwait(false);
        if (requests.Count == 0)
        {
            return Pass(name, "No certificate requests are waiting for a certificate.");
        }

        var stale = requests.Where(request => DateTimeOffset.UtcNow - request.CreatedAt > TimeSpan.FromDays(30)).ToArray();
        var list = string.Join(", ", requests.Select(request => $"{request.SiteName} ({request.CreatedAt:yyyy-MM-dd})"));
        return stale.Length == 0
            ? Pass(name, $"Waiting for the certificate authority: {list}.")
            : new HealthCheckResult(
                name,
                HealthStatus.Warning,
                $"Requests older than 30 days: {string.Join(", ", stale.Select(request => request.SiteName))}.",
                "Install the issued certificate with 'SSLense.Cli complete', or remove the request with 'SSLense.Cli cancel-request'.");
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

    private async Task<HealthCheckResult> CheckAcmeAsync(CertificateAuthority authority, CancellationToken cancellationToken)
    {
        // A directory GET creates nothing and needs no account; it only proves outbound HTTPS works.
        var name = authority.Name;
        var isLetsEncrypt = authority.Id is CertificateAuthorities.LetsEncryptId or CertificateAuthorities.LetsEncryptStagingId;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(NetworkTimeout);
        try
        {
            using var response = await httpClient.GetAsync(authority.DirectoryUri, timeout.Token).ConfigureAwait(false);
            return response.IsSuccessStatusCode
                ? Pass(name, $"The ACME directory responded with HTTP {(int)response.StatusCode}.")
                : new HealthCheckResult(
                    name,
                    HealthStatus.Fail,
                    $"The ACME directory responded with HTTP {(int)response.StatusCode}.",
                    isLetsEncrypt
                        ? "Check https://letsencrypt.status.io for outages, and any outbound proxy."
                        : "Check the certificate authority's status page for outages, and any outbound proxy.");
        }
        catch (Exception exception) when (exception is HttpRequestException ||
                                          exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new HealthCheckResult(
                name,
                HealthStatus.Fail,
                $"Could not reach {authority.DirectoryUri}: {exception.Message}",
                $"Allow outbound HTTPS (port 443) to {authority.DirectoryUri.Host}, and check DNS, proxy, and TLS-inspection settings.");
        }
    }

    private static HealthCheckResult CheckNotifications(AppConfig? config)
    {
        const string name = "Notifications";
        if (config is null)
        {
            return new HealthCheckResult(name, HealthStatus.Warning, "Configuration could not be read.");
        }

        var notifications = config.Notifications;
        var channels = new List<string>();
        if (notifications.Email is { } email)
        {
            channels.Add($"email via {email.Host}");
        }

        channels.AddRange(notifications.Chat.Select(Notifications.Notifier.DescribeChat));
        if (notifications.Heartbeat is not null)
        {
            channels.Add("heartbeat");
        }

        var eventLog = notifications.EventLogEnabled ? "The Windows Event Log also records every notification." : "The Windows Event Log is turned off.";
        if (channels.Count > 0)
        {
            return Pass(name, $"Configured: {string.Join(", ", channels)}. {eventLog} Use 'SSLense.Cli notifications test' to check delivery.");
        }

        const string fix = "Add email, Teams, Slack, ntfy, or a heartbeat with 'SSLense.Cli notifications' or in Settings.";
        return notifications.EventLogEnabled
            ? new HealthCheckResult(
                name,
                HealthStatus.Warning,
                "Problems are only written to the Windows Event Log, so nobody is alerted unless that log is monitored.",
                fix)
            : new HealthCheckResult(
                name,
                HealthStatus.Warning,
                "No notification channel is configured and the Event Log is off, so renewal failures and expiry warnings are recorded only in SSLense's own log.",
                fix);
    }

    private static HealthCheckResult Pass(string name, string message) => new(name, HealthStatus.Pass, message);

    private static string FormatAge(TimeSpan age) =>
        age.TotalMinutes < 90 ? $"{Math.Max(0, (int)age.TotalMinutes)} min" :
        age.TotalHours < 48 ? $"{(int)age.TotalHours} h" :
        $"{(int)age.TotalDays} days";
}
