using System.Reflection;
using SSLense.Core;
using SSLense.Core.Certificates;
using SSLense.Core.Diagnostics;
using SSLense.Core.Notifications;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;

namespace SSLense.Service;

internal sealed class RenewalWorker(
    IRenewalService renewalService,
    IReminderService reminderService,
    ICertificateRecoveryService recoveryService,
    IServiceHeartbeatStore heartbeatStore,
    INotifier notifier,
    ILogger<RenewalWorker> logger) : BackgroundService
{
    // Hourly checks are cheap: certificates that are not due and retries still backing off
    // are skipped from saved state, and ARI responses are cached by the provider.
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(1);

    private static readonly string Version =
        (typeof(RenewalWorker).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? "unknown").Split('+')[0];

    private ServiceHeartbeat _heartbeat = new(Version, DateTimeOffset.UtcNow);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await SaveHeartbeatAsync(_heartbeat, stoppingToken).ConfigureAwait(false);
        await RecoverAsync(stoppingToken).ConfigureAwait(false);
        await RunCycleAsync(stoppingToken).ConfigureAwait(false);

        using var timer = new PeriodicTimer(CheckInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await RunCycleAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task RunCycleAsync(CancellationToken cancellationToken)
    {
        await SaveHeartbeatAsync(_heartbeat with { LastCycleStartedAt = DateTimeOffset.UtcNow }, cancellationToken)
            .ConfigureAwait(false);

        // Reminders run first and separately so they still go out when renewal itself is broken.
        var reminderProblem = await CheckRemindersAsync(cancellationToken).ConfigureAwait(false);
        var renewalProblem = await RunRenewalAsync(cancellationToken).ConfigureAwait(false);
        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        var problem = renewalProblem ?? reminderProblem;
        await SaveHeartbeatAsync(
                _heartbeat with
                {
                    LastCycleCompletedAt = DateTimeOffset.UtcNow,
                    LastCycleSucceeded = problem is null,
                    LastCycleMessage = problem
                },
                cancellationToken)
            .ConfigureAwait(false);

        // Ping only when healthy: pings then stop both when the service dies and while renewals keep failing,
        // so an external monitor alerts in either case even with no other channel configured.
        if (problem is null)
        {
            await PingHeartbeatAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task PingHeartbeatAsync(CancellationToken cancellationToken)
    {
        try
        {
            await notifier.PingHeartbeatAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogWarning("Heartbeat ping failed: {Message}", exception is OperationCanceledException ? "timed out" : exception.Message);
        }
    }

    private async Task SaveHeartbeatAsync(ServiceHeartbeat heartbeat, CancellationToken cancellationToken)
    {
        _heartbeat = heartbeat;
        try
        {
            await heartbeatStore.SaveAsync(heartbeat, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            // The heartbeat only feeds the health check; failing to write it must not stop renewals.
            logger.LogWarning(exception, "Could not record the service heartbeat");
        }
    }

    private async Task RecoverAsync(CancellationToken cancellationToken)
    {
        try
        {
            foreach (var result in await recoveryService.RecoverAsync(cancellationToken).ConfigureAwait(false))
            {
                if (result.Succeeded)
                {
                    logger.LogInformation("{RecoveryMessage}", result.Message);
                }
                else
                {
                    logger.LogWarning("{RecoveryMessage}", result.Message);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Certificate operation recovery failed; continuing with renewal");
        }
    }

    /// <returns>A problem description, or null when the check ran.</returns>
    private async Task<string?> CheckRemindersAsync(CancellationToken cancellationToken)
    {
        try
        {
            foreach (var result in await reminderService.CheckAsync(cancellationToken).ConfigureAwait(false))
            {
                if (result.Failed)
                {
                    logger.LogWarning("{ReminderMessage}", result.Message);
                }
                else
                {
                    logger.LogInformation("{ReminderMessage}", result.Message);
                }
            }

            return null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Certificate reminder check failed");
            return $"Reminder check failed: {exception.Message}";
        }
    }

    /// <returns>A problem description, or null when every attempted renewal succeeded.</returns>
    private async Task<string?> RunRenewalAsync(CancellationToken cancellationToken)
    {
        try
        {
            logger.LogInformation("Starting scheduled certificate renewal check");
            var progress = new Progress<ProgressEvent>(value =>
                logger.LogInformation("[{Step}] {Message}", value.Step, value.Message));
            var results = await renewalService.RenewAsync(
                    new RenewalRequest(All: true, Scheduled: true),
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);

            foreach (var result in results)
            {
                if (result.Succeeded)
                {
                    logger.LogInformation(
                        "Scheduled renewal result for {SiteName}: {Message}",
                        result.SiteName,
                        result.Message);
                }
                else if (result.Attempted)
                {
                    logger.LogError(
                        "Scheduled renewal failed for {SiteName}: {Message}",
                        result.SiteName,
                        result.Message);
                }
                else
                {
                    logger.LogWarning(
                        "Scheduled renewal for {SiteName} is backing off: {Message}",
                        result.SiteName,
                        result.Message);
                }
            }

            var failed = results.Where(result => !result.Succeeded).Select(result => result.SiteName).ToArray();
            return failed.Length == 0 ? null : $"Renewal is failing for: {string.Join(", ", failed)}.";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Scheduled certificate renewal check failed");
            return $"Renewal check failed: {exception.Message}";
        }
    }
}
