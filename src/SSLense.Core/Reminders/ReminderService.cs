using SSLense.Core.Config;
using SSLense.Core.Notifications;
using SSLense.Core.Renewal;

namespace SSLense.Core.Reminders;

/// <param name="Failed">The digest could not be sent; it is retried at the next hourly check.</param>
public sealed record ReminderCheckResult(string Message, bool Failed = false);

/// <summary>
/// Sends the daily reminder digest (docs/design/expiry-reminders.md). It runs separately from renewal, so a broken
/// schedule, an ARI outage, or repeated renewal failures still produce reminders.
/// </summary>
public interface IReminderService
{
    /// <summary>
    /// Called on every hourly check: once a day, from the configured hour, sends the digest when something needs
    /// attention (or the weekly summary is due) and records it. Returns what happened, for the service log.
    /// </summary>
    Task<IReadOnlyList<ReminderCheckResult>> CheckAsync(CancellationToken cancellationToken = default);

    /// <summary>Today's digest as it would be sent now, regardless of the send time; nothing is sent or recorded.</summary>
    Task<ReminderDigest> PreviewAsync(CancellationToken cancellationToken = default);
}

internal sealed class ReminderService(
    IManagedCertificateStore managedStore,
    IConfigStore configStore,
    IRenewalService renewalService,
    IReminderStateStore stateStore,
    INotifier notifier,
    TimeProvider? timeProvider = null) : IReminderService
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public async Task<IReadOnlyList<ReminderCheckResult>> CheckAsync(CancellationToken cancellationToken = default)
    {
        var now = _time.GetLocalNow();
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var settings = config.Reminders;
        var today = DateOnly.FromDateTime(now.DateTime);
        var state = await stateStore.GetAsync(cancellationToken).ConfigureAwait(false);
        if (now.Hour < settings.SendAtHour || state.LastDigestDate == today)
        {
            return [];
        }

        var weekly = settings.WeeklySummaryDay == now.DayOfWeek && state.LastWeeklySummaryDate != today;
        var digest = await BuildAsync(settings, now, weekly, cancellationToken).ConfigureAwait(false);
        if (!digest.HasContent)
        {
            await stateStore.SaveAsync(state with { LastDigestDate = today }, CancellationToken.None).ConfigureAwait(false);
            return [new ReminderCheckResult("No certificate needs a reminder today.")];
        }

        // Recorded only after delivery, so a failed send is retried at the next hourly check.
        try
        {
            await notifier.NotifyAsync(digest.ToMessage(Environment.MachineName), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return [new ReminderCheckResult($"Could not send the reminder digest: {exception.Message} It will be retried at the next check.", Failed: true)];
        }

        await managedStore.RecordRemindersAsync(digest.ToRecords(), now, CancellationToken.None).ConfigureAwait(false);
        await stateStore.SaveAsync(
                state with { LastDigestDate = today, LastWeeklySummaryDate = weekly ? today : state.LastWeeklySummaryDate },
                CancellationToken.None)
            .ConfigureAwait(false);
        return [new ReminderCheckResult(
            $"Sent the reminder digest: {digest.NeedsAttention.Count} need attention, {digest.Upcoming.Count} upcoming automatic renewal(s)" +
            $"{(weekly ? ", weekly summary" : string.Empty)}.")];
    }

    public async Task<ReminderDigest> PreviewAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var now = _time.GetLocalNow();
        return await BuildAsync(config.Reminders, now, weeklySummary: config.Reminders.WeeklySummaryDay == now.DayOfWeek, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<ReminderDigest> BuildAsync(
        ReminderConfig settings,
        DateTimeOffset now,
        bool weeklySummary,
        CancellationToken cancellationToken)
    {
        var certificates = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var scheduled = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        foreach (var certificate in certificates.Where(value =>
                     value.Source == CertificateSource.Acme && !ReminderDigestBuilder.IsMuted(value, now)))
        {
            try
            {
                scheduled[certificate.SiteName] = await renewalService.GetScheduledRenewalAsync(certificate, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // Without a schedule the certificate can still be reminded about by expiry and failures.
            }
        }

        return ReminderDigestBuilder.Build(certificates, settings, now, scheduled, weeklySummary);
    }
}
