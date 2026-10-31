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

    /// <summary>
    /// Sends today's digest marked as a sample, so the administrator can see it and check delivery. When nothing needs
    /// attention it is sent as a summary. Nothing is recorded, so the real reminders are unchanged.
    /// </summary>
    Task<ReminderDigest> SendSampleAsync(CancellationToken cancellationToken = default);

    Task<ReminderOverview> GetOverviewAsync(CancellationToken cancellationToken = default);

    Task SaveSettingsAsync(ReminderConfig settings, CancellationToken cancellationToken = default);

    /// <param name="snoozeDays">With <see cref="ReminderMode.Snoozed"/>: days until reminders resume.</param>
    Task SetCertificateRemindersAsync(
        string siteName,
        ReminderMode mode,
        int? snoozeDays = null,
        CancellationToken cancellationToken = default);
}

/// <param name="LastDigestDate">The last day the digest was handled by the service, or null if it never ran.</param>
public sealed record ReminderOverview(
    ReminderConfig Settings,
    IReadOnlyList<ManagedCertificate> Certificates,
    DateOnly? LastDigestDate);

internal sealed class ReminderService(
    IManagedCertificateStore managedStore,
    IConfigStore configStore,
    IRenewalService renewalService,
    IReminderStateStore stateStore,
    INotifier notifier,
    IOutsideRenewalDetector outsideRenewals,
    TimeProvider? timeProvider = null) : IReminderService
{
    public const int MaximumSnoozeDays = 90;

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public async Task<IReadOnlyList<ReminderCheckResult>> CheckAsync(CancellationToken cancellationToken = default)
    {
        // Every hour, so a certificate replaced by hand stops being reminded about before the next digest.
        var results = new List<ReminderCheckResult>();
        try
        {
            results.AddRange((await outsideRenewals.DetectAsync(cancellationToken).ConfigureAwait(false))
                .Select(change => new ReminderCheckResult(change)));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            results.Add(new ReminderCheckResult($"Could not check for certificates replaced outside SSLense: {exception.Message}", Failed: true));
        }

        results.AddRange(await SendDigestIfDueAsync(cancellationToken).ConfigureAwait(false));
        return results;
    }

    private async Task<IReadOnlyList<ReminderCheckResult>> SendDigestIfDueAsync(CancellationToken cancellationToken)
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
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
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

    public async Task<ReminderDigest> SendSampleAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var digest = await BuildAsync(config.Reminders, _time.GetLocalNow(), weeklySummary: false, cancellationToken).ConfigureAwait(false);
        if (!digest.HasContent)
        {
            digest = digest with { IsWeeklySummary = true };
        }

        await notifier.NotifyAsync(digest.ToMessage(Environment.MachineName, sample: true), cancellationToken).ConfigureAwait(false);
        return digest;
    }

    public async Task<ReminderOverview> GetOverviewAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var certificates = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var state = await stateStore.GetAsync(cancellationToken).ConfigureAwait(false);
        return new ReminderOverview(config.Reminders, certificates, state.LastDigestDate);
    }

    public async Task SaveSettingsAsync(ReminderConfig settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.Validate();
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        await configStore.SaveAsync(config with { Reminders = settings }, cancellationToken).ConfigureAwait(false);
    }

    public async Task SetCertificateRemindersAsync(
        string siteName,
        ReminderMode mode,
        int? snoozeDays = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        DateTimeOffset? until = null;
        if (mode == ReminderMode.Snoozed)
        {
            if (snoozeDays is not (>= 1 and <= MaximumSnoozeDays))
            {
                throw new ArgumentOutOfRangeException(nameof(snoozeDays), $"Snooze for 1 to {MaximumSnoozeDays} days.");
            }

            until = _time.GetUtcNow().AddDays(snoozeDays.Value);
        }

        if (!await managedStore.SetReminderModeAsync(siteName, mode, until, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"IIS site '{siteName}' is not managed by SSLense.");
        }
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
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // Without a schedule the certificate can still be reminded about by expiry and failures.
            }
        }

        return ReminderDigestBuilder.Build(certificates, settings, now, scheduled, weeklySummary);
    }
}
