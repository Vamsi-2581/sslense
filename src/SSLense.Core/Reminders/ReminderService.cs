using SSLense.Core.Config;
using SSLense.Core.Diagnostics;
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

    /// <summary>
    /// An estimate of what happens next, for display. The daily checks are not run for it, so a problem they would find is
    /// not counted. Nothing is sent or recorded.
    /// </summary>
    Task<ReminderOutlook> GetOutlookAsync(CancellationToken cancellationToken = default);

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

/// <param name="NextCheck">The service's next hourly check, or null when it has not checked recently and may not be running.</param>
/// <param name="NextDigest">When the digest is next looked at; it is only sent if something is due.</param>
/// <param name="NextEmail">When the next digest is expected to be sent, or null when nothing is expected.</param>
/// <param name="Certificates">One for each managed certificate, with its next reminder moved to a day a digest can run.</param>
public sealed record ReminderOutlook(
    DateTimeOffset? NextCheck,
    DateTimeOffset NextDigest,
    DateTimeOffset? NextEmail,
    IReadOnlyList<ReminderDecision> Certificates)
{
    public IReadOnlyList<string> Lines =>
    [
        NextCheck is { } check
            ? $"Next service check: {Text(check)}"
            : "Next service check: unknown. The service has not checked in the last two hours; check that it is running.",
        $"Next digest check: {Text(NextDigest)}, sent only if something is due",
        NextEmail is { } email ? $"Next email expected: {Text(email)}" : "Next email expected: none",
        .. Certificates.OrderBy(decision => decision.NextReminder ?? DateOnly.MaxValue).Select(decision => decision.OutlookLine)
    ];

    private static string Text(DateTimeOffset time) => time.ToString("ddd dd MMM yyyy HH:mm");
}

internal sealed class ReminderService(
    IManagedCertificateStore managedStore,
    IConfigStore configStore,
    IRenewalService renewalService,
    IReminderStateStore stateStore,
    INotifier notifier,
    IOutsideRenewalDetector outsideRenewals,
    IRenewalReadinessCheck readinessCheck,
    IServedCertificateCheck servedCheck,
    IServiceHeartbeatStore heartbeatStore,
    TimeProvider? timeProvider = null) : IReminderService
{
    public const int MaximumSnoozeDays = 90;

    /// <summary>A brief outage or a site restart should not cause an email.</summary>
    private const int FailuresBeforeReporting = 2;
    private const string ReadinessPrefix = "readiness:";
    private const string ServedPrefix = "served:";

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
        if (state.LastDigestDate == today)
        {
            return [new ReminderCheckResult($"Reminder check: today is already handled. The next digest is from {settings.SendAtHour:00}:00 tomorrow.")];
        }

        if (now.Hour < settings.SendAtHour)
        {
            return [new ReminderCheckResult($"Reminder check: not sending yet. The send time is {settings.SendAtHour:00}:00.")];
        }

        var weekly = settings.WeeklySummaryDay == now.DayOfWeek && state.LastWeeklySummaryDate != today;
        var build = await BuildAsync(config, now, weekly, state, cancellationToken).ConfigureAwait(false);
        var digest = build.Digest;
        var results = build.Errors.Select(error => new ReminderCheckResult(error, Failed: true)).ToList();
        results.AddRange(digest.Decisions.Select(decision => new ReminderCheckResult($"Reminder check: {decision.LogLine}")));
        if (!digest.HasContent)
        {
            await MarkHandledAsync(settings, today, weekly, build.CheckFailures).ConfigureAwait(false);
            results.Add(new ReminderCheckResult("No certificate needs a reminder today."));
            return results;
        }

        // Recorded only after delivery, so a failed send is retried at the next hourly check.
        try
        {
            await notifier.NotifyAsync(digest.ToMessage(Environment.MachineName), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            await stateStore.UpdateAsync(
                    current => Task.FromResult(current with { CheckFailures = build.CheckFailures, LastChecksDate = today }),
                    CancellationToken.None)
                .ConfigureAwait(false);
            results.Add(new ReminderCheckResult($"Could not send the reminder digest: {exception.Message} It will be retried at the next check.", Failed: true));
            return results;
        }

        await managedStore.RecordRemindersAsync(digest.ToRecords(), now, CancellationToken.None).ConfigureAwait(false);
        await MarkHandledAsync(settings, today, weekly, build.CheckFailures).ConfigureAwait(false);
        results.Add(new ReminderCheckResult(
            $"Sent the reminder digest: {digest.NeedsAttention.Count} need attention, {digest.Upcoming.Count} upcoming automatic renewal(s)" +
            $"{(weekly ? ", weekly summary" : string.Empty)}."));
        return results;
    }

    /// <param name="handledWith">The settings today's digest was built from.</param>
    private Task MarkHandledAsync(ReminderConfig handledWith, DateOnly today, bool weekly, IReadOnlyDictionary<string, int> checkFailures) =>
        stateStore.UpdateAsync(
            async state =>
            {
                // Read inside the lock: settings saved while the digest was being built or sent must not be marked as
                // handled, or they would wait until tomorrow. SaveSettingsAsync saves them before it takes this lock.
                var current = await configStore.LoadAsync(CancellationToken.None).ConfigureAwait(false);
                return state with
                {
                    LastDigestDate = current.Reminders == handledWith ? today : state.LastDigestDate,
                    LastWeeklySummaryDate = weekly ? today : state.LastWeeklySummaryDate,
                    CheckFailures = checkFailures,
                    LastChecksDate = today
                };
            },
            CancellationToken.None);

    public async Task<ReminderDigest> PreviewAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var now = _time.GetLocalNow();
        var build = await BuildAsync(config, now, weeklySummary: config.Reminders.WeeklySummaryDay == now.DayOfWeek, countFrom: null, cancellationToken)
            .ConfigureAwait(false);
        return build.Digest;
    }

    public async Task<ReminderDigest> SendSampleAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var digest = (await BuildAsync(config, _time.GetLocalNow(), weeklySummary: false, countFrom: null, cancellationToken).ConfigureAwait(false)).Digest;
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

    public async Task<ReminderOutlook> GetOutlookAsync(CancellationToken cancellationToken = default)
    {
        var now = _time.GetLocalNow();
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var settings = config.Reminders;
        var state = await stateStore.GetAsync(cancellationToken).ConfigureAwait(false);
        var certificates = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var scheduled = await GetScheduledRenewalsAsync(certificates, config, now, cancellationToken).ConfigureAwait(false);
        var digest = ReminderDigestBuilder.Build(certificates, settings, now, scheduled, weeklySummary: false);
        var nextCheck = await GetNextCheckAsync(now, cancellationToken).ConfigureAwait(false);

        var today = DateOnly.FromDateTime(now.DateTime);
        var firstDay = state.LastDigestDate == today ? today.AddDays(1) : today;
        var decisions = digest.Decisions
            .Select(decision => decision.NextReminder is { } day && day < firstDay ? decision with { NextReminder = firstDay } : decision)
            .ToArray();
        var emailDays = decisions
            .Where(decision => decision.NextReminder is not null)
            .Select(decision => decision.NextReminder!.Value)
            .ToList();
        if (NextWeeklySummary(settings, state, firstDay) is { } weekly)
        {
            emailDays.Add(weekly);
        }

        return new ReminderOutlook(
            nextCheck,
            FirstCheckFrom(firstDay, settings, nextCheck, now),
            emailDays.Count > 0 ? FirstCheckFrom(emailDays.Min(), settings, nextCheck, now) : null,
            decisions);
    }

    /// <summary>The next check, counted from the last one the service recorded; null when that was too long ago.</summary>
    private async Task<DateTimeOffset?> GetNextCheckAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        ServiceHeartbeat? heartbeat;
        try
        {
            heartbeat = await heartbeatStore.GetAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }

        if (heartbeat?.LastCycleStartedAt is not { } last || now - last > 2 * ServiceHeartbeat.CheckInterval)
        {
            return null;
        }

        var next = last.ToOffset(now.Offset) + ServiceHeartbeat.CheckInterval;
        return next > now ? next : next + ServiceHeartbeat.CheckInterval;
    }

    private DateTimeOffset FirstCheckFrom(DateOnly day, ReminderConfig settings, DateTimeOffset? nextCheck, DateTimeOffset now)
    {
        var local = day.ToDateTime(new TimeOnly(settings.SendAtHour, 0));
        var sendAt = new DateTimeOffset(local, _time.LocalTimeZone.GetUtcOffset(local));
        if (nextCheck is not { } check)
        {
            return sendAt > now ? sendAt : now;
        }

        if (sendAt <= check)
        {
            return check;
        }

        var checks = Math.Ceiling((sendAt - check) / ServiceHeartbeat.CheckInterval);
        return check + (checks * ServiceHeartbeat.CheckInterval);
    }

    private static DateOnly? NextWeeklySummary(ReminderConfig settings, ReminderState state, DateOnly from)
    {
        if (settings.WeeklySummaryDay is not { } weeklyDay)
        {
            return null;
        }

        var day = Enumerable.Range(0, 8)
            .Select(from.AddDays)
            .First(candidate => candidate.DayOfWeek == weeklyDay && candidate != state.LastWeeklySummaryDate);
        return day;
    }

    public async Task SaveSettingsAsync(ReminderConfig settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.Validate();
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        await configStore.SaveAsync(config with { Reminders = settings }, cancellationToken).ConfigureAwait(false);

        // Today's digest may already have been handled under the old settings, for example with nothing due. The next
        // hourly check looks again. Nothing is sent twice: certificates reminded today wait for their repeat interval,
        // notices are sent once, and the weekly summary keeps its own date.
        await stateStore.UpdateAsync(state => Task.FromResult(state with { LastDigestDate = null }), CancellationToken.None)
            .ConfigureAwait(false);
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

    /// <param name="countFrom">
    /// The state to count check failures from, for the real digest, which reports a problem only after two daily failures
    /// in a row. Null for a preview or sample, which shows every current problem and counts nothing.
    /// </param>
    private async Task<(ReminderDigest Digest, IReadOnlyList<string> Errors, IReadOnlyDictionary<string, int> CheckFailures)> BuildAsync(
        AppConfig config,
        DateTimeOffset now,
        bool weeklySummary,
        ReminderState? countFrom,
        CancellationToken cancellationToken)
    {
        var certificates = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var scheduled = await GetScheduledRenewalsAsync(certificates, config, now, cancellationToken).ConfigureAwait(false);

        if (!config.Reminders.ProactiveChecks)
        {
            var plain = ReminderDigestBuilder.Build(certificates, config.Reminders, now, scheduled, weeklySummary);
            return (plain, [], new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase));
        }

        var readiness = await RunCheckAsync(
                "renewal readiness",
                () => readinessCheck.CheckAsync(certificates, scheduled, now, cancellationToken),
                cancellationToken)
            .ConfigureAwait(false);
        var served = await RunCheckAsync(
                "served certificate",
                () => servedCheck.CheckAllAsync(certificates, now, cancellationToken),
                cancellationToken)
            .ConfigureAwait(false);

        var failures = new Dictionary<string, int>(countFrom?.CheckFailures ?? new Dictionary<string, int>(), StringComparer.OrdinalIgnoreCase);
        var increment = countFrom?.LastChecksDate == DateOnly.FromDateTime(now.DateTime) ? 0 : 1;
        CountFailures(failures, ReadinessPrefix, readiness, increment);
        CountFailures(failures, ServedPrefix, served, increment);
        var digest = ReminderDigestBuilder.Build(
            certificates,
            config.Reminders,
            now,
            scheduled,
            weeklySummary,
            ProblemsToReport(readiness, ReadinessPrefix, failures, countFrom is null),
            ProblemsToReport(served, ServedPrefix, failures, countFrom is null));
        return (digest, [.. readiness.Errors, .. served.Errors], countFrom is null ? new Dictionary<string, int>() : failures);
    }

    private async Task<Dictionary<string, DateTimeOffset>> GetScheduledRenewalsAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        AppConfig config,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
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
                // The lifetime-relative fallback, as renewal itself would use: an overdue renewal is still reported
                // when the CA's renewal window cannot be fetched.
                scheduled[certificate.SiteName] = RenewalService.GetFallbackRenewalTime(certificate, config.RenewalThresholdDays);
            }
        }

        return scheduled;
    }

    /// <summary>Reminders matter more than the checks: when one cannot run, the digest still goes out without it.</summary>
    private static async Task<ProactiveCheckResult> RunCheckAsync(
        string name,
        Func<Task<ProactiveCheckResult>> check,
        CancellationToken cancellationToken)
    {
        try
        {
            return await check().ConfigureAwait(false);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            return new ProactiveCheckResult(new Dictionary<string, string>(), [], [$"Could not run the {name} checks: {exception.Message}"]);
        }
    }

    /// <summary>
    /// Updates the consecutive-failure counts. A day counts once even when a failed send makes the digest run again that
    /// day. A pass resets a site's count; a site that was not checked, for example because it was busy, keeps its count.
    /// </summary>
    private static void CountFailures(Dictionary<string, int> counts, string prefix, ProactiveCheckResult result, int increment)
    {
        foreach (var site in result.Passed)
        {
            counts.Remove($"{prefix}{site}");
        }

        foreach (var site in result.Problems.Keys)
        {
            var key = $"{prefix}{site}";
            counts[key] = Math.Max(counts.GetValueOrDefault(key) + increment, 1);
        }
    }

    private static Dictionary<string, string> ProblemsToReport(
        ProactiveCheckResult result,
        string prefix,
        Dictionary<string, int> failures,
        bool reportAll) =>
        result.Problems
            .Where(problem => reportAll || failures.GetValueOrDefault($"{prefix}{problem.Key}") >= FailuresBeforeReporting)
            .ToDictionary(problem => problem.Key, problem => problem.Value, StringComparer.OrdinalIgnoreCase);
}
