using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Notifications;

namespace SSLense.Core.Renewal;

internal sealed class RenewalService : IRenewalService
{
    // Failure 1 and 2 retry quickly; later failures settle into a steady cadence that stays well
    // inside Let's Encrypt's failed-validation limits.
    private static readonly TimeSpan[] RetryDelays =
    [
        TimeSpan.FromHours(1),
        TimeSpan.FromHours(2),
        TimeSpan.FromHours(6)
    ];

    private static readonly TimeSpan RateLimitedRetryDelay = TimeSpan.FromHours(24);
    private static readonly TimeSpan UrgentWindow = TimeSpan.FromDays(2);
    private static readonly TimeSpan UrgentRetryDelay = TimeSpan.FromHours(1);

    /// <summary>Scheduled runs notify on this failure and then about once a day while failures continue.</summary>
    private const int NotifyAfterFailures = 3;

    private readonly IManagedCertificateStore _managedStore;
    private readonly IConfigStore _configStore;
    private readonly IAcmeService _acmeService;
    private readonly IIisService _iisService;
    private readonly ICertificateStore _certificateStore;
    private readonly INotifier _notifier;
    private readonly IRenewalInfoProvider _renewalInfoProvider;
    private readonly ICertificateAuthorityRegistry _authorities;

    public RenewalService(
        IManagedCertificateStore managedStore,
        IConfigStore configStore,
        IAcmeService acmeService,
        IIisService iisService,
        ICertificateStore certificateStore,
        INotifier notifier,
        IRenewalInfoProvider? renewalInfoProvider = null,
        ICertificateAuthorityRegistry? authorities = null)
    {
        _managedStore = managedStore;
        _configStore = configStore;
        _acmeService = acmeService;
        _iisService = iisService;
        _certificateStore = certificateStore;
        _notifier = notifier;
        _renewalInfoProvider = renewalInfoProvider ?? new NoOpRenewalInfoProvider();
        _authorities = authorities ?? CertificateAuthorityRegistry.BuiltInOnly;
    }

    public async Task<IReadOnlyList<ManagedCertificateStatus>> GetStatusAsync(
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var records = await _managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var statuses = new List<ManagedCertificateStatus>();
        foreach (var value in records.OrderBy(value => value.NotAfter))
        {
            var authority = await _authorities.DescribeAsync(value, cancellationToken).ConfigureAwait(false);
            statuses.Add(new ManagedCertificateStatus(
                value.SiteName,
                value.Hosts,
                value.NotBefore,
                value.NotAfter,
                (int)Math.Floor((value.NotAfter - now).TotalDays),
                value.Thumbprint,
                value.LastRenewalAttempt,
                value.LastRenewalSucceeded,
                value.LastRenewalMessage,
                value.AuthorityId,
                value.ConsecutiveFailures,
                value.NextRetryAt,
                authority.Name,
                authority.IsTest,
                value.Source,
                value.Issuer,
                value.Reminders,
                value.SnoozedUntil,
                value.LastRemindedAt));
        }

        return statuses;
    }

    public async Task<IReadOnlyList<RenewalResult>> RenewAsync(
        RenewalRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);

        var records = await _managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var selected = request.All
            ? records
            : records.Where(value => string.Equals(
                value.SiteName,
                request.SiteName,
                StringComparison.OrdinalIgnoreCase)).ToArray();
        if (!request.All && selected.Count == 0)
        {
            throw ManagedCertificateNotFound.Create(request.SiteName!, records);
        }

        var config = await _configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (config.RenewalThresholdDays < 0)
        {
            throw new InvalidDataException("RenewalThresholdDays cannot be negative.");
        }

        var results = new List<RenewalResult>();
        foreach (var certificate in selected)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // No CA renews an imported certificate for SSLense; ExpiryMonitor reminds the administrator instead.
            if (certificate.Source == CertificateSource.Imported)
            {
                results.Add(new RenewalResult(
                    certificate.SiteName,
                    false,
                    true,
                    "Skipped: imported certificate, renewed manually. Order the replacement from " +
                    $"{certificate.Issuer ?? "the issuer"} with a certificate request: Other Providers in the app, or 'SSLense.Cli csr --site \"{certificate.SiteName}\"' then 'complete'.",
                    certificate.Thumbprint));
                continue;
            }

            // Only the service honors the saved backoff; an administrator renewing by hand means "now".
            if (request.Scheduled && !request.Force &&
                certificate.NextRetryAt is { } retryAt && DateTimeOffset.UtcNow < retryAt)
            {
                results.Add(new RenewalResult(
                    certificate.SiteName,
                    false,
                    false,
                    $"Waiting: attempt {certificate.ConsecutiveFailures + 1} is scheduled for " +
                    $"{retryAt:yyyy-MM-dd HH:mm} UTC after {certificate.ConsecutiveFailures} failure(s).",
                    certificate.Thumbprint));
                continue;
            }

            var renewalAt = request.Force
                ? DateTimeOffset.MinValue
                : await GetRenewalTimeAsync(certificate, config, progress, cancellationToken)
                    .ConfigureAwait(false);
            if (!request.Force && DateTimeOffset.UtcNow < renewalAt)
            {
                results.Add(new RenewalResult(
                    certificate.SiteName,
                    false,
                    true,
                    $"Skipped: renewal is scheduled for {renewalAt:yyyy-MM-dd HH:mm} UTC " +
                    $"(certificate expires {certificate.NotAfter:yyyy-MM-dd}).",
                    certificate.Thumbprint));
                continue;
            }

            results.Add(await RenewOneAsync(certificate, request.Scheduled, progress, cancellationToken)
                .ConfigureAwait(false));
        }

        return results;
    }

    private async Task<RenewalResult> RenewOneAsync(
        ManagedCertificate certificate,
        bool scheduled,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        try
        {
            progress?.Report(new ProgressEvent(
                "renewal",
                $"Renewing {certificate.SiteName} (attempt {certificate.ConsecutiveFailures + 1})."));
            var issued = await _acmeService.IssueAsync(
                    new AcmeIssueRequest(
                        certificate.SiteName,
                        certificate.Hosts,
                        certificate.Email,
                        certificate.OutputDirectory,
                        true,
                        certificate.AuthorityId,
                        certificate.Thumbprint),
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);
            var newThumbprint = issued.CertificateThumbprint
                ?? throw new InvalidOperationException("The renewed certificate has no thumbprint.");

            var cleanupMessage = await RemoveOldCertificateIfUnusedAsync(
                    certificate.Thumbprint,
                    newThumbprint,
                    cancellationToken)
                .ConfigureAwait(false);
            await TryNotifyAsync(
                    new NotificationMessage(
                        NotificationKind.RenewalSuccess,
                        $"SSLense renewal succeeded: {certificate.SiteName}",
                        $"The {CertificateAuthorities.Label(certificate.AuthorityId)} certificate for {certificate.SiteName} " +
                        $"({string.Join(", ", certificate.Hosts)}) " +
                        $"was renewed successfully. New thumbprint: {newThumbprint}."),
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);
            return new RenewalResult(
                certificate.SiteName,
                true,
                true,
                cleanupMessage ?? "Renewed and rebound successfully.",
                certificate.Thumbprint,
                newThumbprint);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (CertificateStateChangedException exception)
        {
            return new RenewalResult(
                certificate.SiteName,
                false,
                true,
                $"Skipped: {exception.Message}",
                certificate.Thumbprint);
        }
        catch (Exception exception)
        {
            return await RecordFailureAsync(certificate, exception, scheduled, progress).ConfigureAwait(false);
        }
    }

    private async Task<RenewalResult> RecordFailureAsync(
        ManagedCertificate certificate,
        Exception exception,
        bool scheduled,
        IProgress<ProgressEvent>? progress)
    {
        var now = DateTimeOffset.UtcNow;
        var rateLimited = exception is AcmeRateLimitedException;
        var failures = certificate.ConsecutiveFailures + 1;
        var nextRetryAt = now + GetRetryDelay(failures, rateLimited, certificate.NotAfter - now);
        var updated = await _managedStore.RecordRenewalFailureAsync(
                certificate.SiteName,
                now,
                exception.Message,
                nextRetryAt,
                CancellationToken.None)
            .ConfigureAwait(false);
        failures = updated?.ConsecutiveFailures ?? failures;

        var message = $"{exception.Message} Next automatic attempt: {nextRetryAt:yyyy-MM-dd HH:mm} UTC.";
        progress?.Report(new ProgressEvent("retry", $"Renewal failed for {certificate.SiteName}. {message}"));
        if (ShouldNotifyFailure(failures, scheduled, rateLimited))
        {
            await TryNotifyAsync(
                    new NotificationMessage(
                        NotificationKind.RenewalFailure,
                        $"SSLense renewal failed: {certificate.SiteName}",
                        $"The {CertificateAuthorities.Label(certificate.AuthorityId)} certificate renewal for {certificate.SiteName} " +
                        $"({string.Join(", ", certificate.Hosts)}) has failed {failures} consecutive time(s). " +
                        $"The existing IIS binding was retained. The certificate expires at {certificate.NotAfter:O}. " +
                        $"Error: {message}"),
                    progress,
                    CancellationToken.None)
                .ConfigureAwait(false);
        }

        return new RenewalResult(
            certificate.SiteName,
            true,
            false,
            message,
            certificate.Thumbprint);
    }

    internal static TimeSpan GetRetryDelay(int consecutiveFailures, bool rateLimited, TimeSpan remainingLifetime)
    {
        var delay = rateLimited
            ? RateLimitedRetryDelay
            : RetryDelays[Math.Clamp(consecutiveFailures, 1, RetryDelays.Length) - 1];

        // Close to expiry, keep trying hourly; a rate limit still waits, because retrying only extends it.
        return !rateLimited && remainingLifetime < UrgentWindow && delay > UrgentRetryDelay
            ? UrgentRetryDelay
            : delay;
    }

    internal static bool ShouldNotifyFailure(int consecutiveFailures, bool scheduled, bool rateLimited) =>
        !scheduled || rateLimited || consecutiveFailures == NotifyAfterFailures ||
        (consecutiveFailures > NotifyAfterFailures && (consecutiveFailures - NotifyAfterFailures) % 4 == 0);

    private async Task TryNotifyAsync(
        NotificationMessage message,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        try
        {
            await _notifier.NotifyAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            progress?.Report(new ProgressEvent(
                "notification",
                $"Notification could not be sent: {exception.Message}"));
        }
    }

    public async Task<DateTimeOffset> GetScheduledRenewalAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default)
    {
        var config = await _configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        return await GetRenewalTimeAsync(certificate, config, progress: null, cancellationToken).ConfigureAwait(false);
    }

    private async Task<DateTimeOffset> GetRenewalTimeAsync(
        ManagedCertificate certificate,
        AppConfig config,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var window = await _renewalInfoProvider
            .GetWindowAsync(certificate, cancellationToken)
            .ConfigureAwait(false);
        if (window is not null)
        {
            var selected = SelectTimeInWindow(window, certificate.Thumbprint);
            progress?.Report(new ProgressEvent(
                "schedule",
                $"ACME ARI scheduled {certificate.SiteName} for {selected:yyyy-MM-dd HH:mm} UTC."));
            return selected;
        }

        var lifetime = certificate.NotAfter - certificate.NotBefore;
        var relativeLeadDays = Math.Max(1, lifetime.TotalDays / 3d);
        var configuredLeadDays = Math.Max(1, config.RenewalThresholdDays);
        var leadDays = Math.Min(configuredLeadDays, relativeLeadDays);
        var fallback = certificate.NotAfter.AddDays(-leadDays);
        progress?.Report(new ProgressEvent(
            "schedule",
            $"ARI is unavailable for {certificate.SiteName}; using the lifetime-relative fallback " +
            $"of {fallback:yyyy-MM-dd HH:mm} UTC."));
        return fallback;
    }

    internal static DateTimeOffset SelectTimeInWindow(RenewalWindow window, string seed)
    {
        if (window.End <= window.Start)
        {
            throw new ArgumentException("The renewal window end must be after its start.", nameof(window));
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var sample = BinaryPrimitives.ReadUInt64BigEndian(hash);
        var fraction = sample / (double)ulong.MaxValue;
        return window.Start + TimeSpan.FromTicks((long)((window.End - window.Start).Ticks * fraction));
    }

    private async Task<string?> RemoveOldCertificateIfUnusedAsync(
        string oldThumbprint,
        string newThumbprint,
        CancellationToken cancellationToken)
    {
        if (string.Equals(oldThumbprint, newThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var sites = await _iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var stillUsed = sites.SelectMany(value => value.Bindings).Any(binding =>
            string.Equals(binding.CertificateThumbprint, oldThumbprint, StringComparison.OrdinalIgnoreCase));
        if (stillUsed)
        {
            return "Renewed successfully; the old certificate was retained because another IIS binding uses it.";
        }

        try
        {
            await _certificateStore.RemoveAsync(oldThumbprint, cancellationToken).ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return $"Renewed successfully, but the unused old certificate could not be removed: {exception.Message}";
        }
    }

    private static void ValidateRequest(RenewalRequest request)
    {
        var hasSite = !string.IsNullOrWhiteSpace(request.SiteName);
        if (request.All == hasSite)
        {
            throw new ArgumentException("Specify exactly one of --all or --site.", nameof(request));
        }
    }
}
