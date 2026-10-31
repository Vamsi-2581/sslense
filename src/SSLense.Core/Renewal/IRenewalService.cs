namespace SSLense.Core.Renewal;

public interface IRenewalService
{
    Task<IReadOnlyList<ManagedCertificateStatus>> GetStatusAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// When an automatically renewed certificate is scheduled for renewal: the time the CA recommends (ARI), or the
    /// fallback schedule when it offers none. The same rule <see cref="RenewAsync"/> uses.
    /// </summary>
    Task<DateTimeOffset> GetScheduledRenewalAsync(
        Config.ManagedCertificate certificate,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RenewalResult>> RenewAsync(
        RenewalRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);
}
