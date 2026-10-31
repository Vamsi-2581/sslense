namespace SSLense.Core.Config;

public interface IManagedCertificateStore
{
    Task<IReadOnlyList<ManagedCertificate>> GetAllAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces the site's record. An empty <see cref="ManagedCertificate.Id"/> keeps the site's existing ID. The reminder
    /// fields are kept from the existing record; when the thumbprint changes they reset, except
    /// <see cref="ReminderMode.Off"/>, which is permanent.
    /// </summary>
    Task UpsertAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a failed attempt, increments the consecutive-failure count, and stores the next retry time.
    /// Returns the updated record, or null when the site is no longer managed.
    /// </summary>
    Task<ManagedCertificate?> RecordRenewalFailureAsync(
        string siteName,
        DateTimeOffset attemptedAt,
        string message,
        DateTimeOffset nextRetryAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Records what a delivered digest said about each certificate. An entry is ignored when its site's certificate
    /// has been replaced since the digest was built.
    /// </summary>
    Task RecordRemindersAsync(
        IReadOnlyList<ReminderRecord> sent,
        DateTimeOffset sentAt,
        CancellationToken cancellationToken = default);

    /// <summary>Sets whether the site's certificate is included in reminders. Returns false when the site is not managed.</summary>
    Task<bool> SetReminderModeAsync(
        string siteName,
        ReminderMode mode,
        DateTimeOffset? snoozedUntil,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(string siteName, CancellationToken cancellationToken = default);
}

/// <param name="Reminded">Listed as needing attention, which starts the repeat interval again.</param>
/// <param name="NoticeSent">Listed as an upcoming automatic renewal, which is said only once.</param>
public sealed record ReminderRecord(string SiteName, string Thumbprint, bool Reminded, bool NoticeSent);
