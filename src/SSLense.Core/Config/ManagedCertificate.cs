using SSLense.Core.Acme;

namespace SSLense.Core.Config;

/// <param name="AuthorityId">
/// The <see cref="CertificateAuthority"/> that issued this certificate and renews it. Schema 1 stored a
/// staging/production environment instead; see <see cref="ManagedCertificateMigrations"/>.
/// </param>
/// <param name="Source">Whether SSLense obtains and renews this certificate, or it was installed from elsewhere.</param>
/// <param name="Issuer">The issuing CA's name, as shown in the certificate, for display.</param>
/// <param name="Reminders">Whether this certificate is included in reminder digests; see <see cref="ReminderMode"/>.</param>
/// <param name="SnoozedUntil">With <see cref="ReminderMode.Snoozed"/>, when reminders resume.</param>
/// <param name="LastRemindedAt">When this certificate was last included in a sent digest as needing attention.</param>
/// <param name="UpcomingNoticeSent">Whether the one upcoming-renewal notice was sent for this certificate.</param>
/// <remarks>
/// The reminder fields belong to the record, not to a certificate: <see cref="IManagedCertificateStore.UpsertAsync"/> keeps
/// them across installs and resets them when the thumbprint changes (except <see cref="ReminderMode.Off"/>).
/// </remarks>
public sealed record ManagedCertificate(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string Email,
    string Thumbprint,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string? OutputDirectory = null,
    DateTimeOffset? LastRenewalAttempt = null,
    bool? LastRenewalSucceeded = null,
    string? LastRenewalMessage = null,
    string AuthorityId = CertificateAuthorities.LetsEncryptStagingId,
    int ConsecutiveFailures = 0,
    DateTimeOffset? NextRetryAt = null,
    Guid Id = default,
    CertificateSource Source = CertificateSource.Acme,
    string? Issuer = null,
    ReminderMode Reminders = ReminderMode.On,
    DateTimeOffset? SnoozedUntil = null,
    DateTimeOffset? LastRemindedAt = null,
    bool UpcomingNoticeSent = false);

public enum ReminderMode
{
    On = 0,

    /// <summary>Not reminding until <see cref="ManagedCertificate.SnoozedUntil"/>, or until the certificate is replaced.</summary>
    Snoozed = 1,

    /// <summary>Not reminding until the certificate is replaced; the replacement is reminded about again.</summary>
    OffUntilReplaced = 2,

    /// <summary>Never reminding about this site's certificate, including its replacements.</summary>
    Off = 3
}

/// <summary>How close a certificate is to expiry, relative to its lifetime; used by the health check.</summary>
public enum ExpiryWarningLevel
{
    None = 0,
    Warning = 1,
    Critical = 2,
    Expired = 3
}

public enum CertificateSource
{
    /// <summary>Obtained and renewed automatically by SSLense from an ACME certificate authority.</summary>
    Acme = 0,

    /// <summary>Obtained elsewhere (bought from a reseller, or issued by another tool) and renewed manually.</summary>
    Imported = 1
}
