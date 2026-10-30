using SSLense.Core.Acme;

namespace SSLense.Core.Config;

/// <param name="AuthorityId">
/// The <see cref="CertificateAuthority"/> that issued this certificate and renews it. Schema 1 stored a
/// staging/production environment instead; see <see cref="ManagedCertificateMigrations"/>.
/// </param>
/// <param name="Source">Whether SSLense obtains and renews this certificate, or it was installed from elsewhere.</param>
/// <param name="Issuer">The issuing CA's name, as shown in the certificate, for display.</param>
/// <param name="ReminderDaysSent">
/// For imported certificates, the smallest "days before expiry" reminder already sent (30, 14, 7, or 1).
/// </param>
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
    ExpiryWarningLevel ExpiryWarningSent = ExpiryWarningLevel.None,
    Guid Id = default,
    CertificateSource Source = CertificateSource.Acme,
    string? Issuer = null,
    int? ReminderDaysSent = null);

/// <summary>Expiry notification levels, each sent at most once per certificate.</summary>
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
