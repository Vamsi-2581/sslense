using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Renewal;

/// <param name="AuthorityName">Display name of the issuing certificate authority profile.</param>
/// <param name="IsTestAuthority">True when the certificate comes from a test CA that browsers do not trust.</param>
public sealed record ManagedCertificateStatus(
    string SiteName,
    IReadOnlyList<string> Hosts,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    int DaysRemaining,
    string Thumbprint,
    DateTimeOffset? LastRenewalAttempt,
    bool? LastRenewalSucceeded,
    string? LastRenewalMessage,
    string AuthorityId = CertificateAuthorities.LetsEncryptStagingId,
    int ConsecutiveFailures = 0,
    DateTimeOffset? NextRetryAt = null,
    string AuthorityName = "Let's Encrypt staging",
    bool IsTestAuthority = true,
    CertificateSource Source = CertificateSource.Acme,
    string? Issuer = null);
