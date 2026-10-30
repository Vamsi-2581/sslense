using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

public sealed record CertificateDetails(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string Thumbprint,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    IReadOnlyList<string> BoundSites,
    IReadOnlyList<string> RecentLogLines,
    string AuthorityId = CertificateAuthorities.LetsEncryptStagingId,
    string AuthorityName = "Let's Encrypt staging",
    bool IsTestAuthority = true,
    CertificateSource Source = CertificateSource.Acme);
