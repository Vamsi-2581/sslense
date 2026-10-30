namespace SSLense.Core.Acme;

/// <param name="AuthorityId">The certificate authority to issue from; Let's Encrypt staging unless chosen otherwise.</param>
public sealed record AcmeIssueRequest(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string Email,
    string? OutputDirectory = null,
    bool Force = false,
    string AuthorityId = CertificateAuthorities.LetsEncryptStagingId,
    string? ExpectedCurrentThumbprint = null);
