namespace SSLense.Core.Certificates;

public sealed record InstalledCertificate(
    string Thumbprint,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    bool HasPrivateKey,
    string? Issuer = null,
    IReadOnlyList<string>? DnsNames = null,
    string? IssuerName = null);
