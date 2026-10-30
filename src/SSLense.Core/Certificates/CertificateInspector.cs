using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SSLense.Core.Certificates;

/// <summary>Checks a certificate from outside SSLense before it is bound to IIS. Pure and side-effect free.</summary>
internal static class CertificateInspector
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    public static IReadOnlyList<string> GetDnsNames(X509Certificate2 certificate)
    {
        var names = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(extension => extension.EnumerateDnsNames())
            .ToList();

        // Very old certificates may carry the host only in the subject.
        if (names.Count == 0 && certificate.GetNameInfo(X509NameType.DnsName, forIssuer: false) is { Length: > 0 } subjectName)
        {
            names.Add(subjectName);
        }

        return names.Select(name => name.Trim().TrimEnd('.').ToLowerInvariant()).Distinct().ToArray();
    }

    /// <summary>A wildcard covers exactly one label: *.example.com covers www.example.com, not example.com.</summary>
    public static bool Covers(IReadOnlyList<string> dnsNames, string host)
    {
        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        return dnsNames.Any(name => name == host ||
            (name.StartsWith("*.", StringComparison.Ordinal) &&
             host.EndsWith(name[1..], StringComparison.Ordinal) &&
             host.IndexOf('.') == host.Length - name.Length + 1));
    }

    public static string Describe(X509Certificate2 certificate) =>
        $"{certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false)} " +
        $"(issued by {certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true)}, " +
        $"thumbprint {certificate.Thumbprint})";

    /// <summary>
    /// Returns every reason the certificate must not be bound for <paramref name="hosts"/>, or an empty list.
    /// </summary>
    /// <param name="customRoots">Test-only trust anchors; production validation uses the machine's trusted roots.</param>
    public static IReadOnlyList<string> Validate(
        X509Certificate2 certificate,
        IReadOnlyList<string> hosts,
        IReadOnlyList<X509Certificate2> intermediates,
        DateTimeOffset now,
        IReadOnlyList<X509Certificate2>? customRoots = null)
    {
        var problems = new List<string>();
        var dnsNames = GetDnsNames(certificate);
        var uncovered = hosts.Where(host => !Covers(dnsNames, host)).ToArray();
        if (uncovered.Length > 0)
        {
            problems.Add(
                $"The certificate does not cover {string.Join(", ", uncovered)}. It is issued for " +
                $"{(dnsNames.Count == 0 ? "no host names" : string.Join(", ", dnsNames))}.");
        }

        if (certificate.NotBefore.ToUniversalTime() > now.UtcDateTime)
        {
            problems.Add($"The certificate is not valid until {certificate.NotBefore.ToUniversalTime():yyyy-MM-dd HH:mm} UTC.");
        }

        if (certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
        {
            problems.Add($"The certificate expired on {certificate.NotAfter.ToUniversalTime():yyyy-MM-dd HH:mm} UTC.");
        }

        var usages = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        if (usages.Length > 0 && !usages.Any(usage =>
                usage.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == ServerAuthenticationOid)))
        {
            problems.Add("The certificate is not issued for server authentication (TLS web server), so browsers would reject it.");
        }

        if (GetChainProblem(certificate, intermediates, customRoots) is { } chainProblem)
        {
            problems.Add(chainProblem);
        }

        return problems;
    }

    /// <summary>Null when the certificate chains to a trusted root; otherwise what is missing.</summary>
    public static string? GetChainProblem(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> intermediates,
        IReadOnlyList<X509Certificate2>? customRoots = null)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        chain.ChainPolicy.ExtraStore.AddRange(intermediates.ToArray());
        if (customRoots is not null)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(customRoots.ToArray());
        }

        if (chain.Build(certificate))
        {
            return null;
        }

        var statuses = chain.ChainStatus.Select(status => status.Status).ToHashSet();
        return statuses.Contains(X509ChainStatusFlags.PartialChain)
            ? "The certificate chain is incomplete. Add the intermediate certificate bundle from your certificate " +
              "provider (often named ca-bundle, chain, or intermediate) as the chain file (--chain in the CLI)."
            : statuses.Contains(X509ChainStatusFlags.UntrustedRoot)
                ? "The certificate chains to a root that this server does not trust. Install the issuer's root " +
                  "certificate in the Trusted Root Certification Authorities store if it is your own internal CA."
                : "The certificate chain is not valid: " +
                  string.Join("; ", chain.ChainStatus.Select(status => status.StatusInformation.Trim()).Distinct());
    }

    /// <summary>Separates a PEM or DER file into certificates, so a leaf and its bundle can share one file.</summary>
    public static IReadOnlyList<X509Certificate2> LoadCertificates(byte[] content)
    {
        var text = System.Text.Encoding.ASCII.GetString(content);
        if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            var collection = new X509Certificate2Collection();
            collection.ImportFromPem(text);
            return collection.Count > 0
                ? collection.Cast<X509Certificate2>().ToArray()
                : throw new InvalidDataException("The file contains no certificates.");
        }

        try
        {
            return [X509CertificateLoader.LoadCertificate(content)];
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "The file is not a PEM or DER certificate. If you have a .p7b or .pfx file, export the certificate as " +
                "Base-64 (.crt or .pem), or use 'import' for a .pfx.",
                exception);
        }
    }

    public static bool IsCertificateAuthority(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(extension => extension.CertificateAuthority);
}
