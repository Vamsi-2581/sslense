using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SSLense.Tests.Certificates;

/// <summary>A throwaway root and intermediate CA that issue real certificates, like a commercial CA would.</summary>
internal sealed class TestCertificateAuthority : IDisposable
{
    private readonly RSA _rootKey = RSA.Create(2048);
    private readonly RSA _intermediateKey = RSA.Create(2048);

    /// <param name="intermediateExpires">When the intermediate expires; default two years ahead.</param>
    public TestCertificateAuthority(DateTimeOffset? intermediateExpires = null)
    {
        var rootRequest = new CertificateRequest("CN=SSLense Test Root", _rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        Root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-1), DateTimeOffset.UtcNow.AddYears(5));

        var intermediateRequest = new CertificateRequest("CN=SSLense Test Intermediate", _intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var intermediate = intermediateRequest.Create(Root, DateTimeOffset.UtcNow.AddDays(-300), intermediateExpires ?? DateTimeOffset.UtcNow.AddYears(2), [1, 2, 3, 4]);
        Intermediate = intermediate.CopyWithPrivateKey(_intermediateKey);
    }

    public X509Certificate2 Root { get; }

    public X509Certificate2 Intermediate { get; }

    /// <summary>Issues a certificate for a CSR, honouring its subject alternative names, as a CA does.</summary>
    public X509Certificate2 Issue(string csrPem, int validDays = 90, bool serverAuth = true, DateTimeOffset? notBefore = null)
    {
        var request = CertificateRequest.LoadSigningRequestPem(
            csrPem,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        return Sign(request, validDays, serverAuth, notBefore);
    }

    /// <summary>Issues a certificate for a fresh key (not tied to any CSR), for PFX and mismatch tests.</summary>
    public (X509Certificate2 Certificate, RSA Key) IssueWithNewKey(params string[] hosts)
    {
        var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={hosts[0]}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        foreach (var host in hosts)
        {
            names.AddDnsName(host);
        }

        request.CertificateExtensions.Add(names.Build());
        return (Sign(request, 90, serverAuth: true, notBefore: null), key);
    }

    public string ChainPem => Intermediate.ExportCertificatePem();

    /// <summary>A PFX holding the certificate, its key and the intermediate, as providers usually supply it.</summary>
    public byte[] ExportPfx(X509Certificate2 certificate, RSA key, string password)
    {
        using var withKey = certificate.CopyWithPrivateKey(key);
        using var intermediate = X509CertificateLoader.LoadCertificate(Intermediate.RawData);
        return new X509Certificate2Collection(new[] { withKey, intermediate }).Export(X509ContentType.Pfx, password)!;
    }

    public void Dispose()
    {
        Root.Dispose();
        Intermediate.Dispose();
        _rootKey.Dispose();
        _intermediateKey.Dispose();
    }

    private X509Certificate2 Sign(CertificateRequest request, int validDays, bool serverAuth, DateTimeOffset? notBefore)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        if (!request.CertificateExtensions.OfType<X509EnhancedKeyUsageExtension>().Any())
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid(serverAuth ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.4")], false));
        }

        var start = notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-5);
        return request.Create(
            Intermediate.SubjectName,
            X509SignatureGenerator.CreateForRSA(_intermediateKey, RSASignaturePadding.Pkcs1),
            start,
            start.AddDays(validDays),
            RandomNumberGenerator.GetBytes(8));
    }
}
