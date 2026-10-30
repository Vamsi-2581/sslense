using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Certificates;
using Xunit;

namespace SSLense.Tests.Certificates;

public sealed class CertificateInspectorTests : IDisposable
{
    private readonly TestCertificateAuthority _ca = new();

    [Theory]
    [InlineData("www.example.com", true)]
    [InlineData("WWW.Example.com.", true)]
    [InlineData("example.com", false)]
    [InlineData("a.b.example.com", false)]
    [InlineData("www.example.org", false)]
    public void Covers_WildcardsMatchExactlyOneLabel(string host, bool expected)
    {
        Assert.Equal(expected, CertificateInspector.Covers(["*.example.com"], host));
    }

    [Fact]
    public void Validate_CompleteChainCoveringTheHosts_HasNoProblems()
    {
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com", "www.shop.example.com");
        using (certificate)
        using (key)
        {
            var problems = CertificateInspector.Validate(
                certificate, ["shop.example.com", "www.shop.example.com"], [_ca.Intermediate], DateTimeOffset.UtcNow, [_ca.Root]);

            Assert.Empty(problems);
        }
    }

    [Fact]
    public void Validate_MissingIntermediate_AsksForTheBundle()
    {
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com");
        using (certificate)
        using (key)
        {
            var problem = Assert.Single(CertificateInspector.Validate(
                certificate, ["shop.example.com"], [], DateTimeOffset.UtcNow, [_ca.Root]));

            Assert.Contains("--chain", problem, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Validate_UntrustedRoot_IsRefused()
    {
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com");
        using (certificate)
        using (key)
        {
            // The bundle includes the root, but this machine does not trust it.
            var problems = CertificateInspector.Validate(
                certificate, ["shop.example.com"], [_ca.Intermediate, _ca.Root], DateTimeOffset.UtcNow);

            Assert.Contains(problems, problem => problem.Contains("does not trust", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Validate_ReportsUncoveredHostsExpiryAndWrongPurpose()
    {
        using var keyHolder = System.Security.Cryptography.RSA.Create(2048);
        var request = new CertificateRequest("CN=shop.example.com", keyHolder, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var certificate = _ca.Issue(request.CreateSigningRequestPem(), validDays: 10, serverAuth: false,
            notBefore: DateTimeOffset.UtcNow.AddDays(-30));

        var problems = CertificateInspector.Validate(
            certificate, ["shop.example.com", "other.example.com"], [_ca.Intermediate], DateTimeOffset.UtcNow, [_ca.Root]);

        Assert.Contains(problems, problem => problem.Contains("does not cover other.example.com", StringComparison.Ordinal));
        Assert.Contains(problems, problem => problem.Contains("expired", StringComparison.Ordinal));
        Assert.Contains(problems, problem => problem.Contains("server authentication", StringComparison.Ordinal));
    }

    [Fact]
    public void LoadCertificates_ReadsALeafAndBundleFromOnePemFileOrDer()
    {
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com");
        using (certificate)
        using (key)
        {
            var pem = certificate.ExportCertificatePem() + "\n" + _ca.ChainPem;

            var fromPem = CertificateInspector.LoadCertificates(System.Text.Encoding.ASCII.GetBytes(pem));
            var fromDer = CertificateInspector.LoadCertificates(certificate.RawData);

            Assert.Equal(2, fromPem.Count);
            Assert.Equal(certificate.Thumbprint, Assert.Single(fromDer).Thumbprint);
        }
    }

    public void Dispose() => _ca.Dispose();
}
