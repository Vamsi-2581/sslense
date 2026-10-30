using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Acme;

public sealed class CertificateAuthorityRegistryTests
{
    private static readonly CertificateAuthority ZeroSsl = new(
        "zerossl", "ZeroSSL", new Uri("https://acme.zerossl.com/v2/DV90"), IsTest: false, EabKeyId: "kid");

    [Fact]
    public async Task GetAllAsync_ListsBuiltInProfilesThenConfiguredOnes()
    {
        var registry = CreateRegistry(ZeroSsl);

        var all = await registry.GetAllAsync();

        Assert.Equal(["letsencrypt-staging", "letsencrypt", "zerossl"], all.Select(authority => authority.Id));
    }

    [Fact]
    public async Task GetAllAsync_ConfiguredEntryCannotReplaceABuiltInProfile()
    {
        var registry = CreateRegistry(new CertificateAuthority(
            CertificateAuthorities.LetsEncryptId, "Impostor", new Uri("https://evil.example/directory"), IsTest: false));

        var letsEncrypt = await registry.GetAsync(CertificateAuthorities.LetsEncryptId);

        Assert.Equal(CertificateAuthorities.LetsEncrypt.DirectoryUri, letsEncrypt.DirectoryUri);
        Assert.Single(await registry.GetAllAsync(), authority => authority.Id == CertificateAuthorities.LetsEncryptId);
    }

    [Fact]
    public async Task GetAsync_UnknownId_ListsWhatIsAvailable()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateRegistry(ZeroSsl).GetAsync("google"));

        Assert.Contains("'google' is not configured", exception.Message, StringComparison.Ordinal);
        Assert.Contains("zerossl", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(CertificateSource.Acme, "zerossl", null, "ZeroSSL", false)]
    [InlineData(CertificateSource.Acme, CertificateAuthorities.LetsEncryptStagingId, null, "Let's Encrypt staging", true)]
    [InlineData(CertificateSource.Acme, "removed-profile", null, "removed-profile", false)]
    [InlineData(CertificateSource.Imported, CertificateAuthorities.LetsEncryptStagingId, "Sectigo RSA DV", "Imported (Sectigo RSA DV)", false)]
    public async Task DescribeAsync_NeverThrowsAndNamesTheSource(
        CertificateSource source, string authorityId, string? issuer, string expectedName, bool expectedTest)
    {
        var certificate = new ManagedCertificate(
            "Shop", ["shop.example.com"], "a@example.com", "AA", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90),
            AuthorityId: authorityId, Source: source, Issuer: issuer);

        var (name, isTest) = await CreateRegistry(ZeroSsl).DescribeAsync(certificate);

        Assert.Equal(expectedName, name);
        Assert.Equal(expectedTest, isTest);
    }

    [Theory]
    [InlineData("zerossl", true)]
    [InlineData("google-trust-services", true)]
    [InlineData("ZeroSSL", false)]
    [InlineData("-leading", false)]
    [InlineData("has space", false)]
    public void IsValidId_AllowsOnlySafeFileNameCharacters(string id, bool expected)
    {
        Assert.Equal(expected, CertificateAuthorities.IsValidId(id));
    }

    private static CertificateAuthorityRegistry CreateRegistry(params CertificateAuthority[] configured)
    {
        var configStore = new Mock<IConfigStore>(MockBehavior.Strict);
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { CertificateAuthorities = configured });
        return new CertificateAuthorityRegistry(configStore.Object);
    }
}
