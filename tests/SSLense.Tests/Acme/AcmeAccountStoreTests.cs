using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Acme;

public sealed class AcmeAccountStoreTests
{
    [Fact]
    public async Task SaveAndLoad_UsesProtectedPayloadInsteadOfPlaintext()
    {
        const string accountKey = "-----BEGIN EC PRIVATE KEY-----secret-----END EC PRIVATE KEY-----";
        string? savedValue = null;
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        fileSystem.Setup(value => value.WriteAllTextAtomicAsync(
                AppPaths.AccountKeyFile,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((_, contents, _) => savedValue = contents)
            .Returns(Task.CompletedTask);
        fileSystem.Setup(value => value.FileExists(AppPaths.AccountKeyFile)).Returns(true);
        fileSystem.Setup(value => value.ReadAllTextAsync(
                AppPaths.AccountKeyFile,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => savedValue!);
        var protector = new Mock<ISecretProtector>(MockBehavior.Strict);
        protector.Setup(value => value.Protect(It.IsAny<byte[]>())).Returns([10, 20, 30]);
        protector.Setup(value => value.Unprotect(It.Is<byte[]>(bytes => bytes.SequenceEqual(new byte[] { 10, 20, 30 }))))
            .Returns(Encoding.UTF8.GetBytes(accountKey));
        var store = new AcmeAccountStore(fileSystem.Object, protector.Object);

        await store.SaveKeyAsync(CertificateAuthorities.LetsEncryptStagingId, accountKey, CancellationToken.None);
        var loaded = await store.LoadKeyAsync(CertificateAuthorities.LetsEncryptStagingId, CancellationToken.None);

        Assert.Equal(accountKey, loaded);
        Assert.Equal(Convert.ToBase64String(new byte[] { 10, 20, 30 }), savedValue);
        Assert.DoesNotContain("PRIVATE KEY", savedValue, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProductionAndStaging_UseSeparateAccountKeyFiles()
    {
        const string productionKey = "production-private-key";
        string? savedValue = null;
        var productionPath = AppPaths.GetAccountKeyFile(CertificateAuthorities.LetsEncryptId);
        var stagingPath = AppPaths.GetAccountKeyFile(CertificateAuthorities.LetsEncryptStagingId);
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        fileSystem.Setup(value => value.WriteAllTextAtomicAsync(
                productionPath, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((_, contents, _) => savedValue = contents)
            .Returns(Task.CompletedTask);
        fileSystem.Setup(value => value.FileExists(productionPath)).Returns(true);
        fileSystem.Setup(value => value.ReadAllTextAsync(productionPath, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => savedValue!);
        fileSystem.Setup(value => value.FileExists(stagingPath)).Returns(false);
        var protector = new Mock<ISecretProtector>(MockBehavior.Strict);
        protector.Setup(value => value.Protect(It.IsAny<byte[]>())).Returns([1, 2, 3]);
        protector.Setup(value => value.Unprotect(It.IsAny<byte[]>()))
            .Returns(Encoding.UTF8.GetBytes(productionKey));
        var store = new AcmeAccountStore(fileSystem.Object, protector.Object);

        await store.SaveKeyAsync(CertificateAuthorities.LetsEncryptId, productionKey, CancellationToken.None);
        var loadedProduction = await store.LoadKeyAsync(
            CertificateAuthorities.LetsEncryptId, CancellationToken.None);
        var loadedStaging = await store.LoadKeyAsync(
            CertificateAuthorities.LetsEncryptStagingId, CancellationToken.None);

        Assert.Equal(productionKey, loadedProduction);
        Assert.Null(loadedStaging);
        Assert.NotEqual(productionPath, stagingPath);
        fileSystem.VerifyAll();
    }

    [Theory]
    // Existing installations keep their Let's Encrypt accounts, so these names must never change.
    [InlineData(CertificateAuthorities.LetsEncryptStagingId, "account-key.staging.dat")]
    [InlineData(CertificateAuthorities.LetsEncryptId, "account-key.production.dat")]
    [InlineData("zerossl", "account-key.zerossl.dat")]
    public void GetAccountKeyFile_KeepsExistingNamesAndSeparatesEachAuthority(string authorityId, string expectedFile)
    {
        Assert.Equal(expectedFile, Path.GetFileName(AppPaths.GetAccountKeyFile(authorityId)));
    }

    [Theory]
    [InlineData(@"..\evil")]
    [InlineData("Upper")]
    [InlineData("")]
    public void GetAccountKeyFile_RejectsIdsThatCouldEscapeTheDataFolder(string authorityId)
    {
        Assert.Throws<ArgumentException>(() => AppPaths.GetAccountKeyFile(authorityId));
    }
}
