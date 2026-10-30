using Moq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Acme;

public sealed class AcmeServiceTests
{
    [Fact]
    public async Task IssueAsync_ValidRequest_CompletesChallengeAndSavesArtifacts()
    {
        var challenge = new AcmeHttpChallenge("example.com", "token", "key-authorization");
        var site = CreateSite("example.com");
        var iis = MockIis(site);
        var order = new Mock<IAcmeOrderSession>(MockBehavior.Strict);
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.ValidateAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        order.Setup(value => value.FinalizeAsync(
                "example.com",
                It.Is<string>(password => password.Length > 20),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateBundle());
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                "admin@example.com",
                It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "example.com" })),
                It.Is<CertificateAuthority>(authority => authority.Id == CertificateAuthorities.LetsEncryptStagingId),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var cleanup = new TrackingCleanup();
        var handler = new Mock<IChallengeHandler>(MockBehavior.Strict);
        handler.Setup(value => value.PrepareAsync("C:\\inetpub\\site", challenge, It.IsAny<CancellationToken>()))
            .ReturnsAsync(cleanup);
        var probe = new Mock<IChallengeProbe>(MockBehavior.Strict);
        probe.Setup(value => value.VerifyAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var expected = new AcmeIssueResult("certificate.pem", "certificate.pfx", ["example.com"]);
        var artifacts = new Mock<ICertificateArtifactStore>(MockBehavior.Strict);
        artifacts.Setup(value => value.SaveAsync(
                "My Site",
                It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "example.com" })),
                It.IsAny<CertificateBundle>(),
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(expected);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(90);
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.ImportPfxAsync(
                It.IsAny<byte[]>(),
                It.Is<string>(password => password.Length > 20),
                It.Is<string>(name => name.StartsWith("SSLense: example.com", StringComparison.Ordinal)),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("AABBCC", notBefore, notAfter, true));
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                "My Site",
                It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "example.com" })),
                "AABBCC",
                "My",
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var managedStore = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managedStore.Setup(value => value.UpsertAsync(
                It.Is<ManagedCertificate>(record =>
                    record.SiteName == "My Site" &&
                    record.Thumbprint == "AABBCC" &&
                    record.Hosts.SequenceEqual(new[] { "example.com" }) &&
                    record.LastRenewalSucceeded == true),
                CancellationToken.None))
            .Returns(Task.CompletedTask);
        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            handler.Object,
            probe.Object,
            artifacts.Object,
            certificateStore.Object,
            managedStore.Object);

        var result = await service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["EXAMPLE.com."], "admin@example.com"));

        Assert.Equal(expected.CertificatePemPath, result.CertificatePemPath);
        Assert.Equal("AABBCC", result.CertificateThumbprint);
        Assert.Equal(notAfter, result.NotAfter);
        Assert.True(cleanup.WasDisposed);
        protocol.VerifyAll();
        order.VerifyAll();
        handler.VerifyAll();
        probe.VerifyAll();
        artifacts.VerifyAll();
        certificateStore.VerifyAll();
        managedStore.VerifyAll();
    }

    [Fact]
    public async Task IssueAsync_MissingPort80Binding_StopsBeforeAcmeOrder()
    {
        var site = new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", []);
        var iis = MockIis(site);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            Mock.Of<ICertificateStore>(),
            Mock.Of<IManagedCertificateStore>());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        Assert.Contains("HTTP binding on port 80", exception.Message, StringComparison.Ordinal);
        protocol.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task IssueAsync_ValidationFails_StillRemovesChallengeFiles()
    {
        var challenge = new AcmeHttpChallenge("example.com", "token", "key-authorization");
        var iis = MockIis(CreateSite("example.com"));
        var order = new Mock<IAcmeOrderSession>(MockBehavior.Strict);
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.ValidateAsync(challenge, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("rejected"));
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                It.IsAny<string>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<CertificateAuthority>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var cleanup = new TrackingCleanup();
        var handler = new Mock<IChallengeHandler>(MockBehavior.Strict);
        handler.Setup(value => value.PrepareAsync(
                It.IsAny<string>(),
                challenge,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(cleanup);
        var probe = new Mock<IChallengeProbe>(MockBehavior.Strict);
        probe.Setup(value => value.VerifyAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            handler.Object,
            probe.Object,
            Mock.Of<ICertificateArtifactStore>(),
            Mock.Of<ICertificateStore>(),
            Mock.Of<IManagedCertificateStore>());

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        Assert.True(cleanup.WasDisposed);
    }

    [Fact]
    public async Task IssueAsync_ValidCertificateAlreadyBound_RequiresForceBeforeCreatingOrder()
    {
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC",
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(60),
                true));
        var site = new IisSite(
            1,
            "My Site",
            "Started",
            "C:\\inetpub\\site",
            [
                new IisBinding("http", "*", 80, "example.com", null, null, false),
                new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true)
            ]);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            MockIis(site).Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            certificateStore.Object,
            Mock.Of<IManagedCertificateStore>());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        Assert.Contains("--force", exception.Message, StringComparison.Ordinal);
        protocol.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("CN=(STAGING) Pseudo Plum E5, O=(STAGING) Let's Encrypt, C=US", CertificateAuthorities.LetsEncryptId, true)]
    [InlineData("CN=E5, O=Let's Encrypt, C=US", CertificateAuthorities.LetsEncryptStagingId, true)]
    [InlineData("CN=E5, O=Let's Encrypt, C=US", CertificateAuthorities.LetsEncryptId, false)]
    public async Task IssueAsync_ProductionRequest_DoesNotTreatStagingCertificateAsCoverage(
        string issuer,
        string managedAuthorityId,
        bool expectOrder)
    {
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC",
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(60),
                true,
                issuer));
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new ManagedCertificate(
                "My Site", ["example.com"], "admin@example.com", "AABBCC",
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60),
                AuthorityId: managedAuthorityId)]);
        var site = new IisSite(
            1,
            "My Site",
            "Started",
            "C:\\inetpub\\site",
            [
                new IisBinding("http", "*", 80, "example.com", null, null, false),
                new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true)
            ]);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                "admin@example.com",
                It.IsAny<IReadOnlyList<string>>(),
                It.Is<CertificateAuthority>(authority => authority.Id == CertificateAuthorities.LetsEncryptId),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("order requested"));
        var service = new AcmeService(
            MockIis(site).Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            certificateStore.Object,
            managed.Object);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest(
                "My Site", ["example.com"], "admin@example.com",
                AuthorityId: CertificateAuthorities.LetsEncryptId)));

        if (expectOrder)
        {
            Assert.Equal("order requested", exception.Message);
        }
        else
        {
            Assert.Contains("--force", exception.Message, StringComparison.Ordinal);
            protocol.VerifyNoOtherCalls();
        }
    }

    [Theory]
    [InlineData("urn:ietf:params:acme:error:rateLimited", true)]
    [InlineData("urn:ietf:params:acme:error:unauthorized", false)]
    public void IsRateLimited_RecognizesOnlyTheRateLimitProblemType(string problemType, bool expected)
    {
        var exception = new Certes.AcmeRequestException(
            "request failed",
            new Certes.Acme.AcmeError { Type = problemType, Detail = "too many certificates" });

        Assert.Equal(expected, CertesAcmeProtocolClient.IsRateLimited(exception));
        if (expected)
        {
            var mapped = CertesAcmeProtocolClient.ToRateLimitedException(exception, CertificateAuthorities.LetsEncryptStaging);
            Assert.Contains("too many certificates", mapped.Message, StringComparison.Ordinal);
            Assert.Contains("will not retry", mapped.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task IssueAsync_ExpectedCertificateChanged_StopsBeforeIisOrAcme()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new ManagedCertificate(
                "My Site", ["example.com"], "admin@example.com", "NEW",
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(45))]);
        var scope = new Mock<IAsyncDisposable>(MockBehavior.Strict);
        scope.Setup(value => value.DisposeAsync()).Returns(ValueTask.CompletedTask);
        var operationLock = new Mock<ICertificateOperationLock>(MockBehavior.Strict);
        operationLock.Setup(value => value.AcquireAsync("My Site", It.IsAny<CancellationToken>()))
            .ReturnsAsync(scope.Object);
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            Mock.Of<ICertificateStore>(),
            managed.Object,
            operationLock.Object);

        var exception = await Assert.ThrowsAsync<CertificateStateChangedException>(() => service.IssueAsync(
            new AcmeIssueRequest(
                "My Site", ["example.com"], "admin@example.com",
                Force: true, ExpectedCurrentThumbprint: "OLD")));

        Assert.Contains("changed", exception.Message, StringComparison.OrdinalIgnoreCase);
        iis.VerifyNoOtherCalls();
        protocol.VerifyNoOtherCalls();
        managed.VerifyAll();
        operationLock.VerifyAll();
        scope.VerifyAll();
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task IssueAsync_BindingFails_RemovesCertificateOnlyWhenBindingsWereRestored(
        bool previousBindingsRestored,
        bool expectRemoval)
    {
        var challenge = new AcmeHttpChallenge("example.com", "token", "key-authorization");
        var iis = MockIis(CreateSite("example.com"));
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                It.IsAny<string>(),
                It.IsAny<IReadOnlyList<string>>(),
                "AABBCC",
                "My",
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new IisBindingException(
                "binding failed",
                previousBindingsRestored,
                new InvalidOperationException("IIS error")));
        var order = new Mock<IAcmeOrderSession>(MockBehavior.Strict);
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.ValidateAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        order.Setup(value => value.FinalizeAsync(
                "example.com",
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateBundle());
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                It.IsAny<string>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<CertificateAuthority>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var handler = new Mock<IChallengeHandler>(MockBehavior.Strict);
        handler.Setup(value => value.PrepareAsync(
                It.IsAny<string>(),
                challenge,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TrackingCleanup());
        var probe = new Mock<IChallengeProbe>(MockBehavior.Strict);
        probe.Setup(value => value.VerifyAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var artifacts = new Mock<ICertificateArtifactStore>(MockBehavior.Strict);
        artifacts.Setup(value => value.SaveAsync(
                It.IsAny<string>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<CertificateBundle>(),
                It.IsAny<string?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", "certificate.pfx", ["example.com"]));
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.ImportPfxAsync(
                It.IsAny<byte[]>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddDays(90),
                true));
        if (expectRemoval)
        {
            certificateStore.Setup(value => value.RemoveAsync("AABBCC", CancellationToken.None))
                .Returns(Task.CompletedTask);
        }

        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            handler.Object,
            probe.Object,
            artifacts.Object,
            certificateStore.Object,
            Mock.Of<IManagedCertificateStore>());

        await Assert.ThrowsAsync<IisBindingException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        certificateStore.Verify(
            value => value.RemoveAsync("AABBCC", CancellationToken.None),
            expectRemoval ? Times.Once() : Times.Never());
    }

    private static Mock<IIisService> MockIis(IisSite site)
    {
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([site]);
        return iis;
    }

    private static IisSite CreateSite(string host) => new(
        1,
        "My Site",
        "Started",
        "C:\\inetpub\\site",
        [new IisBinding("http", "*", 80, host, null, null, false)]);

    private static CertificateBundle CreateBundle()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=example.com",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        return new CertificateBundle(certificate.ExportCertificatePem(), [1, 2, 3]);
    }

    private sealed class TrackingCleanup : IAsyncDisposable
    {
        public bool WasDisposed { get; private set; }

        public ValueTask DisposeAsync()
        {
            WasDisposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
