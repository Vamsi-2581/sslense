using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using Xunit;

namespace SSLense.Tests.Certificates;

public sealed class CertificateRecoveryServiceTests
{
    [Fact]
    public async Task RecoverAsync_ImportedCertificate_CompletesBindingsAndState()
    {
        var certificate = new ManagedCertificate(
            "My Site", ["example.com"], "admin@example.com", "AABBCC",
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(44));
        var transaction = new CertificateTransaction(
            Guid.NewGuid(), certificate, "OLD",
            CertificateTransactionStage.CertificateImported, DateTimeOffset.UtcNow);
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([transaction]);
        journal.Setup(value => value.GetAsync(transaction.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction);
        journal.Setup(value => value.UpdateStageAsync(
                transaction.Id, CertificateTransactionStage.BindingsUpdated, CancellationToken.None))
            .Returns(Task.CompletedTask);
        journal.Setup(value => value.UpdateStageAsync(
                transaction.Id, CertificateTransactionStage.StateSaved, CancellationToken.None))
            .Returns(Task.CompletedTask);
        journal.Setup(value => value.CompleteAsync(transaction.Id, CancellationToken.None))
            .Returns(Task.CompletedTask);
        var scope = new Mock<IAsyncDisposable>(MockBehavior.Strict);
        scope.Setup(value => value.DisposeAsync()).Returns(ValueTask.CompletedTask);
        var operationLock = new Mock<ICertificateOperationLock>(MockBehavior.Strict);
        operationLock.Setup(value => value.TryAcquire("My Site"))
            .Returns(scope.Object);
        var store = new Mock<ICertificateStore>(MockBehavior.Strict);
        store.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC", certificate.NotBefore, certificate.NotAfter, true));
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [])]);
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                "My Site",
                It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "example.com" })),
                "AABBCC",
                "My",
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.UpsertAsync(certificate, CancellationToken.None))
            .Returns(Task.CompletedTask);
        var service = new CertificateRecoveryService(
            journal.Object, operationLock.Object, store.Object, managed.Object, iis.Object);

        var messages = await service.RecoverAsync();

        Assert.True(Assert.Single(messages).Succeeded);
        journal.VerifyAll();
        operationLock.VerifyAll();
        scope.VerifyAll();
        store.VerifyAll();
        iis.VerifyAll();
        managed.VerifyAll();
    }

    [Fact]
    public async Task RecoverAsync_LockHeldByLiveProcess_SkipsTransactionWithoutWaiting()
    {
        var transaction = CreateTransaction("My Site");
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([transaction]);
        var operationLock = new Mock<ICertificateOperationLock>(MockBehavior.Strict);
        operationLock.Setup(value => value.TryAcquire("My Site")).Returns((IAsyncDisposable?)null);
        var service = CreateService(journal, operationLock);

        var results = await service.RecoverAsync();

        Assert.Empty(results);
        journal.Verify(value => value.GetAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task RecoverAsync_SiteDeleted_AbandonsTransactionInsteadOfThrowing()
    {
        var transaction = CreateTransaction("Deleted Site");
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([transaction]);
        journal.Setup(value => value.GetAsync(transaction.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction);
        journal.Setup(value => value.CompleteAsync(transaction.Id, CancellationToken.None))
            .Returns(Task.CompletedTask);
        var store = new Mock<ICertificateStore>(MockBehavior.Strict);
        store.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC", transaction.Certificate.NotBefore, transaction.Certificate.NotAfter, true));
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var service = CreateService(journal, MockLock(), store, iis);

        var result = Assert.Single(await service.RecoverAsync());

        Assert.False(result.Succeeded);
        Assert.Contains("no longer exists", result.Message, StringComparison.Ordinal);
        journal.VerifyAll();
    }

    [Fact]
    public async Task RecoverAsync_UnreadableJournal_ReportsFailureInsteadOfThrowing()
    {
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidDataException("contains invalid JSON"));
        var service = CreateService(journal, new Mock<ICertificateOperationLock>(MockBehavior.Strict));

        var result = Assert.Single(await service.RecoverAsync());

        Assert.False(result.Succeeded);
        Assert.Contains("invalid JSON", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RecoverAsync_OneTransactionFails_StillRecoversTheOthers()
    {
        var failing = CreateTransaction("Broken Site");
        var healthy = CreateTransaction("My Site") with { Stage = CertificateTransactionStage.StateSaved };
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([failing, healthy]);
        journal.Setup(value => value.GetAsync(failing.Id, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new IOException("disk error"));
        journal.Setup(value => value.GetAsync(healthy.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(healthy);
        journal.Setup(value => value.CompleteAsync(healthy.Id, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var service = CreateService(journal, MockLock());

        var results = await service.RecoverAsync();

        Assert.Collection(
            results,
            result => Assert.False(result.Succeeded),
            result => Assert.True(result.Succeeded));
        journal.VerifyAll();
    }

    [Fact]
    public async Task RecoverAsync_TransactionFromNewerVersion_IsReportedAndLeftUntouched()
    {
        var transaction = CreateTransaction("My Site") with { SchemaVersion = 99 };
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([transaction]);
        journal.Setup(value => value.GetAsync(transaction.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction);
        var service = CreateService(journal, MockLock());

        var result = Assert.Single(await service.RecoverAsync());

        Assert.False(result.Succeeded);
        Assert.Contains("schema version 99", result.Message, StringComparison.Ordinal);
        journal.Verify(value => value.CompleteAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task RecoverAsync_CleansUpAbandonedChallengeFilesFirst()
    {
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var challenges = new Mock<SSLense.Core.Validation.IChallengeHandler>(MockBehavior.Strict);
        challenges.Setup(value => value.CleanUpAbandonedAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(["Removed HTTP-01 challenge files left in 'C:\\inetpub\\site'."]);
        var service = new CertificateRecoveryService(
            journal.Object,
            new Mock<ICertificateOperationLock>(MockBehavior.Strict).Object,
            new Mock<ICertificateStore>(MockBehavior.Strict).Object,
            new Mock<IManagedCertificateStore>(MockBehavior.Strict).Object,
            new Mock<IIisService>(MockBehavior.Strict).Object,
            challenges.Object);

        var result = Assert.Single(await service.RecoverAsync());

        Assert.True(result.Succeeded);
        Assert.Contains("challenge files", result.Message, StringComparison.Ordinal);
    }

    private static CertificateTransaction CreateTransaction(string siteName) => new(
        Guid.NewGuid(),
        new ManagedCertificate(
            siteName, ["example.com"], "admin@example.com", "AABBCC",
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(44)),
        "OLD",
        CertificateTransactionStage.CertificateImported,
        DateTimeOffset.UtcNow);

    private static Mock<ICertificateOperationLock> MockLock()
    {
        var scope = new Mock<IAsyncDisposable>();
        var operationLock = new Mock<ICertificateOperationLock>(MockBehavior.Strict);
        operationLock.Setup(value => value.TryAcquire(It.IsAny<string>())).Returns(scope.Object);
        return operationLock;
    }

    private static CertificateRecoveryService CreateService(
        Mock<ICertificateTransactionJournal> journal,
        Mock<ICertificateOperationLock> operationLock,
        Mock<ICertificateStore>? store = null,
        Mock<IIisService>? iis = null) =>
        new(
            journal.Object,
            operationLock.Object,
            (store ?? new Mock<ICertificateStore>(MockBehavior.Strict)).Object,
            new Mock<IManagedCertificateStore>(MockBehavior.Strict).Object,
            (iis ?? new Mock<IIisService>(MockBehavior.Strict)).Object);
}
