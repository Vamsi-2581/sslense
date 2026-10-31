using Moq;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Config;

public sealed class JsonManagedCertificateStoreTests
{
    private const string StatePath = @"C:\ProgramData\SSLense\managed-certificates.json";
    private const string LockPath = @"C:\ProgramData\SSLense\managed-certificates.lock";

    [Fact]
    public async Task UpsertAsync_UsesLockAndPersistsRecordAtomically()
    {
        string? json = null;
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        fileSystem.Setup(value => value.AcquireExclusiveFileLockAsync(
                LockPath,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new NoOpLock());
        fileSystem.Setup(value => value.FileExists(StatePath)).Returns(() => json is not null);
        fileSystem.Setup(value => value.WriteAllTextAtomicAsync(
                StatePath,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((_, contents, _) => json = contents)
            .Returns(Task.CompletedTask);
        fileSystem.Setup(value => value.ReadAllTextAsync(StatePath, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => json!);
        var store = new JsonManagedCertificateStore(fileSystem.Object, StatePath, LockPath);
        var certificate = new ManagedCertificate(
            "My Site", ["example.com"], "admin@example.com", "AABBCC",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));

        await store.UpsertAsync(certificate);
        var saved = Assert.Single(await store.GetAllAsync());

        Assert.Equal(certificate.SiteName, saved.SiteName);
        Assert.Equal(certificate.Hosts, saved.Hosts);
        Assert.Equal(certificate.Email, saved.Email);
        Assert.Equal(certificate.Thumbprint, saved.Thumbprint);
        Assert.Equal(certificate.NotBefore, saved.NotBefore);
        Assert.Equal(certificate.NotAfter, saved.NotAfter);
        Assert.Contains("AABBCC", json, StringComparison.Ordinal);
        fileSystem.Verify(value => value.AcquireExclusiveFileLockAsync(
            LockPath, It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Fact]
    public async Task GetAllAsync_LegacyArrayFile_ReadsWithStableIdsAndDoesNotRewrite()
    {
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[StatePath] = LegacyJson;
        var store = new JsonManagedCertificateStore(fileSystem, StatePath, LockPath);

        var first = Assert.Single(await store.GetAllAsync());
        var second = Assert.Single(await store.GetAllAsync());

        Assert.Equal("My Site", first.SiteName);
        Assert.NotEqual(Guid.Empty, first.Id);
        Assert.Equal(first.Id, second.Id);
        Assert.Equal(LegacyJson, fileSystem.Files[StatePath]);
        Assert.False(fileSystem.FileExists($"{StatePath}.v0.bak"));
    }

    [Fact]
    public async Task UpdateAsync_LegacyArrayFile_BacksUpThenWritesVersionedDocument()
    {
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[StatePath] = LegacyJson;
        var store = new JsonManagedCertificateStore(fileSystem, StatePath, LockPath);
        var migratedId = Assert.Single(await store.GetAllAsync()).Id;

        await store.RecordRenewalFailureAsync(
            "My Site", DateTimeOffset.UtcNow, "failed", DateTimeOffset.UtcNow.AddHours(1));

        Assert.Equal(LegacyJson, fileSystem.Files[$"{StatePath}.v0.bak"]);
        Assert.Contains($"\"schemaVersion\": {StateSchema.ManagedCertificates}", fileSystem.Files[StatePath], StringComparison.Ordinal);
        Assert.Equal(migratedId, Assert.Single(await store.GetAllAsync()).Id);
    }

    [Fact]
    public async Task GetAllAsync_NewerSchema_FailsWithoutChangingTheFile()
    {
        var fileSystem = new InMemoryFileSystem();
        const string newer = """{ "schemaVersion": 99, "certificates": [] }""";
        fileSystem.Files[StatePath] = newer;
        var store = new JsonManagedCertificateStore(fileSystem, StatePath, LockPath);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => store.GetAllAsync());
        await Assert.ThrowsAsync<InvalidDataException>(() => store.UpsertAsync(CreateCertificate()));

        Assert.Contains("schema version 99", exception.Message, StringComparison.Ordinal);
        Assert.Equal(newer, fileSystem.Files[StatePath]);
    }

    [Fact]
    public async Task UpsertAsync_RecordWithoutId_KeepsTheSitesExistingId()
    {
        var store = new JsonManagedCertificateStore(new InMemoryFileSystem(), StatePath, LockPath);
        await store.UpsertAsync(CreateCertificate());
        var originalId = Assert.Single(await store.GetAllAsync()).Id;

        await store.UpsertAsync(CreateCertificate() with { Thumbprint = "NEW" });

        var renewed = Assert.Single(await store.GetAllAsync());
        Assert.Equal("NEW", renewed.Thumbprint);
        Assert.Equal(originalId, renewed.Id);
    }

    [Fact]
    public async Task RecordRenewalFailureAsync_IncrementsFailuresAndPersistsNextRetry()
    {
        var store = new JsonManagedCertificateStore(new InMemoryFileSystem(), StatePath, LockPath);
        await store.UpsertAsync(CreateCertificate());
        var retryAt = new DateTimeOffset(2026, 10, 29, 12, 0, 0, TimeSpan.Zero);

        await store.RecordRenewalFailureAsync("My Site", DateTimeOffset.UtcNow, "first", retryAt.AddHours(-1));
        var updated = await store.RecordRenewalFailureAsync("my site", DateTimeOffset.UtcNow, "second", retryAt);

        var saved = Assert.Single(await store.GetAllAsync());
        Assert.Equal(2, updated!.ConsecutiveFailures);
        Assert.Equal(2, saved.ConsecutiveFailures);
        Assert.Equal(retryAt, saved.NextRetryAt);
        Assert.Equal("second", saved.LastRenewalMessage);
        Assert.Null(await store.RecordRenewalFailureAsync("Other", DateTimeOffset.UtcNow, "x", retryAt));
    }

    [Fact]
    public async Task RecordRemindersAsync_IgnoresCertificatesReplacedSinceTheDigestWasBuilt()
    {
        var store = new JsonManagedCertificateStore(new InMemoryFileSystem(), StatePath, LockPath);
        await store.UpsertAsync(CreateCertificate());
        var sentAt = new DateTimeOffset(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);

        await store.RecordRemindersAsync([new ReminderRecord("My Site", "AABBCC", Reminded: false, NoticeSent: true)], sentAt);
        await store.RecordRemindersAsync([new ReminderRecord("My Site", "REPLACED", Reminded: true, NoticeSent: false)], sentAt.AddDays(1));

        var record = Assert.Single(await store.GetAllAsync());
        Assert.True(record.UpcomingNoticeSent);
        Assert.Null(record.LastRemindedAt);
    }

    [Theory]
    [InlineData(ReminderMode.Snoozed, ReminderMode.On)]
    [InlineData(ReminderMode.OffUntilReplaced, ReminderMode.On)]
    [InlineData(ReminderMode.Off, ReminderMode.Off)]
    public async Task UpsertAsync_NewCertificate_ResetsRemindersUnlessOffPermanently(ReminderMode before, ReminderMode after)
    {
        var store = new JsonManagedCertificateStore(new InMemoryFileSystem(), StatePath, LockPath);
        await store.UpsertAsync(CreateCertificate() with
        {
            Reminders = before,
            SnoozedUntil = DateTimeOffset.UtcNow.AddDays(5),
            LastRemindedAt = DateTimeOffset.UtcNow,
            UpcomingNoticeSent = true
        });

        // A renewal or import builds a fresh record; the store carries the reminder state across.
        await store.UpsertAsync(CreateCertificate());
        Assert.Equal(before, Assert.Single(await store.GetAllAsync()).Reminders);

        await store.UpsertAsync(CreateCertificate() with { Thumbprint = "NEW" });
        var replaced = Assert.Single(await store.GetAllAsync());
        Assert.Equal(after, replaced.Reminders);
        Assert.Null(replaced.SnoozedUntil);
        Assert.Null(replaced.LastRemindedAt);
        Assert.False(replaced.UpcomingNoticeSent);
    }

    [Fact]
    public async Task SchemaTwoFile_DropsTheOldReminderMarkersAndStartsWithRemindersOn()
    {
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[StatePath] = """
            {
              "schemaVersion": 2,
              "certificates": [
                { "siteName": "My Site", "hosts": [ "example.com" ], "email": "", "thumbprint": "AABBCC",
                  "notBefore": "2026-09-01T00:00:00+00:00", "notAfter": "2026-11-30T00:00:00+00:00",
                  "source": 1, "expiryWarningSent": 1, "reminderDaysSent": 14 }
              ]
            }
            """;
        var store = new JsonManagedCertificateStore(fileSystem, StatePath, LockPath);

        Assert.Equal(ReminderMode.On, Assert.Single(await store.GetAllAsync()).Reminders);
        await store.RecordRemindersAsync([new ReminderRecord("My Site", "AABBCC", Reminded: true, NoticeSent: false)], DateTimeOffset.UtcNow);

        Assert.True(fileSystem.Files.ContainsKey($"{StatePath}.v2.bak"));
        Assert.DoesNotContain("reminderDaysSent", fileSystem.Files[StatePath], StringComparison.Ordinal);
        Assert.DoesNotContain("expiryWarningSent", fileSystem.Files[StatePath], StringComparison.Ordinal);
    }

    private const string LegacyJson = """
        [
          {
            "siteName": "My Site",
            "hosts": [ "example.com" ],
            "email": "admin@example.com",
            "thumbprint": "AABBCC",
            "notBefore": "2026-09-01T00:00:00+00:00",
            "notAfter": "2026-11-30T00:00:00+00:00",
            "environment": 0
          }
        ]
        """;

    private static ManagedCertificate CreateCertificate() => new(
        "My Site", ["example.com"], "admin@example.com", "AABBCC",
        DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));

    private sealed class NoOpLock : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
