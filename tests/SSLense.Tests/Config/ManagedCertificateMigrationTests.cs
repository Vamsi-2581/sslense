using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Config;

/// <summary>
/// Schema 1 recorded a Let's Encrypt environment (0 = staging, 1 = production). After the upgrade every record,
/// and every interrupted transaction, must keep pointing at the same CA, or a production certificate could be
/// renewed or recovered as staging.
/// </summary>
public sealed class ManagedCertificateMigrationTests
{
    private const string StatePath = @"C:\ProgramData\SSLense\managed-certificates.json";
    private const string LockPath = @"C:\ProgramData\SSLense\managed-certificates.lock";
    private const string JournalDirectory = @"C:\ProgramData\SSLense\transactions";

    private const string SchemaOneState = """
        {
          "schemaVersion": 1,
          "certificates": [
            { "siteName": "Prod Site", "hosts": [ "shop.example.com" ], "email": "a@example.com", "thumbprint": "AA",
              "notBefore": "2026-09-01T00:00:00+00:00", "notAfter": "2026-11-30T00:00:00+00:00",
              "environment": 1, "id": "11111111-1111-1111-1111-111111111111" },
            { "siteName": "Test Site", "hosts": [ "test.example.com" ], "email": "a@example.com", "thumbprint": "BB",
              "notBefore": "2026-09-01T00:00:00+00:00", "notAfter": "2026-11-30T00:00:00+00:00",
              "environment": 0, "id": "22222222-2222-2222-2222-222222222222" }
          ]
        }
        """;

    [Fact]
    public async Task SchemaOneRecords_KeepTheirCertificateAuthority()
    {
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[StatePath] = SchemaOneState;
        var store = new JsonManagedCertificateStore(fileSystem, StatePath, LockPath);

        var records = await store.GetAllAsync();

        var production = Assert.Single(records, record => record.SiteName == "Prod Site");
        var staging = Assert.Single(records, record => record.SiteName == "Test Site");
        Assert.Equal(CertificateAuthorities.LetsEncryptId, production.AuthorityId);
        Assert.Equal(CertificateAuthorities.LetsEncryptStagingId, staging.AuthorityId);
        Assert.All(records, record => Assert.Equal(CertificateSource.Acme, record.Source));
        Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), production.Id);
    }

    [Fact]
    public async Task SchemaOneFile_IsBackedUpThenRewrittenWithoutTheEnvironmentField()
    {
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[StatePath] = SchemaOneState;
        var store = new JsonManagedCertificateStore(fileSystem, StatePath, LockPath);

        await store.RecordRemindersAsync([new ReminderRecord("Prod Site", "AA", Reminded: true, NoticeSent: false)], DateTimeOffset.UtcNow);

        Assert.Equal(SchemaOneState, fileSystem.Files[$"{StatePath}.v1.bak"]);
        var rewritten = fileSystem.Files[StatePath];
        Assert.Contains($"\"schemaVersion\": {StateSchema.ManagedCertificates}", rewritten, StringComparison.Ordinal);
        Assert.Contains("\"authorityId\": \"letsencrypt\"", rewritten, StringComparison.Ordinal);
        Assert.DoesNotContain("\"environment\"", rewritten, StringComparison.Ordinal);
        Assert.Equal(CertificateAuthorities.LetsEncryptId, (await store.GetAllAsync()).Single(record => record.SiteName == "Prod Site").AuthorityId);
    }

    [Fact]
    public async Task UnversionedArray_WithEnvironment_IsUpgradedToo()
    {
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[StatePath] = """
            [ { "siteName": "Prod Site", "hosts": [ "shop.example.com" ], "email": "a@example.com", "thumbprint": "AA",
                "notBefore": "2026-09-01T00:00:00+00:00", "notAfter": "2026-11-30T00:00:00+00:00", "environment": 1 } ]
            """;

        var record = Assert.Single(await new JsonManagedCertificateStore(fileSystem, StatePath, LockPath).GetAllAsync());

        Assert.Equal(CertificateAuthorities.LetsEncryptId, record.AuthorityId);
    }

    [Fact]
    public async Task InterruptedSchemaOneTransaction_IsRecoveredWithItsProductionAuthority()
    {
        // Written by a version before certificate-authority profiles existed, then interrupted.
        var fileSystem = new InMemoryFileSystem();
        var id = Guid.NewGuid();
        fileSystem.Files[Path.Combine(JournalDirectory, $"{id:N}.json")] = $$"""
            {
              "id": "{{id}}",
              "certificate": { "siteName": "Prod Site", "hosts": [ "shop.example.com" ], "email": "a@example.com",
                "thumbprint": "CC", "notBefore": "2026-10-01T00:00:00+00:00", "notAfter": "2026-12-30T00:00:00+00:00",
                "environment": 1 },
              "previousThumbprint": "AA",
              "stage": 1,
              "startedAt": "2026-10-29T08:00:00+00:00",
              "schemaVersion": 1
            }
            """;
        var journal = new JsonCertificateTransactionJournal(fileSystem, JournalDirectory);

        var transaction = Assert.Single(await journal.GetPendingAsync());

        Assert.Equal(CertificateAuthorities.LetsEncryptId, transaction.Certificate.AuthorityId);
        Assert.Equal(CertificateSource.Acme, transaction.Certificate.Source);
    }
}
