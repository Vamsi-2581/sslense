using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Validation;

public sealed class Http01HandlerTests
{
    [Fact]
    public async Task PrepareAndDispose_WritesChallengeThenRestoresExistingWebConfig()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sslense-test-{Guid.NewGuid():N}");
        var challengeDirectory = Path.Combine(root, ".well-known", "acme-challenge");
        var webConfigPath = Path.Combine(challengeDirectory, "web.config");
        var tokenPath = Path.Combine(challengeDirectory, "token");
        Directory.CreateDirectory(challengeDirectory);
        await File.WriteAllTextAsync(webConfigPath, "original-config");
        var handler = new Http01Handler(new PhysicalFileSystem());

        try
        {
            await using (await handler.PrepareAsync(
                root,
                new AcmeHttpChallenge("example.com", "token", "key-authorization"),
                CancellationToken.None))
            {
                Assert.Equal("key-authorization", await File.ReadAllTextAsync(tokenPath));
                var generatedWebConfig = await File.ReadAllTextAsync(webConfigPath);
                Assert.Contains("SSLenseAcmeChallenge", generatedWebConfig);
                Assert.Contains("fileExtension=\".\" mimeType=\"text/plain\"", generatedWebConfig);
            }

            Assert.False(File.Exists(tokenPath));
            Assert.Equal("original-config", await File.ReadAllTextAsync(webConfigPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CleanUpAbandonedAsync_AfterCrash_RestoresSiteOnlyOnceOwnerHasExited()
    {
        var fileSystem = new InMemoryFileSystem();
        var ownerAlive = true;
        var journal = new JsonChallengeJournal(fileSystem, JournalDirectory, (_, _) => ownerAlive);
        var handler = new Http01Handler(fileSystem, journal);
        fileSystem.Files[WebConfigPath] = "original-config";

        // Prepared but never disposed: the process "crashed" mid-validation.
        _ = await handler.PrepareAsync(SiteRoot, Challenge, CancellationToken.None);
        Assert.Equal("key-authorization", fileSystem.Files[TokenPath]);
        Assert.Single(fileSystem.GetFiles(JournalDirectory, "*.json"));

        // A live owner may still be validating, so nothing is touched.
        Assert.Empty(await handler.CleanUpAbandonedAsync(CancellationToken.None));
        Assert.True(fileSystem.FileExists(TokenPath));

        ownerAlive = false;
        var messages = await handler.CleanUpAbandonedAsync(CancellationToken.None);

        Assert.Single(messages);
        Assert.False(fileSystem.FileExists(TokenPath));
        Assert.Equal("original-config", fileSystem.Files[WebConfigPath]);
        Assert.Empty(fileSystem.GetFiles(JournalDirectory, "*.json"));
    }

    [Fact]
    public async Task Dispose_CompletesTheJournalEntry()
    {
        var fileSystem = new InMemoryFileSystem();
        var handler = new Http01Handler(fileSystem, new JsonChallengeJournal(fileSystem, JournalDirectory, (_, _) => false));

        await (await handler.PrepareAsync(SiteRoot, Challenge, CancellationToken.None)).DisposeAsync();

        Assert.Empty(fileSystem.GetFiles(JournalDirectory, "*.json"));
        Assert.False(fileSystem.FileExists(TokenPath));
        Assert.False(fileSystem.FileExists(WebConfigPath));
    }

    [Fact]
    public void IsProcessAlive_RecognizesCurrentProcessAndRejectsReusedOrMissingIds()
    {
        var (processId, startedAt) = JsonChallengeJournal.CurrentProcess;

        Assert.True(JsonChallengeJournal.IsProcessAlive(processId, startedAt));
        Assert.False(JsonChallengeJournal.IsProcessAlive(processId, startedAt.AddHours(-1)));
        Assert.False(JsonChallengeJournal.IsProcessAlive(int.MaxValue - 1, startedAt));
    }

    private const string SiteRoot = @"C:\inetpub\site";
    private const string JournalDirectory = @"C:\ProgramData\SSLense\challenges";
    private static readonly string TokenPath = Path.Combine(SiteRoot, ".well-known", "acme-challenge", "token");
    private static readonly string WebConfigPath = Path.Combine(SiteRoot, ".well-known", "acme-challenge", "web.config");
    private static readonly AcmeHttpChallenge Challenge = new("example.com", "token", "key-authorization");
}
