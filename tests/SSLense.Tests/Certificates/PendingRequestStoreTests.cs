using System.Text.Json.Nodes;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Certificates;

public sealed class PendingRequestStoreTests
{
    private const string StatePath = @"C:\data\pending-requests.json";
    private const string LockPath = @"C:\data\pending-requests.lock";

    [Fact]
    public async Task SaveAsync_OneRequestPerSite_ReturnsTheOneItReplaces()
    {
        var files = new InMemoryFileSystem();
        var store = new JsonPendingRequestStore(files, StatePath, LockPath);

        Assert.Null(await store.SaveAsync(Request("SSLense-request-1")));
        var replaced = await store.SaveAsync(Request("SSLense-request-2") with { SiteName = "SHOP" });

        Assert.Equal("SSLense-request-1", replaced!.KeyName);
        var saved = Assert.Single(await new JsonPendingRequestStore(files, StatePath, LockPath).GetAllAsync());
        Assert.Equal("SSLense-request-2", saved.KeyName);
        Assert.Equal(["shop.example.com", "www.shop.example.com"], saved.Hosts);
        Assert.Equal(StateSchema.PendingRequests, (int)JsonNode.Parse(files.Files[StatePath])!["schemaVersion"]!);
    }

    [Fact]
    public async Task RemoveAsync_DropsOnlyThatSite()
    {
        var store = new JsonPendingRequestStore(new InMemoryFileSystem(), StatePath, LockPath);
        await store.SaveAsync(Request("SSLense-request-1"));
        await store.SaveAsync(Request("SSLense-request-2") with { SiteName = "Blog" });

        await store.RemoveAsync("shop");

        Assert.Null(await store.GetAsync("Shop"));
        Assert.NotNull(await store.GetAsync("Blog"));
    }

    private static PendingCertificateRequest Request(string keyName) => new(
        "Shop", ["shop.example.com", "www.shop.example.com"], keyName, PrivateKeyTypes.Rsa2048,
        "-----BEGIN CERTIFICATE REQUEST-----", DateTimeOffset.UtcNow);
}
