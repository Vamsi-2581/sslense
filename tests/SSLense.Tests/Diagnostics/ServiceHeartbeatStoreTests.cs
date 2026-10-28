using SSLense.Core.Diagnostics;
using Xunit;

namespace SSLense.Tests.Diagnostics;

public sealed class ServiceHeartbeatStoreTests
{
    private const string HeartbeatPath = @"C:\ProgramData\SSLense\service-heartbeat.json";

    [Fact]
    public async Task SaveThenGet_RoundTripsAndStampsTheSchemaVersion()
    {
        var fileSystem = new InMemoryFileSystem();
        var store = new JsonServiceHeartbeatStore(fileSystem, HeartbeatPath);
        var heartbeat = new ServiceHeartbeat(
            "0.9.0",
            new DateTimeOffset(2026, 10, 28, 8, 0, 0, TimeSpan.Zero),
            LastCycleCompletedAt: new DateTimeOffset(2026, 10, 28, 9, 0, 0, TimeSpan.Zero),
            LastCycleSucceeded: false,
            LastCycleMessage: "Renewal is failing for: My Site.");

        Assert.Null(await store.GetAsync());
        await store.SaveAsync(heartbeat);

        Assert.Equal(heartbeat, await store.GetAsync());
        Assert.Contains("\"schemaVersion\": 1", fileSystem.Files[HeartbeatPath], StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAsync_NewerSchema_IsRefused()
    {
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[HeartbeatPath] = """{ "version": "9.0.0", "processStartedAt": "2026-10-28T08:00:00+00:00", "schemaVersion": 99 }""";

        await Assert.ThrowsAsync<InvalidDataException>(() => new JsonServiceHeartbeatStore(fileSystem, HeartbeatPath).GetAsync());
    }
}
