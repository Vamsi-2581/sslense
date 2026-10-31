using Moq;
using SSLense.Core.Config;
using SSLense.Core.Logs;
using Xunit;

namespace SSLense.Tests.Logs;

public sealed class LogServiceTests
{
    [Fact]
    public async Task ReadCurrentAsync_SelectsNewestFileAndFiltersLevel()
    {
        var oldFile = Path.Combine(AppPaths.LogDirectory, "sslense-20261026.log");
        var currentFile = Path.Combine(AppPaths.LogDirectory, "sslense-20261027.log");
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        fileSystem.Setup(value => value.GetFiles(AppPaths.LogDirectory, "sslense-*.log"))
            .Returns([oldFile, currentFile]);
        fileSystem.Setup(value => value.ReadAllLinesAsync(currentFile, It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                "[20:00:00 INF] Information",
                "[20:00:01 WRN] Warning",
                "[20:00:02 ERR] Error",
                "[20:00:03 FTL] Fatal"
            ]);
        var service = new LogService(fileSystem.Object);

        var snapshot = await service.ReadCurrentAsync("Error");

        Assert.Equal(currentFile, snapshot.FilePath);
        Assert.Equal(2, snapshot.Lines.Count);
        Assert.All(snapshot.Lines, line =>
            Assert.True(line.Contains(" ERR]", StringComparison.Ordinal) ||
                        line.Contains(" FTL]", StringComparison.Ordinal)));
        fileSystem.VerifyAll();
    }

    [Fact]
    public void Filter_RealFileFormat_KeepsStackTracesWithTheirEntry()
    {
        string[] lines =
        [
            "2026-10-31 10:00:00.100 +00:00 [INF] Started",
            "2026-10-31 10:00:01.200 +00:00 [ERR] Dashboard operation failed",
            "System.Security.Cryptography.CryptographicException: The object identifier does not represent a valid object.",
            "   at SSLense.Core.Certificates.CertificateInspector.GetDnsNames(X509Certificate2 certificate)",
            "2026-10-31 10:00:02.300 +00:00 [WRN] Slow",
            "   continuation of the warning"
        ];

        Assert.Equal(lines[1..4], LogService.Filter(lines, "Error"));
        Assert.Equal(lines[4..], LogService.Filter(lines, "Warning"));
        Assert.Equal(lines, LogService.Filter(lines, "All"));
    }

    [Fact]
    public void Filter_Since_HidesEarlierEntriesWithTheirStackTraces()
    {
        string[] lines =
        [
            "2026-10-31 06:44:59.263 +00:00 [ERR] Could not initialize the issue wizard",
            "System.Runtime.InteropServices.COMException (0x800710D8): The object identifier does not represent a valid object.",
            "2026-10-31 07:14:32.510 +00:00 [ERR] Settings operation failed",
            "System.ArgumentException: The sender address is not a valid email address."
        ];

        var since = new DateTimeOffset(2026, 10, 31, 9, 0, 0, TimeSpan.FromHours(2)); // 07:00 UTC

        Assert.Equal(lines[2..], LogService.Filter(lines, "All", since));
        Assert.Equal(lines[2..], LogService.Filter(lines, "Error", since));
    }

    [Fact]
    public async Task SaveCopyAsync_WritesTodaysLogToTheGivenFolder()
    {
        var fileSystem = new InMemoryFileSystem();
        var log = Path.Combine(AppPaths.LogDirectory, "sslense-20261031.log");
        fileSystem.Files[log] = "2026-10-31 10:00:00.100 +00:00 [INF] Started\n";

        var copy = await new LogService(fileSystem).SaveCopyAsync(@"C:\Users\admin\Desktop");

        Assert.StartsWith(@"C:\Users\admin\Desktop\sslense-20261031-", copy, StringComparison.Ordinal);
        Assert.Contains("[INF] Started", fileSystem.Files[copy], StringComparison.Ordinal);
    }
}
