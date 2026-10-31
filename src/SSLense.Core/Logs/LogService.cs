using System.Text.RegularExpressions;
using SSLense.Core.Config;

namespace SSLense.Core.Logs;

/// <param name="exclusive">Runs an operation under <see cref="LogFileLock"/>; replaced in tests.</param>
internal sealed partial class LogService(
    IFileSystem fileSystem,
    Func<Func<Task<string?>>, Task<string?>>? exclusive = null) : ILogService
{
    /// <summary>Backups of cleared logs kept; older ones are deleted when a log is cleared again.</summary>
    internal const int BackupsKept = 20;

    internal static string BackupDirectory => Path.Combine(AppPaths.LogDirectory, "cleared");

    public async Task<LogSnapshot> ReadCurrentAsync(
        string level,
        int maximumLines = 1000,
        CancellationToken cancellationToken = default)
    {
        if (FindCurrentFile() is not { } file)
        {
            return new LogSnapshot(null, []);
        }

        return await ReadAsync(file, level, null, maximumLines, cancellationToken).ConfigureAwait(false);
    }

    public IReadOnlyList<LogFileInfo> ListFiles() =>
        DailyFiles().Select(path => Describe(path, isBackup: false))
            .Concat(Backups().Select(path => Describe(path, isBackup: true)))
            .ToArray();

    public async Task<LogSnapshot> ReadAsync(
        string filePath,
        string level,
        string? search,
        int maximumLines,
        CancellationToken cancellationToken = default)
    {
        if (maximumLines <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumLines));
        }

        var file = EnsureLogFile(filePath);
        var lines = await fileSystem.ReadAllLinesAsync(file, cancellationToken).ConfigureAwait(false);
        return new LogSnapshot(file, Filter(lines, level, search).TakeLast(maximumLines).ToArray());
    }

    public async Task<string> SaveCopyAsync(string filePath, string directory, CancellationToken cancellationToken = default)
    {
        var file = EnsureLogFile(filePath);
        // Read with sharing: the service and other SSLense processes keep today's file open for writing.
        var lines = await fileSystem.ReadAllLinesAsync(file, cancellationToken).ConfigureAwait(false);
        var copy = Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(file)}-{DateTime.Now:HHmmss}.txt");
        await fileSystem.WriteAllTextAsync(copy, string.Join(Environment.NewLine, lines) + Environment.NewLine, cancellationToken)
            .ConfigureAwait(false);
        return copy;
    }

    public async Task<string?> ClearCurrentAsync(CancellationToken cancellationToken = default)
    {
        var file = FindCurrentFile()
            ?? throw new InvalidOperationException($"There is no log file in '{AppPaths.LogDirectory}' yet.");

        // Every SSLense process writes the log under the same lock, so no entry can arrive between reading and emptying.
        var backup = await (exclusive ?? DefaultExclusive)(async () =>
            {
                var lines = await fileSystem.ReadAllLinesAsync(file, cancellationToken).ConfigureAwait(false);
                if (lines.All(string.IsNullOrEmpty))
                {
                    return null;
                }

                // The backup is written first: if that fails, the log is left as it was.
                fileSystem.CreateDirectory(BackupDirectory);
                var path = Path.Combine(BackupDirectory, $"{Path.GetFileNameWithoutExtension(file)}-cleared-{DateTime.Now:HHmmss}.log");
                await fileSystem.WriteAllTextAsync(path, string.Join(Environment.NewLine, lines) + Environment.NewLine, cancellationToken)
                    .ConfigureAwait(false);
                await fileSystem.TruncateAsync(file, CancellationToken.None).ConfigureAwait(false);
                return path;
            })
            .ConfigureAwait(false);

        if (backup is not null)
        {
            foreach (var old in Backups().Skip(BackupsKept))
            {
                fileSystem.DeleteFile(old);
            }
        }

        return backup;
    }

    private static Task<string?> DefaultExclusive(Func<Task<string?>> operation) =>
        LogFileLock.RunExclusiveAsync(operation, TimeSpan.FromSeconds(10));

    /// <summary>
    /// Keeps the entries of the chosen level that contain <paramref name="search"/>. An exception's stack trace follows
    /// its entry on lines without a level, so those lines belong to the entry above them; without this, filtering by
    /// Error would hide every stack trace.
    /// </summary>
    internal static IEnumerable<string> Filter(IEnumerable<string> lines, string level, string? search = null)
    {
        var entries = new List<List<string>>();
        foreach (var line in lines)
        {
            if (EntryLevel().IsMatch(line) || entries.Count == 0)
            {
                entries.Add([]);
            }

            entries[^1].Add(line);
        }

        return entries
            .Where(entry => Matches(EntryLevel().Match(entry[0]).Groups["level"].Value, level))
            .Where(entry => string.IsNullOrWhiteSpace(search) ||
                            entry.Any(line => line.Contains(search.Trim(), StringComparison.OrdinalIgnoreCase)))
            .SelectMany(entry => entry);
    }

    private static bool Matches(string entryLevel, string level) => level switch
    {
        "Debug" => entryLevel is "DBG" or "VRB",
        "Information" => entryLevel == "INF",
        "Warning" => entryLevel == "WRN",
        "Error" => entryLevel is "ERR" or "FTL",
        _ => true
    };

    private string? FindCurrentFile() => DailyFiles().FirstOrDefault();

    // Only files directly in each folder: backups live in a subfolder, and Serilog's retention must never see them.
    private IEnumerable<string> DailyFiles() => FilesIn(AppPaths.LogDirectory, "sslense-*.log");

    private IEnumerable<string> Backups() => FilesIn(BackupDirectory, "sslense-*.log");

    private IEnumerable<string> FilesIn(string directory, string pattern) =>
        fileSystem.GetFiles(directory, pattern)
            .Where(path => string.Equals(Path.GetDirectoryName(path), directory, StringComparison.OrdinalIgnoreCase) &&
                           path.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(Path.GetFileName, StringComparer.OrdinalIgnoreCase);

    /// <summary>Only files SSLense lists may be read or copied, never an arbitrary path.</summary>
    private string EnsureLogFile(string filePath) =>
        DailyFiles().Concat(Backups()).FirstOrDefault(path => string.Equals(path, filePath, StringComparison.OrdinalIgnoreCase))
        ?? throw new InvalidOperationException($"'{filePath}' is not an SSLense log file.");

    private static LogFileInfo Describe(string path, bool isBackup)
    {
        var info = new FileInfo(path);
        return new LogFileInfo(
            Path.GetFileName(path),
            path,
            info.Exists ? info.Length : 0,
            info.Exists ? info.LastWriteTimeUtc : DateTimeOffset.MinValue,
            isBackup);
    }

    // Serilog's file format ("2026-10-31 10:00:00.123 +00:00 [ERR] ...") and the console format ("[10:00:00 ERR] ...").
    [GeneratedRegex(@"^(?:\d{4}-\d{2}-\d{2} [\d:.]+ [+-]\d{2}:\d{2} \[(?<level>[A-Z]{3})\]|\[\d{2}:\d{2}:\d{2} (?<level>[A-Z]{3})\])")]
    private static partial Regex EntryLevel();
}
