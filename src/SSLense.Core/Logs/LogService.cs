using System.Globalization;
using System.Text.RegularExpressions;
using SSLense.Core.Config;

namespace SSLense.Core.Logs;

internal sealed partial class LogService(IFileSystem fileSystem) : ILogService
{
    public async Task<LogSnapshot> ReadCurrentAsync(
        string level,
        int maximumLines = 1000,
        CancellationToken cancellationToken = default,
        DateTimeOffset? since = null)
    {
        if (maximumLines <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumLines));
        }

        if (FindCurrentFile() is not { } file)
        {
            return new LogSnapshot(null, []);
        }

        var lines = await fileSystem.ReadAllLinesAsync(file, cancellationToken).ConfigureAwait(false);
        return new LogSnapshot(file, Filter(lines, level, since).TakeLast(maximumLines).ToArray());
    }

    public async Task<string> SaveCopyAsync(string directory, CancellationToken cancellationToken = default)
    {
        var file = FindCurrentFile()
            ?? throw new InvalidOperationException($"There is no log file in '{AppPaths.LogDirectory}' yet.");
        // Read with sharing: the service and other SSLense processes keep today's file open for writing.
        var lines = await fileSystem.ReadAllLinesAsync(file, cancellationToken).ConfigureAwait(false);
        var copy = Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(file)}-{DateTime.Now:HHmmss}.txt");
        await fileSystem.WriteAllTextAsync(copy, string.Join(Environment.NewLine, lines) + Environment.NewLine, cancellationToken)
            .ConfigureAwait(false);
        return copy;
    }

    private string? FindCurrentFile() =>
        fileSystem.GetFiles(AppPaths.LogDirectory, "sslense-*.log")
            .OrderByDescending(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

    /// <summary>
    /// Keeps the entries of the chosen level, written at or after <paramref name="since"/>. An exception's stack trace
    /// follows its entry on lines without a level, so those lines belong to the entry above them; without this,
    /// filtering by Error would hide every stack trace.
    /// </summary>
    internal static IEnumerable<string> Filter(IEnumerable<string> lines, string level, DateTimeOffset? since = null)
    {
        var include = level == "All" && since is null;
        foreach (var line in lines)
        {
            var match = EntryLevel().Match(line);
            if (match.Success)
            {
                include = Matches(match.Groups["level"].Value, level) && !IsBefore(match.Groups["time"].Value, since);
            }

            if (include)
            {
                yield return line;
            }
        }
    }

    private static bool Matches(string entryLevel, string level) => level switch
    {
        "Debug" => entryLevel is "DBG" or "VRB",
        "Information" => entryLevel == "INF",
        "Warning" => entryLevel == "WRN",
        "Error" => entryLevel is "ERR" or "FTL",
        _ => true
    };

    private static bool IsBefore(string time, DateTimeOffset? since) =>
        since is { } start &&
        DateTimeOffset.TryParseExact(time, "yyyy-MM-dd HH:mm:ss.fff zzz", CultureInfo.InvariantCulture, DateTimeStyles.None, out var at) &&
        at < start;

    // Serilog's file format ("2026-10-31 10:00:00.123 +00:00 [ERR] ...") and the console format ("[10:00:00 ERR] ...").
    [GeneratedRegex(@"^(?:(?<time>\d{4}-\d{2}-\d{2} [\d:.]+ [+-]\d{2}:\d{2}) \[(?<level>[A-Z]{3})\]|\[\d{2}:\d{2}:\d{2} (?<level>[A-Z]{3})\])")]
    private static partial Regex EntryLevel();
}
