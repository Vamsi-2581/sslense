using System.Text.RegularExpressions;
using SSLense.Core.Config;

namespace SSLense.Core.Logs;

internal sealed partial class LogService(IFileSystem fileSystem) : ILogService
{
    public async Task<LogSnapshot> ReadCurrentAsync(
        string level,
        int maximumLines = 1000,
        CancellationToken cancellationToken = default)
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
        return new LogSnapshot(file, Filter(lines, level).TakeLast(maximumLines).ToArray());
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
    /// Keeps the entries of the chosen level. An exception's stack trace follows its entry on lines without a level,
    /// so those lines belong to the entry above them; without this, filtering by Error would hide every stack trace.
    /// </summary>
    internal static IEnumerable<string> Filter(IEnumerable<string> lines, string level)
    {
        var include = level == "All";
        foreach (var line in lines)
        {
            var match = EntryLevel().Match(line);
            if (match.Success)
            {
                include = Matches(match.Groups["level"].Value, level);
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

    // Serilog's file format ("2026-10-31 10:00:00.123 +00:00 [ERR] ...") and the console format ("[10:00:00 ERR] ...").
    [GeneratedRegex(@"^(?:\d{4}-\d{2}-\d{2} [\d:.]+ [+-]\d{2}:\d{2} \[(?<level>[A-Z]{3})\]|\[\d{2}:\d{2}:\d{2} (?<level>[A-Z]{3})\])")]
    private static partial Regex EntryLevel();
}
