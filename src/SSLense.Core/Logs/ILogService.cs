namespace SSLense.Core.Logs;

/// <param name="IsBackup">A copy saved by <see cref="ILogService.ClearCurrentAsync"/>, not a daily file.</param>
public sealed record LogFileInfo(string Name, string Path, long Length, DateTimeOffset LastWritten, bool IsBackup);

public interface ILogService
{
    /// <summary>The newest daily log file's entries of <paramref name="level"/>, at most <paramref name="maximumLines"/>.</summary>
    Task<LogSnapshot> ReadCurrentAsync(
        string level,
        int maximumLines = 1000,
        CancellationToken cancellationToken = default);

    /// <summary>Daily log files, newest first, followed by the backups made when a log was cleared.</summary>
    IReadOnlyList<LogFileInfo> ListFiles();

    /// <summary>
    /// Entries of <paramref name="level"/> containing <paramref name="search"/> (case-insensitive; a matching stack-trace
    /// line keeps its whole entry) from <paramref name="filePath"/>, which must come from <see cref="ListFiles"/>.
    /// </summary>
    Task<LogSnapshot> ReadAsync(
        string filePath,
        string level,
        string? search,
        int maximumLines,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Copies the log file into <paramref name="directory"/> and returns the copy's path. The log folder itself is
    /// restricted to Administrators and SYSTEM, and Explorer runs unelevated, so it cannot be opened directly.
    /// </summary>
    Task<string> SaveCopyAsync(string filePath, string directory, CancellationToken cancellationToken = default);

    /// <summary>
    /// Empties today's log file after saving its contents as a backup in the protected log folder, so earlier entries
    /// are kept for troubleshooting. Returns the backup's path, or null when the file was already empty.
    /// </summary>
    Task<string?> ClearCurrentAsync(CancellationToken cancellationToken = default);
}
