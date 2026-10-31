namespace SSLense.Core.Logs;

public interface ILogService
{
    Task<LogSnapshot> ReadCurrentAsync(
        string level,
        int maximumLines = 1000,
        CancellationToken cancellationToken = default,
        DateTimeOffset? since = null);

    /// <summary>
    /// Copies today's log file into <paramref name="directory"/> and returns the copy's path. The log folder itself is
    /// restricted to Administrators and SYSTEM, and Explorer runs unelevated, so it cannot be opened directly.
    /// </summary>
    Task<string> SaveCopyAsync(string directory, CancellationToken cancellationToken = default);
}
