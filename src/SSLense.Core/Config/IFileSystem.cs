namespace SSLense.Core.Config;

public interface IFileSystem
{
    bool FileExists(string path);

    bool DirectoryExists(string path);

    void CreateDirectory(string path);

    Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken);

    Task<string[]> ReadAllLinesAsync(string path, CancellationToken cancellationToken);

    IReadOnlyList<string> GetFiles(string path, string searchPattern);

    Task WriteAllTextAsync(string path, string contents, CancellationToken cancellationToken);

    Task WriteAllBytesAsync(string path, byte[] contents, CancellationToken cancellationToken);

    Task WriteAllTextAtomicAsync(string path, string contents, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the file's text and empties it through one handle that shares access with other writers, as when another
    /// process is still appending log entries to it.
    /// </summary>
    Task<string> TakeAllTextAsync(string path, CancellationToken cancellationToken);

    Task<IAsyncDisposable> AcquireExclusiveFileLockAsync(
        string path,
        CancellationToken cancellationToken);

    IAsyncDisposable? TryAcquireExclusiveFileLock(string path);

    void DeleteFile(string path);

    void DeleteDirectoryIfEmpty(string path);
}
