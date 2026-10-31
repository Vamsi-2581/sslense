using SSLense.Core.Config;

namespace SSLense.Tests;

/// <summary>A minimal in-memory <see cref="IFileSystem"/> for state-file tests.</summary>
internal sealed class InMemoryFileSystem : IFileSystem
{
    public Dictionary<string, string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool FileExists(string path) => Files.ContainsKey(path);

    public bool DirectoryExists(string path) => true;

    public void CreateDirectory(string path)
    {
    }

    public Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken) =>
        Task.FromResult(Files[path]);

    public Task<string[]> ReadAllLinesAsync(string path, CancellationToken cancellationToken) =>
        Task.FromResult(Files[path].Split('\n'));

    public IReadOnlyList<string> GetFiles(string path, string searchPattern) =>
        Files.Keys.Where(key => key.StartsWith(path, StringComparison.OrdinalIgnoreCase)).ToArray();

    /// <summary>Writes to paths starting with this fail, as on a full disk.</summary>
    public string? FailWritesUnder { get; set; }

    public Task WriteAllTextAsync(string path, string contents, CancellationToken cancellationToken)
    {
        if (FailWritesUnder is not null && path.StartsWith(FailWritesUnder, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("There is not enough space on the disk.");
        }

        Files[path] = contents;
        return Task.CompletedTask;
    }

    public Task WriteAllBytesAsync(string path, byte[] contents, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task WriteAllTextAtomicAsync(string path, string contents, CancellationToken cancellationToken) =>
        WriteAllTextAsync(path, contents, cancellationToken);

    public Task<IAsyncDisposable> AcquireExclusiveFileLockAsync(string path, CancellationToken cancellationToken) =>
        Task.FromResult<IAsyncDisposable>(new Scope());

    public IAsyncDisposable? TryAcquireExclusiveFileLock(string path) => new Scope();

    public Task TruncateAsync(string path, CancellationToken cancellationToken)
    {
        Files[path] = string.Empty;
        return Task.CompletedTask;
    }

    public void DeleteFile(string path) => Files.Remove(path);

    public void DeleteDirectoryIfEmpty(string path)
    {
    }

    private sealed class Scope : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
