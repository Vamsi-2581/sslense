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

    public Task WriteAllTextAsync(string path, string contents, CancellationToken cancellationToken)
    {
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

    public Task<string> TakeAllTextAsync(string path, CancellationToken cancellationToken)
    {
        var text = Files[path];
        Files[path] = string.Empty;
        return Task.FromResult(text);
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
