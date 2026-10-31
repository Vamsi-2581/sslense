using System.Text;

namespace SSLense.Core.Config;

internal sealed class PhysicalFileSystem : IFileSystem
{
    public bool FileExists(string path) => File.Exists(path);

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public void CreateDirectory(string path) => Directory.CreateDirectory(path);

    public Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken) =>
        File.ReadAllTextAsync(path, cancellationToken);

    public async Task<string[]> ReadAllLinesAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var lines = new List<string>();
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            lines.Add(line);
        }

        return [.. lines];
    }

    public async Task<string> TakeAllTextAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.ReadWrite | FileShare.Delete,
            4096,
            FileOptions.Asynchronous);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        var text = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        stream.SetLength(0);
        return text;
    }

    public IReadOnlyList<string> GetFiles(string path, string searchPattern) =>
        Directory.Exists(path) ? Directory.GetFiles(path, searchPattern) : [];

    public Task WriteAllTextAsync(string path, string contents, CancellationToken cancellationToken) =>
        File.WriteAllTextAsync(path, contents, new UTF8Encoding(false), cancellationToken);

    public Task WriteAllBytesAsync(string path, byte[] contents, CancellationToken cancellationToken) =>
        File.WriteAllBytesAsync(path, contents, cancellationToken);

    public async Task WriteAllTextAtomicAsync(
        string path,
        string contents,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("The file path must include a directory.", nameof(path));
        Directory.CreateDirectory(directory);

        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, contents, new UTF8Encoding(false), cancellationToken)
                .ConfigureAwait(false);
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public async Task<IAsyncDisposable> AcquireExclusiveFileLockAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("The lock path must include a directory.", nameof(path));
        Directory.CreateDirectory(directory);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new AsyncFileLock(new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous));
            }
            catch (IOException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException exception)
            {
                throw new InvalidOperationException(
                    $"Access to SSLense state at '{path}' was denied. Run SSLense as Administrator.",
                    exception);
            }
        }
    }

    public IAsyncDisposable? TryAcquireExclusiveFileLock(string path)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("The lock path must include a directory.", nameof(path));
        Directory.CreateDirectory(directory);
        try
        {
            return new AsyncFileLock(new FileStream(
                path,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.Asynchronous));
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidOperationException(
                $"Access to SSLense state at '{path}' was denied. Run SSLense as Administrator.",
                exception);
        }
    }

    public void DeleteFile(string path) => File.Delete(path);

    public void DeleteDirectoryIfEmpty(string path)
    {
        if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any())
        {
            Directory.Delete(path);
        }
    }


    private sealed class AsyncFileLock(FileStream stream) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => stream.DisposeAsync();
    }
}
