using System.Diagnostics;
using System.Text.Json;
using SSLense.Core.Config;

namespace SSLense.Core.Validation;

/// <summary>
/// Everything needed to undo one HTTP-01 challenge: the files SSLense wrote into the site, what they
/// replaced, and which folders it created. Recorded before the site is touched, removed after cleanup.
/// </summary>
public sealed record ChallengeArtifacts(
    Guid Id,
    string TokenPath,
    string? OriginalToken,
    string WebConfigPath,
    string? OriginalWebConfig,
    string ChallengeDirectory,
    string WellKnownDirectory,
    bool CreatedChallengeDirectory,
    bool CreatedWellKnown,
    int OwnerProcessId,
    DateTimeOffset OwnerProcessStartedAt,
    DateTimeOffset CreatedAt,
    int SchemaVersion = StateSchema.Transactions);

public interface IChallengeJournal
{
    Task RecordAsync(ChallengeArtifacts artifacts, CancellationToken cancellationToken);

    Task CompleteAsync(Guid id);

    /// <summary>Entries whose owning process has exited without cleaning up.</summary>
    Task<IReadOnlyList<ChallengeArtifacts>> GetAbandonedAsync(CancellationToken cancellationToken);
}

internal sealed class JsonChallengeJournal : IChallengeJournal
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly IFileSystem _fileSystem;
    private readonly string _directory;
    private readonly Func<int, DateTimeOffset, bool> _isProcessAlive;

    public JsonChallengeJournal(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.ChallengeJournalDirectory, IsProcessAlive)
    {
    }

    internal JsonChallengeJournal(IFileSystem fileSystem, string directory, Func<int, DateTimeOffset, bool> isProcessAlive)
    {
        _fileSystem = fileSystem;
        _directory = directory;
        _isProcessAlive = isProcessAlive;
    }

    public static (int ProcessId, DateTimeOffset StartedAt) CurrentProcess
    {
        get
        {
            using var process = Process.GetCurrentProcess();
            return (process.Id, process.StartTime.ToUniversalTime());
        }
    }

    public Task RecordAsync(ChallengeArtifacts artifacts, CancellationToken cancellationToken)
    {
        _fileSystem.CreateDirectory(_directory);
        return _fileSystem.WriteAllTextAtomicAsync(
            GetPath(artifacts.Id),
            JsonSerializer.Serialize(artifacts, SerializerOptions),
            cancellationToken);
    }

    public Task CompleteAsync(Guid id)
    {
        _fileSystem.DeleteFile(GetPath(id));
        _fileSystem.DeleteDirectoryIfEmpty(_directory);
        return Task.CompletedTask;
    }

    public async Task<IReadOnlyList<ChallengeArtifacts>> GetAbandonedAsync(CancellationToken cancellationToken)
    {
        var abandoned = new List<ChallengeArtifacts>();
        foreach (var path in _fileSystem.GetFiles(_directory, "*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ChallengeArtifacts? artifacts;
            try
            {
                artifacts = JsonSerializer.Deserialize<ChallengeArtifacts>(
                    await _fileSystem.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false),
                    SerializerOptions);
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException($"Challenge journal entry '{path}' contains invalid JSON.", exception);
            }

            if (artifacts is null)
            {
                continue;
            }

            StateSchema.EnsureSupported(artifacts.SchemaVersion, StateSchema.Transactions, path);
            if (!_isProcessAlive(artifacts.OwnerProcessId, artifacts.OwnerProcessStartedAt))
            {
                abandoned.Add(artifacts);
            }
        }

        return abandoned;
    }

    /// <summary>
    /// The start time guards against a reused process ID. When liveness cannot be determined, the owner
    /// is treated as alive, so a running validation never loses its challenge files.
    /// </summary>
    internal static bool IsProcessAlive(int processId, DateTimeOffset startedAt)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return Math.Abs((process.StartTime.ToUniversalTime() - startedAt).TotalSeconds) < 2;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return true;
        }
    }

    private string GetPath(Guid id) => Path.Combine(_directory, $"{id:N}.json");
}

internal sealed class NoOpChallengeJournal : IChallengeJournal
{
    public Task RecordAsync(ChallengeArtifacts artifacts, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task CompleteAsync(Guid id) => Task.CompletedTask;

    public Task<IReadOnlyList<ChallengeArtifacts>> GetAbandonedAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ChallengeArtifacts>>([]);
}
