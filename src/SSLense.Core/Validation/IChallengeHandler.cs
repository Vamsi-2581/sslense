using SSLense.Core.Acme;

namespace SSLense.Core.Validation;

public interface IChallengeHandler
{
    Task<IAsyncDisposable> PrepareAsync(
        string sitePhysicalPath,
        AcmeHttpChallenge challenge,
        CancellationToken cancellationToken);

    /// <summary>
    /// Restores sites whose challenge files were left behind by a process that exited mid-validation.
    /// Returns a message for each site restored.
    /// </summary>
    Task<IReadOnlyList<string>> CleanUpAbandonedAsync(CancellationToken cancellationToken);
}
