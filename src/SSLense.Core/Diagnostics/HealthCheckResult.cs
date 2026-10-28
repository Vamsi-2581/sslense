namespace SSLense.Core.Diagnostics;

public enum HealthStatus
{
    Pass = 0,
    Warning = 1,
    Fail = 2
}

/// <param name="Fix">What the administrator should do, when the check did not pass.</param>
public sealed record HealthCheckResult(string Name, HealthStatus Status, string Message, string? Fix = null);

public interface IHealthCheckService
{
    /// <summary>
    /// Runs every check and never throws for an individual check; a check that cannot run is reported as failed.
    /// Read-only apart from the pre-flight probe file, which is written to each site's challenge folder and removed.
    /// </summary>
    Task<IReadOnlyList<HealthCheckResult>> RunAsync(
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);
}
