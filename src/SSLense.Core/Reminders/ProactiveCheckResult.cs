namespace SSLense.Core.Reminders;

/// <summary>What one kind of daily report-only check found (docs/design/proactive-checks.md).</summary>
/// <param name="Problems">By site: what failed, for certificates that were checked and did not pass.</param>
/// <param name="Passed">Sites that were checked and passed.</param>
/// <param name="Errors">Checks that could not run; logged, and they never stop the digest.</param>
public sealed record ProactiveCheckResult(
    IReadOnlyDictionary<string, string> Problems,
    IReadOnlyList<string> Passed,
    IReadOnlyList<string> Errors)
{
    public static ProactiveCheckResult None { get; } = new(new Dictionary<string, string>(), [], []);
}
