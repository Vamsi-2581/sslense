namespace SSLense.Core.Config;

public static class AppPaths
{
    public static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SSLense");

    public static string ConfigFile => Path.Combine(DataDirectory, "config.json");

    public static string ConfigLockFile => Path.Combine(DataDirectory, "config.lock");

    public static string LogDirectory => Path.Combine(DataDirectory, "logs");

    public static string AccountKeyFile => Path.Combine(DataDirectory, "account-key.staging.dat");

    /// <summary>
    /// One ACME account key per certificate authority. The Let's Encrypt profiles keep the file names they had
    /// before other authorities were supported, so existing accounts are reused.
    /// </summary>
    public static string GetAccountKeyFile(string authorityId) => Path.Combine(
        DataDirectory,
        authorityId switch
        {
            Acme.CertificateAuthorities.LetsEncryptStagingId => "account-key.staging.dat",
            Acme.CertificateAuthorities.LetsEncryptId => "account-key.production.dat",
            _ when Acme.CertificateAuthorities.IsValidId(authorityId) => $"account-key.{authorityId}.dat",
            _ => throw new ArgumentException($"'{authorityId}' is not a valid certificate authority ID.", nameof(authorityId))
        });

    public static string CertificateDirectory => Path.Combine(DataDirectory, "certificates");

    public static string ManagedCertificatesFile => Path.Combine(DataDirectory, "managed-certificates.json");

    public static string ManagedCertificatesLockFile => Path.Combine(DataDirectory, "managed-certificates.lock");

    public static string OperationLockDirectory => Path.Combine(DataDirectory, "locks");

    public static string TransactionDirectory => Path.Combine(DataDirectory, "transactions");

    public static string ServiceHeartbeatFile => Path.Combine(DataDirectory, "service-heartbeat.json");

    public static string ChallengeJournalDirectory => Path.Combine(DataDirectory, "challenges");

    public static string PendingRequestsFile => Path.Combine(DataDirectory, "pending-requests.json");

    public static string ReminderStateFile => Path.Combine(DataDirectory, "reminder-state.json");

    public static string PendingRequestsLockFile => Path.Combine(DataDirectory, "pending-requests.lock");
}
