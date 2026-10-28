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

    public static string GetAccountKeyFile(Acme.AcmeEnvironment environment) => Path.Combine(
        DataDirectory,
        environment == Acme.AcmeEnvironment.Production
            ? "account-key.production.dat"
            : "account-key.staging.dat");

    public static string CertificateDirectory => Path.Combine(DataDirectory, "certificates");

    public static string ManagedCertificatesFile => Path.Combine(DataDirectory, "managed-certificates.json");

    public static string ManagedCertificatesLockFile => Path.Combine(DataDirectory, "managed-certificates.lock");

    public static string OperationLockDirectory => Path.Combine(DataDirectory, "locks");

    public static string TransactionDirectory => Path.Combine(DataDirectory, "transactions");

    public static string ServiceHeartbeatFile => Path.Combine(DataDirectory, "service-heartbeat.json");
}
