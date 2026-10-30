namespace SSLense.Core.Config;

/// <summary>
/// Schema versions for SSLense state files. Increment a version whenever its file's shape changes,
/// and add a migration from every earlier version.
/// </summary>
internal static class StateSchema
{
    /// <summary>
    /// Version 0 was a bare JSON array; version 1 wraps it with a version and adds record IDs. Version 2 replaces
    /// the Let's Encrypt environment with a certificate authority ID and adds the certificate source
    /// (see <see cref="ManagedCertificateMigrations"/>).
    /// </summary>
    public const int ManagedCertificates = 2;

    /// <summary>
    /// Version 0 had no version field. Version 2 replaced the single SMTP server and generic webhook with
    /// email, chat channels, a heartbeat, and the Event Log (see <see cref="ConfigMigrations"/>). Version 3 adds
    /// configured certificate authorities.
    /// </summary>
    public const int Config = 3;

    /// <summary>Version 2 stores the certificate snapshot in managed-certificate schema 2.</summary>
    public const int Transactions = 2;

    public const int ServiceHeartbeat = 1;

    public const int PendingRequests = 1;

    public static void EnsureSupported(int version, int supportedVersion, string path)
    {
        if (version > supportedVersion)
        {
            throw new InvalidDataException(
                $"'{path}' uses state schema version {version}, but this SSLense version supports up to " +
                $"version {supportedVersion}. Install the newer SSLense version that created it. The file was not changed.");
        }
    }

    /// <summary>
    /// Copies the file to <c>&lt;path&gt;.v&lt;version&gt;.bak</c> before its first rewrite in a newer schema.
    /// An existing backup is kept, so the oldest copy of each version survives.
    /// </summary>
    public static async Task BackupBeforeMigrationAsync(
        IFileSystem fileSystem,
        string path,
        int fromVersion,
        CancellationToken cancellationToken)
    {
        var backupPath = $"{path}.v{fromVersion}.bak";
        if (!fileSystem.FileExists(path) || fileSystem.FileExists(backupPath))
        {
            return;
        }

        var contents = await fileSystem.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        await fileSystem.WriteAllTextAtomicAsync(backupPath, contents, cancellationToken).ConfigureAwait(false);
    }
}
