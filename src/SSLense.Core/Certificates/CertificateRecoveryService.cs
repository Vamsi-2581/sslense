using SSLense.Core.Validation;
using SSLense.Core.Config;
using SSLense.Core.Iis;

namespace SSLense.Core.Certificates;

internal sealed class CertificateRecoveryService(
    ICertificateTransactionJournal journal,
    ICertificateOperationLock operationLock,
    ICertificateStore certificateStore,
    IManagedCertificateStore managedStore,
    IIisService iisService,
    IChallengeHandler? challengeHandler = null) : ICertificateRecoveryService
{
    public async Task<IReadOnlyList<CertificateRecoveryResult>> RecoverAsync(
        CancellationToken cancellationToken = default)
    {
        var results = new List<CertificateRecoveryResult>();
        if (challengeHandler is not null)
        {
            try
            {
                results.AddRange(
                    (await challengeHandler.CleanUpAbandonedAsync(cancellationToken).ConfigureAwait(false))
                    .Select(message => new CertificateRecoveryResult(true, message)));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                results.Add(new CertificateRecoveryResult(
                    false,
                    $"Leftover HTTP-01 challenge files could not be cleaned up: {exception.Message} " +
                    "It will be retried on the next start."));
            }
        }

        IReadOnlyList<CertificateTransaction> pending;
        try
        {
            pending = await journal.GetPendingAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            results.Add(new CertificateRecoveryResult(
                false,
                $"Interrupted certificate operations could not be read: {exception.Message}"));
            return results;
        }

        foreach (var snapshot in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var siteName = snapshot.Certificate.SiteName;

            // A held lock means a live GUI, CLI, or service process still owns this transaction.
            await using var siteLock = operationLock.TryAcquire(siteName);
            if (siteLock is null)
            {
                continue;
            }

            try
            {
                var transaction = await journal.GetAsync(snapshot.Id, cancellationToken).ConfigureAwait(false);
                if (transaction is null)
                {
                    continue;
                }

                // Leave the entry untouched so the newer version that wrote it can finish it.
                StateSchema.EnsureSupported(
                    transaction.SchemaVersion,
                    StateSchema.Transactions,
                    $"certificate transaction {transaction.Id:N}");
                results.Add(await RecoverOneAsync(transaction, cancellationToken).ConfigureAwait(false));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                results.Add(new CertificateRecoveryResult(
                    false,
                    $"Could not recover certificate transaction {snapshot.Id:N} for '{siteName}': " +
                    $"{exception.Message} It will be retried on the next start."));
            }
        }

        return results;
    }

    private async Task<CertificateRecoveryResult> RecoverOneAsync(
        CertificateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var recovered = new CertificateRecoveryResult(
            true,
            $"Recovered certificate transaction {transaction.Id:N} for '{transaction.Certificate.SiteName}'.");
        if (transaction.Stage == CertificateTransactionStage.StateSaved)
        {
            await journal.CompleteAsync(transaction.Id, cancellationToken).ConfigureAwait(false);
            return recovered;
        }

        var certificate = transaction.Certificate;
        var installed = await certificateStore
            .FindByThumbprintAsync(certificate.Thumbprint, cancellationToken)
            .ConfigureAwait(false);
        if (installed is null)
        {
            await journal.CompleteAsync(transaction.Id, cancellationToken).ConfigureAwait(false);
            return recovered;
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.SingleOrDefault(value => string.Equals(
            value.Name,
            certificate.SiteName,
            StringComparison.OrdinalIgnoreCase));
        if (site is null)
        {
            // Nothing can be bound any more; retrying on every start would never succeed.
            await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
            return new CertificateRecoveryResult(
                false,
                $"Abandoned certificate transaction {transaction.Id:N} because IIS site " +
                $"'{certificate.SiteName}' no longer exists. Certificate {certificate.Thumbprint} " +
                "was left in LocalMachine\\My for manual review.");
        }
        var allBindingsActive = certificate.Hosts.All(host => site.Bindings.Any(binding =>
            string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
            binding.Port == 443 &&
            string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(
                NormalizeThumbprint(binding.CertificateThumbprint),
                NormalizeThumbprint(certificate.Thumbprint),
                StringComparison.Ordinal)));
        if (!allBindingsActive)
        {
            await iisService.ConfigureHttpsBindingsAsync(
                    certificate.SiteName,
                    certificate.Hosts,
                    certificate.Thumbprint,
                    "My",
                    cancellationToken)
                .ConfigureAwait(false);
        }

        await journal.UpdateStageAsync(
                transaction.Id,
                CertificateTransactionStage.BindingsUpdated,
                CancellationToken.None)
            .ConfigureAwait(false);
        await managedStore.UpsertAsync(certificate, CancellationToken.None).ConfigureAwait(false);
        await journal.UpdateStageAsync(
                transaction.Id,
                CertificateTransactionStage.StateSaved,
                CancellationToken.None)
            .ConfigureAwait(false);
        await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
        return recovered;
    }

    private static string NormalizeThumbprint(string? thumbprint) =>
        string.Concat((thumbprint ?? string.Empty).Where(Uri.IsHexDigit)).ToUpperInvariant();
}
