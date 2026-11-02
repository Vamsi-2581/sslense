using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;

namespace SSLense.Core.Reminders;

/// <summary>
/// Compares the certificate this server really serves with the one SSLense expects
/// (docs/design/proactive-checks.md, section 4). Report-only. It connects from this server, so it shows what IIS serves,
/// not necessarily what visitors receive through a CDN, reverse proxy, or load balancer.
/// </summary>
public interface IServedCertificateCheck
{
    /// <summary>Checks every managed certificate with reminders on, on sites that are started.</summary>
    Task<ProactiveCheckResult> CheckAllAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>Checks one certificate's hosts. Returns what is wrong, or null when all of them serve the expected certificate.</summary>
    Task<string?> CheckAsync(ManagedCertificate certificate, IisSite site, CancellationToken cancellationToken = default);
}

internal sealed class ServedCertificateCheck(
    IIisService iisService,
    ITlsBindingProbe tlsProbe,
    ICertificateStore certificateStore,
    ICertificateOperationLock operationLock) : IServedCertificateCheck
{
    internal const string StartedState = "Started";

    public async Task<ProactiveCheckResult> CheckAllAsync(
        IReadOnlyList<ManagedCertificate> certificates,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        var candidates = certificates.Where(value => !ReminderDigestBuilder.IsMuted(value, now)).ToArray();
        if (candidates.Length == 0)
        {
            return ProactiveCheckResult.None;
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var problems = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var passed = new List<string>();
        var errors = new List<string>();
        foreach (var certificate in candidates)
        {
            var site = sites.FirstOrDefault(value => string.Equals(value.Name, certificate.SiteName, StringComparison.OrdinalIgnoreCase));
            if (site is not { State: StartedState })
            {
                continue;
            }

            // During an install the binding may briefly serve either certificate; this site is looked at again tomorrow.
            await using var siteLock = operationLock.TryAcquire(certificate.SiteName);
            if (siteLock is null)
            {
                continue;
            }

            try
            {
                if (await CheckAsync(certificate, site, cancellationToken).ConfigureAwait(false) is { } problem)
                {
                    problems[certificate.SiteName] = problem;
                }
                else
                {
                    passed.Add(certificate.SiteName);
                }
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                errors.Add($"Could not check the served certificate for '{certificate.SiteName}': {exception.Message}");
            }
        }

        return new ProactiveCheckResult(problems, passed, errors);
    }

    public async Task<string?> CheckAsync(ManagedCertificate certificate, IisSite site, CancellationToken cancellationToken = default)
    {
        var problems = new List<string>();
        foreach (var host in certificate.Hosts)
        {
            var bindings = site.Bindings
                .Where(binding =>
                    string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                    binding.Port == 443 &&
                    string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (bindings.Length == 0)
            {
                problems.Add($"{host} has no HTTPS binding on port 443.");
            }

            foreach (var binding in bindings)
            {
                if (await CheckBindingAsync(certificate, host, binding, cancellationToken).ConfigureAwait(false) is { } problem)
                {
                    problems.Add(problem);
                }
            }
        }

        return problems.Count == 0
            ? null
            : $"{string.Join(" ", problems.Distinct())} Check the site's HTTPS binding in IIS.";
    }

    private async Task<string?> CheckBindingAsync(
        ManagedCertificate certificate,
        string host,
        IisBinding binding,
        CancellationToken cancellationToken)
    {
        // A wildcard binding also listens on loopback, so the check never leaves this machine.
        var address = binding.IpAddress is "*" or "" ? "127.0.0.1" : binding.IpAddress.Trim('[', ']');
        string served;
        try
        {
            served = Normalize(await tlsProbe.GetServedThumbprintAsync(address, host, 443, cancellationToken).ConfigureAwait(false));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            return $"{host} did not answer on port 443 ({exception.Message}).";
        }

        var expected = Normalize(certificate.Thumbprint);
        if (string.Equals(served, expected, StringComparison.Ordinal))
        {
            return null;
        }

        var installed = await certificateStore.FindByThumbprintAsync(served, cancellationToken).ConfigureAwait(false);
        var expiry = installed is null
            ? "It is not in this server's certificate store."
            : installed.NotAfter <= DateTimeOffset.UtcNow
                ? $"It expired on {installed.NotAfter:yyyy-MM-dd}."
                : $"It expires on {installed.NotAfter:yyyy-MM-dd}.";
        return $"{host} serves a different certificate from the one SSLense expects: expected {Short(expected)}, served {Short(served)}. {expiry}";
    }

    private static string Normalize(string thumbprint) => thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();

    private static string Short(string thumbprint) => thumbprint.Length <= 8 ? thumbprint : $"{thumbprint[..8]}…";
}
