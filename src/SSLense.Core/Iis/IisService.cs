using Microsoft.Web.Administration;

namespace SSLense.Core.Iis;

internal sealed class IisService(ITlsBindingProbe tlsProbe) : IIisService
{
    private static readonly TimeSpan LiveVerificationTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan LiveVerificationInterval = TimeSpan.FromMilliseconds(500);

    public Task<IReadOnlyList<IisSite>> GetSitesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS site discovery is only supported on Windows.");
        }

        try
        {
            using var serverManager = new ServerManager();
            var sites = serverManager.Sites
                .Select(MapSite)
                .OrderBy(site => site.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return Task.FromResult<IReadOnlyList<IisSite>>(sites);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidOperationException(
                "IIS configuration could not be read. Run SSLense from an Administrator terminal.",
                exception);
        }
        catch (FileNotFoundException exception)
        {
            throw new InvalidOperationException(
                "IIS management components were not found. Install IIS Management Scripts and Tools.",
                exception);
        }
    }

    public async Task ConfigureHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateThumbprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateStoreName);
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS binding configuration is only supported on Windows.");
        }

        var certificateHash = Convert.FromHexString(NormalizeThumbprint(certificateThumbprint));
        var changes = new List<BindingChange>();
        var probeTargets = new List<(string IpAddress, string Host)>();
        var siteStarted = false;
        try
        {
            using (var serverManager = new ServerManager())
            {
                var site = FindSite(serverManager, siteName);
                siteStarted = IsStarted(site);
                foreach (var host in hosts)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var binding = FindHttpsBinding(site, host);
                    if (binding is null)
                    {
                        binding = site.Bindings.Add(
                            $"*:443:{host}",
                            certificateHash,
                            certificateStoreName,
                            SslFlags.Sni);
                        changes.Add(new BindingChange(host, WasAdded: true, null, null, SslFlags.None));
                    }
                    else
                    {
                        changes.Add(new BindingChange(
                            host,
                            WasAdded: false,
                            binding.CertificateHash?.ToArray(),
                            binding.CertificateStoreName,
                            binding.SslFlags));
                        binding.CertificateHash = certificateHash;
                        binding.CertificateStoreName = certificateStoreName;

                        // Keep unrelated flags such as DisableHTTP2; SSLense binds from the store, not the CCS.
                        binding.SslFlags = (binding.SslFlags | SslFlags.Sni) & ~SslFlags.CentralCertStore;
                    }

                    probeTargets.Add((ParseBindingInformation(binding.BindingInformation).IpAddress, host));
                }

                serverManager.CommitChanges();
            }

            using var verificationManager = new ServerManager();
            var verificationSite = FindSite(verificationManager, siteName);
            foreach (var host in hosts)
            {
                var binding = FindHttpsBinding(verificationSite, host)
                    ?? throw new InvalidOperationException(
                        $"HTTPS binding verification failed for '{host}': the binding was not found.");
                if (binding.CertificateHash is null ||
                    !binding.CertificateHash.SequenceEqual(certificateHash) ||
                    !string.Equals(binding.CertificateStoreName, certificateStoreName, StringComparison.OrdinalIgnoreCase) ||
                    (binding.SslFlags & SslFlags.Sni) != SslFlags.Sni)
                {
                    throw new InvalidOperationException(
                        $"HTTPS binding verification failed for '{host}': IIS did not retain the certificate and SNI settings.");
                }
            }

            // A stopped site has no HTTP.sys listener, so there is nothing live to verify yet.
            if (siteStarted)
            {
                foreach (var (ipAddress, host) in probeTargets)
                {
                    await VerifyServedCertificateAsync(ipAddress, host, certificateThumbprint, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
        }
        catch (Exception exception)
        {
            try
            {
                if (changes.Count > 0)
                {
                    RollBackBindings(siteName, changes);
                }
            }
            catch (Exception rollbackException)
            {
                throw new IisBindingException(
                    "IIS binding configuration failed and the previous bindings could not be fully restored.",
                    previousBindingsRestored: false,
                    new AggregateException(exception, rollbackException));
            }

            if (exception is UnauthorizedAccessException)
            {
                throw new IisBindingException(
                    "IIS bindings could not be changed. Run SSLense from an Administrator terminal.",
                    previousBindingsRestored: true,
                    exception);
            }

            throw new IisBindingException(
                $"Could not configure HTTPS bindings for IIS site '{siteName}'. No existing binding was intentionally removed.",
                previousBindingsRestored: true,
                exception);
        }
    }

    public Task RemoveHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string expectedCertificateThumbprint,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var expectedHash = Convert.FromHexString(NormalizeThumbprint(expectedCertificateThumbprint));
        try
        {
            using var serverManager = new ServerManager();
            var site = FindSite(serverManager, siteName);
            foreach (var host in hosts)
            {
                var binding = FindHttpsBinding(site, host);
                if (binding is null)
                {
                    continue;
                }

                if (binding.CertificateHash is null || !binding.CertificateHash.SequenceEqual(expectedHash))
                {
                    throw new InvalidOperationException(
                        $"The HTTPS binding for '{host}' uses a different certificate and was not removed.");
                }

                site.Bindings.Remove(binding);
            }

            serverManager.CommitChanges();

            using var verificationManager = new ServerManager();
            var verificationSite = FindSite(verificationManager, siteName);
            foreach (var host in hosts)
            {
                var binding = FindHttpsBinding(verificationSite, host);
                if (binding?.CertificateHash is { } hash && hash.SequenceEqual(expectedHash))
                {
                    throw new InvalidOperationException(
                        $"HTTPS binding removal verification failed for '{host}'. The certificate was not removed from the store.");
                }
            }

            return Task.CompletedTask;
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new InvalidOperationException(
                "IIS bindings could not be removed. Run SSLense as Administrator.",
                exception);
        }
    }

    private async Task VerifyServedCertificateAsync(
        string bindingIpAddress,
        string host,
        string expectedThumbprint,
        CancellationToken cancellationToken)
    {
        // A wildcard binding also listens on loopback, so the check never leaves this machine.
        var ipAddress = bindingIpAddress is "*" or "" ? "127.0.0.1" : bindingIpAddress.Trim('[', ']');
        var expected = NormalizeThumbprint(expectedThumbprint);
        var deadline = DateTimeOffset.UtcNow + LiveVerificationTimeout;
        string observed;
        while (true)
        {
            try
            {
                observed = NormalizeThumbprint(await tlsProbe
                    .GetServedThumbprintAsync(ipAddress, host, 443, cancellationToken)
                    .ConfigureAwait(false));
                if (string.Equals(observed, expected, StringComparison.Ordinal))
                {
                    return;
                }

                observed = $"certificate {observed}";
            }
            catch (Exception exception) when (exception is not OperationCanceledException ||
                                              !cancellationToken.IsCancellationRequested)
            {
                observed = $"error: {exception.Message}";
            }

            // HTTP.sys applies configuration changes asynchronously after CommitChanges.
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new InvalidOperationException(
                    $"HTTPS verification failed for '{host}': {ipAddress}:443 did not serve certificate " +
                    $"{expected} within {LiveVerificationTimeout.TotalSeconds:0} seconds (last result: {observed}).");
            }

            await Task.Delay(LiveVerificationInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsStarted(Site site)
    {
        try
        {
            return site.State == ObjectState.Started;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // State is unavailable when the Windows Process Activation Service is stopped.
            return false;
        }
    }

    private static IisSite MapSite(Site site)
    {
        var rootApplication = site.Applications.FirstOrDefault(application => application.Path == "/");
        var rootDirectory = rootApplication?.VirtualDirectories.FirstOrDefault(directory => directory.Path == "/");
        var physicalPath = rootDirectory?.PhysicalPath is { } path
            ? Environment.ExpandEnvironmentVariables(path)
            : null;

        var bindings = site.Bindings.Select(MapBinding).ToArray();
        return new IisSite(site.Id, site.Name, ReadState(site), physicalPath, bindings);
    }

    /// <summary>
    /// Some sites have no run state: FTP-only sites, sites whose bindings use only non-HTTP protocols, or any site while
    /// the Windows Process Activation Service is stopped. Reading it then throws (0x800710D8, "The object identifier does
    /// not represent a valid object"), which must not stop every other site from being listed.
    /// </summary>
    private static string ReadState(Site site)
    {
        try
        {
            return site.State.ToString();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            return "Unknown";
        }
    }

    private static IisBinding MapBinding(Binding binding)
    {
        var (ipAddress, port, hostName) = ParseBindingInformation(binding.BindingInformation);
        var thumbprint = binding.CertificateHash is { Length: > 0 } hash
            ? Convert.ToHexString(hash)
            : null;

        return new IisBinding(
            binding.Protocol,
            ipAddress,
            port,
            hostName,
            thumbprint,
            binding.CertificateStoreName,
            (binding.SslFlags & SslFlags.Sni) == SslFlags.Sni);
    }

    private static Site FindSite(ServerManager serverManager, string siteName) =>
        serverManager.Sites.FirstOrDefault(site =>
            string.Equals(site.Name, siteName, StringComparison.OrdinalIgnoreCase))
        ?? throw new InvalidOperationException($"IIS site '{siteName}' was not found.");

    private static Binding? FindHttpsBinding(Site site, string host) =>
        site.Bindings.FirstOrDefault(binding =>
        {
            if (!string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var (_, port, bindingHost) = ParseBindingInformation(binding.BindingInformation);
            return port == 443 && string.Equals(bindingHost, host, StringComparison.OrdinalIgnoreCase);
        });

    private static void RollBackBindings(string siteName, IReadOnlyList<BindingChange> changes)
    {
        using var serverManager = new ServerManager();
        var site = FindSite(serverManager, siteName);
        foreach (var change in changes)
        {
            var binding = FindHttpsBinding(site, change.Host);
            if (change.WasAdded)
            {
                if (binding is not null)
                {
                    site.Bindings.Remove(binding);
                }

                continue;
            }

            if (binding is null)
            {
                throw new InvalidOperationException(
                    $"Cannot restore the previous HTTPS binding for '{change.Host}' because it no longer exists.");
            }

            binding.CertificateHash = change.CertificateHash;
            binding.CertificateStoreName = change.CertificateStoreName;
            binding.SslFlags = change.SslFlags;
        }

        serverManager.CommitChanges();
    }

    private static string NormalizeThumbprint(string thumbprint) =>
        string.Concat(thumbprint.Where(Uri.IsHexDigit)).ToUpperInvariant();

    private static (string IpAddress, int Port, string HostName) ParseBindingInformation(string value)
    {
        var hostSeparator = value.LastIndexOf(':');
        var portSeparator = hostSeparator > 0 ? value.LastIndexOf(':', hostSeparator - 1) : -1;
        if (portSeparator < 0 || hostSeparator < 0 ||
            !int.TryParse(value.AsSpan(portSeparator + 1, hostSeparator - portSeparator - 1), out var port))
        {
            throw new InvalidDataException($"IIS returned an invalid binding: '{value}'.");
        }

        return (value[..portSeparator], port, value[(hostSeparator + 1)..]);
    }

    private sealed record BindingChange(
        string Host,
        bool WasAdded,
        byte[]? CertificateHash,
        string? CertificateStoreName,
        SslFlags SslFlags);
}
