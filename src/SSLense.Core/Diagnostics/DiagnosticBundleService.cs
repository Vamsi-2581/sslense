using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.WindowsServices;

namespace SSLense.Core.Diagnostics;

/// <param name="RedactHosts">Replace site and host names with placeholders, for posting publicly.</param>
public sealed record DiagnosticBundleRequest(string OutputPath, bool RedactHosts = false);

public sealed record DiagnosticBundleResult(string Path, IReadOnlyList<string> Notes);

public interface IDiagnosticBundleService
{
    /// <summary>
    /// Writes a zip for attaching to a GitHub issue. Secrets are never included: passwords, keys, protected
    /// values, and webhook URLs are removed, and every text passes through <see cref="SecretRedactor"/>.
    /// </summary>
    Task<DiagnosticBundleResult> CreateAsync(
        DiagnosticBundleRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);
}

internal sealed class DiagnosticBundleService(
    IHealthCheckService healthCheckService,
    IConfigStore configStore,
    IManagedCertificateStore managedStore,
    ICertificateTransactionJournal journal,
    IServiceHeartbeatStore heartbeatStore,
    IWindowsServiceManager serviceManager,
    IIisService iisService,
    IFileSystem fileSystem) : IDiagnosticBundleService
{
    private const int LogFilesIncluded = 3;
    private const int LogLinesPerFile = 3000;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public async Task<DiagnosticBundleResult> CreateAsync(
        DiagnosticBundleRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.OutputPath);

        var entries = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var notes = new List<string>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        async Task Collect(string entry, string description, Func<Task<object?>> collect)
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new ProgressEvent("diagnostics", $"Collecting {description}."));
            try
            {
                var value = await collect().ConfigureAwait(false);
                entries[entry] = value as string ?? JsonSerializer.Serialize(value, SerializerOptions);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                entries[entry] = $"Could not collect {description}: {exception.Message}";
                notes.Add($"{description}: {exception.Message}");
            }
        }

        await Collect("summary.json", "system summary", async () => await CreateSummaryAsync(cancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
        await Collect("health.json", "health check results", async () =>
            await healthCheckService.RunAsync(progress, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        await Collect("config.json", "configuration", async () =>
            RedactConfig(await configStore.LoadAsync(cancellationToken).ConfigureAwait(false))).ConfigureAwait(false);
        await Collect("managed-certificates.json", "managed certificates", async () =>
        {
            var records = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
            foreach (var record in records)
            {
                names.Add(record.SiteName);
                names.UnionWith(record.Hosts);
            }

            return records.Select(record => record with { Email = SecretRedactor.MaskEmail(record.Email) ?? string.Empty });
        }).ConfigureAwait(false);
        await Collect("iis-sites.json", "IIS sites and bindings", async () =>
        {
            var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
            foreach (var site in sites)
            {
                names.Add(site.Name);
                names.UnionWith(site.Bindings.Select(binding => binding.HostName).Where(host => host.Length > 0));
            }

            return sites;
        }).ConfigureAwait(false);
        await Collect("interrupted-operations.json", "interrupted operations", async () =>
            (await journal.GetPendingAsync(cancellationToken).ConfigureAwait(false)).Select(transaction => new
            {
                transaction.Id,
                transaction.Certificate.SiteName,
                transaction.Stage,
                transaction.StartedAt,
                transaction.PreviousThumbprint,
                NewThumbprint = transaction.Certificate.Thumbprint
            })).ConfigureAwait(false);
        await Collect("service-heartbeat.json", "service heartbeat", async () =>
            await heartbeatStore.GetAsync(cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        progress?.Report(new ProgressEvent("diagnostics", "Collecting recent logs."));
        foreach (var logFile in fileSystem.GetFiles(AppPaths.LogDirectory, "sslense-*.log")
                     .OrderByDescending(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
                     .Take(LogFilesIncluded))
        {
            try
            {
                var lines = await fileSystem.ReadAllLinesAsync(logFile, cancellationToken).ConfigureAwait(false);
                entries[$"logs/{Path.GetFileName(logFile)}"] = string.Join(Environment.NewLine, lines.TakeLast(LogLinesPerFile));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                notes.Add($"Log '{Path.GetFileName(logFile)}': {exception.Message}");
            }
        }

        var hostMap = request.RedactHosts ? CreateHostMap(names) : [];
        entries["README.txt"] = CreateReadme(request.RedactHosts, notes);

        progress?.Report(new ProgressEvent("diagnostics", "Redacting and writing the bundle."));
        var outputPath = Path.GetFullPath(request.OutputPath);
        var directory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await using (var stream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            foreach (var (name, content) in entries)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                await using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
                await writer.WriteAsync(ApplyHostMap(SecretRedactor.Redact(content), hostMap)).ConfigureAwait(false);
            }
        }

        return new DiagnosticBundleResult(outputPath, notes);
    }

    internal static AppConfig RedactConfig(AppConfig config) => config with
    {
        DefaultEmail = SecretRedactor.MaskEmail(config.DefaultEmail),
        Notifications = config.Notifications with
        {
            Email = config.Notifications.Email is { } email
                ? email with
                {
                    // An email-style login keeps its domain for diagnosis; any other login is removed.
                    Username = email.Username is null ? null
                        : email.Username.Contains('@') ? SecretRedactor.MaskEmail(email.Username)
                        : SecretRedactor.Marker,
                    ProtectedPassword = email.ProtectedPassword is null ? null : SecretRedactor.Marker,
                    From = SecretRedactor.MaskEmail(email.From) ?? string.Empty,
                    To = email.To.Select(recipient => SecretRedactor.MaskEmail(recipient) ?? string.Empty).ToArray()
                }
                : null,

            // Channel types and names help diagnosis; the URLs carry the credential.
            Chat = config.Notifications.Chat.Select(chat => chat with { ProtectedUrl = SecretRedactor.Marker }).ToArray(),
            Heartbeat = config.Notifications.Heartbeat is null ? null : new HeartbeatNotificationConfig(SecretRedactor.Marker),
            Smtp = null,
            Webhook = null
        }
    };

    private async Task<object> CreateSummaryAsync(CancellationToken cancellationToken)
    {
        string serviceStatus;
        try
        {
            serviceStatus = (await serviceManager.GetStatusAsync(cancellationToken).ConfigureAwait(false)).ToString();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            serviceStatus = $"unknown ({exception.Message})";
        }

        return new
        {
            SSLenseVersion = GetVersion(),
            CreatedAtUtc = DateTimeOffset.UtcNow,
            Os = RuntimeInformation.OSDescription,
            OsArchitecture = RuntimeInformation.OSArchitecture.ToString(),
            DotNet = RuntimeInformation.FrameworkDescription,
            IisVersion = GetIisVersion(),
            Elevated = WindowsElevation.IsAdministrator(),
            ServiceStatus = serviceStatus,
            DataDirectory = AppPaths.DataDirectory
        };
    }

    internal static string GetVersion()
    {
        var version = typeof(DiagnosticBundleService).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        return version.Split('+')[0];
    }

    private static string GetIisVersion()
    {
        if (!OperatingSystem.IsWindows())
        {
            return "not available";
        }

        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\InetStp");
        return key?.GetValue("MajorVersion") is int major
            ? $"{major}.{key.GetValue("MinorVersion") as int? ?? 0}"
            : "not installed";
    }

    internal static IReadOnlyList<(Regex Pattern, string Replacement)> CreateHostMap(IEnumerable<string> names)
    {
        var siteIndex = 0;
        var hostIndex = 0;

        // Longest first, so "www.example.com" is replaced before "example.com".
        return names
            .Where(name => name.Length > 2)
            .OrderByDescending(name => name.Length)
            .Select(name => (
                new Regex($@"(?<![A-Za-z0-9.\-]){Regex.Escape(name)}(?![A-Za-z0-9\-])", RegexOptions.IgnoreCase),
                name.Contains('.') ? $"host-{++hostIndex}.example" : $"site-{++siteIndex}"))
            .ToArray();
    }

    private static string ApplyHostMap(string text, IReadOnlyList<(Regex Pattern, string Replacement)> map) =>
        map.Aggregate(text, (current, item) => item.Pattern.Replace(current, item.Replacement));

    private static string CreateReadme(bool hostsRedacted, IReadOnlyList<string> notes)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"SSLense diagnostic bundle, version {GetVersion()}, created {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm} UTC.");
        builder.AppendLine();
        builder.AppendLine("Contents: system summary, health check results, configuration, managed certificates,");
        builder.AppendLine("IIS sites and bindings, interrupted operations, service heartbeat, and the newest log files.");
        builder.AppendLine();
        builder.AppendLine("Never included: private keys, ACME account keys, PFX files, SMTP passwords, webhook URLs,");
        builder.AppendLine("and DPAPI-protected values. Email addresses are masked, and URL paths and query strings are");
        builder.AppendLine("removed except for Let's Encrypt and HTTP-01 challenge URLs.");
        builder.AppendLine();
        builder.AppendLine(hostsRedacted
            ? "Site and host names were replaced with placeholders such as site-1 and host-1.example."
            : "Site and host names are included. Create the bundle with host redaction before posting it publicly if they are private.");
        builder.AppendLine("Certificate thumbprints are included; they are public identifiers, not secrets.");
        builder.AppendLine();
        builder.AppendLine("Review the files before sharing them.");
        if (notes.Count > 0)
        {
            builder.AppendLine();
            builder.AppendLine("Some information could not be collected:");
            foreach (var note in notes)
            {
                builder.AppendLine($"- {note}");
            }
        }

        return builder.ToString();
    }
}
