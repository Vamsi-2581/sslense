using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core;
using SSLense.Core.Certificates;
using SSLense.Core.Iis;

namespace SSLense.Gui.ViewModels;

/// <summary>
/// Certificates from providers such as 123-reg: request (CSR), complete, import a PFX, or adopt one already bound.
/// Every action is a call to <see cref="IImportedCertificateService"/>; this class only gathers input and shows results.
/// </summary>
public partial class OtherProvidersViewModel : ObservableObject
{
    private readonly IImportedCertificateService _service;
    private readonly IPendingRequestStore _pendingStore;
    private readonly IIisService _iisService;
    private readonly ILogger<OtherProvidersViewModel> _logger;
    private readonly AsyncRelayCommand _refreshCommand;
    private readonly AsyncRelayCommand _createRequestCommand;
    private readonly AsyncRelayCommand _completeCommand;
    private readonly AsyncRelayCommand _cancelRequestCommand;
    private readonly AsyncRelayCommand _importCommand;
    private readonly AsyncRelayCommand _adoptCommand;

    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private string? resultMessage;

    [ObservableProperty] private IisSiteOption? requestSite;
    [ObservableProperty] private string requestHosts = string.Empty;
    [ObservableProperty] private KeyTypeOption selectedKeyType;

    [ObservableProperty] private PendingRequestRowViewModel? selectedPending;
    [ObservableProperty] private string certificatePath = string.Empty;
    [ObservableProperty] private string chainPath = string.Empty;
    [ObservableProperty] private bool completeForce;

    [ObservableProperty] private IisSiteOption? importSite;
    [ObservableProperty] private string pfxPath = string.Empty;
    [ObservableProperty] private string pfxPassword = string.Empty;
    [ObservableProperty] private string importHosts = string.Empty;
    [ObservableProperty] private bool importForce;

    [ObservableProperty] private DiscoveredBindingRowViewModel? selectedBinding;

    public OtherProvidersViewModel(
        IImportedCertificateService service,
        IPendingRequestStore pendingStore,
        IIisService iisService,
        ILogger<OtherProvidersViewModel> logger)
    {
        _service = service;
        _pendingStore = pendingStore;
        _iisService = iisService;
        _logger = logger;
        KeyTypes =
        [
            new KeyTypeOption(PrivateKeyTypes.Rsa2048, "RSA 2048 (accepted by every provider)"),
            new KeyTypeOption(PrivateKeyTypes.Rsa3072, "RSA 3072"),
            new KeyTypeOption(PrivateKeyTypes.EcdsaP256, "ECDSA P-256 (smaller; not accepted everywhere)")
        ];
        selectedKeyType = KeyTypes[0];
        _refreshCommand = new AsyncRelayCommand(token => RunAsync(LoadAsync, token), () => !IsBusy);
        _createRequestCommand = new AsyncRelayCommand(CreateRequestAsync, () => !IsBusy && RequestSite is not null && ParseHosts(RequestHosts).Count > 0);
        _completeCommand = new AsyncRelayCommand(CompleteAsync, () => !IsBusy && SelectedPending is not null && CertificatePath.Length > 0);
        _cancelRequestCommand = new AsyncRelayCommand(CancelRequestAsync, () => !IsBusy && SelectedPending is not null);
        _importCommand = new AsyncRelayCommand(ImportAsync, () => !IsBusy && ImportSite is not null && PfxPath.Length > 0);
        _adoptCommand = new AsyncRelayCommand(AdoptAsync, () => !IsBusy && SelectedBinding?.CanAdopt == true);
    }

    public ObservableCollection<IisSiteOption> Sites { get; } = [];
    public IReadOnlyList<KeyTypeOption> KeyTypes { get; }
    public ObservableCollection<PendingRequestRowViewModel> PendingRequests { get; } = [];
    public ObservableCollection<DiscoveredBindingRowViewModel> Bindings { get; } = [];
    public ObservableCollection<string> ProgressLines { get; } = [];
    public IAsyncRelayCommand RefreshCommand => _refreshCommand;
    public IAsyncRelayCommand CreateRequestCommand => _createRequestCommand;
    public IAsyncRelayCommand CompleteCommand => _completeCommand;
    public IAsyncRelayCommand CancelRequestCommand => _cancelRequestCommand;
    public IAsyncRelayCommand ImportCommand => _importCommand;
    public IAsyncRelayCommand AdoptCommand => _adoptCommand;

    /// <summary>The selected request's CSR, to copy into the provider's order form.</summary>
    public string? SelectedCsr => SelectedPending?.Request.CsrPem;
    public bool HasSelectedPending => SelectedPending is not null;
    public string SuggestedCsrFileName =>
        SelectedPending is { } pending ? $"sslense-{pending.Request.Hosts[0].Replace('*', '_')}-{pending.Created:yyyyMMdd}.csr" : "request.csr";

    /// <param name="replaceSite">A site whose imported certificate is due: preselected for a new request.</param>
    public async Task InitializeAsync(string? replaceSite = null)
    {
        await _refreshCommand.ExecuteAsync(null);
        if (replaceSite is not null && Sites.FirstOrDefault(site =>
                string.Equals(site.Name, replaceSite, StringComparison.OrdinalIgnoreCase)) is { } site)
        {
            RequestSite = site;
            ResultMessage = $"To replace the certificate for '{site.Name}', create a request below and submit it to your " +
                            "certificate provider as a renewal or reissue. When the new certificate arrives, complete the request.";
        }
    }

    public async Task SaveCsrAsync(string path)
    {
        if (SelectedCsr is not { } csr) return;
        try
        {
            await File.WriteAllTextAsync(path, csr).ConfigureAwait(true);
            ResultMessage = $"Saved the request to {path}.";
        }
        catch (Exception exception)
        {
            ErrorMessage = exception.Message;
        }
    }

    partial void OnIsBusyChanged(bool value) => NotifyCommands();
    partial void OnRequestHostsChanged(string value) => NotifyCommands();
    partial void OnCertificatePathChanged(string value) => NotifyCommands();
    partial void OnPfxPathChanged(string value) => NotifyCommands();
    partial void OnImportSiteChanged(IisSiteOption? value) => NotifyCommands();
    partial void OnSelectedBindingChanged(DiscoveredBindingRowViewModel? value) => NotifyCommands();

    partial void OnRequestSiteChanged(IisSiteOption? value)
    {
        RequestHosts = value is null ? string.Empty : string.Join(", ", SiteHosts(value.Site));
        NotifyCommands();
    }

    partial void OnSelectedPendingChanged(PendingRequestRowViewModel? value)
    {
        CertificatePath = string.Empty;
        ChainPath = string.Empty;
        CompleteForce = false;
        OnPropertyChanged(nameof(SelectedCsr));
        OnPropertyChanged(nameof(HasSelectedPending));
        OnPropertyChanged(nameof(SuggestedCsrFileName));
        NotifyCommands();
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        var requestSite = RequestSite?.Name;
        var importSite = ImportSite?.Name;
        var pendingSite = SelectedPending?.SiteName;

        var sites = await _iisService.GetSitesAsync(cancellationToken).ConfigureAwait(true);
        Sites.Clear();
        foreach (var site in sites) Sites.Add(new IisSiteOption(site.Name, site));
        RequestSite = Sites.FirstOrDefault(site => site.Name == requestSite) ?? Sites.FirstOrDefault();
        ImportSite = Sites.FirstOrDefault(site => site.Name == importSite) ?? Sites.FirstOrDefault();

        await LoadPendingAsync(pendingSite, cancellationToken).ConfigureAwait(true);
        Bindings.Clear();
        foreach (var binding in await _service.DiscoverAsync(cancellationToken).ConfigureAwait(true))
        {
            Bindings.Add(new DiscoveredBindingRowViewModel(binding));
        }
    }

    private async Task LoadPendingAsync(string? selectSite, CancellationToken cancellationToken)
    {
        PendingRequests.Clear();
        foreach (var request in await _pendingStore.GetAllAsync(cancellationToken).ConfigureAwait(true))
        {
            PendingRequests.Add(new PendingRequestRowViewModel(request));
        }

        SelectedPending = PendingRequests.FirstOrDefault(row => string.Equals(row.SiteName, selectSite, StringComparison.OrdinalIgnoreCase))
            ?? PendingRequests.FirstOrDefault();
    }

    private Task CreateRequestAsync(CancellationToken cancellationToken) => RunAsync(async token =>
    {
        var (siteName, hosts, keyType) = (RequestSite!.Name, ParseHosts(RequestHosts), SelectedKeyType.Id);
        var request = await OffUiThread(() => _service.CreateRequestAsync(siteName, hosts, keyType, token)).ConfigureAwait(true);
        await LoadPendingAsync(request.SiteName, token).ConfigureAwait(true);
        ResultMessage = $"Request created for {string.Join(", ", request.Hosts)}. Copy or save it below and submit it to your " +
                        "certificate provider. When the certificate is issued, complete the request here.";
    }, cancellationToken);

    private Task CompleteAsync(CancellationToken cancellationToken) => RunAsync(async token =>
    {
        var site = SelectedPending!.SiteName;
        var certificate = await File.ReadAllBytesAsync(CertificatePath, token).ConfigureAwait(true);
        var chain = ChainPath.Length > 0 ? await File.ReadAllBytesAsync(ChainPath, token).ConfigureAwait(true) : null;
        var (force, progress) = (CompleteForce, CreateProgress());
        var result = await OffUiThread(() => _service.CompleteRequestAsync(site, certificate, chain, force, progress, token))
            .ConfigureAwait(true);
        ShowResult(result);
        await LoadAsync(token).ConfigureAwait(true);
    }, cancellationToken);

    private Task CancelRequestAsync(CancellationToken cancellationToken) => RunAsync(async token =>
    {
        var site = SelectedPending!.SiteName;
        await _service.CancelRequestAsync(site, token).ConfigureAwait(true);
        await LoadPendingAsync(null, token).ConfigureAwait(true);
        ResultMessage = $"Cancelled the request for '{site}' and deleted its private key.";
    }, cancellationToken);

    private Task ImportAsync(CancellationToken cancellationToken) => RunAsync(async token =>
    {
        var pfx = await File.ReadAllBytesAsync(PfxPath, token).ConfigureAwait(true);
        try
        {
            var (siteName, hosts, password, force, progress) = (ImportSite!.Name, ParseHosts(ImportHosts), PfxPassword, ImportForce, CreateProgress());
            var result = await OffUiThread(() => _service.ImportPfxAsync(siteName, hosts, pfx, password, force, progress, token))
                .ConfigureAwait(true);
            ShowResult(result);
            PfxPath = string.Empty;
            PfxPassword = string.Empty;
            ImportForce = false;
        }
        finally
        {
            Array.Clear(pfx);
        }

        await LoadAsync(token).ConfigureAwait(true);
    }, cancellationToken);

    private Task AdoptAsync(CancellationToken cancellationToken) => RunAsync(async token =>
    {
        var binding = SelectedBinding!.Binding;
        var record = await OffUiThread(() => _service.AdoptAsync(binding.SiteName, binding.Thumbprint, token)).ConfigureAwait(true);
        ResultMessage = $"SSLense now monitors the certificate for '{record.SiteName}' ({string.Join(", ", record.Hosts)}), " +
                        $"expiring {record.NotAfter.LocalDateTime:dd MMM yyyy}. IIS was not changed.";
        await LoadAsync(token).ConfigureAwait(true);
    }, cancellationToken);

    /// <summary>
    /// Key generation, PFX parsing and chain building are synchronous inside Core and can take seconds (chain building may
    /// fetch intermediates), so they run on the thread pool to keep the window responsive. Progress is created on the UI
    /// thread beforehand, so its reports still arrive there.
    /// </summary>
    private static Task<T> OffUiThread<T>(Func<Task<T>> operation) => Task.Run(operation);

    private void ShowResult(ImportResult result)
    {
        var certificate = result.Certificate;
        ResultMessage = string.Join(" ", new[]
        {
            $"Installed and bound the certificate for '{certificate.SiteName}' ({string.Join(", ", certificate.Hosts)}), " +
            $"expiring {certificate.NotAfter.LocalDateTime:dd MMM yyyy}."
        }.Concat(result.Notes));
    }

    private async Task RunAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        IsBusy = true;
        ErrorMessage = null;
        ResultMessage = null;
        try { await action(cancellationToken).ConfigureAwait(true); }
        catch (OperationCanceledException) { ResultMessage = "Operation cancelled."; }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Other providers operation failed");
            ErrorMessage = exception.Message;
            AddProgress("error", exception.Message);
        }
        finally { IsBusy = false; }
    }

    private IProgress<ProgressEvent> CreateProgress() =>
        new Progress<ProgressEvent>(value => AddProgress(value.Step, value.Message));

    private void AddProgress(string step, string message)
    {
        ProgressLines.Add($"[{DateTime.Now:HH:mm:ss}] [{step}] {message}");
        while (ProgressLines.Count > 200) ProgressLines.RemoveAt(0);
    }

    private static IReadOnlyList<string> SiteHosts(IisSite site) => site.Bindings
        .Select(binding => binding.HostName)
        .Where(host => !string.IsNullOrWhiteSpace(host))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static IReadOnlyList<string> ParseHosts(string value) =>
        value.Split([',', ';', ' ', '\r', '\n', '\t'], StringSplitOptions.RemoveEmptyEntries);

    private void NotifyCommands()
    {
        _refreshCommand.NotifyCanExecuteChanged();
        _createRequestCommand.NotifyCanExecuteChanged();
        _completeCommand.NotifyCanExecuteChanged();
        _cancelRequestCommand.NotifyCanExecuteChanged();
        _importCommand.NotifyCanExecuteChanged();
        _adoptCommand.NotifyCanExecuteChanged();
    }
}
