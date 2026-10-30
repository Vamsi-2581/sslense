using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Renewal;

namespace SSLense.Gui.ViewModels;

public partial class CertificateDetailsViewModel : ObservableObject
{
    private readonly ICertificateManagementService _managementService;
    private readonly IRenewalService _renewalService;
    private readonly ILogger<CertificateDetailsViewModel> _logger;
    private readonly AsyncRelayCommand _refreshCommand;
    private readonly AsyncRelayCommand _renewCommand;
    private readonly AsyncRelayCommand _removeCommand;
    private bool _suppressSelectionRefresh;

    [ObservableProperty] private string? selectedSite;
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private string hosts = string.Empty;
    [ObservableProperty] private string issuer = string.Empty;
    [ObservableProperty] private string thumbprint = string.Empty;
    [ObservableProperty] private string issueDate = string.Empty;
    [ObservableProperty] private string expiryDate = string.Empty;
    [ObservableProperty] private string boundSites = string.Empty;
    [ObservableProperty] private string resultMessage = string.Empty;
    [ObservableProperty] private string environment = string.Empty;

    public CertificateDetailsViewModel(
        ICertificateManagementService managementService,
        IRenewalService renewalService,
        ILogger<CertificateDetailsViewModel> logger)
    {
        _managementService = managementService;
        _renewalService = renewalService;
        _logger = logger;
        _refreshCommand = new AsyncRelayCommand(RefreshAsync, CanOperate);
        _renewCommand = new AsyncRelayCommand(RenewAsync, CanOperate);
        _removeCommand = new AsyncRelayCommand(RemoveAsync, CanOperate);
    }

    public ObservableCollection<string> Sites { get; } = [];
    public ObservableCollection<string> RecentLogLines { get; } = [];
    public IAsyncRelayCommand RefreshCommand => _refreshCommand;
    public IAsyncRelayCommand RenewCommand => _renewCommand;
    public IAsyncRelayCommand RemoveCommand => _removeCommand;

    public async Task InitializeAsync(string? requestedSite = null)
    {
        try
        {
            var statuses = await _renewalService.GetStatusAsync();
            Sites.Clear();
            foreach (var status in statuses) Sites.Add(status.SiteName);
            _suppressSelectionRefresh = true;
            SelectedSite = requestedSite is not null && Sites.Contains(requestedSite) ? requestedSite : Sites.FirstOrDefault();
            _suppressSelectionRefresh = false;
            if (SelectedSite is not null) await RefreshAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            _suppressSelectionRefresh = false;
            _logger.LogError(exception, "Could not initialize certificate details");
            ErrorMessage = exception.Message;
        }
    }

    partial void OnSelectedSiteChanged(string? value)
    {
        NotifyCommands();
        if (value is not null && !IsBusy && !_suppressSelectionRefresh) _ = _refreshCommand.ExecuteAsync(null);
    }

    partial void OnIsBusyChanged(bool value) => NotifyCommands();

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        await RunAsync(async token =>
        {
            var detail = await _managementService.GetDetailsAsync(SelectedSite, token).ConfigureAwait(true);
            Hosts = string.Join(", ", detail.Hosts);
            Issuer = detail.Issuer;
            Thumbprint = detail.Thumbprint;
            IssueDate = detail.NotBefore.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
            ExpiryDate = detail.NotAfter.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
            BoundSites = detail.BoundSites.Count == 0 ? "None" : string.Join(", ", detail.BoundSites);
            Environment = detail.AuthorityName;
            RecentLogLines.Clear();
            foreach (var line in detail.RecentLogLines) RecentLogLines.Add(line);
        }, cancellationToken);
    }

    private async Task RenewAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        await RunAsync(async token =>
        {
            var result = AssertSingle(await _renewalService.RenewAsync(
                new RenewalRequest(SiteName: SelectedSite, Force: true), null, token).ConfigureAwait(true));
            ResultMessage = result.Message;
            if (!result.Succeeded) throw new InvalidOperationException(result.Message);
            await RefreshAsync(token).ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task RemoveAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null) return;
        var removedSite = SelectedSite;
        await RunAsync(async token =>
        {
            await _managementService.RemoveAsync(removedSite, token).ConfigureAwait(true);
            ResultMessage = $"Removed the managed certificate and its matching IIS HTTPS bindings for '{removedSite}'.";
            await InitializeAsync().ConfigureAwait(true);
        }, cancellationToken);
    }

    private async Task RunAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        IsBusy = true; ErrorMessage = null;
        try { await action(cancellationToken).ConfigureAwait(true); }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Certificate details operation failed");
            ErrorMessage = exception.Message;
        }
        finally { IsBusy = false; }
    }

    private bool CanOperate() => !IsBusy && SelectedSite is not null;
    private void NotifyCommands() { _refreshCommand.NotifyCanExecuteChanged(); _renewCommand.NotifyCanExecuteChanged(); _removeCommand.NotifyCanExecuteChanged(); }
    private static RenewalResult AssertSingle(IReadOnlyList<RenewalResult> results) => results.Single();
}
