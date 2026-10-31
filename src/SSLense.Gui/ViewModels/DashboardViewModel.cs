using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core;
using SSLense.Core.Diagnostics;
using SSLense.Core.Renewal;

namespace SSLense.Gui.ViewModels;

public partial class DashboardViewModel : ObservableObject
{
    private readonly IRenewalService _renewalService;
    private readonly IHealthCheckService _healthCheckService;
    private readonly ILogger<DashboardViewModel> _logger;
    private readonly INavigationService _navigation;
    private readonly AsyncRelayCommand _refreshCommand;
    private readonly AsyncRelayCommand _renewSelectedCommand;
    private readonly AsyncRelayCommand _renewAllCommand;
    private readonly RelayCommand _cancelCommand;

    [ObservableProperty]
    private CertificateRowViewModel? selectedCertificate;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private string activity = "Ready.";

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasHealthAlert))]
    private string? healthAlertTitle;

    [ObservableProperty]
    private string? healthAlertDetails;

    public DashboardViewModel(
        IRenewalService renewalService,
        IHealthCheckService healthCheckService,
        ILogger<DashboardViewModel> logger,
        INavigationService navigation)
    {
        _renewalService = renewalService;
        _healthCheckService = healthCheckService;
        _logger = logger;
        _navigation = navigation;
        _refreshCommand = new AsyncRelayCommand(RefreshAsync, CanRun);
        _renewSelectedCommand = new AsyncRelayCommand(RenewSelectedAsync, CanRenewSelected);
        _renewAllCommand = new AsyncRelayCommand(RenewAllAsync, CanRenewAll);
        _cancelCommand = new RelayCommand(Cancel, CanCancel);
        IssueNewCommand = new RelayCommand(() => _navigation.Navigate("Issue"), () => !IsBusy);
        OpenHealthCommand = new RelayCommand(() => _navigation.Navigate("Health"));
        ViewDetailsCommand = new RelayCommand(
            () => _navigation.Navigate("Details", SelectedCertificate?.SiteName),
            CanRenewSelected);
    }

    public ObservableCollection<CertificateRowViewModel> Certificates { get; } = [];

    public ObservableCollection<string> ProgressLines { get; } = [];

    public int TotalCount => Certificates.Count;

    public int HealthyCount => Certificates.Count(value => value.StatusKey == "Green");

    public int AttentionCount => Certificates.Count(value => value.StatusKey == "Amber");

    public int FailedCount => Certificates.Count(value => value.StatusKey == "Red");

    public IAsyncRelayCommand RefreshCommand => _refreshCommand;

    public IAsyncRelayCommand RenewSelectedCommand => _renewSelectedCommand;

    public IAsyncRelayCommand RenewAllCommand => _renewAllCommand;

    public IRelayCommand CancelCommand => _cancelCommand;
    public IRelayCommand IssueNewCommand { get; }
    public IRelayCommand OpenHealthCommand { get; }

    public bool HasHealthAlert => HealthAlertTitle is not null;
    public IRelayCommand ViewDetailsCommand { get; }

    public Task InitializeAsync() => _refreshCommand.ExecuteAsync(null);

    partial void OnSelectedCertificateChanged(CertificateRowViewModel? value) =>
        NotifySelectionCommands();

    partial void OnIsBusyChanged(bool value)
    {
        _refreshCommand.NotifyCanExecuteChanged();
        _renewSelectedCommand.NotifyCanExecuteChanged();
        _renewAllCommand.NotifyCanExecuteChanged();
        _cancelCommand.NotifyCanExecuteChanged();
        (IssueNewCommand as RelayCommand)?.NotifyCanExecuteChanged();
        (ViewDetailsCommand as RelayCommand)?.NotifyCanExecuteChanged();
    }

    private Task RefreshAsync(CancellationToken cancellationToken) =>
        RunOperationAsync("Refreshing managed certificates...", LoadCertificatesAsync, cancellationToken);

    private Task RenewSelectedAsync(CancellationToken cancellationToken)
    {
        var selected = SelectedCertificate;
        if (selected is null)
        {
            return Task.CompletedTask;
        }

        return RunOperationAsync(
            $"Renewing {selected.SiteName}...",
            async token =>
            {
                var results = await _renewalService.RenewAsync(
                        new RenewalRequest(SiteName: selected.SiteName, Force: true),
                        CreateProgress(),
                        token)
                    .ConfigureAwait(true);
                AddResults(results);
                await LoadCertificatesAsync(token).ConfigureAwait(true);
            },
            cancellationToken);
    }

    private Task RenewAllAsync(CancellationToken cancellationToken) =>
        RunOperationAsync(
            "Checking all managed certificates for renewal...",
            async token =>
            {
                var results = await _renewalService.RenewAsync(
                        new RenewalRequest(All: true),
                        CreateProgress(),
                        token)
                    .ConfigureAwait(true);
                AddResults(results);
                await LoadCertificatesAsync(token).ConfigureAwait(true);
            },
            cancellationToken);

    private async Task RunOperationAsync(
        string activity,
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        IsBusy = true;
        ErrorMessage = null;
        Activity = activity;
        try
        {
            await action(cancellationToken).ConfigureAwait(true);
            Activity = "Ready.";
        }
        catch (OperationCanceledException)
        {
            Activity = "Operation cancelled.";
            AddProgress("cancel", "Operation cancelled.");
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Dashboard operation failed");
            ErrorMessage = exception.Message;
            Activity = "Operation failed.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadCertificatesAsync(CancellationToken cancellationToken)
    {
        var statuses = await _renewalService.GetStatusAsync(cancellationToken).ConfigureAwait(true);
        Certificates.Clear();
        foreach (var status in statuses)
        {
            Certificates.Add(new CertificateRowViewModel(status));
        }

        Activity = statuses.Count == 0
            ? "No managed certificates yet. Issue a Let's Encrypt certificate, or adopt existing certificates on the Other Providers page."
            : $"Loaded {statuses.Count} managed certificate(s).";
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(HealthyCount));
        OnPropertyChanged(nameof(AttentionCount));
        OnPropertyChanged(nameof(FailedCount));
        _renewAllCommand.NotifyCanExecuteChanged();
        await UpdateHealthAlertAsync(cancellationToken).ConfigureAwait(true);
    }

    private async Task UpdateHealthAlertAsync(CancellationToken cancellationToken)
    {
        try
        {
            var problems = (await _healthCheckService.RunQuickAsync(cancellationToken).ConfigureAwait(true))
                .Where(result => result.Status != HealthStatus.Pass)
                .OrderByDescending(result => result.Status)
                .ToArray();
            HealthAlertDetails = problems.Length == 0
                ? null
                : string.Join(" ", problems.Take(2).Select(result => $"{result.Name}: {result.Message}")) +
                  (problems.Length > 2 ? $" (+{problems.Length - 2} more)" : string.Empty);
            HealthAlertTitle = problems.Length == 0
                ? null
                : problems[0].Status == HealthStatus.Fail
                    ? $"{problems.Length} health problem(s) need attention"
                    : $"{problems.Length} health warning(s)";
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // The banner is advisory; the certificate list above has already loaded.
            _logger.LogWarning(exception, "Quick health check failed");
        }
    }

    private IProgress<ProgressEvent> CreateProgress() =>
        new Progress<ProgressEvent>(value => AddProgress(value.Step, value.Message));

    private void AddResults(IEnumerable<RenewalResult> results)
    {
        foreach (var result in results)
        {
            AddProgress(result.Succeeded ? "result" : "error", $"{result.SiteName}: {result.Message}");
        }
    }

    private void AddProgress(string step, string message)
    {
        ProgressLines.Add($"[{DateTime.Now:HH:mm:ss}] [{step}] {message}");
        while (ProgressLines.Count > 200)
        {
            ProgressLines.RemoveAt(0);
        }
    }

    private bool CanRun() => !IsBusy;

    private bool CanRenewSelected() => !IsBusy && SelectedCertificate is not null;

    private bool CanRenewAll() => !IsBusy && Certificates.Count > 0;

    private bool CanCancel() => IsBusy;

    private void Cancel()
    {
        _refreshCommand.Cancel();
        _renewSelectedCommand.Cancel();
        _renewAllCommand.Cancel();
    }

    private void NotifySelectionCommands()
    {
        _renewSelectedCommand.NotifyCanExecuteChanged();
        (ViewDetailsCommand as RelayCommand)?.NotifyCanExecuteChanged();
    }
}
