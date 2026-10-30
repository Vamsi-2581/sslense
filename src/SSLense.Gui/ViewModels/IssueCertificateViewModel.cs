using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Validation;

namespace SSLense.Gui.ViewModels;

public partial class IssueCertificateViewModel : ObservableObject
{
    private readonly IIisService _iisService;
    private readonly IPreflightService _preflightService;
    private readonly IAcmeService _acmeService;
    private readonly ISettingsService _settingsService;
    private readonly ILogger<IssueCertificateViewModel> _logger;
    private readonly AsyncRelayCommand _preflightCommand;
    private readonly AsyncRelayCommand _issueCommand;

    [ObservableProperty] private IisSiteOption? selectedSite;
    [ObservableProperty] private int currentStep = 1;
    [ObservableProperty] private string email = string.Empty;
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private bool preflightPassed;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private string resultMessage = string.Empty;
    [ObservableProperty] private bool useProduction;
    [ObservableProperty] private bool productionRiskAccepted;

    public IssueCertificateViewModel(
        IIisService iisService,
        IPreflightService preflightService,
        IAcmeService acmeService,
        ISettingsService settingsService,
        ILogger<IssueCertificateViewModel> logger)
    {
        _iisService = iisService;
        _preflightService = preflightService;
        _acmeService = acmeService;
        _settingsService = settingsService;
        _logger = logger;
        NextCommand = new RelayCommand(Next, CanNext);
        BackCommand = new RelayCommand(Back, () => !IsBusy && CurrentStep > 1);
        _preflightCommand = new AsyncRelayCommand(RunPreflightAsync, CanRunPreflight);
        _issueCommand = new AsyncRelayCommand(IssueAsync, CanIssue);
        CancelCommand = new RelayCommand(Cancel, () => IsBusy);
        StartOverCommand = new RelayCommand(StartOver, () => !IsBusy);
    }

    public ObservableCollection<IisSiteOption> Sites { get; } = [];
    public ObservableCollection<HostOptionViewModel> Hosts { get; } = [];
    public ObservableCollection<PreflightCheckViewModel> PreflightChecks { get; } = [];
    public ObservableCollection<string> ProgressLines { get; } = [];
    public IRelayCommand NextCommand { get; }
    public IRelayCommand BackCommand { get; }
    public IAsyncRelayCommand PreflightCommand => _preflightCommand;
    public IAsyncRelayCommand IssueCommand => _issueCommand;
    public IRelayCommand CancelCommand { get; }
    public IRelayCommand StartOverCommand { get; }
    public bool IsStepOne => CurrentStep == 1;
    public bool IsStepTwo => CurrentStep == 2;
    public bool IsStepThree => CurrentStep == 3;
    public bool UseStaging
    {
        get => !UseProduction;
        set => UseProduction = !value;
    }
    public string StepTitle => $"Step {CurrentStep} of 3";

    public async Task InitializeAsync()
    {
        if (Sites.Count > 0)
        {
            return;
        }

        try
        {
            var config = await _settingsService.GetAsync();
            Email = config.DefaultEmail ?? string.Empty;
            var sites = await _iisService.GetSitesAsync();
            foreach (var site in sites)
            {
                Sites.Add(new IisSiteOption(site.Name, site));
            }
            SelectedSite = Sites.FirstOrDefault();
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not initialize the issue wizard");
            ErrorMessage = exception.Message;
        }
    }

    partial void OnSelectedSiteChanged(IisSiteOption? value)
    {
        foreach (var host in Hosts)
        {
            host.PropertyChanged -= OnHostPropertyChanged;
        }
        Hosts.Clear();
        if (value is not null)
        {
            var names = value.Site.Bindings.Where(binding => !string.IsNullOrWhiteSpace(binding.HostName))
                .Select(binding => binding.HostName).Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var name in names)
            {
                var ready = value.Site.Bindings.Any(binding =>
                    string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) &&
                    binding.Port == 80 && string.Equals(binding.HostName, name, StringComparison.OrdinalIgnoreCase));
                var option = new HostOptionViewModel(name, ready);
                option.PropertyChanged += OnHostPropertyChanged;
                Hosts.Add(option);
            }
        }
        NotifyCommands();
    }

    partial void OnCurrentStepChanged(int value)
    {
        OnPropertyChanged(nameof(IsStepOne));
        OnPropertyChanged(nameof(IsStepTwo));
        OnPropertyChanged(nameof(IsStepThree));
        OnPropertyChanged(nameof(StepTitle));
        NotifyCommands();
    }

    partial void OnEmailChanged(string value) => NotifyCommands();
    partial void OnPreflightPassedChanged(bool value) => NotifyCommands();
    partial void OnIsBusyChanged(bool value) => NotifyCommands();
    partial void OnUseProductionChanged(bool value)
    {
        OnPropertyChanged(nameof(UseStaging));
        if (!value)
        {
            ProductionRiskAccepted = false;
        }
        PreflightPassed = false;
        NotifyCommands();
    }
    partial void OnProductionRiskAcceptedChanged(bool value) => NotifyCommands();

    private void OnHostPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(HostOptionViewModel.IsSelected))
        {
            PreflightPassed = false;
            NotifyCommands();
        }
    }

    private void Next()
    {
        CurrentStep = 2;
        PreflightPassed = false;
        PreflightChecks.Clear();
    }

    private void Back() => CurrentStep = Math.Max(1, CurrentStep - 1);

    private async Task RunPreflightAsync(CancellationToken cancellationToken)
    {
        await RunBusyAsync(async token =>
        {
            PreflightChecks.Clear();
            var checks = await _preflightService.CheckAsync(
                SelectedSite!.Name, SelectedHosts(), token).ConfigureAwait(true);
            foreach (var check in checks)
            {
                PreflightChecks.Add(new PreflightCheckViewModel(check));
            }
            PreflightPassed = checks.Count > 0 && checks.All(check => check.Succeeded);
            ResultMessage = PreflightPassed ? "All pre-flight checks passed." : "Fix the failed checks before issuing.";
        }, cancellationToken);
    }

    private async Task IssueAsync(CancellationToken cancellationToken)
    {
        CurrentStep = 3;
        ProgressLines.Clear();
        ResultMessage = string.Empty;
        await RunBusyAsync(async token =>
        {
            var result = await _acmeService.IssueAsync(
                new AcmeIssueRequest(
                    SelectedSite!.Name,
                    SelectedHosts(),
                    Email,
                    Force: false,
                    AuthorityId: UseProduction ? CertificateAuthorities.LetsEncryptId : CertificateAuthorities.LetsEncryptStagingId),
                new Progress<ProgressEvent>(value =>
                    ProgressLines.Add($"[{DateTime.Now:HH:mm:ss}] [{value.Step}] {value.Message}")),
                token).ConfigureAwait(true);
            var environment = UseProduction ? "Production" : "Staging";
            ResultMessage = $"{environment} certificate installed successfully. Thumbprint: {result.CertificateThumbprint}";
        }, cancellationToken);
    }

    private async Task RunBusyAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        IsBusy = true;
        ErrorMessage = null;
        try { await action(cancellationToken).ConfigureAwait(true); }
        catch (OperationCanceledException) { ResultMessage = "Operation cancelled."; }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Issue wizard operation failed");
            ErrorMessage = exception.Message;
        }
        finally { IsBusy = false; }
    }

    private IReadOnlyList<string> SelectedHosts() => Hosts.Where(value => value.IsSelected).Select(value => value.Host).ToArray();
    private bool CanNext() => !IsBusy && CurrentStep == 1 && SelectedSite is not null && Hosts.Any(value => value.IsSelected);
    private bool CanRunPreflight() => !IsBusy && CurrentStep == 2 && SelectedSite is not null && !string.IsNullOrWhiteSpace(Email);
    private bool CanIssue() =>
        !IsBusy && CurrentStep == 2 && PreflightPassed && (!UseProduction || ProductionRiskAccepted);
    private void Cancel() { _preflightCommand.Cancel(); _issueCommand.Cancel(); }
    private void StartOver() { CurrentStep = 1; PreflightPassed = false; ProductionRiskAccepted = false; PreflightChecks.Clear(); ProgressLines.Clear(); ErrorMessage = null; ResultMessage = string.Empty; }
    private void NotifyCommands()
    {
        (NextCommand as RelayCommand)?.NotifyCanExecuteChanged();
        (BackCommand as RelayCommand)?.NotifyCanExecuteChanged();
        _preflightCommand.NotifyCanExecuteChanged();
        _issueCommand.NotifyCanExecuteChanged();
        (CancelCommand as RelayCommand)?.NotifyCanExecuteChanged();
        (StartOverCommand as RelayCommand)?.NotifyCanExecuteChanged();
    }
}
