using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;

namespace SSLense.Gui.ViewModels;

public partial class CertificateDetailsViewModel : ObservableObject
{
    private readonly ICertificateManagementService _managementService;
    private readonly IRenewalService _renewalService;
    private readonly ILogger<CertificateDetailsViewModel> _logger;
    private readonly INavigationService _navigation;
    private readonly IReminderService _reminderService;
    private readonly AsyncRelayCommand _applyReminderCommand;
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
    [ObservableProperty] private bool isImported;
    [ObservableProperty] private ReminderChoice? selectedReminderChoice;
    [ObservableProperty] private string reminderState = string.Empty;
    [ObservableProperty] private string lastReminded = string.Empty;

    public CertificateDetailsViewModel(
        ICertificateManagementService managementService,
        IRenewalService renewalService,
        ILogger<CertificateDetailsViewModel> logger,
        INavigationService navigation,
        IReminderService reminderService)
    {
        _reminderService = reminderService;
        _applyReminderCommand = new AsyncRelayCommand(ApplyReminderAsync, () => CanOperate() && SelectedReminderChoice is not null);
        _managementService = managementService;
        _renewalService = renewalService;
        _logger = logger;
        _navigation = navigation;
        OrderReplacementCommand = new RelayCommand(() => _navigation.Navigate("Other Providers", SelectedSite), () => !IsBusy && IsImported);
        _refreshCommand = new AsyncRelayCommand(RefreshAsync, CanOperate);
        _renewCommand = new AsyncRelayCommand(RenewAsync, () => CanOperate() && !IsImported);
        _removeCommand = new AsyncRelayCommand(RemoveAsync, CanOperate);
    }

    public ObservableCollection<string> Sites { get; } = [];
    public ObservableCollection<string> RecentLogLines { get; } = [];
    public IAsyncRelayCommand RefreshCommand => _refreshCommand;
    public IAsyncRelayCommand RenewCommand => _renewCommand;
    public IAsyncRelayCommand RemoveCommand => _removeCommand;

    /// <summary>Imported certificates are replaced by ordering again from their provider; SSLense cannot renew them.</summary>
    public IRelayCommand OrderReplacementCommand { get; }

    public IAsyncRelayCommand ApplyReminderCommand => _applyReminderCommand;

    public IReadOnlyList<ReminderChoice> ReminderChoices { get; } =
    [
        new("On", ReminderMode.On, null),
        new("Snooze for 7 days", ReminderMode.Snoozed, 7),
        new("Snooze for 30 days", ReminderMode.Snoozed, 30),
        new("Off until this certificate is replaced", ReminderMode.OffUntilReplaced, null),
        new("Off permanently", ReminderMode.Off, null)
    ];

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
            IsImported = detail.Source == CertificateSource.Imported;
            await LoadReminderAsync(token).ConfigureAwait(true);
            RecentLogLines.Clear();
            foreach (var line in detail.RecentLogLines) RecentLogLines.Add(line);
        }, cancellationToken);
    }

    private async Task LoadReminderAsync(CancellationToken cancellationToken)
    {
        var overview = await _reminderService.GetOverviewAsync(cancellationToken).ConfigureAwait(true);
        var record = overview.Certificates.FirstOrDefault(value =>
            string.Equals(value.SiteName, SelectedSite, StringComparison.OrdinalIgnoreCase));
        if (record is null) return;
        ReminderState = record.Reminders switch
        {
            ReminderMode.Snoozed when record.SnoozedUntil is { } until && until > DateTimeOffset.UtcNow =>
                $"Snoozed until {until.ToLocalTime():dd MMM yyyy HH:mm}",
            ReminderMode.OffUntilReplaced => "Off until this certificate is replaced",
            ReminderMode.Off => "Off permanently (renewal failures are still reported)",
            _ => $"On: from {overview.Settings.StartDays} days before expiry, in the daily digest at {overview.Settings.SendAtHour:00}:00"
        };
        LastReminded = record.LastRemindedAt is { } at ? at.ToLocalTime().ToString("dd MMM yyyy HH:mm") : "Not yet";
        SelectedReminderChoice = record.Reminders switch
        {
            ReminderMode.OffUntilReplaced => ReminderChoices[3],
            ReminderMode.Off => ReminderChoices[4],
            _ => ReminderChoices[0]
        };
    }

    private async Task ApplyReminderAsync(CancellationToken cancellationToken)
    {
        if (SelectedSite is null || SelectedReminderChoice is not { } choice) return;
        await RunAsync(async token =>
        {
            await _reminderService.SetCertificateRemindersAsync(SelectedSite, choice.Mode, choice.SnoozeDays, token).ConfigureAwait(true);
            await LoadReminderAsync(token).ConfigureAwait(true);
            ResultMessage = $"Reminders for '{SelectedSite}': {ReminderState}.";
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
    partial void OnIsImportedChanged(bool value) => NotifyCommands();
    private void NotifyCommands()
    {
        _refreshCommand.NotifyCanExecuteChanged(); _renewCommand.NotifyCanExecuteChanged(); _removeCommand.NotifyCanExecuteChanged();
        (OrderReplacementCommand as RelayCommand)?.NotifyCanExecuteChanged();
        _applyReminderCommand?.NotifyCanExecuteChanged();
    }
    partial void OnSelectedReminderChoiceChanged(ReminderChoice? value) => _applyReminderCommand?.NotifyCanExecuteChanged();
    private static RenewalResult AssertSingle(IReadOnlyList<RenewalResult> results) => results.Single();
}

public sealed record ReminderChoice(string Label, ReminderMode Mode, int? SnoozeDays)
{
    public override string ToString() => Label;
}
