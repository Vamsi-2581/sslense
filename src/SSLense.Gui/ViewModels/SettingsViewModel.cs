using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using System.IO;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using SSLense.Core.WindowsServices;

namespace SSLense.Gui.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ISettingsService _settingsService;
    private readonly INotificationSettingsService _notificationSettingsService;
    private readonly INotifier _notifier;
    private readonly IWindowsServiceManager _serviceManager;
    private readonly ILogger<SettingsViewModel> _logger;

    [ObservableProperty] private string defaultEmail = string.Empty;
    [ObservableProperty] private int renewalThresholdDays = 30;

    [ObservableProperty] private EmailPreset? selectedPreset;
    [ObservableProperty] private string emailHost = string.Empty;
    [ObservableProperty] private int emailPort = 587;
    [ObservableProperty] private SmtpSecurity emailSecurity = SmtpSecurity.Auto;
    [ObservableProperty] private SmtpAuthentication emailAuthentication = SmtpAuthentication.None;
    [ObservableProperty] private string emailUsername = string.Empty;
    [ObservableProperty] private string emailPassword = string.Empty;
    [ObservableProperty] private string emailFrom = string.Empty;
    [ObservableProperty] private string emailTo = string.Empty;
    [ObservableProperty] private string emailStatus = "Not configured.";

    [ObservableProperty] private ChatFormat newChatFormat = ChatFormat.Teams;
    [ObservableProperty] private string newChatName = string.Empty;
    [ObservableProperty] private string newChatUrl = string.Empty;
    [ObservableProperty] private ChatOverview? selectedChat;

    [ObservableProperty] private string heartbeatUrl = string.Empty;
    [ObservableProperty] private string heartbeatStatus = "Not configured.";
    [ObservableProperty] private bool eventLogEnabled = true;
    [ObservableProperty] private bool notifyOnSuccess;

    [ObservableProperty] private string serviceStatus = "Checking...";
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private string resultMessage = string.Empty;

    public SettingsViewModel(
        ISettingsService settingsService,
        INotificationSettingsService notificationSettingsService,
        INotifier notifier,
        IWindowsServiceManager serviceManager,
        ILogger<SettingsViewModel> logger)
    {
        _settingsService = settingsService;
        _notificationSettingsService = notificationSettingsService;
        _notifier = notifier;
        _serviceManager = serviceManager;
        _logger = logger;
        SaveGeneralCommand = Command(SaveGeneralAsync);
        SaveEmailCommand = Command(SaveEmailAsync);
        RemoveEmailCommand = Command(token => ChangeNotificationsAsync(
            ct => _notificationSettingsService.RemoveEmailAsync(ct), "Email settings removed.", token));
        AddChatCommand = Command(AddChatAsync);
        RemoveChatCommand = Command(RemoveChatAsync);
        SaveHeartbeatCommand = Command(token => ChangeNotificationsAsync(
            ct => _notificationSettingsService.SetHeartbeatAsync(HeartbeatUrl, ct), "Heartbeat saved.", token));
        RemoveHeartbeatCommand = Command(token => ChangeNotificationsAsync(
            ct => _notificationSettingsService.SetHeartbeatAsync(null, ct), "Heartbeat removed.", token));
        SaveOptionsCommand = Command(token => ChangeNotificationsAsync(
            ct => _notificationSettingsService.SetOptionsAsync(EventLogEnabled, NotifyOnSuccess, ct), "Notification options saved.", token));
        TestNotificationCommand = Command(TestNotificationAsync);
        RefreshServiceCommand = Command(RefreshServiceAsync);
        StartServiceCommand = Command(StartServiceAsync);
        StopServiceCommand = Command(StopServiceAsync);
        RestartServiceCommand = Command(RestartServiceAsync);
    }

    public IReadOnlyList<EmailPreset> EmailPresets => EmailPreset.All;
    public IReadOnlyList<SmtpSecurity> SecurityOptions { get; } = Enum.GetValues<SmtpSecurity>();
    public IReadOnlyList<SmtpAuthentication> AuthenticationOptions { get; } = Enum.GetValues<SmtpAuthentication>();
    public IReadOnlyList<ChatFormat> ChatFormats { get; } = Enum.GetValues<ChatFormat>();
    public ObservableCollection<ChatOverview> ChatChannels { get; } = [];
    public ObservableCollection<ChannelResult> TestResults { get; } = [];
    public string PresetHint => SelectedPreset?.Hint ?? string.Empty;

    public IAsyncRelayCommand SaveGeneralCommand { get; }
    public IAsyncRelayCommand SaveEmailCommand { get; }
    public IAsyncRelayCommand RemoveEmailCommand { get; }
    public IAsyncRelayCommand AddChatCommand { get; }
    public IAsyncRelayCommand RemoveChatCommand { get; }
    public IAsyncRelayCommand SaveHeartbeatCommand { get; }
    public IAsyncRelayCommand RemoveHeartbeatCommand { get; }
    public IAsyncRelayCommand SaveOptionsCommand { get; }
    public IAsyncRelayCommand TestNotificationCommand { get; }
    public IAsyncRelayCommand RefreshServiceCommand { get; }
    public IAsyncRelayCommand StartServiceCommand { get; }
    public IAsyncRelayCommand StopServiceCommand { get; }
    public IAsyncRelayCommand RestartServiceCommand { get; }

    public async Task InitializeAsync()
    {
        await RunAsync(async token =>
        {
            var config = await _settingsService.GetAsync(token).ConfigureAwait(true);
            DefaultEmail = config.DefaultEmail ?? string.Empty;
            RenewalThresholdDays = config.RenewalThresholdDays;
            await LoadNotificationsAsync(token).ConfigureAwait(true);
            await RefreshServiceCoreAsync(token).ConfigureAwait(true);
        }, CancellationToken.None);
    }

    partial void OnIsBusyChanged(bool value)
    {
        foreach (var command in AllCommands()) command.NotifyCanExecuteChanged();
    }

    // A preset only fills in defaults; every field stays editable because organisations differ.
    partial void OnSelectedPresetChanged(EmailPreset? value)
    {
        OnPropertyChanged(nameof(PresetHint));
        if (value is null) return;
        if (value.Host is not null) EmailHost = value.Host;
        EmailPort = value.Port;
        EmailSecurity = value.Security;
        EmailAuthentication = value.Authentication;
        if (value.DefaultUsername is not null) EmailUsername = value.DefaultUsername;
    }

    private async Task LoadNotificationsAsync(CancellationToken token)
    {
        var overview = await _notificationSettingsService.GetOverviewAsync(token).ConfigureAwait(true);
        if (overview.Email is { } email)
        {
            EmailHost = email.Host; EmailPort = email.Port; EmailSecurity = email.Security;
            EmailAuthentication = email.Authentication; EmailUsername = email.Username ?? string.Empty;
            EmailFrom = email.From; EmailTo = string.Join(", ", email.To);
            EmailStatus = $"Sending through {email.Host}:{email.Port}" +
                          (email.Authentication == SmtpAuthentication.None ? " without sign-in." : $" as {email.Username}.");
        }
        else
        {
            EmailStatus = "Not configured.";
        }

        ChatChannels.Clear();
        foreach (var chat in overview.Chat) ChatChannels.Add(chat);
        HeartbeatStatus = overview.HeartbeatHost is { } host ? $"Pinging {host} after every healthy hourly check." : "Not configured.";
        EventLogEnabled = overview.EventLogEnabled;
        NotifyOnSuccess = overview.NotifyOnSuccess;
    }

    private AsyncRelayCommand Command(Func<CancellationToken, Task> action) => new(action, () => !IsBusy);

    private Task SaveGeneralAsync(CancellationToken token) => RunAsync(async ct =>
    {
        await _settingsService.SaveGeneralAsync(DefaultEmail, RenewalThresholdDays, ct).ConfigureAwait(true);
        ResultMessage = "General settings saved. Staging remains the default for new issuance.";
    }, token);

    private Task SaveEmailAsync(CancellationToken token) => ChangeNotificationsAsync(ct => _notificationSettingsService.SetEmailAsync(
            new EmailSettingsRequest(
                EmailHost, EmailPort, EmailSecurity, EmailAuthentication,
                string.IsNullOrWhiteSpace(EmailUsername) ? null : EmailUsername,
                string.IsNullOrEmpty(EmailPassword) ? null : EmailPassword,
                EmailFrom,
                EmailTo.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)),
            ct),
        "Email settings saved. Use Send test to check delivery.", token);

    private Task AddChatAsync(CancellationToken token) => ChangeNotificationsAsync(ct => _notificationSettingsService.AddChatAsync(
            new ChatSettingsRequest(NewChatFormat, NewChatUrl, NewChatName), ct),
        $"{NewChatFormat} channel added. Use Send test to check delivery.", token);

    private Task RemoveChatAsync(CancellationToken token) => SelectedChat is { } chat
        ? ChangeNotificationsAsync(ct => _notificationSettingsService.RemoveChatAsync(chat.Number, ct), $"{chat.Format} channel removed.", token)
        : RunAsync(_ =>
        {
            ErrorMessage = "Select a chat channel to remove.";
            return Task.CompletedTask;
        }, token);

    private Task ChangeNotificationsAsync(Func<CancellationToken, Task> change, string message, CancellationToken token) => RunAsync(async ct =>
    {
        await change(ct).ConfigureAwait(true);

        // Secrets are cleared from memory as soon as they are saved.
        EmailPassword = string.Empty; NewChatUrl = string.Empty; NewChatName = string.Empty; HeartbeatUrl = string.Empty;
        await LoadNotificationsAsync(ct).ConfigureAwait(true);
        ResultMessage = message;
    }, token);

    private Task TestNotificationAsync(CancellationToken token) => RunAsync(async ct =>
    {
        TestResults.Clear();
        var results = await _notifier.TestAsync(ct).ConfigureAwait(true);
        foreach (var result in results) TestResults.Add(result);
        var failed = results.Count(result => !result.Succeeded);
        ResultMessage = failed == 0
            ? $"Test delivered through {results.Count} channel(s): {string.Join(", ", results.Select(result => result.Channel))}."
            : string.Empty;
        // Shown in the banner, not only in the list under Options, which may be scrolled out of view.
        ErrorMessage = failed == 0
            ? null
            : $"{failed} of {results.Count} channel(s) failed. " +
              string.Join(" ", results.Where(result => !result.Succeeded).Select(result => $"{result.Channel}: {result.Message}"));
    }, token);

    private Task RefreshServiceAsync(CancellationToken token) => RunAsync(RefreshServiceCoreAsync, token);
    private Task StartServiceAsync(CancellationToken token) => ServiceActionAsync(_serviceManager.StartAsync, "Service started.", token);
    private Task StopServiceAsync(CancellationToken token) => ServiceActionAsync(_serviceManager.StopAsync, "Service stopped.", token);
    // The installer registers and starts the service; these are for troubleshooting, e.g. after changing settings by hand.
    private Task RestartServiceAsync(CancellationToken token) => ServiceActionAsync(async ct =>
    {
        await _serviceManager.StopAsync(ct).ConfigureAwait(true);
        await _serviceManager.StartAsync(ct).ConfigureAwait(true);
    }, "Service restarted.", token);

    private Task ServiceActionAsync(Func<CancellationToken, Task> action, string message, CancellationToken token) => RunAsync(async ct =>
    {
        await action(ct).ConfigureAwait(true); ResultMessage = message; await RefreshServiceCoreAsync(ct).ConfigureAwait(true);
    }, token);

    private async Task RefreshServiceCoreAsync(CancellationToken token) =>
        ServiceStatus = (await _serviceManager.GetStatusAsync(token).ConfigureAwait(true)).ToString();

    private async Task RunAsync(Func<CancellationToken, Task> action, CancellationToken token)
    {
        IsBusy = true; ErrorMessage = null; ResultMessage = string.Empty;
        try { await action(token).ConfigureAwait(true); }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Settings operation failed"); ErrorMessage = exception.Message;
        }
        finally { IsBusy = false; }
    }

    private IEnumerable<AsyncRelayCommand> AllCommands() =>
    [
        (AsyncRelayCommand)SaveGeneralCommand, (AsyncRelayCommand)SaveEmailCommand, (AsyncRelayCommand)RemoveEmailCommand,
        (AsyncRelayCommand)AddChatCommand, (AsyncRelayCommand)RemoveChatCommand, (AsyncRelayCommand)SaveHeartbeatCommand,
        (AsyncRelayCommand)RemoveHeartbeatCommand, (AsyncRelayCommand)SaveOptionsCommand, (AsyncRelayCommand)TestNotificationCommand,
        (AsyncRelayCommand)RefreshServiceCommand, (AsyncRelayCommand)RestartServiceCommand,
        (AsyncRelayCommand)StartServiceCommand, (AsyncRelayCommand)StopServiceCommand
    ];
}
