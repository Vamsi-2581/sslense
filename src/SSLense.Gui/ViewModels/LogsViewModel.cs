using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core.Logs;

namespace SSLense.Gui.ViewModels;

public partial class LogsViewModel : ObservableObject, IDisposable
{
    private readonly ILogService _logService;
    private readonly ILogger<LogsViewModel> _logger;
    private readonly DispatcherTimer _timer;
    private readonly AsyncRelayCommand _refreshCommand;

    [ObservableProperty]
    private string selectedLevel = "All";

    [ObservableProperty]
    private string filePath = "No log file found.";

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isRefreshing;

    [ObservableProperty]
    private string? statusMessage;

    /// <summary>Entries written before this are hidden. Set by Clear view; the log file itself is never cleared.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsViewCleared))]
    private DateTimeOffset? showSince;

    public LogsViewModel(ILogService logService, ILogger<LogsViewModel> logger)
    {
        _logService = logService;
        _logger = logger;
        _refreshCommand = new AsyncRelayCommand(RefreshAsync, () => !IsRefreshing);
        SaveCopyCommand = new AsyncRelayCommand(SaveCopyAsync);
        CopyCommand = new RelayCommand(Copy);
        ClearViewCommand = new RelayCommand(() => ShowSince = DateTimeOffset.Now);
        ShowAllCommand = new RelayCommand(() => ShowSince = null);
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += OnTimerTick;
    }

    public IReadOnlyList<string> Levels { get; } = ["All", "Debug", "Information", "Warning", "Error"];

    public ObservableCollection<string> Lines { get; } = [];

    public IAsyncRelayCommand RefreshCommand => _refreshCommand;

    public IAsyncRelayCommand SaveCopyCommand { get; }

    public IRelayCommand CopyCommand { get; }

    public IRelayCommand ClearViewCommand { get; }

    public IRelayCommand ShowAllCommand { get; }

    public bool IsViewCleared => ShowSince is not null;

    public void StartLiveUpdates()
    {
        if (!_timer.IsEnabled)
        {
            _timer.Start();
            _ = _refreshCommand.ExecuteAsync(null);
        }
    }

    partial void OnSelectedLevelChanged(string value) => _ = _refreshCommand.ExecuteAsync(null);

    partial void OnShowSinceChanged(DateTimeOffset? value)
    {
        StatusMessage = value is null ? null : $"Showing entries from {value:HH:mm:ss}. The log file is kept; Show all brings back earlier entries.";
        _ = _refreshCommand.ExecuteAsync(null);
    }

    partial void OnIsRefreshingChanged(bool value) => _refreshCommand.NotifyCanExecuteChanged();

    private async void OnTimerTick(object? sender, EventArgs e)
    {
        if (!IsRefreshing)
        {
            await _refreshCommand.ExecuteAsync(null);
        }
    }

    private async Task RefreshAsync()
    {
        IsRefreshing = true;
        ErrorMessage = null;
        try
        {
            var snapshot = await _logService.ReadCurrentAsync(SelectedLevel, since: ShowSince).ConfigureAwait(true);
            FilePath = snapshot.FilePath ?? "No log file found.";
            Lines.Clear();
            foreach (var line in snapshot.Lines)
            {
                Lines.Add(line);
            }
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not refresh the GUI log viewer");
            ErrorMessage = exception.Message;
        }
        finally
        {
            IsRefreshing = false;
        }
    }

    /// <summary>The log folder is restricted to Administrators and SYSTEM, which unelevated Explorer cannot open; a copy on
    /// the Desktop can be opened, attached, or pasted from.</summary>
    private async Task SaveCopyAsync()
    {
        ErrorMessage = null;
        try
        {
            var path = await _logService.SaveCopyAsync(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)).ConfigureAwait(true);
            StatusMessage = $"Saved a copy of today's log to {path}.";
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not save a copy of the log");
            ErrorMessage = exception.Message;
        }
    }

    private void Copy()
    {
        ErrorMessage = null;
        try
        {
            Clipboard.SetText(string.Join(Environment.NewLine, Lines));
            StatusMessage = $"Copied {Lines.Count} line(s) to the clipboard.";
        }
        catch (Exception exception)
        {
            // The clipboard can be briefly locked by another application.
            ErrorMessage = $"Could not copy to the clipboard: {exception.Message} Try again.";
        }
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Tick -= OnTimerTick;
    }
}
