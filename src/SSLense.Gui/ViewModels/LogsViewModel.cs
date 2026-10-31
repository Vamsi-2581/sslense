using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core.Logs;

namespace SSLense.Gui.ViewModels;

public sealed record LogFileOption(LogFileInfo File, string Label);

public partial class LogsViewModel : ObservableObject, IDisposable
{
    private const int MaximumLines = 5000;
    private readonly ILogService _logService;
    private readonly ILogger<LogsViewModel> _logger;
    private readonly DispatcherTimer _timer;
    private readonly AsyncRelayCommand _refreshCommand;
    private bool _selectingFile;

    [ObservableProperty] private string selectedLevel = "All";
    [ObservableProperty] private string search = string.Empty;
    [ObservableProperty] private LogFileOption? selectedFile;
    [ObservableProperty] private bool isLive = true;
    [ObservableProperty] private string text = string.Empty;
    [ObservableProperty] private string summary = string.Empty;
    [ObservableProperty] private string? emptyMessage;
    [ObservableProperty] private string? statusMessage;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private bool isRefreshing;

    public LogsViewModel(ILogService logService, ILogger<LogsViewModel> logger)
    {
        _logService = logService;
        _logger = logger;
        _refreshCommand = new AsyncRelayCommand(RefreshAsync, () => !IsRefreshing);
        SaveCopyCommand = new AsyncRelayCommand(SaveCopyAsync);
        CopyAllCommand = new RelayCommand(CopyAll);
        ClearLogCommand = new AsyncRelayCommand(ClearLogAsync);
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += OnTimerTick;
    }

    public IReadOnlyList<string> Levels { get; } = ["All", "Error", "Warning", "Information", "Debug"];

    public ObservableCollection<LogFileOption> Files { get; } = [];

    public IAsyncRelayCommand RefreshCommand => _refreshCommand;

    public IAsyncRelayCommand SaveCopyCommand { get; }

    public IRelayCommand CopyAllCommand { get; }

    /// <summary>Empties today's log after backing it up; only today's file is written to, so only it can be cleared.</summary>
    public IAsyncRelayCommand ClearLogCommand { get; }

    public bool IsTodaySelected => SelectedFile is { File.IsBackup: false } && ReferenceEquals(SelectedFile, Files.FirstOrDefault());

    /// <summary>
    /// Set by the view while text is selected, so a live update does not replace the text and lose the selection.
    /// </summary>
    public bool HoldUpdates { get; set; }

    public void StartLiveUpdates()
    {
        if (!_timer.IsEnabled)
        {
            _timer.Start();
            _ = _refreshCommand.ExecuteAsync(null);
        }
    }

    partial void OnSelectedLevelChanged(string value) => _ = _refreshCommand.ExecuteAsync(null);

    partial void OnSearchChanged(string value) => _ = _refreshCommand.ExecuteAsync(null);

    partial void OnSelectedFileChanged(LogFileOption? value)
    {
        OnPropertyChanged(nameof(IsTodaySelected));
        // A reload that restores the selection happens inside a refresh; it must not start a second one.
        if (!_selectingFile) _ = _refreshCommand.ExecuteAsync(null);
    }

    partial void OnIsRefreshingChanged(bool value) => _refreshCommand.NotifyCanExecuteChanged();

    private async void OnTimerTick(object? sender, EventArgs e)
    {
        // Only today's file changes; older files and backups are read once.
        if (IsLive && !HoldUpdates && !IsRefreshing && IsTodaySelected)
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
            ReloadFiles();
            if (SelectedFile is not { } file)
            {
                Text = string.Empty;
                Summary = string.Empty;
                EmptyMessage = "No log file yet. SSLense writes one as soon as it does something.";
                return;
            }

            var snapshot = await _logService.ReadAsync(file.File.Path, SelectedLevel, Search, MaximumLines).ConfigureAwait(true);
            var text = string.Join(Environment.NewLine, snapshot.Lines);
            if (text != Text)
            {
                Text = text;
            }

            EmptyMessage = snapshot.Lines.Count > 0
                ? null
                : SelectedLevel == "All" && string.IsNullOrWhiteSpace(Search)
                    ? "This log file is empty."
                    : $"No {(SelectedLevel == "All" ? string.Empty : SelectedLevel.ToLowerInvariant() + " ")}entries" +
                      $"{(string.IsNullOrWhiteSpace(Search) ? string.Empty : $" containing \"{Search.Trim()}\"")} in this file.";
            Summary = $"{snapshot.Lines.Count} line(s){(snapshot.Lines.Count >= MaximumLines ? $" (last {MaximumLines})" : string.Empty)} " +
                      $"from {file.File.Path} · updated {DateTime.Now:HH:mm:ss}";
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

    /// <summary>Keeps the list of files current (a new day or a backup adds one) without disturbing the selection.</summary>
    private void ReloadFiles()
    {
        var files = _logService.ListFiles();
        if (files.Select(file => file.Path).SequenceEqual(Files.Select(option => option.File.Path)))
        {
            return;
        }

        var selectedPath = SelectedFile?.File.Path;

        // Clearing the list makes the ComboBox reset the selection, which would start a second refresh in the middle of
        // this one; both then added every file, so each name appeared twice. The guard covers the whole rebuild.
        _selectingFile = true;
        try
        {
            Files.Clear();
            for (var index = 0; index < files.Count; index++)
            {
                var file = files[index];
                var label = file.IsBackup
                    ? $"Cleared backup: {file.Name}"
                    : index == 0 ? $"Today: {file.Name}" : file.Name;
                Files.Add(new LogFileOption(file, label));
            }

            SelectedFile = Files.FirstOrDefault(option => option.File.Path == selectedPath) ?? Files.FirstOrDefault();
        }
        finally
        {
            _selectingFile = false;
        }
        OnPropertyChanged(nameof(IsTodaySelected));
    }

    /// <summary>The log folder is restricted to Administrators and SYSTEM, which unelevated Explorer cannot open; a copy on
    /// the Desktop can be opened, attached, or pasted from.</summary>
    private async Task SaveCopyAsync()
    {
        ErrorMessage = null;
        if (SelectedFile is not { } file) return;
        try
        {
            var path = await _logService.SaveCopyAsync(file.File.Path, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory))
                .ConfigureAwait(true);
            StatusMessage = $"Saved a copy to {path}.";
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not save a copy of the log");
            ErrorMessage = exception.Message;
        }
    }

    private void CopyAll()
    {
        ErrorMessage = null;
        try
        {
            Clipboard.SetText(Text);
            StatusMessage = "Copied the shown entries to the clipboard. To copy part of the log, select it and press Ctrl+C.";
        }
        catch (Exception exception)
        {
            // The clipboard can be briefly locked by another application.
            ErrorMessage = $"Could not copy to the clipboard: {exception.Message} Try again.";
        }
    }

    private async Task ClearLogAsync()
    {
        ErrorMessage = null;
        try
        {
            var backup = await _logService.ClearCurrentAsync().ConfigureAwait(true);
            StatusMessage = backup is null
                ? "Today's log was already empty."
                : $"Cleared today's log. Its earlier entries are kept in \"Cleared backup\" in the file list ({backup}).";
            _logger.LogInformation("Log cleared from the GUI; the previous entries were saved to {Backup}", backup);
            await _refreshCommand.ExecuteAsync(null);
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Could not clear the log");
            ErrorMessage = exception.Message;
        }
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Tick -= OnTimerTick;
    }
}
