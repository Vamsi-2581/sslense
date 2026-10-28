using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SSLense.Core;
using SSLense.Core.Diagnostics;

namespace SSLense.Gui.ViewModels;

public partial class HealthViewModel : ObservableObject
{
    private readonly IHealthCheckService _healthCheckService;
    private readonly IDiagnosticBundleService _bundleService;
    private readonly ILogger<HealthViewModel> _logger;
    private readonly AsyncRelayCommand _runCommand;
    private readonly AsyncRelayCommand _createBundleCommand;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private string summary = "Run the health check to see whether SSLense can renew your certificates.";

    [ObservableProperty]
    private string? statusMessage;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool redactHosts;

    [ObservableProperty]
    private string? bundlePath;

    public HealthViewModel(
        IHealthCheckService healthCheckService,
        IDiagnosticBundleService bundleService,
        ILogger<HealthViewModel> logger)
    {
        _healthCheckService = healthCheckService;
        _bundleService = bundleService;
        _logger = logger;
        _runCommand = new AsyncRelayCommand(RunAsync, () => !IsBusy);
        _createBundleCommand = new AsyncRelayCommand(CreateBundleAsync, () => !IsBusy);
        ShowBundleCommand = new RelayCommand(ShowBundle, () => BundlePath is not null);
    }

    public ObservableCollection<HealthCheckRowViewModel> Results { get; } = [];

    public IAsyncRelayCommand RunCommand => _runCommand;

    public IAsyncRelayCommand CreateBundleCommand => _createBundleCommand;

    public IRelayCommand ShowBundleCommand { get; }

    partial void OnIsBusyChanged(bool value)
    {
        _runCommand.NotifyCanExecuteChanged();
        _createBundleCommand.NotifyCanExecuteChanged();
    }

    partial void OnBundlePathChanged(string? value) => ShowBundleCommand.NotifyCanExecuteChanged();

    private async Task RunAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        StatusMessage = "Running checks…";
        try
        {
            var progress = new Progress<ProgressEvent>(value => StatusMessage = value.Message);
            var results = await _healthCheckService.RunAsync(progress).ConfigureAwait(true);
            Results.Clear();
            foreach (var result in results.OrderByDescending(value => value.Status))
            {
                Results.Add(new HealthCheckRowViewModel(result));
            }

            var failures = results.Count(value => value.Status == HealthStatus.Fail);
            var warnings = results.Count(value => value.Status == HealthStatus.Warning);
            Summary = failures > 0
                ? $"{failures} check(s) failed and {warnings} need attention. Problems are listed first."
                : warnings > 0
                    ? $"No failures; {warnings} check(s) need attention."
                    : $"All {results.Count} checks passed.";
            StatusMessage = $"Last run {DateTime.Now:HH:mm:ss}.";
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Health check failed");
            ErrorMessage = exception.Message;
            StatusMessage = null;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CreateBundleAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                $"sslense-diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.zip");
            var progress = new Progress<ProgressEvent>(value => StatusMessage = value.Message);
            var result = await _bundleService
                .CreateAsync(new DiagnosticBundleRequest(path, RedactHosts), progress)
                .ConfigureAwait(true);
            BundlePath = result.Path;
            StatusMessage = $"Diagnostic bundle saved to {result.Path}. Review it before sharing.";
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Failed to create the diagnostic bundle");
            ErrorMessage = exception.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ShowBundle()
    {
        if (BundlePath is null)
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{BundlePath}\"") { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Could not open Explorer for the diagnostic bundle");
            ErrorMessage = $"Could not open Explorer: {exception.Message}";
        }
    }
}

public sealed class HealthCheckRowViewModel(HealthCheckResult result)
{
    public string Name { get; } = result.Name;

    public HealthStatus Status { get; } = result.Status;

    // Text label so status never depends on colour alone.
    public string Result { get; } = result.Status switch
    {
        HealthStatus.Pass => "PASS",
        HealthStatus.Warning => "WARN",
        _ => "FAIL"
    };

    public string Message { get; } = result.Message;

    public string Fix { get; } = result.Fix ?? string.Empty;
}
