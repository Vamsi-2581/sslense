using System.Windows;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using SSLense.Core;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui;

public partial class App : Application
{
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Secure ProgramData before the logger creates the logs folder inside it.
        var securityWarnings = DataDirectorySecurity.SecureAtStartup();

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.SSLenseLogFile()
            .CreateLogger();
        foreach (var warning in securityWarnings)
        {
            Log.Warning("{SecurityWarning}", warning);
        }

        try
        {
            var builder = Host.CreateApplicationBuilder(e.Args);
            builder.Services.AddSerilog();
            builder.Services.AddSSLenseCore();
            builder.Services.AddSingleton<INavigationService, NavigationService>();
            builder.Services.AddSingleton<DashboardViewModel>();
            builder.Services.AddSingleton<IssueCertificateViewModel>();
            builder.Services.AddSingleton<OtherProvidersViewModel>();
            builder.Services.AddSingleton<CertificateDetailsViewModel>();
            builder.Services.AddSingleton<SettingsViewModel>();
            builder.Services.AddSingleton<HealthViewModel>();
            builder.Services.AddSingleton<LogsViewModel>();
            builder.Services.AddSingleton<MainViewModel>();
            builder.Services.AddSingleton<MainWindow>();
            _host = builder.Build();
            await _host.StartAsync().ConfigureAwait(true);

            var recovery = _host.Services.GetRequiredService<ICertificateRecoveryService>();
            try
            {
                foreach (var result in await recovery.RecoverAsync().ConfigureAwait(true))
                {
                    if (result.Succeeded)
                    {
                        Log.Information("{RecoveryMessage}", result.Message);
                    }
                    else
                    {
                        Log.Warning("{RecoveryMessage}", result.Message);
                    }
                }
            }
            catch (Exception exception)
            {
                Log.Error(exception, "Certificate operation recovery failed");
            }

            var window = _host.Services.GetRequiredService<MainWindow>();
            MainWindow = window;
            window.Show();
        }
        catch (Exception exception)
        {
            Log.Fatal(exception, "SSLense GUI failed to start");
            MessageBox.Show(
                exception.Message,
                "SSLense could not start",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            _host.StopAsync().GetAwaiter().GetResult();
            _host.Dispose();
        }

        Log.CloseAndFlush();
        base.OnExit(e);
    }
}
