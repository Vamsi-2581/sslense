using SSLense;
using Serilog;
using SSLense.Core;
using SSLense.Core.Config;
using SSLense.Service;

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
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddWindowsService(options => options.ServiceName = "SSLense");
    builder.Services.AddSerilog();
    builder.Services.AddSSLenseCore();
    builder.Services.AddHostedService<RenewalWorker>();
    await builder.Build().RunAsync();
}
catch (Exception exception)
{
    Log.Fatal(exception, "SSLense Renewal Service terminated unexpectedly");
    Environment.ExitCode = 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}
