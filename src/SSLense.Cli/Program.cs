using SSLense.Core;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Renewal;
using SSLense.Core.WindowsServices;
using SSLense.Core.Notifications;
using SSLense.Core.Certificates;
using SSLense.Core.Validation;
using SSLense.Core.Diagnostics;
using SSLense.Cli;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using System.CommandLine;

// Secure ProgramData before the logger creates the logs folder inside it. Does nothing when not elevated.
var securityWarnings = DataDirectorySecurity.SecureAtStartup();

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    // The console shows warnings only: commands print their own results and "Error:" lines, so logged
    // information and errors would just repeat them. The log file below keeps everything, with full exceptions.
    .WriteTo.Logger(console => console
        .Filter.ByIncludingOnly(logEvent => logEvent.Level == LogEventLevel.Warning)
        .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}"))
    .WriteTo.File(
        Path.Combine(AppPaths.LogDirectory, "sslense-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        shared: true)
    .CreateLogger();

foreach (var warning in securityWarnings)
{
    Log.Warning("{SecurityWarning}", warning);
}

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddSerilog();
    builder.Services.AddSSLenseCore();

    using var host = builder.Build();
    var rootCommand = CreateRootCommand(host.Services);
    var parseResult = rootCommand.Parse(args);

    // Help, version, and parse errors need neither elevation nor state recovery.
    var runsCommand = parseResult.Errors.Count == 0 &&
        parseResult.CommandResult.Command != rootCommand &&
        parseResult.Action is not System.CommandLine.Help.HelpAction;
    if (runsCommand)
    {
        if (!WindowsElevation.IsAdministrator())
        {
            Console.Error.WriteLine($"Error: {WindowsElevation.RequiredMessage}");
            return 1;
        }

        // These commands must not change certificate state as a side effect: the installer runs secure-data,
        // and health and diagnostics should report interrupted operations rather than resolve them first.
        var touchesCertificates = parseResult.CommandResult.Command.Name is not
            ("check-permissions" or "secure-data" or "health" or "diagnostics");
        var recovery = host.Services.GetRequiredService<ICertificateRecoveryService>();
        foreach (var result in touchesCertificates
                     ? await recovery.RecoverAsync().ConfigureAwait(false)
                     : [])
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

    return parseResult.Invoke();
}
catch (Exception exception)
{
    Log.Fatal(exception, "SSLense terminated unexpectedly");
    Console.Error.WriteLine($"Error: {exception.Message}");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

static RootCommand CreateRootCommand(IServiceProvider services)
{
    var rootCommand = new RootCommand("Manage Let's Encrypt certificates for IIS.");
    var listSitesCommand = new Command("list-sites", "List IIS sites and their bindings.");

    listSitesCommand.SetAction((_, cancellationToken) =>
        ListSitesAsync(services.GetRequiredService<IIisService>(), cancellationToken));
    rootCommand.Subcommands.Add(listSitesCommand);

    var siteOption = new Option<string>("--site")
    {
        Description = "IIS site name.",
        Required = true
    };
    var hostsOption = new Option<string?>("--hosts")
    {
        Description = "Comma-separated host names. Defaults to named HTTP bindings on the site."
    };
    var emailOption = new Option<string>("--email")
    {
        Description = "Email address for the Let's Encrypt ACME account.",
        Required = true
    };
    var stagingOption = new Option<bool>("--staging")
    {
        Description = "Use Let's Encrypt staging (the safe default)."
    };
    var productionOption = new Option<bool>("--production")
    {
        Description = "Use Let's Encrypt production and obtain a publicly trusted certificate."
    };
    var acceptProductionRiskOption = new Option<bool>("--accept-production-risk")
    {
        Description = "Confirm production issuance, rate-limit impact, and replacement of the live IIS binding."
    };
    var outputOption = new Option<string?>("--output")
    {
        Description = "Directory for the public certificate PEM. Private-key PFX files are not persisted."
    };
    var forceOption = new Option<bool>("--force")
    {
        Description = "Replace an existing valid certificate for the requested hosts."
    };
    var issueCommand = new Command("issue", "Obtain and install a certificate using HTTP-01.");
    issueCommand.Options.Add(siteOption);
    issueCommand.Options.Add(hostsOption);
    issueCommand.Options.Add(emailOption);
    issueCommand.Options.Add(stagingOption);
    issueCommand.Options.Add(productionOption);
    issueCommand.Options.Add(acceptProductionRiskOption);
    issueCommand.Options.Add(outputOption);
    issueCommand.Options.Add(forceOption);
    issueCommand.SetAction((parseResult, cancellationToken) => IssueAsync(
        services.GetRequiredService<IAcmeService>(),
        parseResult.GetRequiredValue(siteOption),
        parseResult.GetValue(hostsOption),
        parseResult.GetRequiredValue(emailOption),
        parseResult.GetValue(outputOption),
        parseResult.GetValue(forceOption),
        parseResult.GetValue(stagingOption),
        parseResult.GetValue(productionOption),
        parseResult.GetValue(acceptProductionRiskOption),
        cancellationToken));
    rootCommand.Subcommands.Add(issueCommand);

    var renewAllOption = new Option<bool>("--all")
    {
        Description = "Renew all managed certificates that are due."
    };
    var renewSiteOption = new Option<string?>("--site")
    {
        Description = "Renew the managed certificate for one IIS site."
    };
    var renewForceOption = new Option<bool>("--force")
    {
        Description = "Renew selected certificates even when they are not due."
    };
    var renewCommand = new Command("renew", "Renew managed certificates that are due according to ARI or the fallback schedule.");
    renewCommand.Options.Add(renewAllOption);
    renewCommand.Options.Add(renewSiteOption);
    renewCommand.Options.Add(renewForceOption);
    renewCommand.SetAction((parseResult, cancellationToken) => RenewAsync(
        services.GetRequiredService<IRenewalService>(),
        parseResult.GetValue(renewAllOption),
        parseResult.GetValue(renewSiteOption),
        parseResult.GetValue(renewForceOption),
        cancellationToken));
    rootCommand.Subcommands.Add(renewCommand);

    var statusCommand = new Command("status", "Show managed certificates, environments, and renewal status.");
    statusCommand.SetAction((_, cancellationToken) =>
        StatusAsync(services.GetRequiredService<IRenewalService>(), cancellationToken));
    rootCommand.Subcommands.Add(statusCommand);

    var checkPermissionsCommand = new Command(
        "check-permissions",
        "Verify that only Administrators and SYSTEM can access the SSLense data directory.");
    checkPermissionsCommand.SetAction(_ => CheckPermissions());
    rootCommand.Subcommands.Add(checkPermissionsCommand);

    var secureDataCommand = new Command(
        "secure-data",
        "Restrict the SSLense data directory to Administrators and SYSTEM. Run by the installer.");
    secureDataCommand.SetAction(_ => SecureData());
    rootCommand.Subcommands.Add(secureDataCommand);

    var healthCommand = new Command(
        "health",
        "Check the service, permissions, IIS, certificates, DNS, port 80, and Let's Encrypt connectivity.");
    healthCommand.SetAction((_, cancellationToken) =>
        HealthAsync(services.GetRequiredService<IHealthCheckService>(), cancellationToken));
    rootCommand.Subcommands.Add(healthCommand);

    var diagnosticsOutputOption = new Option<string?>("--output")
    {
        Description = "Zip file to create (default: sslense-diagnostics-<timestamp>.zip on your Desktop)."
    };
    var diagnosticsRedactHostsOption = new Option<bool>("--redact-hosts")
    {
        Description = "Replace site and host names with placeholders, for posting the bundle publicly."
    };
    var diagnosticsCommand = new Command(
        "diagnostics",
        "Create a redacted diagnostic bundle to attach to a GitHub issue.");
    diagnosticsCommand.Options.Add(diagnosticsOutputOption);
    diagnosticsCommand.Options.Add(diagnosticsRedactHostsOption);
    diagnosticsCommand.SetAction((parseResult, cancellationToken) => DiagnosticsAsync(
        services.GetRequiredService<IDiagnosticBundleService>(),
        parseResult.GetValue(diagnosticsOutputOption),
        parseResult.GetValue(diagnosticsRedactHostsOption),
        cancellationToken));
    rootCommand.Subcommands.Add(diagnosticsCommand);

    var preflightSiteOption = new Option<string>("--site") { Required = true, Description = "IIS site name." };
    var preflightHostsOption = new Option<string>("--hosts") { Required = true, Description = "Comma-separated host names." };
    var preflightCommand = new Command("preflight", "Run IIS and HTTP-01 readiness checks.");
    preflightCommand.Options.Add(preflightSiteOption);
    preflightCommand.Options.Add(preflightHostsOption);
    preflightCommand.SetAction((result, token) => PreflightAsync(
        services.GetRequiredService<IPreflightService>(),
        result.GetRequiredValue(preflightSiteOption),
        result.GetRequiredValue(preflightHostsOption), token));
    rootCommand.Subcommands.Add(preflightCommand);

    var detailsSiteOption = new Option<string>("--site") { Required = true, Description = "Managed IIS site name." };
    var detailsCommand = new Command("details", "Show certificate details, bindings, and recent logs.");
    detailsCommand.Options.Add(detailsSiteOption);
    detailsCommand.SetAction((result, token) => DetailsAsync(
        services.GetRequiredService<ICertificateManagementService>(), result.GetRequiredValue(detailsSiteOption), token));
    rootCommand.Subcommands.Add(detailsCommand);

    var removeSiteOption = new Option<string>("--site") { Required = true, Description = "Managed IIS site name." };
    var removeYesOption = new Option<bool>("--yes") { Description = "Confirm removal of matching HTTPS bindings and the managed certificate." };
    var removeCommand = new Command("remove", "Remove a managed certificate and its matching IIS HTTPS bindings.");
    removeCommand.Options.Add(removeSiteOption); removeCommand.Options.Add(removeYesOption);
    removeCommand.SetAction((result, token) => RemoveAsync(
        services.GetRequiredService<ICertificateManagementService>(), result.GetRequiredValue(removeSiteOption), result.GetValue(removeYesOption), token));
    rootCommand.Subcommands.Add(removeCommand);

    var settingsEmailOption = new Option<string?>("--email") { Description = "Default ACME account email." };
    var settingsDaysOption = new Option<int>("--renewal-days") { Required = true, Description = "Renewal threshold, 1-89 days." };
    var configureCommand = new Command("configure", "Save general defaults and renewal settings.");
    configureCommand.Options.Add(settingsEmailOption); configureCommand.Options.Add(settingsDaysOption);
    configureCommand.SetAction((result, token) => ConfigureGeneralAsync(
        services.GetRequiredService<ISettingsService>(), result.GetValue(settingsEmailOption), result.GetRequiredValue(settingsDaysOption), token));
    rootCommand.Subcommands.Add(configureCommand);

    var servicePathOption = new Option<string?>("--service-path")
    {
        Description = "Path to the published SSLense.Service.exe. Defaults to the CLI directory."
    };
    var installServiceCommand = new Command("install-service", "Install and start the automatic renewal service.");
    installServiceCommand.Options.Add(servicePathOption);
    installServiceCommand.SetAction((parseResult, cancellationToken) => InstallServiceAsync(
        services.GetRequiredService<IWindowsServiceManager>(),
        parseResult.GetValue(servicePathOption),
        cancellationToken));
    rootCommand.Subcommands.Add(installServiceCommand);

    var uninstallServiceCommand = new Command("uninstall-service", "Stop and remove the automatic renewal service.");
    uninstallServiceCommand.SetAction((_, cancellationToken) => UninstallServiceAsync(
        services.GetRequiredService<IWindowsServiceManager>(),
        cancellationToken));
    rootCommand.Subcommands.Add(uninstallServiceCommand);

    foreach (var item in new[]
    {
        (Name: "service-status", Description: "Show the automatic renewal service status.", Action: "status"),
        (Name: "start-service", Description: "Start the automatic renewal service.", Action: "start"),
        (Name: "stop-service", Description: "Stop the automatic renewal service.", Action: "stop")
    })
    {
        var command = new Command(item.Name, item.Description);
        command.SetAction((_, token) => ServiceActionAsync(
            services.GetRequiredService<IWindowsServiceManager>(), item.Action, token));
        rootCommand.Subcommands.Add(command);
    }

    rootCommand.Subcommands.Add(CreateNotificationsCommand(services));

    return rootCommand;
}

static async Task<int> PreflightAsync(IPreflightService service, string site, string hostsValue, CancellationToken token)
{
    try
    {
        var hosts = hostsValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var checks = await service.CheckAsync(site, hosts, token).ConfigureAwait(false);
        foreach (var check in checks) Console.WriteLine($"{(check.Succeeded ? "PASS" : "FAIL")}: {check.Name} - {check.Message}");
        return checks.All(value => value.Succeeded) ? 0 : 1;
    }
    catch (Exception exception) { Log.Error(exception, "Pre-flight check failed"); Console.Error.WriteLine($"Error: {exception.Message}"); return 1; }
}

static async Task<int> DetailsAsync(ICertificateManagementService service, string site, CancellationToken token)
{
    try
    {
        var detail = await service.GetDetailsAsync(site, token).ConfigureAwait(false);
        Console.WriteLine($"Site: {detail.SiteName}\nHosts: {string.Join(", ", detail.Hosts)}\nIssuer: {detail.Issuer}\nThumbprint: {detail.Thumbprint}\nIssued: {detail.NotBefore:O}\nExpires: {detail.NotAfter:O}\nBound sites: {string.Join(", ", detail.BoundSites)}");
        Console.WriteLine("Recent logs:"); foreach (var line in detail.RecentLogLines) Console.WriteLine($"  {line}");
        return 0;
    }
    catch (Exception exception) { Log.Error(exception, "Failed to read certificate details"); Console.Error.WriteLine($"Error: {exception.Message}"); return 1; }
}

static async Task<int> RemoveAsync(ICertificateManagementService service, string site, bool confirmed, CancellationToken token)
{
    if (!confirmed) { Console.Error.WriteLine("Error: --yes is required because removal deletes matching HTTPS bindings."); return 1; }
    try { await service.RemoveAsync(site, token).ConfigureAwait(false); Console.WriteLine($"Removed managed certificate for '{site}'."); return 0; }
    catch (Exception exception) { Log.Error(exception, "Failed to remove certificate for {Site}", site); Console.Error.WriteLine($"Error: {exception.Message}"); return 1; }
}

static async Task<int> ConfigureGeneralAsync(ISettingsService service, string? email, int days, CancellationToken token)
{
    try { await service.SaveGeneralAsync(email, days, token).ConfigureAwait(false); Console.WriteLine("General settings saved. Staging remains the issuance default."); return 0; }
    catch (Exception exception) { Log.Error(exception, "Failed to save general settings"); Console.Error.WriteLine($"Error: {exception.Message}"); return 1; }
}

static async Task<int> ServiceActionAsync(IWindowsServiceManager service, string action, CancellationToken token)
{
    try
    {
        if (action == "start") await service.StartAsync(token).ConfigureAwait(false);
        else if (action == "stop") await service.StopAsync(token).ConfigureAwait(false);
        var status = await service.GetStatusAsync(token).ConfigureAwait(false);
        Console.WriteLine($"SSLense service status: {status}"); return 0;
    }
    catch (Exception exception) { Log.Error(exception, "Service action {Action} failed", action); Console.Error.WriteLine($"Error: {exception.Message}"); return 1; }
}

static Command CreateNotificationsCommand(IServiceProvider services)
{
    INotificationSettingsService Settings() => services.GetRequiredService<INotificationSettingsService>();
    var command = new Command(
        "notifications",
        "Configure where SSLense sends alerts: email, Teams, Slack, Discord, Telegram, ntfy, a heartbeat, and the Windows Event Log.");

    var showCommand = new Command("show", "List the configured notification channels.");
    showCommand.SetAction((_, token) => ShowNotificationsAsync(Settings(), token));
    command.Subcommands.Add(showCommand);

    var presetOption = new Option<string?>("--preset")
    {
        Description = "Start from a common setup: " + string.Join(", ", EmailPreset.All.Select(preset => preset.Id)) + "."
    };
    presetOption.AcceptOnlyFromAmong([.. EmailPreset.All.Select(preset => preset.Id)]);
    var hostOption = new Option<string?>("--host") { Description = "SMTP server or relay host name." };
    var portOption = new Option<int?>("--port") { Description = "SMTP port (25, 587, or 465)." };
    var securityOption = new Option<string?>("--security") { Description = "auto (default), starttls, ssl (TLS on connect, port 465), or none." };
    securityOption.AcceptOnlyFromAmong("auto", "starttls", "ssl", "none");
    var authOption = new Option<string?>("--auth") { Description = "none (relay by IP address) or password. The password is prompted." };
    authOption.AcceptOnlyFromAmong("none", "password");
    var userOption = new Option<string?>("--user") { Description = "SMTP username, with --auth password." };
    var fromOption = new Option<string>("--from") { Required = true, Description = "Sender address." };
    var toOption = new Option<string>("--to") { Required = true, Description = "Recipient addresses, comma-separated." };
    var emailCommand = new Command("email", "Send alerts by email through any SMTP server or relay.");
    foreach (var option in new Option[] { presetOption, hostOption, portOption, securityOption, authOption, userOption, fromOption, toOption })
    {
        emailCommand.Options.Add(option);
    }

    emailCommand.SetAction((parseResult, token) => ConfigureEmailAsync(
        Settings(),
        parseResult.GetValue(presetOption),
        parseResult.GetValue(hostOption),
        parseResult.GetValue(portOption),
        parseResult.GetValue(securityOption),
        parseResult.GetValue(authOption),
        parseResult.GetValue(userOption),
        parseResult.GetRequiredValue(fromOption),
        parseResult.GetRequiredValue(toOption),
        token));
    command.Subcommands.Add(emailCommand);

    var typeOption = new Option<string>("--type") { Required = true, Description = "teams, slack, discord, telegram, ntfy, or generic." };
    typeOption.AcceptOnlyFromAmong("teams", "slack", "discord", "telegram", "ntfy", "generic");
    var nameOption = new Option<string?>("--name") { Description = "Optional label, to tell several channels apart." };
    var chatCommand = new Command("chat", "Add a chat or push channel. The webhook URL is prompted without echo.");
    chatCommand.Options.Add(typeOption);
    chatCommand.Options.Add(nameOption);
    chatCommand.SetAction((parseResult, token) => AddChatAsync(
        Settings(), parseResult.GetRequiredValue(typeOption), parseResult.GetValue(nameOption), token));
    command.Subcommands.Add(chatCommand);

    var heartbeatRemoveOption = new Option<bool>("--remove") { Description = "Stop pinging the heartbeat URL." };
    var heartbeatCommand = new Command(
        "heartbeat",
        "Ping a monitoring URL (healthchecks.io, Uptime Kuma, and similar) after every healthy hourly check. The URL is prompted.");
    heartbeatCommand.Options.Add(heartbeatRemoveOption);
    heartbeatCommand.SetAction((parseResult, token) => ConfigureHeartbeatAsync(
        Settings(), parseResult.GetValue(heartbeatRemoveOption), token));
    command.Subcommands.Add(heartbeatCommand);

    var eventLogOption = new Option<string?>("--event-log") { Description = "on or off: write alerts to the Windows Application event log." };
    eventLogOption.AcceptOnlyFromAmong("on", "off");
    var successOption = new Option<string?>("--notify-success") { Description = "on or off: also send successful renewals to email and chat." };
    successOption.AcceptOnlyFromAmong("on", "off");
    var optionsCommand = new Command("options", "Turn the Event Log and success notifications on or off.");
    optionsCommand.Options.Add(eventLogOption);
    optionsCommand.Options.Add(successOption);
    optionsCommand.SetAction((parseResult, token) => ConfigureNotificationOptionsAsync(
        Settings(), parseResult.GetValue(eventLogOption), parseResult.GetValue(successOption), token));
    command.Subcommands.Add(optionsCommand);

    var removeEmailOption = new Option<bool>("--email") { Description = "Remove the email settings." };
    var removeChatOption = new Option<int?>("--chat") { Description = "Remove chat channel N, as numbered by 'notifications show'." };
    var removeCommand = new Command("remove", "Remove the email settings or one chat channel.");
    removeCommand.Options.Add(removeEmailOption);
    removeCommand.Options.Add(removeChatOption);
    removeCommand.SetAction((parseResult, token) => RemoveNotificationChannelAsync(
        Settings(), parseResult.GetValue(removeEmailOption), parseResult.GetValue(removeChatOption), token));
    command.Subcommands.Add(removeCommand);

    var testCommand = new Command("test", "Send a test through every channel and report each result.");
    testCommand.SetAction((_, token) => TestNotificationsAsync(services.GetRequiredService<INotifier>(), token));
    command.Subcommands.Add(testCommand);

    var clearCommand = new Command("clear", "Remove every notification channel. The Event Log stays on.");
    clearCommand.SetAction((_, token) => RunNotificationChangeAsync(
        () => Settings().ClearAsync(token), "All notification channels were removed. The Windows Event Log stays on."));
    command.Subcommands.Add(clearCommand);
    return command;
}

static async Task<int> ShowNotificationsAsync(INotificationSettingsService settings, CancellationToken token)
{
    try
    {
        var overview = await settings.GetOverviewAsync(token).ConfigureAwait(false);
        Console.WriteLine($"Windows Event Log: {(overview.EventLogEnabled ? "on (source SSLense)" : "off")}");
        Console.WriteLine($"Successful renewals to email and chat: {(overview.NotifyOnSuccess ? "on" : "off")}");
        if (overview.Email is { } email)
        {
            var signIn = email.Authentication == SmtpAuthentication.None ? "no sign-in" : $"sign-in as {email.Username}";
            Console.WriteLine($"Email: {email.Host}:{email.Port}, {email.Security}, {signIn}, from {email.From} to {string.Join(", ", email.To)}");
        }
        else
        {
            Console.WriteLine("Email: not configured");
        }

        if (overview.Chat.Count == 0)
        {
            Console.WriteLine("Chat: none");
        }

        foreach (var chat in overview.Chat)
        {
            var label = string.IsNullOrWhiteSpace(chat.Name) ? string.Empty : $" \"{chat.Name}\"";
            Console.WriteLine($"Chat {chat.Number}: {chat.Format}{label} ({chat.Host})");
        }

        Console.WriteLine($"Heartbeat: {(overview.HeartbeatHost is { } host ? $"pinging {host}" : "not configured")}");
        return 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to read notification settings");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> ConfigureEmailAsync(
    INotificationSettingsService settings,
    string? presetId,
    string? host,
    int? port,
    string? security,
    string? authentication,
    string? user,
    string from,
    string to,
    CancellationToken token)
{
    var preset = presetId is null ? null : EmailPreset.Find(presetId);
    var resolvedHost = host ?? preset?.Host;
    if (string.IsNullOrWhiteSpace(resolvedHost))
    {
        Console.Error.WriteLine(preset is null
            ? "Error: --host is required."
            : $"Error: --host is required for this preset. {preset.Hint}");
        return 1;
    }

    var resolvedAuthentication = authentication switch
    {
        "none" => SmtpAuthentication.None,
        "password" => SmtpAuthentication.Password,
        _ => preset?.Authentication ?? (user is null ? SmtpAuthentication.None : SmtpAuthentication.Password)
    };
    var password = resolvedAuthentication == SmtpAuthentication.Password
        ? ReadHiddenValue("SMTP password (leave empty to keep the saved one): ")
        : null;
    return await RunNotificationChangeAsync(
            () => settings.SetEmailAsync(
                new EmailSettingsRequest(
                    resolvedHost,
                    port ?? preset?.Port ?? 587,
                    security switch
                    {
                        "starttls" => SmtpSecurity.StartTls,
                        "ssl" => SmtpSecurity.SslOnConnect,
                        "none" => SmtpSecurity.None,
                        "auto" => SmtpSecurity.Auto,
                        _ => preset?.Security ?? SmtpSecurity.Auto
                    },
                    resolvedAuthentication,
                    user ?? preset?.DefaultUsername,
                    string.IsNullOrEmpty(password) ? null : password,
                    from,
                    to.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)),
                token),
            "Email settings saved. Run 'SSLense.Cli notifications test' to send a test message.")
        .ConfigureAwait(false);
}

static Task<int> AddChatAsync(INotificationSettingsService settings, string type, string? name, CancellationToken token)
{
    var format = Enum.Parse<ChatFormat>(type, ignoreCase: true);
    var url = ReadHiddenValue(format switch
    {
        ChatFormat.Teams => "Teams workflow webhook URL: ",
        ChatFormat.Telegram => "Telegram URL (https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>): ",
        ChatFormat.Ntfy => "ntfy topic URL (for example https://ntfy.sh/<your-topic>): ",
        _ => $"{format} webhook URL: "
    });
    return RunNotificationChangeAsync(
        () => settings.AddChatAsync(new ChatSettingsRequest(format, url, name), token),
        $"{format} channel added. Run 'SSLense.Cli notifications test' to send a test message.");
}

static Task<int> ConfigureHeartbeatAsync(INotificationSettingsService settings, bool remove, CancellationToken token) =>
    remove
        ? RunNotificationChangeAsync(() => settings.SetHeartbeatAsync(null, token), "Heartbeat removed.")
        : RunNotificationChangeAsync(
            () => settings.SetHeartbeatAsync(ReadHiddenValue("Heartbeat URL: "), token),
            "Heartbeat saved. The service pings it after every healthy hourly check; set your monitor to expect a ping " +
            "every hour with a grace period of two to three hours.");

static async Task<int> ConfigureNotificationOptionsAsync(
    INotificationSettingsService settings,
    string? eventLog,
    string? notifySuccess,
    CancellationToken token)
{
    if (eventLog is null && notifySuccess is null)
    {
        Console.Error.WriteLine("Error: specify --event-log and/or --notify-success.");
        return 1;
    }

    try
    {
        var current = await settings.GetOverviewAsync(token).ConfigureAwait(false);
        return await RunNotificationChangeAsync(
                () => settings.SetOptionsAsync(
                    eventLog is null ? current.EventLogEnabled : eventLog == "on",
                    notifySuccess is null ? current.NotifyOnSuccess : notifySuccess == "on",
                    token),
                "Notification options saved.")
            .ConfigureAwait(false);
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to update notification options");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static Task<int> RemoveNotificationChannelAsync(
    INotificationSettingsService settings,
    bool email,
    int? chat,
    CancellationToken token)
{
    if (email == chat.HasValue)
    {
        Console.Error.WriteLine("Error: specify exactly one of --email or --chat <number>.");
        return Task.FromResult(1);
    }

    return email
        ? RunNotificationChangeAsync(() => settings.RemoveEmailAsync(token), "Email settings removed.")
        : RunNotificationChangeAsync(() => settings.RemoveChatAsync(chat!.Value, token), $"Chat channel {chat} removed.");
}

static async Task<int> RunNotificationChangeAsync(Func<Task> change, string successMessage)
{
    try
    {
        await change().ConfigureAwait(false);
        Console.WriteLine(successMessage);
        return 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to update notification settings");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> TestNotificationsAsync(INotifier notifier, CancellationToken cancellationToken)
{
    try
    {
        var results = await notifier.TestAsync(cancellationToken).ConfigureAwait(false);
        foreach (var result in results)
        {
            Console.WriteLine($"[{(result.Succeeded ? "PASS" : "FAIL")}] {result.Channel}: {result.Message}");
        }

        return results.All(result => result.Succeeded) ? 0 : 1;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Test notification failed");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static string ReadHiddenValue(string prompt)
{
    Console.Write(prompt);
    if (Console.IsInputRedirected)
    {
        return Console.ReadLine() ?? string.Empty;
    }

    var characters = new List<char>();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
        {
            Console.WriteLine();
            return new string(characters.ToArray());
        }

        if (key.Key == ConsoleKey.Backspace)
        {
            if (characters.Count > 0)
            {
                characters.RemoveAt(characters.Count - 1);
            }
            continue;
        }

        if (!char.IsControl(key.KeyChar))
        {
            characters.Add(key.KeyChar);
        }
    }
}

static async Task<int> RenewAsync(
    IRenewalService renewalService,
    bool all,
    string? siteName,
    bool force,
    CancellationToken cancellationToken)
{
    try
    {
        var results = await renewalService.RenewAsync(
                new RenewalRequest(all, siteName, force),
                new ConsoleProgress(),
                cancellationToken)
            .ConfigureAwait(false);
        if (results.Count == 0)
        {
            Console.WriteLine("No managed certificates were found.");
            return 0;
        }

        foreach (var result in results)
        {
            var outcome = !result.Attempted ? "SKIPPED" : result.Succeeded ? "SUCCESS" : "FAILED";
            Console.WriteLine($"{outcome}: {result.SiteName} - {result.Message}");
            if (result.NewThumbprint is not null)
            {
                Console.WriteLine($"  New thumbprint: {result.NewThumbprint}");
            }
        }

        return results.Any(value => !value.Succeeded) ? 1 : 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Certificate renewal command failed");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> HealthAsync(IHealthCheckService healthCheckService, CancellationToken cancellationToken)
{
    try
    {
        var results = await healthCheckService.RunAsync(null, cancellationToken).ConfigureAwait(false);
        foreach (var result in results)
        {
            var label = result.Status switch
            {
                HealthStatus.Pass => "PASS",
                HealthStatus.Warning => "WARN",
                _ => "FAIL"
            };
            Console.WriteLine($"[{label}] {result.Name}: {result.Message}");
            if (result.Status != HealthStatus.Pass && !string.IsNullOrWhiteSpace(result.Fix))
            {
                Console.WriteLine($"       Fix: {result.Fix}");
            }
        }

        var failures = results.Count(result => result.Status == HealthStatus.Fail);
        var warnings = results.Count(result => result.Status == HealthStatus.Warning);
        Console.WriteLine();
        Console.WriteLine($"{results.Count} checks: {results.Count - failures - warnings} passed, {warnings} warning(s), {failures} failed.");
        return failures == 0 ? 0 : 1;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Health check failed");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> DiagnosticsAsync(
    IDiagnosticBundleService bundleService,
    string? output,
    bool redactHosts,
    CancellationToken cancellationToken)
{
    try
    {
        // An elevated terminal usually starts in C:\Windows\System32, so default to the Desktop instead.
        var path = string.IsNullOrWhiteSpace(output)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) is { Length: > 0 } desktop
                    ? desktop
                    : Environment.CurrentDirectory,
                $"sslense-diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.zip")
            : output;

        // Only the bundle's own steps; the embedded health check's per-check progress is noise here.
        var progress = new Progress<ProgressEvent>(value =>
        {
            if (value.Step == "diagnostics")
            {
                Console.WriteLine(value.Message);
            }
        });
        var result = await bundleService
            .CreateAsync(new DiagnosticBundleRequest(path, redactHosts), progress, cancellationToken)
            .ConfigureAwait(false);
        foreach (var note in result.Notes)
        {
            Console.WriteLine($"Note: {note}");
        }

        Console.WriteLine($"Diagnostic bundle created: {result.Path}");
        Console.WriteLine(redactHosts
            ? "Site and host names were replaced with placeholders."
            : "Site and host names are included; add --redact-hosts before posting it publicly if they are private.");
        Console.WriteLine("Secrets are removed automatically, but review the files before sharing them.");
        return 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to create the diagnostic bundle");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static int SecureData()
{
    try
    {
        var problems = DataDirectorySecurity.Secure();
        foreach (var problem in problems)
        {
            Console.WriteLine($"Problem: {problem}");
        }

        if (problems.Count == 0)
        {
            Console.WriteLine($"'{AppPaths.DataDirectory}' is restricted to Administrators and SYSTEM.");
        }

        return problems.Count == 0 ? 0 : 1;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to secure the data directory");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static int CheckPermissions()
{
    try
    {
        var problems = DataDirectorySecurity.Verify();
        if (problems.Count == 0)
        {
            Console.WriteLine($"'{AppPaths.DataDirectory}' is restricted to Administrators and SYSTEM.");
            return 0;
        }

        foreach (var problem in problems)
        {
            Console.WriteLine($"Problem: {problem}");
        }

        Console.WriteLine(
            "Starting SSLense elevated reapplies the restricted permissions; " +
            "links and multi-link files must be removed manually.");
        return 1;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to verify data directory permissions");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> StatusAsync(
    IRenewalService renewalService,
    CancellationToken cancellationToken)
{
    try
    {
        var statuses = await renewalService.GetStatusAsync(cancellationToken).ConfigureAwait(false);
        if (statuses.Count == 0)
        {
            Console.WriteLine("No managed certificates were found.");
            return 0;
        }

        foreach (var status in statuses)
        {
            Console.WriteLine(status.SiteName);
            Console.WriteLine($"  Certificate authority: {status.AuthorityName}");
            if (!string.IsNullOrWhiteSpace(status.Issuer))
            {
                Console.WriteLine($"  Issuer: {status.Issuer}");
            }
            Console.WriteLine($"  Hosts: {string.Join(", ", status.Hosts)}");
            Console.WriteLine($"  Issued: {status.NotBefore:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"  Expires: {status.NotAfter:yyyy-MM-dd HH:mm:ss} UTC ({status.DaysRemaining} days left)");
            Console.WriteLine($"  Thumbprint: {status.Thumbprint}");
            var lastResult = status.LastRenewalSucceeded switch
            {
                true => $"Success - {status.LastRenewalMessage}",
                false => $"Failed - {status.LastRenewalMessage}",
                null => "Not attempted"
            };
            Console.WriteLine($"  Last renewal: {lastResult}");
            if (status.LastRenewalAttempt is not null)
            {
                Console.WriteLine($"  Last attempt: {status.LastRenewalAttempt:yyyy-MM-dd HH:mm:ss} UTC");
            }

            if (status.ConsecutiveFailures > 0)
            {
                Console.WriteLine($"  Consecutive failures: {status.ConsecutiveFailures}");
                if (status.NextRetryAt is not null)
                {
                    Console.WriteLine($"  Next automatic attempt: {status.NextRetryAt:yyyy-MM-dd HH:mm:ss} UTC");
                }
            }
        }

        return 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to read managed certificate status");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> InstallServiceAsync(
    IWindowsServiceManager serviceManager,
    string? servicePath,
    CancellationToken cancellationToken)
{
    try
    {
        var executablePath = servicePath ?? Path.Combine(AppContext.BaseDirectory, "SSLense.Service.exe");
        await serviceManager.InstallAsync(executablePath, cancellationToken).ConfigureAwait(false);
        Console.WriteLine("SSLense Renewal Service was installed and started.");
        return 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to install the SSLense Renewal Service");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> UninstallServiceAsync(
    IWindowsServiceManager serviceManager,
    CancellationToken cancellationToken)
{
    try
    {
        await serviceManager.UninstallAsync(cancellationToken).ConfigureAwait(false);
        Console.WriteLine("SSLense Renewal Service is not installed.");
        return 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to uninstall the SSLense Renewal Service");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> IssueAsync(
    IAcmeService acmeService,
    string siteName,
    string? hostsValue,
    string email,
    string? outputDirectory,
    bool force,
    bool staging,
    bool production,
    bool acceptProductionRisk,
    CancellationToken cancellationToken)
{
    try
    {
        if (staging && production)
        {
            throw new ArgumentException("Specify either --staging or --production, not both.");
        }

        if (production && !acceptProductionRisk)
        {
            throw new InvalidOperationException(
                "Production issuance requires --accept-production-risk. " +
                "Run against staging first and confirm the IIS site and host names are correct.");
        }

        var authorityId = production ? CertificateAuthorities.LetsEncryptId : CertificateAuthorities.LetsEncryptStagingId;
        var hosts = string.IsNullOrWhiteSpace(hostsValue)
            ? Array.Empty<string>()
            : hostsValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var result = await acmeService.IssueAsync(
                new AcmeIssueRequest(siteName, hosts, email, outputDirectory, force, authorityId),
                new ConsoleProgress(),
                cancellationToken)
            .ConfigureAwait(false);

        Console.WriteLine($"{CertificateAuthorities.Label(authorityId)} certificate issued, installed, and bound successfully.");
        Console.WriteLine($"Thumbprint: {result.CertificateThumbprint}");
        Console.WriteLine($"Valid from: {result.NotBefore:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Valid until: {result.NotAfter:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"PEM: {result.CertificatePemPath}");
        Console.WriteLine(result.PfxPath is null
            ? "PFX: not persisted (private key is installed as non-exportable)"
            : $"PFX: {result.PfxPath}");
        return 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to issue a certificate for IIS site {SiteName}", siteName);
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}

static async Task<int> ListSitesAsync(IIisService iisService, CancellationToken cancellationToken)
{
    try
    {
        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        if (sites.Count == 0)
        {
            Console.WriteLine("No IIS sites were found.");
            return 0;
        }

        foreach (var site in sites)
        {
            Console.WriteLine($"{site.Name} (ID {site.Id}, {site.State})");
            Console.WriteLine($"  Path: {site.PhysicalPath ?? "<not configured>"}");

            if (site.Bindings.Count == 0)
            {
                Console.WriteLine("  Bindings: <none>");
                continue;
            }

            foreach (var binding in site.Bindings)
            {
                var host = string.IsNullOrWhiteSpace(binding.HostName) ? "*" : binding.HostName;
                var certificate = binding.CertificateThumbprint is null
                    ? string.Empty
                    : $", certificate {binding.CertificateThumbprint}";
                var sni = binding.UsesSni ? ", SNI" : string.Empty;
                Console.WriteLine(
                    $"  {binding.Protocol}://{host}:{binding.Port} [{binding.IpAddress}]{certificate}{sni}");
            }
        }

        return 0;
    }
    catch (Exception exception)
    {
        Log.Error(exception, "Failed to list IIS sites");
        Console.Error.WriteLine($"Error: {exception.Message}");
        return 1;
    }
}
