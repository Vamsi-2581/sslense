using SSLense.Core.Config;

namespace SSLense.Core.Notifications;

/// <param name="Password">Plain text, protected with DPAPI before saving. Null keeps the saved password.</param>
/// <param name="To">One or more recipients.</param>
public sealed record EmailSettingsRequest(
    string Host,
    int Port,
    SmtpSecurity Security,
    SmtpAuthentication Authentication,
    string? Username,
    string? Password,
    string From,
    IReadOnlyList<string> To);

public sealed record ChatSettingsRequest(ChatFormat Format, string Url, string? Name = null);

/// <summary>What is configured, without any secret: URLs are reduced to their host name.</summary>
public sealed record NotificationOverview(
    EmailOverview? Email,
    IReadOnlyList<ChatOverview> Chat,
    string? HeartbeatHost,
    bool EventLogEnabled,
    bool NotifyOnSuccess);

public sealed record EmailOverview(
    string Host,
    int Port,
    SmtpSecurity Security,
    SmtpAuthentication Authentication,
    string? Username,
    bool HasPassword,
    string From,
    IReadOnlyList<string> To);

/// <param name="Number">1-based, as shown to users and accepted by the remove command.</param>
public sealed record ChatOverview(int Number, ChatFormat Format, string? Name, string Host);

/// <summary>Common SMTP setups. Organisations differ, so these only fill in defaults that can be changed.</summary>
public sealed record EmailPreset(
    string Id,
    string DisplayName,
    string? Host,
    int Port,
    SmtpSecurity Security,
    SmtpAuthentication Authentication,
    string? DefaultUsername,
    string Hint)
{
    public static IReadOnlyList<EmailPreset> All { get; } =
    [
        new("m365-relay", "Microsoft 365 relay (by IP address, no sign-in)", null, 25, SmtpSecurity.StartTls, SmtpAuthentication.None, null,
            "Host is your MX endpoint, such as contoso-com.mail.protection.outlook.com. Requires an inbound connector that accepts this server's public IP address."),
        new("m365", "Microsoft 365 with sign-in (SMTP AUTH)", "smtp.office365.com", 587, SmtpSecurity.StartTls, SmtpAuthentication.Password, null,
            "SMTP AUTH must be enabled for the mailbox. Microsoft is retiring basic authentication; prefer the relay option where possible."),
        new("gmail", "Gmail or Google Workspace", "smtp.gmail.com", 587, SmtpSecurity.StartTls, SmtpAuthentication.Password, null,
            "Use an app password, not the account password."),
        new("sendgrid", "SendGrid", "smtp.sendgrid.net", 587, SmtpSecurity.StartTls, SmtpAuthentication.Password, "apikey",
            "The username is literally 'apikey'; the password is your API key."),
        new("exchange", "Exchange Server relay (internal, no sign-in)", null, 25, SmtpSecurity.StartTls, SmtpAuthentication.None, null,
            "Host is your Exchange server. Requires a receive connector that allows anonymous relay from this server."),
        new("custom", "Other SMTP server", null, 587, SmtpSecurity.Auto, SmtpAuthentication.Password, null,
            "Port 587 with STARTTLS is the most common; port 465 uses TLS from the start.")
    ];

    public static EmailPreset? Find(string id) =>
        All.FirstOrDefault(preset => string.Equals(preset.Id, id, StringComparison.OrdinalIgnoreCase));
}
