using System.Text.Json.Serialization;

namespace SSLense.Core.Config;

public sealed record NotificationConfig
{
    public EmailNotificationConfig? Email { get; init; }

    public IReadOnlyList<ChatNotificationConfig> Chat { get; init; } = [];

    /// <summary>Pinged after every healthy service cycle; an external monitor alerts when pings stop.</summary>
    public HeartbeatNotificationConfig? Heartbeat { get; init; }

    /// <summary>Writes every notification to the Windows Application event log (source "SSLense").</summary>
    public bool EventLogEnabled { get; init; } = true;

    public bool NotifyOnSuccess { get; init; }

    /// <summary>Schema 1 only. Read for migration to <see cref="Email"/>, never written.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SmtpNotificationConfig? Smtp { get; init; }

    /// <summary>Schema 1 only. Read for migration to <see cref="Chat"/>, never written.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public WebhookNotificationConfig? Webhook { get; init; }
}

public enum SmtpSecurity
{
    /// <summary>TLS from the start on port 465, otherwise STARTTLS (required, never silently plain text).</summary>
    Auto = 0,
    StartTls = 1,
    SslOnConnect = 2,

    /// <summary>Plain text; only for internal relays on a trusted network.</summary>
    None = 3
}

public enum SmtpAuthentication
{
    /// <summary>No sign-in, for relays that accept mail by IP address (Microsoft 365 connectors, Exchange receive connectors).</summary>
    None = 0,
    Password = 1
}

public sealed record EmailNotificationConfig(
    string Host,
    int Port,
    SmtpSecurity Security,
    SmtpAuthentication Authentication,
    string? Username,
    string? ProtectedPassword,
    string From,
    IReadOnlyList<string> To);

public enum ChatFormat
{
    /// <summary>SSLense's own JSON: kind, subject, body, severity, occurredAtUtc.</summary>
    Generic = 0,

    /// <summary>Adaptive Card, accepted by Teams Workflows ("Post to a channel when a webhook request is received").</summary>
    Teams = 1,
    Slack = 2,
    Discord = 3,

    /// <summary>Bot API sendMessage URL including chat_id.</summary>
    Telegram = 4,

    /// <summary>ntfy topic URL, such as https://ntfy.sh/your-topic.</summary>
    Ntfy = 5
}

/// <param name="ProtectedUrl">DPAPI-protected; chat webhook URLs usually embed their credential.</param>
/// <param name="Name">Optional label to tell several channels apart.</param>
public sealed record ChatNotificationConfig(ChatFormat Format, string ProtectedUrl, string? Name = null);

public sealed record HeartbeatNotificationConfig(string ProtectedUrl);

/// <summary>Schema 1 email settings.</summary>
public sealed record SmtpNotificationConfig(
    string Host,
    int Port,
    bool EnableSsl,
    string? Username,
    string? ProtectedPassword,
    string From,
    string To);

/// <summary>Schema 1 webhook settings.</summary>
public sealed record WebhookNotificationConfig(string ProtectedUrl);
