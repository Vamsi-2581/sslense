namespace SSLense.Core.Config;

internal static class ConfigMigrations
{
    /// <summary>Upgrades a configuration read from any earlier schema to the current one, in memory.</summary>
    public static AppConfig Migrate(AppConfig config)
    {
        if (config.SchemaVersion < 2)
        {
            config = config with { Notifications = MigrateNotificationsFromV1(config.Notifications) };
        }

        return config;
    }

    /// <summary>Schema 1 had one SMTP server and one generic webhook; schema 2 has email, chat channels, and more.</summary>
    private static NotificationConfig MigrateNotificationsFromV1(NotificationConfig notifications)
    {
        var email = notifications.Smtp is { } smtp
            ? new EmailNotificationConfig(
                smtp.Host,
                smtp.Port,
                !smtp.EnableSsl ? SmtpSecurity.None : smtp.Port == 465 ? SmtpSecurity.SslOnConnect : SmtpSecurity.StartTls,
                // Schema 1 without a username meant a relay that needs no sign-in.
                string.IsNullOrWhiteSpace(smtp.Username) ? SmtpAuthentication.None : SmtpAuthentication.Password,
                smtp.Username,
                smtp.ProtectedPassword,
                smtp.From,
                SplitRecipients(smtp.To))
            : notifications.Email;
        var chat = notifications.Webhook is { } webhook
            ? [.. notifications.Chat, new ChatNotificationConfig(ChatFormat.Generic, webhook.ProtectedUrl)]
            : notifications.Chat;
        return notifications with { Email = email, Chat = chat, Smtp = null, Webhook = null };
    }

    internal static IReadOnlyList<string> SplitRecipients(string recipients) =>
        recipients.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
