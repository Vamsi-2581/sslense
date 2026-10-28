using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Notifications;

internal sealed class NotificationSettingsService(
    IConfigStore configStore,
    ISecretProtector secretProtector) : INotificationSettingsService
{
    public async Task<NotificationOverview> GetOverviewAsync(CancellationToken cancellationToken = default)
    {
        var notifications = (await configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).Notifications;
        return new NotificationOverview(
            notifications.Email is { } email
                ? new EmailOverview(
                    email.Host, email.Port, email.Security, email.Authentication, email.Username,
                    email.ProtectedPassword is not null, email.From, email.To)
                : null,
            notifications.Chat
                .Select((chat, index) => new ChatOverview(index + 1, chat.Format, chat.Name, GetHost(chat.ProtectedUrl)))
                .ToArray(),
            notifications.Heartbeat is { } heartbeat ? GetHost(heartbeat.ProtectedUrl) : null,
            notifications.EventLogEnabled,
            notifications.NotifyOnSuccess);
    }

    public Task SetEmailAsync(EmailSettingsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Host);
        if (request.Port is < 1 or > 65535)
        {
            throw new ArgumentException("The SMTP port must be between 1 and 65535.");
        }

        ValidateEmail(request.From, "The sender address");
        var recipients = request.To.Select(value => value.Trim()).Where(value => value.Length > 0).ToArray();
        if (recipients.Length == 0)
        {
            throw new ArgumentException("Add at least one recipient address.");
        }

        foreach (var recipient in recipients)
        {
            ValidateEmail(recipient, $"The recipient address '{recipient}'");
        }

        if (request.Authentication == SmtpAuthentication.Password)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(request.Username, nameof(request.Username));
            if (request.Security == SmtpSecurity.None)
            {
                throw new ArgumentException(
                    "A password would be sent unencrypted. Choose STARTTLS or TLS on connect, or a relay without sign-in.");
            }
        }

        return UpdateAsync(notifications =>
        {
            // Keep the saved password when none is entered, but only for the same account.
            var existing = notifications.Email;
            var protectedPassword = request.Authentication != SmtpAuthentication.Password ? null
                : !string.IsNullOrEmpty(request.Password) ? Protect(request.Password)
                : existing?.Authentication == SmtpAuthentication.Password &&
                  string.Equals(existing.Username, request.Username?.Trim(), StringComparison.OrdinalIgnoreCase)
                    ? existing.ProtectedPassword
                    : throw new ArgumentException("Enter the SMTP password.");
            return notifications with
            {
                Email = new EmailNotificationConfig(
                    request.Host.Trim(),
                    request.Port,
                    request.Security,
                    request.Authentication,
                    request.Authentication == SmtpAuthentication.Password ? request.Username!.Trim() : null,
                    protectedPassword,
                    request.From.Trim(),
                    recipients)
            };
        }, cancellationToken);
    }

    public Task RemoveEmailAsync(CancellationToken cancellationToken = default) =>
        UpdateAsync(notifications => notifications with { Email = null }, cancellationToken);

    public Task AddChatAsync(ChatSettingsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var url = ParseUrl(request.Url, $"The {request.Format} URL");
        ChatSender.Validate(request.Format, url);
        var chat = new ChatNotificationConfig(
            request.Format,
            Protect(url.AbsoluteUri),
            string.IsNullOrWhiteSpace(request.Name) ? null : request.Name.Trim());
        return UpdateAsync(notifications => notifications with { Chat = [.. notifications.Chat, chat] }, cancellationToken);
    }

    public Task RemoveChatAsync(int number, CancellationToken cancellationToken = default) =>
        UpdateAsync(notifications =>
        {
            if (number < 1 || number > notifications.Chat.Count)
            {
                throw new ArgumentException(
                    $"There is no chat channel {number}. Run 'notifications show' to see the configured channels.");
            }

            return notifications with { Chat = notifications.Chat.Where((_, index) => index != number - 1).ToArray() };
        }, cancellationToken);

    public Task SetHeartbeatAsync(string? url, CancellationToken cancellationToken = default)
    {
        HeartbeatNotificationConfig? heartbeat = null;
        if (!string.IsNullOrWhiteSpace(url))
        {
            var uri = ParseUrl(url, "The heartbeat URL");
            if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            {
                throw new ArgumentException("The heartbeat URL must start with https:// or http://.");
            }

            heartbeat = new HeartbeatNotificationConfig(Protect(uri.AbsoluteUri));
        }

        return UpdateAsync(notifications => notifications with { Heartbeat = heartbeat }, cancellationToken);
    }

    public Task SetOptionsAsync(bool eventLogEnabled, bool notifyOnSuccess, CancellationToken cancellationToken = default) =>
        UpdateAsync(
            notifications => notifications with { EventLogEnabled = eventLogEnabled, NotifyOnSuccess = notifyOnSuccess },
            cancellationToken);

    public Task ClearAsync(CancellationToken cancellationToken = default) =>
        UpdateAsync(_ => new NotificationConfig(), cancellationToken);

    private async Task UpdateAsync(Func<NotificationConfig, NotificationConfig> change, CancellationToken cancellationToken)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        await configStore.SaveAsync(config with { Notifications = change(config.Notifications) }, cancellationToken)
            .ConfigureAwait(false);
    }

    private static Uri ParseUrl(string value, string label) =>
        Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri)
            ? uri
            : throw new ArgumentException($"{label} is not a valid absolute URL.");

    /// <summary>Only the host is shown, because chat and heartbeat URLs carry their credential in the path.</summary>
    private string GetHost(string protectedUrl)
    {
        try
        {
            var plaintext = secretProtector.Unprotect(Convert.FromBase64String(protectedUrl));
            try
            {
                return Uri.TryCreate(Encoding.UTF8.GetString(plaintext), UriKind.Absolute, out var uri) ? uri.Host : "(invalid URL)";
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            return "(cannot be decrypted on this machine)";
        }
    }

    private string Protect(string value)
    {
        var plaintext = Encoding.UTF8.GetBytes(value);
        try
        {
            return Convert.ToBase64String(secretProtector.Protect(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static void ValidateEmail(string value, string label)
    {
        try
        {
            _ = new MailAddress(value);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new ArgumentException($"{label} is not a valid email address.", exception);
        }
    }
}
