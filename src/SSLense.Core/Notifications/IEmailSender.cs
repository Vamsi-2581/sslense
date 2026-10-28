using SSLense.Core.Config;

namespace SSLense.Core.Notifications;

public interface IEmailSender
{
    Task SendAsync(EmailDelivery settings, NotificationMessage message, CancellationToken cancellationToken);
}

/// <param name="Password">Decrypted only for the duration of one send.</param>
public sealed record EmailDelivery(
    string Host,
    int Port,
    SmtpSecurity Security,
    SmtpAuthentication Authentication,
    string? Username,
    string? Password,
    string From,
    IReadOnlyList<string> To);
