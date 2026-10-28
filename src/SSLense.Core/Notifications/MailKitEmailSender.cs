using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using SSLense.Core.Config;

namespace SSLense.Core.Notifications;

/// <summary>
/// Sends through any SMTP setup: relays that accept mail by IP (no sign-in), servers that need a
/// username and password, STARTTLS on 25/587, or TLS from the start on 465.
/// </summary>
internal sealed class MailKitEmailSender : IEmailSender
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public async Task SendAsync(EmailDelivery settings, NotificationMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        using var mail = new MimeMessage();
        mail.From.Add(MailboxAddress.Parse(settings.From));
        foreach (var recipient in settings.To)
        {
            mail.To.Add(MailboxAddress.Parse(recipient));
        }

        mail.Subject = message.Subject;
        mail.Body = new TextPart("plain") { Text = message.Body };
        if (message.EffectiveSeverity == NotificationSeverity.Error)
        {
            mail.Priority = MessagePriority.Urgent;
        }

        using var client = new SmtpClient { Timeout = (int)Timeout.TotalMilliseconds };
        try
        {
            await client.ConnectAsync(settings.Host, settings.Port, ToSocketOptions(settings.Security, settings.Port), cancellationToken)
                .ConfigureAwait(false);
            if (settings.Authentication == SmtpAuthentication.Password)
            {
                // Password sign-in only; OAuth needs an app registration and is not offered here.
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                await client.AuthenticateAsync(
                        settings.Username ?? throw new InvalidOperationException("Password sign-in needs an SMTP username."),
                        settings.Password ?? throw new InvalidOperationException("No SMTP password is saved; enter it in the email settings."),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            await client.SendAsync(mail, cancellationToken).ConfigureAwait(false);
            await client.DisconnectAsync(quit: true, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException(Describe(exception, settings), exception);
        }
    }

    internal static SecureSocketOptions ToSocketOptions(SmtpSecurity security, int port) => security switch
    {
        SmtpSecurity.SslOnConnect => SecureSocketOptions.SslOnConnect,
        SmtpSecurity.StartTls => SecureSocketOptions.StartTls,
        SmtpSecurity.None => SecureSocketOptions.None,

        // Never StartTlsWhenAvailable: a server or attacker that hides STARTTLS must not downgrade to plain text.
        _ => port == 465 ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls
    };

    private static string Describe(Exception exception, EmailDelivery settings)
    {
        var endpoint = $"'{settings.Host}:{settings.Port}'";
        return exception switch
        {
            AuthenticationException => $"The SMTP server {endpoint} rejected the username or password. " +
                "Many providers need an app password, and Microsoft 365 may have SMTP AUTH disabled; " +
                "a relay that accepts mail by IP address needs no sign-in at all.",
            SslHandshakeException => $"TLS with {endpoint} failed. Try STARTTLS on port 587 or 25, or TLS on connect on port 465.",
            SmtpCommandException command when command.StatusCode is SmtpStatusCode.MailboxUnavailable
                or SmtpStatusCode.MailboxNameNotAllowed or SmtpStatusCode.UserNotLocalTryAlternatePath =>
                $"The SMTP server {endpoint} refused the message: {command.Message} " +
                "Check that this server's IP address or the sender address is allowed to relay.",
            SmtpCommandException command => $"The SMTP server {endpoint} refused the message: {command.Message}",
            SmtpProtocolException => $"The SMTP server {endpoint} sent an unexpected response: {exception.Message}",
            _ => $"Could not send email through {endpoint}: {exception.Message} " +
                "Check the host, port, security setting, and that outbound SMTP is allowed by the firewall."
        };
    }
}
