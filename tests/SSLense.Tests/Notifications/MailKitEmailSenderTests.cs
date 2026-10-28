using System.Net;
using System.Net.Sockets;
using System.Text;
using MailKit.Security;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Notifications;

public sealed class MailKitEmailSenderTests
{
    [Fact]
    public async Task SendAsync_RelayWithoutSignIn_DeliversToEveryRecipient()
    {
        using var server = new FakeSmtpServer();

        await new MailKitEmailSender().SendAsync(
            new EmailDelivery("127.0.0.1", server.Port, SmtpSecurity.None, SmtpAuthentication.None, null, null,
                "alerts@contoso.com", ["ops@contoso.com", "admin@contoso.com"]),
            new NotificationMessage(NotificationKind.RenewalFailure, "SSLense renewal failed: My Site", "Port 80 is not reachable."),
            CancellationToken.None);

        var transcript = await server.Completed;
        Assert.Contains("MAIL FROM:<alerts@contoso.com>", transcript, StringComparison.Ordinal);
        Assert.Contains("RCPT TO:<ops@contoso.com>", transcript, StringComparison.Ordinal);
        Assert.Contains("RCPT TO:<admin@contoso.com>", transcript, StringComparison.Ordinal);
        Assert.Contains("Subject: SSLense renewal failed: My Site", transcript, StringComparison.Ordinal);
        Assert.DoesNotContain("AUTH", transcript, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendAsync_Refused_ExplainsTheLikelyCause()
    {
        using var server = new FakeSmtpServer(rejectRecipients: true);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => new MailKitEmailSender().SendAsync(
            new EmailDelivery("127.0.0.1", server.Port, SmtpSecurity.None, SmtpAuthentication.None, null, null,
                "alerts@contoso.com", ["ops@contoso.com"]),
            new NotificationMessage(NotificationKind.Test, "test", "test"),
            CancellationToken.None));

        Assert.Contains("allowed to relay", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(SmtpSecurity.Auto, 465, SecureSocketOptions.SslOnConnect)]
    [InlineData(SmtpSecurity.Auto, 587, SecureSocketOptions.StartTls)]
    [InlineData(SmtpSecurity.Auto, 25, SecureSocketOptions.StartTls)]
    [InlineData(SmtpSecurity.None, 25, SecureSocketOptions.None)]
    public void ToSocketOptions_AutoNeverFallsBackToPlainText(SmtpSecurity security, int port, SecureSocketOptions expected)
    {
        Assert.Equal(expected, MailKitEmailSender.ToSocketOptions(security, port));
    }

    /// <summary>Just enough SMTP for one message, recording what the client sent.</summary>
    private sealed class FakeSmtpServer : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

        public FakeSmtpServer(bool rejectRecipients = false)
        {
            _listener.Start();
            Completed = Task.Run(() => ServeAsync(rejectRecipients));
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public Task<string> Completed { get; }

        public void Dispose() => _listener.Stop();

        private async Task<string> ServeAsync(bool rejectRecipients)
        {
            var transcript = new StringBuilder();
            using var client = await _listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);
            await using var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
            await writer.WriteLineAsync("220 fake.smtp ready");
            while (await reader.ReadLineAsync() is { } line)
            {
                transcript.AppendLine(line);
                var command = line.Split(' ')[0].ToUpperInvariant();
                switch (command)
                {
                    case "EHLO":
                        await writer.WriteLineAsync("250-fake.smtp");
                        await writer.WriteLineAsync("250 8BITMIME");
                        break;
                    case "RCPT" when rejectRecipients:
                        await writer.WriteLineAsync("550 5.7.54 Unable to relay recipient in non-accepted domain");
                        break;
                    case "DATA":
                        await writer.WriteLineAsync("354 go ahead");
                        while (await reader.ReadLineAsync() is { } data && data != ".")
                        {
                            transcript.AppendLine(data);
                        }

                        await writer.WriteLineAsync("250 queued");
                        break;
                    case "QUIT":
                        await writer.WriteLineAsync("221 bye");
                        return transcript.ToString();
                    default:
                        await writer.WriteLineAsync("250 OK");
                        break;
                }
            }

            return transcript.ToString();
        }
    }
}
