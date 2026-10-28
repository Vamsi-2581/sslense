using System.Net;
using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Notifications;

public sealed class NotifierTests
{
    [Fact]
    public async Task NotifyAsync_AllChannels_DecryptsSecretsAndDeliversToEach()
    {
        var notifications = new NotificationConfig
        {
            Email = new EmailNotificationConfig(
                "smtp.example.com", 587, SmtpSecurity.StartTls, SmtpAuthentication.Password,
                "user", Protected("plain-password"), "from@example.com", ["a@example.com", "b@example.com"]),
            Chat =
            [
                new ChatNotificationConfig(ChatFormat.Teams, Protected("https://teams.example.com/hook")),
                new ChatNotificationConfig(ChatFormat.Ntfy, Protected("https://ntfy.sh/topic"), "phone")
            ]
        };
        var email = new Mock<IEmailSender>(MockBehavior.Strict);
        email.Setup(value => value.SendAsync(
                It.Is<EmailDelivery>(delivery => delivery.Password == "plain-password" && delivery.To.Count == 2),
                It.IsAny<NotificationMessage>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var chat = new Mock<IChatSender>(MockBehavior.Strict);
        chat.Setup(value => value.SendAsync(ChatFormat.Teams, new Uri("https://teams.example.com/hook"), It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        chat.Setup(value => value.SendAsync(ChatFormat.Ntfy, new Uri("https://ntfy.sh/topic"), It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var eventLog = new Mock<IEventLogWriter>(MockBehavior.Strict);
        eventLog.Setup(value => value.Write(It.IsAny<NotificationMessage>()));
        var notifier = CreateNotifier(notifications, email, chat, eventLog);

        await notifier.NotifyAsync(new NotificationMessage(NotificationKind.RenewalFailure, "subject", "body"));

        email.VerifyAll();
        chat.VerifyAll();
        eventLog.VerifyAll();
    }

    [Fact]
    public async Task NotifyAsync_OneChannelFails_StillDeliversToTheOthersThenReports()
    {
        var notifications = new NotificationConfig
        {
            Chat =
            [
                new ChatNotificationConfig(ChatFormat.Slack, Protected("https://slack.example.com/broken")),
                new ChatNotificationConfig(ChatFormat.Discord, Protected("https://discord.example.com/ok"))
            ]
        };
        var chat = new Mock<IChatSender>(MockBehavior.Strict);
        chat.Setup(value => value.SendAsync(ChatFormat.Slack, It.IsAny<Uri>(), It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TaskCanceledException("timed out"));
        chat.Setup(value => value.SendAsync(ChatFormat.Discord, It.IsAny<Uri>(), It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var notifier = CreateNotifier(notifications, chat: chat);

        var exception = await Assert.ThrowsAsync<AggregateException>(() =>
            notifier.NotifyAsync(new NotificationMessage(NotificationKind.RenewalFailure, "subject", "body")));

        Assert.Contains("Slack", Assert.Single(exception.InnerExceptions).Message, StringComparison.Ordinal);
        chat.VerifyAll();
    }

    [Fact]
    public async Task NotifyAsync_SuccessWithoutNotifyOnSuccess_OnlyReachesTheEventLog()
    {
        var notifications = new NotificationConfig
        {
            Chat = [new ChatNotificationConfig(ChatFormat.Slack, Protected("https://slack.example.com/hook"))],
            NotifyOnSuccess = false
        };
        var chat = new Mock<IChatSender>(MockBehavior.Strict);
        var eventLog = new Mock<IEventLogWriter>(MockBehavior.Strict);
        eventLog.Setup(value => value.Write(It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalSuccess)));
        var notifier = CreateNotifier(notifications, chat: chat, eventLog: eventLog);

        await notifier.NotifyAsync(new NotificationMessage(NotificationKind.RenewalSuccess, "subject", "body"));

        eventLog.VerifyAll();
        chat.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task TestAsync_ReportsEachChannelIncludingTheHeartbeat()
    {
        var notifications = new NotificationConfig
        {
            Chat = [new ChatNotificationConfig(ChatFormat.Teams, Protected("https://teams.example.com/hook"))],
            Heartbeat = new HeartbeatNotificationConfig(Protected("https://hc-ping.com/abc"))
        };
        var chat = new Mock<IChatSender>(MockBehavior.Strict);
        chat.Setup(value => value.SendAsync(ChatFormat.Teams, It.IsAny<Uri>(), It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("HTTP 404"));
        var handler = new StubHandler(HttpStatusCode.OK);
        var notifier = CreateNotifier(notifications, chat: chat, handler: handler);

        var results = await notifier.TestAsync();

        Assert.Collection(
            results,
            result => Assert.True(result.Succeeded && result.Channel == "Windows Event Log"),
            result => Assert.False(result.Succeeded),
            result => Assert.True(result.Succeeded && result.Channel == "Heartbeat"));
        Assert.Equal(new Uri("https://hc-ping.com/abc"), handler.LastRequest);
    }

    [Fact]
    public async Task TestAsync_NothingConfiguredAndEventLogOff_ExplainsWhatToConfigure()
    {
        var notifier = CreateNotifier(new NotificationConfig { EventLogEnabled = false });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => notifier.TestAsync());

        Assert.Contains("No notification channels", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PingHeartbeatAsync_NotConfigured_DoesNothing()
    {
        var handler = new StubHandler(HttpStatusCode.OK);

        Assert.False(await CreateNotifier(new NotificationConfig(), handler: handler).PingHeartbeatAsync());
        Assert.Null(handler.LastRequest);
    }

    // The fake protector stores plain text in base64, so tests can read what a channel would receive.
    private static string Protected(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static Notifier CreateNotifier(
        NotificationConfig notifications,
        Mock<IEmailSender>? email = null,
        Mock<IChatSender>? chat = null,
        Mock<IEventLogWriter>? eventLog = null,
        StubHandler? handler = null)
    {
        var configStore = new Mock<IConfigStore>(MockBehavior.Strict);
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { Notifications = notifications });
        var protector = new Mock<ISecretProtector>(MockBehavior.Strict);
        protector.Setup(value => value.Unprotect(It.IsAny<byte[]>())).Returns<byte[]>(bytes => (byte[])bytes.Clone());
        return new Notifier(
            configStore.Object,
            protector.Object,
            (email ?? new Mock<IEmailSender>(MockBehavior.Strict)).Object,
            (chat ?? new Mock<IChatSender>(MockBehavior.Strict)).Object,
            (eventLog ?? new Mock<IEventLogWriter>()).Object,
            new HttpClient(handler ?? new StubHandler(HttpStatusCode.OK)));
    }

    private sealed class StubHandler(HttpStatusCode status) : HttpMessageHandler
    {
        public Uri? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(status));
        }
    }
}
