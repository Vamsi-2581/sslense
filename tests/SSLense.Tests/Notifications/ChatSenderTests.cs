using System.Text.Json;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Notifications;

public sealed class ChatSenderTests
{
    private static readonly NotificationMessage Failure = new(
        NotificationKind.RenewalFailure, "SSLense renewal failed: My Site", "Port 80 is not reachable.");

    [Fact]
    public async Task Teams_SendsAnAdaptiveCard()
    {
        var json = await ReadJsonAsync(ChatFormat.Teams, "https://example.logic.azure.com/workflows/1");

        var attachment = json.GetProperty("attachments")[0];
        Assert.Equal("message", json.GetProperty("type").GetString());
        Assert.Equal("application/vnd.microsoft.card.adaptive", attachment.GetProperty("contentType").GetString());
        var body = attachment.GetProperty("content").GetProperty("body");
        Assert.Equal(Failure.Subject, body[0].GetProperty("text").GetString());
        Assert.Equal(Failure.Body, body[1].GetProperty("text").GetString());
    }

    [Theory]
    [InlineData(ChatFormat.Slack, "text", "*SSLense renewal failed: My Site*")]
    [InlineData(ChatFormat.Discord, "content", "**SSLense renewal failed: My Site**")]
    public async Task SlackAndDiscord_UseTheirTextField(ChatFormat format, string field, string expectedStart)
    {
        var json = await ReadJsonAsync(format, "https://hooks.example.com/1");

        Assert.StartsWith(expectedStart, json.GetProperty(field).GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Telegram_MovesChatIdIntoTheBody()
    {
        using var request = ChatSender.CreateRequest(
            ChatFormat.Telegram, new Uri("https://api.telegram.org/bot123:abc/sendMessage?chat_id=-1001"), Failure);

        var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync()).RootElement;
        Assert.Equal("https://api.telegram.org/bot123:abc/sendMessage", request.RequestUri!.AbsoluteUri);
        Assert.Equal("-1001", json.GetProperty("chat_id").GetString());
    }

    [Fact]
    public async Task Ntfy_SendsPlainTextWithTitleAndHighPriorityForFailures()
    {
        using var request = ChatSender.CreateRequest(ChatFormat.Ntfy, new Uri("https://ntfy.sh/alerts"), Failure);

        Assert.Equal(Failure.Body, await request.Content!.ReadAsStringAsync());
        Assert.Equal(Failure.Subject, Assert.Single(request.Headers.GetValues("Title")));
        Assert.Equal("high", Assert.Single(request.Headers.GetValues("Priority")));
    }

    [Fact]
    public async Task Generic_KeepsTheDocumentedFieldsAndAddsSeverity()
    {
        var json = await ReadJsonAsync(ChatFormat.Generic, "https://example.com/hook");

        foreach (var field in new[] { "kind", "subject", "body", "occurredAtUtc" })
        {
            Assert.True(json.TryGetProperty(field, out _), field);
        }

        Assert.Equal("Error", json.GetProperty("severity").GetString());
    }

    [Fact]
    public async Task Discord_LongMessagesAreTruncatedBelowItsLimit()
    {
        var message = Failure with { Body = new string('x', 5000) };

        using var request = ChatSender.CreateRequest(ChatFormat.Discord, new Uri("https://discord.example.com/1"), message);

        var content = JsonDocument.Parse(await request.Content!.ReadAsStringAsync()).RootElement.GetProperty("content").GetString()!;
        Assert.True(content.Length < 2000);
    }

    private static async Task<JsonElement> ReadJsonAsync(ChatFormat format, string url)
    {
        using var request = ChatSender.CreateRequest(format, new Uri(url), Failure);
        return JsonDocument.Parse(await request.Content!.ReadAsStringAsync()).RootElement;
    }
}
