using System.Net.Http.Json;
using System.Text;
using System.Web;
using SSLense.Core.Config;

namespace SSLense.Core.Notifications;

public interface IChatSender
{
    Task SendAsync(ChatFormat format, Uri url, NotificationMessage message, CancellationToken cancellationToken);
}

/// <summary>Posts to Teams, Slack, Discord, Telegram, ntfy, or a generic webhook in each one's native format.</summary>
internal sealed class ChatSender : IChatSender, IDisposable
{
    // Discord rejects content over 2,000 characters and Telegram over 4,096; notifications are far shorter.
    private const int MaximumTextLength = 1900;

    private readonly HttpClient _httpClient;

    public ChatSender()
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
    }

    internal ChatSender(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task SendAsync(ChatFormat format, Uri url, NotificationMessage message, CancellationToken cancellationToken)
    {
        using var request = CreateRequest(format, url, message);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // The URL is never included: chat webhook URLs embed their credential.
            throw new InvalidOperationException(
                $"The {format} notification was rejected with HTTP {(int)response.StatusCode} by {url.Host}. " +
                "Check that the webhook URL is complete and still active.");
        }
    }

    internal static HttpRequestMessage CreateRequest(ChatFormat format, Uri url, NotificationMessage message)
    {
        var text = Truncate(message.Body);
        var request = new HttpRequestMessage(HttpMethod.Post, url);
        switch (format)
        {
            case ChatFormat.Teams:
                // An Adaptive Card message works with Teams Workflows and the older incoming-webhook connectors.
                request.Content = JsonContent.Create(new
                {
                    type = "message",
                    attachments = new[]
                    {
                        new
                        {
                            contentType = "application/vnd.microsoft.card.adaptive",
                            content = new Dictionary<string, object>
                            {
                                ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
                                ["type"] = "AdaptiveCard",
                                ["version"] = "1.4",
                                ["body"] = new object[]
                                {
                                    new { type = "TextBlock", text = message.Subject, weight = "Bolder", size = "Medium", wrap = true },
                                    new { type = "TextBlock", text, wrap = true }
                                }
                            }
                        }
                    }
                });
                break;
            case ChatFormat.Slack:
                request.Content = JsonContent.Create(new { text = $"*{message.Subject}*\n{text}" });
                break;
            case ChatFormat.Discord:
                request.Content = JsonContent.Create(new { content = $"**{message.Subject}**\n{text}" });
                break;
            case ChatFormat.Telegram:
                // chat_id is read from the configured URL and sent in the body, which the Bot API always accepts.
                var query = HttpUtility.ParseQueryString(url.Query);
                request.RequestUri = new UriBuilder(url) { Query = string.Empty }.Uri;
                request.Content = JsonContent.Create(new { chat_id = query["chat_id"], text = $"{message.Subject}\n\n{text}" });
                break;
            case ChatFormat.Ntfy:
                request.Content = new StringContent(text, Encoding.UTF8, "text/plain");
                request.Headers.Add("Title", ToHeaderValue(message.Subject));
                request.Headers.Add("Priority", message.EffectiveSeverity switch
                {
                    NotificationSeverity.Error => "high",
                    NotificationSeverity.Warning => "default",
                    _ => "low"
                });
                request.Headers.Add("Tags", message.EffectiveSeverity switch
                {
                    NotificationSeverity.Error => "rotating_light",
                    NotificationSeverity.Warning => "warning",
                    _ => "white_check_mark"
                });
                break;
            default:
                request.Content = JsonContent.Create(new
                {
                    kind = message.Kind.ToString(),
                    severity = message.EffectiveSeverity.ToString(),
                    subject = message.Subject,
                    body = message.Body,
                    occurredAtUtc = DateTimeOffset.UtcNow
                });
                break;
        }

        return request;
    }

    /// <summary>
    /// Validates a channel URL when it is saved, so mistakes show up during setup rather than on the first failure.
    /// </summary>
    internal static void Validate(ChatFormat format, Uri url)
    {
        // Plain HTTP is allowed only where self-hosting on an internal network is common.
        if (url.Scheme != Uri.UriSchemeHttps &&
            !(url.Scheme == Uri.UriSchemeHttp && format is ChatFormat.Generic or ChatFormat.Ntfy))
        {
            throw new ArgumentException($"The {format} URL must start with https://.");
        }

        if (format == ChatFormat.Telegram &&
            (!url.AbsolutePath.EndsWith("/sendMessage", StringComparison.Ordinal) ||
             string.IsNullOrWhiteSpace(HttpUtility.ParseQueryString(url.Query)["chat_id"])))
        {
            throw new ArgumentException(
                "Use a Telegram URL of the form https://api.telegram.org/bot<token>/sendMessage?chat_id=<chat id>.");
        }

        if (format == ChatFormat.Ntfy && url.AbsolutePath.Trim('/').Length == 0)
        {
            throw new ArgumentException("Include the topic in the ntfy URL, for example https://ntfy.sh/my-sslense-alerts.");
        }
    }

    public void Dispose() => _httpClient.Dispose();

    private static string Truncate(string text) =>
        text.Length <= MaximumTextLength ? text : string.Concat(text.AsSpan(0, MaximumTextLength), "…");

    // HTTP headers are ASCII; ntfy documents that non-ASCII titles must be encoded, so drop them instead.
    private static string ToHeaderValue(string value) =>
        new(value.Select(character => character is >= ' ' and <= '~' ? character : '?').ToArray());
}
