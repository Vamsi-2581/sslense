using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Notifications;

internal sealed class Notifier(
    IConfigStore configStore,
    ISecretProtector secretProtector,
    IEmailSender emailSender,
    IChatSender chatSender,
    IEventLogWriter eventLogWriter,
    HttpClient httpClient) : INotifier
{
    private static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(15);

    public async Task NotifyAsync(
        NotificationMessage message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);

        // Success always reaches the Event Log as an audit record; other channels only when asked for.
        var external = message.Kind != NotificationKind.RenewalSuccess || config.Notifications.NotifyOnSuccess;
        var failures = (await DeliverAsync(config.Notifications, message, external, cancellationToken).ConfigureAwait(false))
            .Where(result => !result.Succeeded)
            .Select(result => new InvalidOperationException($"{result.Channel}: {result.Message}"))
            .ToArray();
        if (failures.Length > 0)
        {
            throw new AggregateException("One or more notification channels failed.", failures);
        }
    }

    public async Task<IReadOnlyList<ChannelResult>> TestAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var results = (await DeliverAsync(
                    config.Notifications,
                    new NotificationMessage(
                        NotificationKind.Test,
                        "SSLense test notification",
                        "SSLense notification delivery is configured correctly."),
                    external: true,
                    cancellationToken)
                .ConfigureAwait(false))
            .ToList();
        if (config.Notifications.Heartbeat is not null)
        {
            results.Add(await RunChannelAsync("Heartbeat", () => PingHeartbeatAsync(cancellationToken), cancellationToken).ConfigureAwait(false));
        }

        return results.Count > 0
            ? results
            : throw new InvalidOperationException(
                "No notification channels are configured and the Event Log is turned off. " +
                "Configure email, a chat channel, or a heartbeat, or turn the Event Log back on.");
    }

    public async Task<bool> PingHeartbeatAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (config.Notifications.Heartbeat is not { } heartbeat)
        {
            return false;
        }

        var url = new Uri(Unprotect(heartbeat.ProtectedUrl), UriKind.Absolute);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(HeartbeatTimeout);
        using var response = await httpClient.GetAsync(url, timeout.Token).ConfigureAwait(false);
        return response.IsSuccessStatusCode
            ? true
            : throw new InvalidOperationException(
                $"The heartbeat URL on {url.Host} returned HTTP {(int)response.StatusCode}. Check that the check still exists.");
    }

    private async Task<IReadOnlyList<ChannelResult>> DeliverAsync(
        NotificationConfig notifications,
        NotificationMessage message,
        bool external,
        CancellationToken cancellationToken)
    {
        var results = new List<ChannelResult>();
        if (notifications.EventLogEnabled)
        {
            results.Add(await RunChannelAsync("Windows Event Log", () =>
            {
                eventLogWriter.Write(message);
                return Task.CompletedTask;
            }, cancellationToken).ConfigureAwait(false));
        }

        if (!external)
        {
            return results;
        }

        if (notifications.Email is { } email)
        {
            results.Add(await RunChannelAsync($"Email via {email.Host}", async () =>
            {
                var password = email.Authentication == SmtpAuthentication.Password && email.ProtectedPassword is not null
                    ? Unprotect(email.ProtectedPassword)
                    : null;
                await emailSender.SendAsync(
                        new EmailDelivery(
                            email.Host, email.Port, email.Security, email.Authentication,
                            email.Username, password, email.From, email.To),
                        message,
                        cancellationToken)
                    .ConfigureAwait(false);
            }, cancellationToken).ConfigureAwait(false));
        }

        foreach (var chat in notifications.Chat)
        {
            results.Add(await RunChannelAsync(DescribeChat(chat), async () =>
            {
                var url = new Uri(Unprotect(chat.ProtectedUrl), UriKind.Absolute);
                await chatSender.SendAsync(chat.Format, url, message, cancellationToken).ConfigureAwait(false);
            }, cancellationToken).ConfigureAwait(false));
        }

        return results;
    }

    internal static string DescribeChat(ChatNotificationConfig chat) =>
        string.IsNullOrWhiteSpace(chat.Name) ? chat.Format.ToString() : $"{chat.Format} ({chat.Name})";

    /// <summary>
    /// Runs one channel. A timeout counts as that channel failing; only cancellation requested by the caller
    /// stops delivery, so one hanging webhook never blocks the channels after it.
    /// </summary>
    private static async Task<ChannelResult> RunChannelAsync(string channel, Func<Task> send, CancellationToken cancellationToken)
    {
        try
        {
            await send().ConfigureAwait(false);
            return new ChannelResult(channel, true, "Delivered.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new ChannelResult(channel, false, "Timed out. Check that the server is reachable from this machine.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return new ChannelResult(channel, false, exception.Message);
        }
    }

    private string Unprotect(string encoded)
    {
        byte[] protectedBytes;
        try
        {
            protectedBytes = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("A protected notification secret is not valid base64 data.", exception);
        }

        var plaintext = secretProtector.Unprotect(protectedBytes);
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
