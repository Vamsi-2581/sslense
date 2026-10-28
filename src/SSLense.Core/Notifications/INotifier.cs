namespace SSLense.Core.Notifications;

public interface INotifier
{
    /// <summary>
    /// Delivers to every configured channel. Throws an <see cref="AggregateException"/> listing the channels that
    /// failed after trying all of them, so one broken channel never blocks the others.
    /// </summary>
    Task NotifyAsync(
        NotificationMessage message,
        CancellationToken cancellationToken = default);

    /// <summary>Sends a test through every channel, including the heartbeat ping, and reports each result.</summary>
    Task<IReadOnlyList<ChannelResult>> TestAsync(CancellationToken cancellationToken = default);

    /// <summary>Calls the heartbeat URL, if one is configured. Returns false when none is configured.</summary>
    Task<bool> PingHeartbeatAsync(CancellationToken cancellationToken = default);
}

public sealed record ChannelResult(string Channel, bool Succeeded, string Message);
