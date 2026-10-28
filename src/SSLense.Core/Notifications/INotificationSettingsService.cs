namespace SSLense.Core.Notifications;

/// <summary>Each method changes one part of the notification settings and leaves the rest as it is.</summary>
public interface INotificationSettingsService
{
    Task<NotificationOverview> GetOverviewAsync(CancellationToken cancellationToken = default);

    Task SetEmailAsync(EmailSettingsRequest request, CancellationToken cancellationToken = default);

    Task RemoveEmailAsync(CancellationToken cancellationToken = default);

    Task AddChatAsync(ChatSettingsRequest request, CancellationToken cancellationToken = default);

    /// <param name="number">The 1-based number shown in <see cref="NotificationOverview.Chat"/>.</param>
    Task RemoveChatAsync(int number, CancellationToken cancellationToken = default);

    /// <param name="url">The URL to ping after each healthy service cycle, or null to stop pinging.</param>
    Task SetHeartbeatAsync(string? url, CancellationToken cancellationToken = default);

    Task SetOptionsAsync(bool eventLogEnabled, bool notifyOnSuccess, CancellationToken cancellationToken = default);

    /// <summary>Removes every channel. The Event Log stays on, so problems are still recorded.</summary>
    Task ClearAsync(CancellationToken cancellationToken = default);
}
