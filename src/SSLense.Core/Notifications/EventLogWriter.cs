using System.Diagnostics;

namespace SSLense.Core.Notifications;

public interface IEventLogWriter
{
    void Write(NotificationMessage message);
}

/// <summary>
/// Writes to the Windows Application log under source "SSLense", so existing monitoring (Azure Monitor,
/// SCOM, Zabbix, PRTG, and others) sees SSLense problems with no SSLense-specific setup.
/// </summary>
internal sealed class WindowsEventLogWriter : IEventLogWriter
{
    public const string Source = "SSLense";
    private const string LogName = "Application";

    // Stable IDs so monitoring rules can match them; documented in the README. Never renumber.
    public const int RenewalSucceededEventId = 1000;
    public const int RenewalFailedEventId = 1001;
    public const int ExpiryWarningEventId = 1002;
    public const int ExpiryCriticalEventId = 1003;
    public const int TestEventId = 1900;

    public void Write(NotificationMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // Registering the source needs administrator rights; every SSLense process that notifies is elevated.
        if (!EventLog.SourceExists(Source))
        {
            EventLog.CreateEventSource(Source, LogName);
        }

        // The event log limits a message to about 31,000 characters; notifications are far shorter.
        EventLog.WriteEntry(
            Source,
            $"{message.Subject}{Environment.NewLine}{Environment.NewLine}{message.Body}",
            ToEntryType(message.EffectiveSeverity),
            GetEventId(message));
    }

    internal static int GetEventId(NotificationMessage message) => message.Kind switch
    {
        NotificationKind.RenewalSuccess => RenewalSucceededEventId,
        NotificationKind.RenewalFailure => RenewalFailedEventId,
        NotificationKind.ExpiryWarning when message.EffectiveSeverity == NotificationSeverity.Error => ExpiryCriticalEventId,
        NotificationKind.ExpiryWarning => ExpiryWarningEventId,
        _ => TestEventId
    };

    private static EventLogEntryType ToEntryType(NotificationSeverity severity) => severity switch
    {
        NotificationSeverity.Error => EventLogEntryType.Error,
        NotificationSeverity.Warning => EventLogEntryType.Warning,
        _ => EventLogEntryType.Information
    };
}
