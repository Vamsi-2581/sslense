using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Notifications;

public sealed class EventLogWriterTests
{
    // Monitoring rules match these IDs, so they are part of SSLense's public contract.
    [Theory]
    [InlineData(NotificationKind.RenewalSuccess, null, 1000)]
    [InlineData(NotificationKind.RenewalFailure, null, 1001)]
    [InlineData(NotificationKind.ExpiryWarning, NotificationSeverity.Warning, 1002)]
    [InlineData(NotificationKind.ExpiryWarning, NotificationSeverity.Error, 1003)]
    [InlineData(NotificationKind.Test, null, 1900)]
    public void GetEventId_IsStable(NotificationKind kind, NotificationSeverity? severity, int expected)
    {
        Assert.Equal(expected, WindowsEventLogWriter.GetEventId(new NotificationMessage(kind, "subject", "body", severity)));
    }
}
