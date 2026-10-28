namespace SSLense.Core.Notifications;

public enum NotificationKind
{
    Test,
    RenewalFailure,
    RenewalSuccess,
    ExpiryWarning
}

public enum NotificationSeverity
{
    Information,
    Warning,
    Error
}

/// <param name="Severity">Defaults by kind; set it to override, for example for a certificate about to expire.</param>
public sealed record NotificationMessage(
    NotificationKind Kind,
    string Subject,
    string Body,
    NotificationSeverity? Severity = null)
{
    public NotificationSeverity EffectiveSeverity => Severity ?? Kind switch
    {
        NotificationKind.RenewalFailure => NotificationSeverity.Error,
        NotificationKind.ExpiryWarning => NotificationSeverity.Warning,
        _ => NotificationSeverity.Information
    };
}
