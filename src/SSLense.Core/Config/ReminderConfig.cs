namespace SSLense.Core.Config;

/// <summary>When SSLense reminds about certificates that are close to expiry (docs/design/expiry-reminders.md).</summary>
public sealed record ReminderConfig
{
    public const int MaximumStartDays = 365;
    public const int MaximumRepeatDays = 30;

    /// <summary>Reminders start this many days before a certificate expires.</summary>
    public int StartDays { get; init; } = 30;

    /// <summary>Days between reminders for the same certificate. Always 1 in the last seven days.</summary>
    public int RepeatDays { get; init; } = 1;

    /// <summary>Hour of the day, server local time, from which the daily digest is sent.</summary>
    public int SendAtHour { get; init; } = 9;

    /// <summary>One notice when an automatically renewed certificate enters the reminder window.</summary>
    public bool UpcomingRenewalNotices { get; init; } = true;

    /// <summary>When set, a summary is sent on this day every week even if nothing needs attention.</summary>
    public DayOfWeek? WeeklySummaryDay { get; init; }

    /// <summary>Throws when a value is outside its range; settings are checked before they are saved.</summary>
    public void Validate()
    {
        if (StartDays is < 1 or > MaximumStartDays)
        {
            throw new ArgumentOutOfRangeException(nameof(StartDays), $"Start reminding must be between 1 and {MaximumStartDays} days before expiry.");
        }

        if (RepeatDays is < 1 or > MaximumRepeatDays)
        {
            throw new ArgumentOutOfRangeException(nameof(RepeatDays), $"Repeat every must be between 1 and {MaximumRepeatDays} days.");
        }

        if (SendAtHour is < 0 or > 23)
        {
            throw new ArgumentOutOfRangeException(nameof(SendAtHour), "Send at must be an hour from 0 to 23.");
        }
    }
}
