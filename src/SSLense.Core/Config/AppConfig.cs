namespace SSLense.Core.Config;

public sealed record AppConfig
{
    /// <summary>0 for files written before schema versioning; stamped by <see cref="IConfigStore.SaveAsync"/>.</summary>
    public int SchemaVersion { get; init; }

    public string? DefaultEmail { get; init; }

    public bool UseStaging { get; init; } = true;

    /// <summary>
    /// Days before expiry for the Let's Encrypt fallback schedule, used only when the CA offers no renewal window (ARI),
    /// and capped at a third of the certificate's lifetime. Reminders have their own settings.
    /// </summary>
    public int RenewalThresholdDays { get; init; } = 30;

    public NotificationConfig Notifications { get; init; } = new();

    public ReminderConfig Reminders { get; init; } = new();

    /// <summary>Certificate authorities added by the administrator. The Let's Encrypt profiles are built in.</summary>
    public IReadOnlyList<Acme.CertificateAuthority> CertificateAuthorities { get; init; } = [];
}
