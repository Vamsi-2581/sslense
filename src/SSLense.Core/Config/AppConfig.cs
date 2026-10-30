namespace SSLense.Core.Config;

public sealed record AppConfig
{
    /// <summary>0 for files written before schema versioning; stamped by <see cref="IConfigStore.SaveAsync"/>.</summary>
    public int SchemaVersion { get; init; }

    public string? DefaultEmail { get; init; }

    public bool UseStaging { get; init; } = true;

    public int RenewalThresholdDays { get; init; } = 30;

    public NotificationConfig Notifications { get; init; } = new();

    /// <summary>Certificate authorities added by the administrator. The Let's Encrypt profiles are built in.</summary>
    public IReadOnlyList<Acme.CertificateAuthority> CertificateAuthorities { get; init; } = [];
}
