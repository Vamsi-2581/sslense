using System.Text.RegularExpressions;

namespace SSLense.Core.Acme;

/// <summary>
/// An ACME certificate authority SSLense can issue from. The two Let's Encrypt profiles are built in;
/// others are configured by the administrator and stored in config.json.
/// </summary>
/// <param name="Id">Stable identifier stored with each certificate; lowercase letters, digits, and hyphens.</param>
/// <param name="IsTest">
/// True for test endpoints whose certificates browsers do not trust. Every other profile is treated as
/// production and needs an explicit acknowledgement before its first use.
/// </param>
/// <param name="EabKeyId">External Account Binding key ID, for CAs that require one.</param>
/// <param name="ProtectedEabHmacKey">DPAPI-protected EAB HMAC key; used once, when the ACME account is created.</param>
public sealed record CertificateAuthority(
    string Id,
    string Name,
    Uri DirectoryUri,
    bool IsTest,
    string? EabKeyId = null,
    string? ProtectedEabHmacKey = null,
    bool ProductionAcknowledged = false)
{
    public bool IsBuiltIn => CertificateAuthorities.IsBuiltIn(Id);
}

public static partial class CertificateAuthorities
{
    public const string LetsEncryptId = "letsencrypt";
    public const string LetsEncryptStagingId = "letsencrypt-staging";

    public static CertificateAuthority LetsEncrypt { get; } = new(
        LetsEncryptId,
        "Let's Encrypt production",
        new Uri("https://acme-v02.api.letsencrypt.org/directory"),
        IsTest: false);

    public static CertificateAuthority LetsEncryptStaging { get; } = new(
        LetsEncryptStagingId,
        "Let's Encrypt staging",
        new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"),
        IsTest: true);

    public static IReadOnlyList<CertificateAuthority> BuiltIn { get; } = [LetsEncryptStaging, LetsEncrypt];

    public static bool IsBuiltIn(string id) => id is LetsEncryptId or LetsEncryptStagingId;

    /// <summary>Maps the schema 1 environment (0 = staging, 1 = production) to its built-in profile.</summary>
    public static string FromLegacyEnvironment(int environment) => environment == 1 ? LetsEncryptId : LetsEncryptStagingId;

    /// <summary>
    /// The short word used in messages such as "the staging certificate for ...". Built-in profiles keep the
    /// wording SSLense has always used; other profiles use their ID.
    /// </summary>
    public static string Label(string authorityId) => authorityId switch
    {
        LetsEncryptStagingId => "staging",
        LetsEncryptId => "production",
        _ => authorityId
    };

    public static bool IsValidId(string id) => ValidId().IsMatch(id);

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")]
    private static partial Regex ValidId();
}
