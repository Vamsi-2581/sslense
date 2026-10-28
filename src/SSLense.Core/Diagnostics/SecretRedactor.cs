using System.Text.RegularExpressions;

namespace SSLense.Core.Diagnostics;

/// <summary>
/// Removes secrets from free-form text such as log lines before it leaves the machine. Structured
/// values (passwords, protected blobs, webhook URLs) are also removed field by field before this runs;
/// this is the safety net for anything that reached a log message.
/// </summary>
public static partial class SecretRedactor
{
    public const string Marker = "[REDACTED]";

    public static string Redact(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        text = PemBlock().Replace(text, "[REDACTED PEM BLOCK]");
        text = BearerToken().Replace(text, $"Bearer {Marker}");
        text = SecretAssignment().Replace(text, match => $"{match.Groups["key"].Value}{match.Groups["sep"].Value}{Marker}");
        text = Url().Replace(text, match => RedactUrl(match.Value));
        text = LongBlob().Replace(text, Marker);
        text = Email().Replace(text, match => $"{match.Groups["first"].Value}***@{match.Groups["domain"].Value}");
        return text;
    }

    /// <summary>Masks an email address for structured fields, keeping its first character and domain.</summary>
    public static string? MaskEmail(string? email) => email is null ? null : Email().Replace(email, match =>
        $"{match.Groups["first"].Value}***@{match.Groups["domain"].Value}");

    private static string RedactUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return Marker;
        }

        var origin = $"{uri.Scheme}://{uri.Authority}";

        // ACME URLs and HTTP-01 challenge paths are public by design and needed to diagnose validation.
        // Anything else (webhook paths and query strings especially) can embed a credential.
        if (uri.Host.EndsWith("letsencrypt.org", StringComparison.OrdinalIgnoreCase) ||
            (uri.AbsolutePath.StartsWith("/.well-known/acme-challenge/", StringComparison.OrdinalIgnoreCase) && uri.Query.Length == 0))
        {
            return $"{origin}{uri.AbsolutePath}";
        }

        return uri.AbsolutePath is "/" or "" && uri.Query.Length == 0 ? origin : $"{origin}/{Marker}";
    }

    [GeneratedRegex(@"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----")]
    private static partial Regex PemBlock();

    [GeneratedRegex(@"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")]
    private static partial Regex BearerToken();

    [GeneratedRegex(@"(?i)(?<key>\b(?:password|passwd|pwd|secret|client[-_]?secret|token|access[-_]?token|api[-_]?key|apikey|authorization|protected(?:password|url)))(?<sep>""?\s*[:=]\s*""?)[^\s"",;}]+")]
    private static partial Regex SecretAssignment();

    [GeneratedRegex(@"https?://[^\s""'<>\])]+", RegexOptions.IgnoreCase)]
    private static partial Regex Url();

    // DPAPI blobs, keys, and tokens; 48+ characters stays clear of 40-character thumbprints.
    [GeneratedRegex(@"[A-Za-z0-9+/_\-]{48,}={0,2}")]
    private static partial Regex LongBlob();

    [GeneratedRegex(@"(?<first>[A-Za-z0-9])[A-Za-z0-9._%+\-]*@(?<domain>[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})")]
    private static partial Regex Email();
}
