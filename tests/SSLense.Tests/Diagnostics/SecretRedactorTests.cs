using SSLense.Core.Diagnostics;
using Xunit;

namespace SSLense.Tests.Diagnostics;

public sealed class SecretRedactorTests
{
    [Theory]
    [InlineData("SMTP login failed for password=Hunter2Secret! on host", "Hunter2Secret!")]
    [InlineData("{\"protectedPassword\": \"AQAAANCMnd8BFdERjHoAwE\"}", "AQAAANCMnd8BFdERjHoAwE")]
    [InlineData("Authorization: Bearer eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM", "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM")]
    [InlineData("POST https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX failed", "XXXXSECRETXXXX")]
    [InlineData("webhook https://example.com/hook?token=abc123SECRET returned 500", "abc123SECRET")]
    [InlineData("blob AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAh8e5ZWVsukKYZ2kQe0dPOgAAAAACAAAAAAAQZgAAAAEAACAAAAD", "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAh8e5ZWVsukKYZ2kQe0dPOgAAAAACAAAAAAAQZgAAAAEAACAAAAD")]
    [InlineData("account admin@example.com registered", "admin@example.com")]
    public void Redact_RemovesSecrets(string input, string secret)
    {
        var redacted = SecretRedactor.Redact(input);

        Assert.DoesNotContain(secret, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_RemovesPemBlocks()
    {
        var input = "key:\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\nend";

        var redacted = SecretRedactor.Redact(input);

        Assert.DoesNotContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7", redacted, StringComparison.Ordinal);
        Assert.Contains("[REDACTED PEM BLOCK]", redacted, StringComparison.Ordinal);
    }

    [Theory]
    // Needed for diagnosis and not secret: thumbprints, ACME URLs, challenge URLs, and plain origins.
    [InlineData("Thumbprint 6533D7B01A1F3C4BDF85551F375A3EFC4BD45F5F bound")]
    [InlineData("GET https://acme-staging-v02.api.letsencrypt.org/acme/order/123/456 returned 200")]
    [InlineData("Self-check http://acme-test.sslense.com/.well-known/acme-challenge/tokenABC returned 404")]
    [InlineData("Could not reach https://mail.example.com")]
    public void Redact_KeepsDiagnosticValues(string input)
    {
        Assert.Equal(input, SecretRedactor.Redact(input));
    }

    [Fact]
    public void MaskEmail_KeepsFirstCharacterAndDomain()
    {
        Assert.Equal("a***@example.com", SecretRedactor.MaskEmail("admin@example.com"));
    }
}
