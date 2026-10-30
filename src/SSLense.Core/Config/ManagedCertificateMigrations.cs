using System.Text.Json;
using System.Text.Json.Nodes;
using SSLense.Core.Acme;

namespace SSLense.Core.Config;

/// <summary>
/// Upgrades serialized <see cref="ManagedCertificate"/> records. Applied both to managed-certificates.json and
/// to the certificate snapshot inside transaction journal entries, so an operation interrupted before an
/// upgrade is recovered with the right certificate authority.
/// </summary>
internal static class ManagedCertificateMigrations
{
    /// <summary>
    /// Schema 1 recorded a Let's Encrypt "environment" (0 or "Staging", 1 or "Production"); schema 2 records the
    /// certificate authority's ID and the certificate source.
    /// </summary>
    public static void UpgradeRecord(JsonObject record)
    {
        if (record.ContainsKey("authorityId"))
        {
            return;
        }

        var environment = record["environment"] switch
        {
            JsonValue value when value.TryGetValue<int>(out var number) => number,
            JsonValue value when value.TryGetValue<string>(out var text) =>
                string.Equals(text, "Production", StringComparison.OrdinalIgnoreCase) ? 1 : 0,
            _ => 0
        };
        record.Remove("environment");
        record["authorityId"] = CertificateAuthorities.FromLegacyEnvironment(environment);
        record["source"] = JsonValue.Create((int)CertificateSource.Acme);
    }

    public static void UpgradeRecords(JsonArray records)
    {
        foreach (var record in records.OfType<JsonObject>())
        {
            UpgradeRecord(record);
        }
    }

    public static T Deserialize<T>(JsonNode node, JsonSerializerOptions options) =>
        node.Deserialize<T>(options) ?? throw new JsonException("The record is empty.");
}
