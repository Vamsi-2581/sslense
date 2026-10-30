using System.Security.Cryptography;

namespace SSLense.Core.Certificates;

/// <summary>Private keys for certificate requests, kept in the Windows key store and never exported.</summary>
public interface IPrivateKeyStore
{
    /// <summary>Creates a persisted, non-exportable key and returns a handle to it.</summary>
    AsymmetricAlgorithm Create(string keyName, string keyType);

    /// <summary>Opens a key created by <see cref="Create"/>, or returns null when it no longer exists.</summary>
    AsymmetricAlgorithm? Open(string keyName);

    void Delete(string keyName);
}

public static class PrivateKeyTypes
{
    public const string Rsa2048 = "rsa2048";
    public const string Rsa3072 = "rsa3072";
    public const string EcdsaP256 = "ec256";

    /// <summary>RSA 2048 by default: some resellers still reject ECDSA certificate requests.</summary>
    public const string Default = Rsa2048;

    public static IReadOnlyList<string> All { get; } = [Rsa2048, Rsa3072, EcdsaP256];
}

/// <summary>
/// CNG keys in the Microsoft Software Key Storage Provider. Machine-scoped in production, so IIS (HTTP.sys, running
/// as SYSTEM) can use them; user-scoped in tests, which run without elevation.
/// </summary>
internal sealed class CngPrivateKeyStore(bool machineScope = true) : IPrivateKeyStore
{
    public AsymmetricAlgorithm Create(string keyName, string keyType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        var parameters = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyCreationOptions = machineScope ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.AllUsages
        };
        switch (keyType)
        {
            case PrivateKeyTypes.Rsa2048 or PrivateKeyTypes.Rsa3072:
                var bits = keyType == PrivateKeyTypes.Rsa3072 ? 3072 : 2048;
                parameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(bits), CngPropertyOptions.None));
                return new RSACng(CngKey.Create(CngAlgorithm.Rsa, keyName, parameters));
            case PrivateKeyTypes.EcdsaP256:
                return new ECDsaCng(CngKey.Create(CngAlgorithm.ECDsaP256, keyName, parameters));
            default:
                throw new ArgumentException(
                    $"Unknown key type '{keyType}'. Use {string.Join(", ", PrivateKeyTypes.All)}.", nameof(keyType));
        }
    }

    public AsymmetricAlgorithm? Open(string keyName)
    {
        var options = machineScope ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        if (!CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, options))
        {
            return null;
        }

        var key = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, options);
        return key.AlgorithmGroup == CngAlgorithmGroup.Rsa ? new RSACng(key) : new ECDsaCng(key);
    }

    public void Delete(string keyName)
    {
        using var key = Open(keyName);
        switch (key)
        {
            case RSACng rsa:
                rsa.Key.Delete();
                break;
            case ECDsaCng ecdsa:
                ecdsa.Key.Delete();
                break;
        }
    }
}
