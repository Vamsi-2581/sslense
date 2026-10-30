namespace SSLense.Core.Acme;

public interface IAcmeProtocolClient
{
    /// <summary>Loads or creates the ACME account for <paramref name="authority"/>, then creates an order.</summary>
    Task<IAcmeOrderSession> CreateOrderAsync(
        string email,
        IReadOnlyList<string> hosts,
        CertificateAuthority authority,
        CancellationToken cancellationToken);
}
