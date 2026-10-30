using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>
/// The bring-your-own-certificate flow with real cryptography: a persisted, non-exportable key, a real CSR, a
/// certificate issued for it by a test CA, and real chain validation. Keys are user-scoped (tests run without
/// elevation) and deleted afterwards; the machine certificate store is never touched.
/// </summary>
public sealed class ImportedCertificateServiceTests : IDisposable
{
    private const string Site = "Shop";
    private readonly TestCertificateAuthority _ca = new();
    private readonly CngPrivateKeyStore _keys = new(machineScope: false);
    private readonly InMemoryFileSystem _files = new();
    private readonly JsonPendingRequestStore _pending;
    private readonly FakeCertificateStore _store = new();
    private readonly List<ManagedCertificate> _managed = [];
    private readonly Mock<IIisService> _iis = new(MockBehavior.Strict);

    public ImportedCertificateServiceTests()
    {
        _pending = new JsonPendingRequestStore(_files, @"C:\data\pending-requests.json", @"C:\data\pending-requests.lock");
        _iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => [new IisSite(1, Site, "Started", @"C:\inetpub\shop", [
                new IisBinding("http", "*", 80, "shop.example.com", null, null, false),
                new IisBinding("https", "*", 443, "shop.example.com", _managed.FirstOrDefault()?.Thumbprint, "My", true)
            ])]);
        _iis.Setup(value => value.ConfigureHttpsBindingsAsync(Site, It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), "My", It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
    }

    [Fact]
    public async Task CreateRequest_MakesANonExportableKeyAndACsrForEveryHost()
    {
        var request = await CreateService().CreateRequestAsync(Site, ["Shop.Example.com", "www.shop.example.com"]);

        var csr = CertificateRequest.LoadSigningRequestPem(request.CsrPem, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var names = csr.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().Single().EnumerateDnsNames();
        Assert.Equal(["shop.example.com", "www.shop.example.com"], names);
        Assert.Equal("CN=shop.example.com", csr.SubjectName.Name);
        using var key = (RSA)_keys.Open(request.KeyName)!;
        Assert.ThrowsAny<CryptographicException>(() => key.ExportParameters(includePrivateParameters: true));
        Assert.NotNull(await _pending.GetAsync(Site));
    }

    [Fact]
    public async Task Complete_InstallsTheIssuedCertificateWithItsKeyAndBindsIt()
    {
        var service = CreateService();
        var request = await service.CreateRequestAsync(Site, ["shop.example.com"]);
        using var issued = _ca.Issue(request.CsrPem);

        var result = await service.CompleteRequestAsync(Site, Encoding.ASCII.GetBytes(issued.ExportCertificatePem()),
            Encoding.ASCII.GetBytes(_ca.ChainPem));

        Assert.Equal(issued.Thumbprint, result.Certificate.Thumbprint);
        Assert.Equal(CertificateSource.Imported, result.Certificate.Source);
        Assert.Equal("SSLense Test Intermediate", result.Certificate.Issuer);
        Assert.True(_store.AddedWithPrivateKey);
        Assert.Equal(_ca.Intermediate.Thumbprint, Assert.Single(_store.Intermediates));
        Assert.Null(await _pending.GetAsync(Site));
        _iis.Verify(value => value.ConfigureHttpsBindingsAsync(Site, It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "shop.example.com" })),
            issued.Thumbprint, "My", It.IsAny<CancellationToken>()));
        Assert.Single(_managed);
    }

    [Fact]
    public async Task Complete_CertificateForADifferentKey_IsRefusedBeforeAnythingChanges()
    {
        var service = CreateService();
        await service.CreateRequestAsync(Site, ["shop.example.com"]);
        var (other, otherKey) = _ca.IssueWithNewKey("shop.example.com");
        using (other)
        using (otherKey)
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                service.CompleteRequestAsync(Site, other.RawData, Encoding.ASCII.GetBytes(_ca.ChainPem)));

            Assert.Contains("belongs to this server's pending request", exception.Message, StringComparison.Ordinal);
        }

        Assert.Null(_store.Added);
        Assert.NotNull(await _pending.GetAsync(Site));
    }

    [Fact]
    public async Task Complete_WithoutTheIntermediate_ExplainsTheMissingBundle()
    {
        var service = CreateService();
        var request = await service.CreateRequestAsync(Site, ["shop.example.com"]);
        using var issued = _ca.Issue(request.CsrPem);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.CompleteRequestAsync(Site, issued.RawData, chainFile: null));

        Assert.Contains("--chain", exception.Message, StringComparison.Ordinal);
        Assert.Null(_store.Added);
    }

    [Fact]
    public async Task Complete_BindingRolledBack_RemovesTheNewCertificateButKeepsTheRequest()
    {
        _iis.Setup(value => value.ConfigureHttpsBindingsAsync(Site, It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), "My", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new IisBindingException("HTTPS verification failed", previousBindingsRestored: true, new InvalidOperationException()));
        var service = CreateService();
        var request = await service.CreateRequestAsync(Site, ["shop.example.com"]);
        using var issued = _ca.Issue(request.CsrPem);

        await Assert.ThrowsAsync<IisBindingException>(() =>
            service.CompleteRequestAsync(Site, issued.RawData, Encoding.ASCII.GetBytes(_ca.ChainPem)));

        Assert.Equal(issued.Thumbprint, _store.Removed);
        Assert.NotNull(await _pending.GetAsync(Site));
        Assert.Empty(_managed);
    }

    [Fact]
    public async Task Import_OverACertificateSslenseRenews_NeedsForce()
    {
        _managed.Add(new ManagedCertificate(Site, ["shop.example.com"], "a@example.com", "AABB",
            DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(50), AuthorityId: CertificateAuthorities.LetsEncryptId));
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com");
        using (certificate)
        using (key)
        {
            var pfx = _ca.ExportPfx(certificate, key, "secret");

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                CreateService().ImportPfxAsync(Site, [], pfx, "secret"));

            Assert.Contains("--force", exception.Message, StringComparison.Ordinal);
            Assert.Null(_store.Added);
        }
    }

    [Fact]
    public async Task Import_Pfx_DefaultsToTheSiteHostsTheCertificateCovers()
    {
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com", "other.example.com");
        using (certificate)
        using (key)
        {
            var pfx = _ca.ExportPfx(certificate, key, "secret");

            var result = await CreateService().ImportPfxAsync(Site, [], pfx, "secret");

            Assert.Equal(["shop.example.com"], result.Certificate.Hosts);
            Assert.Equal(certificate.Thumbprint, _store.ImportedPfxThumbprint);
        }
    }

    [Fact]
    public async Task Adopt_RecordsTheBoundCertificateWithoutChangingIis()
    {
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com");
        using (certificate)
        using (key)
        {
            _store.Installed[certificate.Thumbprint] = new InstalledCertificate(
                certificate.Thumbprint, certificate.NotBefore, certificate.NotAfter, true, IssuerName: "Sectigo RSA DV");
            _iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync([new IisSite(1, Site, "Started", @"C:\inetpub\shop", [
                    new IisBinding("https", "*", 443, "shop.example.com", certificate.Thumbprint, "My", true)
                ])]);

            var record = await CreateService().AdoptAsync(Site);

            Assert.Equal(CertificateSource.Imported, record.Source);
            Assert.Equal("Sectigo RSA DV", record.Issuer);
            Assert.Equal(["shop.example.com"], record.Hosts);
            _iis.Verify(value => value.ConfigureHttpsBindingsAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        }
    }

    [Fact]
    public async Task CancelRequest_DeletesTheKey()
    {
        var service = CreateService();
        var request = await service.CreateRequestAsync(Site, ["shop.example.com"]);

        await service.CancelRequestAsync(Site);

        Assert.Null(_keys.Open(request.KeyName));
        Assert.Null(await _pending.GetAsync(Site));
    }

    public void Dispose()
    {
        foreach (var request in _pending.GetAllAsync().GetAwaiter().GetResult())
        {
            _keys.Delete(request.KeyName);
        }

        foreach (var keyName in _store.KeyNamesToDelete)
        {
            _keys.Delete(keyName);
        }

        _ca.Dispose();
    }

    private ImportedCertificateService CreateService()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => _managed.ToArray());
        managed.Setup(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .Callback<ManagedCertificate, CancellationToken>((record, _) =>
            {
                _managed.RemoveAll(value => value.SiteName == record.SiteName);
                _managed.Add(record);
            })
            .Returns(Task.CompletedTask);
        return new ImportedCertificateService(
            _iis.Object, _store, managed.Object, _pending, _keys,
            new NoOpCertificateOperationLock(), new NoOpCertificateTransactionJournal(),
            trustedRootsForTesting: [_ca.Root]);
    }

    /// <summary>Records what would be written to LocalMachine\My and \CA, without touching them.</summary>
    private sealed class FakeCertificateStore : ICertificateStore
    {
        public Dictionary<string, InstalledCertificate> Installed { get; } = new(StringComparer.OrdinalIgnoreCase);
        public string? Added { get; private set; }
        public bool AddedWithPrivateKey { get; private set; }
        public string? ImportedPfxThumbprint { get; private set; }
        public string? Removed { get; private set; }
        public List<string> Intermediates { get; } = [];
        public List<string> KeyNamesToDelete { get; } = [];

        public Task<InstalledCertificate?> FindByThumbprintAsync(string thumbprint, CancellationToken cancellationToken = default) =>
            Task.FromResult(Installed.GetValueOrDefault(thumbprint));

        public Task<X509Certificate2?> OpenAsync(string thumbprint, CancellationToken cancellationToken = default) =>
            Task.FromResult<X509Certificate2?>(null);

        public Task<InstalledCertificate> ImportPfxAsync(byte[] pfxBytes, string password, string friendlyName, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<InstalledCertificate> ImportPfxWithChainAsync(byte[] pfxBytes, string password, string friendlyName, CancellationToken cancellationToken = default)
        {
            using var certificate = X509CertificateLoader.LoadPkcs12(pfxBytes, password, X509KeyStorageFlags.EphemeralKeySet);
            Added = ImportedPfxThumbprint = certificate.Thumbprint;
            return Task.FromResult(new InstalledCertificate(certificate.Thumbprint, certificate.NotBefore, certificate.NotAfter, true));
        }

        public Task<InstalledCertificate> AddAsync(X509Certificate2 certificateWithKey, string friendlyName, CancellationToken cancellationToken = default)
        {
            Added = certificateWithKey.Thumbprint;
            AddedWithPrivateKey = certificateWithKey.HasPrivateKey;
            return Task.FromResult(new InstalledCertificate(
                certificateWithKey.Thumbprint, certificateWithKey.NotBefore, certificateWithKey.NotAfter, certificateWithKey.HasPrivateKey));
        }

        public Task AddIntermediatesAsync(IReadOnlyList<X509Certificate2> intermediates, CancellationToken cancellationToken = default)
        {
            Intermediates.AddRange(intermediates.Select(value => value.Thumbprint));
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string thumbprint, CancellationToken cancellationToken = default)
        {
            Removed = thumbprint;
            return Task.CompletedTask;
        }
    }
}
