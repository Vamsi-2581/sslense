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
    private readonly RecordingLock _lock = new();
    private readonly JsonCertificateTransactionJournal _journal;

    public ImportedCertificateServiceTests()
    {
        _pending = new JsonPendingRequestStore(_files, @"C:\data\pending-requests.json", @"C:\data\pending-requests.lock");
        _journal = new JsonCertificateTransactionJournal(_files, @"C:\data\transactions");
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
    public async Task Import_BindingRolledBack_KeepsACertificateThatWasAlreadyInstalled()
    {
        _iis.Setup(value => value.ConfigureHttpsBindingsAsync(Site, It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), "My", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new IisBindingException("HTTPS verification failed", previousBindingsRestored: true, new InvalidOperationException()));
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com");
        using (certificate)
        using (key)
        {
            // Already in LocalMachine\My, for example bound to another site.
            _store.Installed[certificate.Thumbprint] = new InstalledCertificate(certificate.Thumbprint, certificate.NotBefore, certificate.NotAfter, true);

            await Assert.ThrowsAsync<IisBindingException>(() =>
                CreateService().ImportPfxAsync(Site, [], _ca.ExportPfx(certificate, key, "secret"), "secret"));

            Assert.Null(_store.Removed);
        }
    }

    [Fact]
    public async Task Import_FailingBeforeInstall_LeavesNothingForRecoveryToFinish()
    {
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com");
        using (certificate)
        using (key)
        {
            // Already installed for another site, so recovery would find it in the store.
            _store.Installed[certificate.Thumbprint] = new InstalledCertificate(certificate.Thumbprint, certificate.NotBefore, certificate.NotAfter, true);
            _store.FailIntermediates = true;

            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                CreateService().ImportPfxAsync(Site, [], _ca.ExportPfx(certificate, key, "secret"), "secret"));

            Assert.Empty(await _journal.GetPendingAsync());
            Assert.Null(_store.Removed);
        }
    }

    [Fact]
    public async Task Complete_Succeeding_CompletesItsJournalEntry()
    {
        var service = CreateService();
        var request = await service.CreateRequestAsync(Site, ["shop.example.com"]);
        using var issued = _ca.Issue(request.CsrPem);

        await service.CompleteRequestAsync(Site, issued.RawData, Encoding.ASCII.GetBytes(_ca.ChainPem));

        Assert.Empty(await _journal.GetPendingAsync());
    }

    [Fact]
    public async Task CancelOrReplaceRequest_WhoseCertificateIsAlreadyInstalled_KeepsTheKey()
    {
        // As after a completion interrupted between installing and removing the request, then recovered.
        var service = CreateService();
        var request = await service.CreateRequestAsync(Site, ["shop.example.com"]);
        _store.KeyNamesToDelete.Add(request.KeyName);
        using var issued = _ca.Issue(request.CsrPem);
        _store.Certificates[issued.Thumbprint] = issued.RawData;
        _managed.Add(new ManagedCertificate(Site, ["shop.example.com"], "", issued.Thumbprint, issued.NotBefore, issued.NotAfter,
            Source: CertificateSource.Imported));

        var replacement = await service.CreateRequestAsync(Site, ["shop.example.com"]);
        Assert.NotNull(_keys.Open(request.KeyName));

        await service.CancelRequestAsync(Site);
        Assert.Null(_keys.Open(replacement.KeyName));
        Assert.NotNull(_keys.Open(request.KeyName));
    }

    [Fact]
    public async Task RequestLifecycle_RunsUnderTheSiteLock()
    {
        var service = CreateService();
        var request = await service.CreateRequestAsync(Site, ["shop.example.com"]);
        using var issued = _ca.Issue(request.CsrPem);
        await service.CompleteRequestAsync(Site, issued.RawData, Encoding.ASCII.GetBytes(_ca.ChainPem));
        await service.CreateRequestAsync(Site, ["shop.example.com"]);
        await service.CancelRequestAsync(Site);

        // One acquisition per operation; RecordingLock also fails on any nested acquisition.
        Assert.Equal([Site, Site, Site, Site], _lock.Acquisitions);
    }

    [Fact]
    public async Task Import_CertificateWithoutKey_ExplainsThatAPfxIsNeeded()
    {
        var (certificate, key) = _ca.IssueWithNewKey("shop.example.com");
        using (certificate)
        using (key)
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                CreateService().ImportPfxAsync(Site, [], certificate.RawData, ""));

            Assert.Contains("without its private key", exception.Message, StringComparison.Ordinal);
            Assert.Contains("export the certificate with its private key as a PFX", exception.Message, StringComparison.Ordinal);
            Assert.Null(_store.Added);
        }
    }

    [Fact]
    public async Task Import_CertificateForAPendingRequest_PointsToComplete()
    {
        var service = CreateService();
        var request = await service.CreateRequestAsync(Site, ["shop.example.com"]);
        using var issued = _ca.Issue(request.CsrPem);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.ImportPfxAsync(Site, [], Encoding.ASCII.GetBytes(issued.ExportCertificatePem()), ""));

        Assert.Contains("pending request of IIS site 'Shop'", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Complete a request", exception.Message, StringComparison.Ordinal);
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
    public async Task Adopt_BindingOnAnotherPort_IsRefused()
    {
        _iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new IisSite(1, Site, "Started", @"C:\inetpub\shop", [
                new IisBinding("https", "*", 443, "shop.example.com", "AABB", "My", true),
                new IisBinding("https", "*", 8443, "shop.example.com", "AABB", "My", true)
            ])]);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateService().AdoptAsync(Site));

        Assert.Contains("shop.example.com:8443", exception.Message, StringComparison.Ordinal);
        Assert.Contains("port 443 only", exception.Message, StringComparison.Ordinal);
        Assert.Empty(_managed);
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
            _lock, _journal,
            trustedRootsForTesting: [_ca.Root]);
    }

    /// <summary>Records each acquisition and fails if one is attempted while the lock is held (it is not reentrant).</summary>
    private sealed class RecordingLock : ICertificateOperationLock
    {
        private bool _held;

        public List<string> Acquisitions { get; } = [];

        public Task<IAsyncDisposable> AcquireAsync(string siteName, CancellationToken cancellationToken = default)
        {
            Assert.False(_held, $"The lock for '{siteName}' was acquired while already held.");
            _held = true;
            Acquisitions.Add(siteName);
            return Task.FromResult<IAsyncDisposable>(new Scope(this));
        }

        public IAsyncDisposable? TryAcquire(string siteName) => throw new NotSupportedException();

        private sealed class Scope(RecordingLock owner) : IAsyncDisposable
        {
            public ValueTask DisposeAsync()
            {
                owner._held = false;
                return ValueTask.CompletedTask;
            }
        }
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
        public bool FailIntermediates { get; set; }

        /// <summary>Public certificates present in the store, as <see cref="OpenAsync"/> returns them.</summary>
        public Dictionary<string, byte[]> Certificates { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Task<InstalledCertificate?> FindByThumbprintAsync(string thumbprint, CancellationToken cancellationToken = default) =>
            Task.FromResult(Installed.GetValueOrDefault(thumbprint));

        public Task<X509Certificate2?> OpenAsync(string thumbprint, CancellationToken cancellationToken = default) =>
            Task.FromResult(Certificates.TryGetValue(thumbprint, out var raw) ? X509CertificateLoader.LoadCertificate(raw) : null);

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
            Certificates[certificateWithKey.Thumbprint] = certificateWithKey.RawData;
            // The completed request's key now belongs to the certificate; the test deletes it afterwards.
            if (certificateWithKey.GetRSAPrivateKey() is RSACng { Key.KeyName: { } keyName }) KeyNamesToDelete.Add(keyName);
            return Task.FromResult(new InstalledCertificate(
                certificateWithKey.Thumbprint, certificateWithKey.NotBefore, certificateWithKey.NotAfter, certificateWithKey.HasPrivateKey));
        }

        public Task AddIntermediatesAsync(IReadOnlyList<X509Certificate2> intermediates, CancellationToken cancellationToken = default)
        {
            if (FailIntermediates) throw new OperationCanceledException();
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
