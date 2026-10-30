using SSLense.Core.Certificates;

namespace SSLense.Gui.ViewModels;

public sealed record KeyTypeOption(string Id, string Label);

public sealed class PendingRequestRowViewModel(PendingCertificateRequest request)
{
    public PendingCertificateRequest Request { get; } = request;
    public string SiteName => Request.SiteName;
    public string Hosts => string.Join(", ", Request.Hosts);
    public string KeyType => Request.KeyType;
    public DateTime Created => Request.CreatedAt.LocalDateTime;
    public int AgeDays => Math.Max(0, (int)(DateTimeOffset.UtcNow - Request.CreatedAt).TotalDays);
}

public sealed class DiscoveredBindingRowViewModel(DiscoveredBinding binding)
{
    public DiscoveredBinding Binding { get; } = binding;
    public string SiteName => Binding.SiteName;
    public string Address => $"{(Binding.Host.Length == 0 ? "(no host name)" : Binding.Host)}:{Binding.Port}";
    public string Issuer => Binding.Thumbprint is null ? "No certificate" : Binding.IssuerName ?? "Unknown";
    public DateTime? Expires => Binding.NotAfter?.LocalDateTime;
    public string Managed => Binding.IsManaged ? "Managed" : string.Empty;
    public bool CanAdopt => Binding.Thumbprint is not null && !Binding.IsManaged;
}
