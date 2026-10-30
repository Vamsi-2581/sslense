using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Renewal;

namespace SSLense.Gui.ViewModels;

public sealed class CertificateRowViewModel
{
    public CertificateRowViewModel(ManagedCertificateStatus status)
    {
        SiteName = status.SiteName;
        Hosts = string.Join(", ", status.Hosts);
        Expiry = status.NotAfter;
        DaysRemaining = status.DaysRemaining;
        Thumbprint = status.Thumbprint;
        IsImported = status.Source == CertificateSource.Imported;
        Environment = IsImported
            ? "Imported"
            : CertificateAuthorities.IsBuiltIn(status.AuthorityId)
                ? status.IsTestAuthority ? "Staging" : "Production"
                : status.AuthorityName;

        if (status.LastRenewalSucceeded == false)
        {
            Status = "Renewal failed";
            StatusKey = "Red";
        }
        else if (status.DaysRemaining < 0)
        {
            Status = "Expired";
            StatusKey = "Red";
        }
        else if (status.DaysRemaining <= 30)
        {
            // SSLense cannot renew an imported certificate; the administrator orders the next one.
            Status = IsImported ? "Order renewal" : "Renew soon";
            StatusKey = "Amber";
        }
        else
        {
            Status = "Healthy";
            StatusKey = "Green";
        }
    }

    public string SiteName { get; }

    public string Hosts { get; }

    public DateTimeOffset Expiry { get; }

    public int DaysRemaining { get; }

    public string Thumbprint { get; }

    public string Environment { get; }

    public bool IsImported { get; }

    public string Status { get; }

    public string StatusKey { get; }
}
