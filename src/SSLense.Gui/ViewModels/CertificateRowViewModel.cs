using SSLense.Core.Acme;
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
        Environment = status.IsTestAuthority ? "Staging" : "Production";

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
            Status = "Renew soon";
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

    public string Status { get; }

    public string StatusKey { get; }
}
