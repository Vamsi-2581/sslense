using SSLense.Core.Iis;

namespace SSLense.Gui.ViewModels;

/// <param name="HttpsSummary">The certificates the site already serves over HTTPS, when it has any.</param>
public sealed record IisSiteOption(string Name, IisSite Site, string? HttpsSummary = null)
{
    public string DisplayName => HttpsSummary is null ? Name : $"{Name}  (HTTPS enabled)";

    public bool HasHttps => HttpsSummary is not null;
}
