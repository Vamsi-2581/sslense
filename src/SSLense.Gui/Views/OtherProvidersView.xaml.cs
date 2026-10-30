using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

/// <summary>
/// File dialogs, the clipboard, and confirmations live here; the PFX password is passed to the view model because
/// PasswordBox cannot be data-bound, and the box is cleared once the view model clears its copy after an import.
/// </summary>
public partial class OtherProvidersView : UserControl
{
    private const string CertificateFilter = "Certificates (*.crt;*.cer;*.pem;*.ca-bundle)|*.crt;*.cer;*.pem;*.ca-bundle|All files (*.*)|*.*";

    public OtherProvidersView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private OtherProvidersViewModel? ViewModel => DataContext as OtherProvidersViewModel;

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is OtherProvidersViewModel oldViewModel) oldViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        if (e.NewValue is OtherProvidersViewModel newViewModel) newViewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(OtherProvidersViewModel.PfxPassword) && ViewModel?.PfxPassword.Length == 0) PfxPasswordBox.Clear();
        // The banners are at the top of a long page; without this, an outcome of an action further down goes unseen.
        if (e.PropertyName == nameof(OtherProvidersViewModel.ErrorMessage) && ViewModel?.ErrorMessage is not null) ShowBanner(ErrorBannerBorder);
        if (e.PropertyName == nameof(OtherProvidersViewModel.ResultMessage) && ViewModel?.ResultMessage is not null) ShowBanner(ResultBannerBorder);
    }

    private void ShowBanner(FrameworkElement banner) =>
        Dispatcher.BeginInvoke(() => banner.BringIntoView(), System.Windows.Threading.DispatcherPriority.Loaded);

    private void OnPfxPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.PfxPassword = PfxPasswordBox.Password;
    }

    private void OnCopyCsrClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.SelectedCsr is { } csr) Clipboard.SetText(csr);
    }

    private async void OnSaveCsrClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm) return;
        var dialog = new SaveFileDialog
        {
            FileName = vm.SuggestedCsrFileName,
            Filter = "Certificate request (*.csr)|*.csr|All files (*.*)|*.*",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };
        if (dialog.ShowDialog() == true) await vm.SaveCsrAsync(dialog.FileName);
    }

    private void OnBrowseCertificateClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && Browse(CertificateFilter) is { } path) vm.CertificatePath = path;
    }

    private void OnBrowseChainClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && Browse(CertificateFilter) is { } path) vm.ChainPath = path;
    }

    private void OnBrowsePfxClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm && Browse("PFX files (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*") is { } path) vm.PfxPath = path;
    }

    private async void OnCancelRequestClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { SelectedPending: { } pending } vm) return;
        var answer = MessageBox.Show(
            $"Cancel the certificate request for '{pending.SiteName}'? Its private key is deleted, so a certificate the provider " +
            "issues for this request can no longer be installed.",
            "Confirm cancelling the request",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes) await vm.CancelRequestCommand.ExecuteAsync(null);
    }

    private static string? Browse(string filter)
    {
        var dialog = new OpenFileDialog { Filter = filter };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }
}
