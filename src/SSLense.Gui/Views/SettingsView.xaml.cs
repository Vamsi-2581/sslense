using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

/// <summary>
/// PasswordBox cannot be data-bound, so secrets are passed to the view model here, and the boxes are cleared
/// once the view model clears its copy after saving.
/// </summary>
public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private SettingsViewModel? ViewModel => DataContext as SettingsViewModel;

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is SettingsViewModel oldViewModel) oldViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        if (e.NewValue is SettingsViewModel newViewModel) newViewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (ViewModel is not { } vm) return;
        if (e.PropertyName == nameof(SettingsViewModel.EmailPassword) && vm.EmailPassword.Length == 0) EmailPasswordBox.Clear();
        if (e.PropertyName == nameof(SettingsViewModel.NewChatUrl) && vm.NewChatUrl.Length == 0) ChatUrlBox.Clear();
        if (e.PropertyName == nameof(SettingsViewModel.HeartbeatUrl) && vm.HeartbeatUrl.Length == 0) HeartbeatUrlBox.Clear();
    }

    private void OnEmailPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.EmailPassword = EmailPasswordBox.Password;
    }

    private void OnChatUrlChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.NewChatUrl = ChatUrlBox.Password;
    }

    private void OnHeartbeatUrlChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.HeartbeatUrl = HeartbeatUrlBox.Password;
    }
}
