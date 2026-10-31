using System.Windows;
using System.Windows.Controls;
using SSLense.Gui.ViewModels;

namespace SSLense.Gui.Views;

/// <summary>
/// Keeps the log readable while it updates: it stays at the newest entry unless the reader scrolled up, and live updates
/// pause while text is selected so a selection is never lost before it is copied.
/// </summary>
public partial class LogsView : UserControl
{
    private bool _followNewest = true;

    public LogsView()
    {
        InitializeComponent();
    }

    private LogsViewModel? ViewModel => DataContext as LogsViewModel;

    private void OnLogSelectionChanged(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { } vm) vm.HoldUpdates = LogText.SelectionLength > 0;
    }

    private void OnLogTextChanged(object sender, TextChangedEventArgs e)
    {
        if (_followNewest) LogText.ScrollToEnd();
    }

    private void OnLogScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        // Only a scroll by the reader changes this; growth of the text alone does not.
        if (e.ExtentHeightChange == 0)
        {
            _followNewest = e.VerticalOffset + e.ViewportHeight >= e.ExtentHeight - 2;
        }
    }

    private async void OnClearLogClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm) return;
        var answer = MessageBox.Show(
            "Clear today's log? Its current entries are saved as a backup, which you can still open from the File list.",
            "Clear log",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (answer == MessageBoxResult.Yes) await vm.ClearLogCommand.ExecuteAsync(null);
    }
}
