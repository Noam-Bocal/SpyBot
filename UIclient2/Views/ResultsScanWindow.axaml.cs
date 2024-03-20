using Avalonia.Controls;
using UIclient2.ViewModels;

namespace UIclient2;

public partial class ResultsScanWindow : Window
{
    public ResultsScanWindow(string[] result)
    {
        InitializeComponent();
        DataContext = new ResultsWindowViewModel(result);
    }
}