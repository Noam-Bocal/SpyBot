using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using UIclient2.ViewModels;
using UIclient2.Views;

namespace UIclient2
{
    public partial class App : Application
    {
        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                Communication communication = new Communication();
                var mainWindow = new MainWindow();
                desktop.MainWindow = mainWindow;

            }

            base.OnFrameworkInitializationCompleted();
        }
    }
}