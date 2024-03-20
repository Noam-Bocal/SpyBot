using ReactiveUI;
using System.Collections.ObjectModel;

namespace UIclient2.ViewModels
{
    public class ResultsWindowViewModel : ViewModelBase
    {
        private ObservableCollection<string> _scanResults;
        private bool _isScanResultsVisible;
        private bool _isResultBoxVisible;

        public ObservableCollection<string> ScanResults
        {
            get => _scanResults;
            private set => this.RaiseAndSetIfChanged(ref _scanResults, value);
        }

        public bool IsScanResultsVisible
        {
            get => _isScanResultsVisible;
            private set => this.RaiseAndSetIfChanged(ref _isScanResultsVisible, value);
        }

        public bool IsResultBoxVisible
        {
            get => _isResultBoxVisible;
            private set => this.RaiseAndSetIfChanged(ref _isResultBoxVisible, value);
        }

        public ResultsWindowViewModel(string[] result)
        {
            ScanResults = new ObservableCollection<string>(result);
            IsScanResultsVisible = ScanResults.Count > 0;
            IsResultBoxVisible = !IsScanResultsVisible;
        }
    }
}

