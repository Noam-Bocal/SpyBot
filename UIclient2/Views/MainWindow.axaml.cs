using Avalonia.Controls;
using Avalonia.Interactivity;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UIclient2.ViewModels;

namespace UIclient2.Views
{
    public class YaraData
    {
        public string pathToYara { get; set; } = "python3 \"/home/noam/implementations/yara_scanner/yara_main.py";
        public string pathToScan { get; set; }
        public string scanType { get; set; }
        public string recursive { get; set; }
    }

    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainWindowViewModel(this);
        }

        public async void QuickScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string[] final_results;
                string[] results1 = await Task.Run(() => yara_scan("/tmp", "--scan-dir", "--recursive"));
                string[] results2 = await Task.Run(() => yara_scan("/var/tmp", "--scan-dir", "--recursive"));
                string[] results3 = await Task.Run(() => yara_scan("/usr/share/applications", "--scan-dir", "--recursive"));
                string[] results4 = await Task.Run(() => yara_scan("/home/noam/.cache", "--scan-dir", "--recursive"));
                string[] results5 = await Task.Run(() => yara_scan("/home/noam", "--scan-dir", ""));

                final_results = results1.Concat(results2).Concat(results3).Concat(results4).Concat(results5).ToArray();

                ResultsScanWindow resultsScanWindow = new ResultsScanWindow(final_results);
                resultsScanWindow.Show();
            }
            catch (Exception ex)
            {
                // Handle any exceptions
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public async void FullScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string[] results = await Task.Run(() => yara_scan("/home", "--scan-dir", "--recursive"));
                ResultsScanWindow resultsScanWindow = new ResultsScanWindow(results);
                resultsScanWindow.Show();
            }
            catch (Exception ex)
            {
                // Handle any exceptions
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private string[] yara_scan(string path, string scan_type, string recursive)
        {
            List<string> results = new List<string>();

            YaraData data = new YaraData { pathToScan = path, scanType = scan_type, recursive = recursive };
            string json = JsonConvert.SerializeObject(data);
            Communication.SendMSG(100, json);

            string respJson = Communication.GetMSG();

            var respStruct = JsonConvert.DeserializeObject<Structs.ScanResponse>(respJson.Substring(7));
            foreach (var entry in respStruct.procInfo)
            {
                string fileName = entry.Key;
                if(entry.Value == 1)
                {
                    string status = "Malicious";
                    results.Add(fileName + " - " + status);
                }
            }
            return results.ToArray();
        }
    }
}
