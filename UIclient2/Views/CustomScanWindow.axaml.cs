using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net;
using System;
using System.Text.RegularExpressions;
using UIclient2.ViewModels;

namespace UIclient2.Views
{
    public class IpData
    {
        public string ip { get; set; }
    }

    public partial class CustomScanWindow : Window
    {
        public CustomScanWindow()
        {
            InitializeComponent();
            DataContext = new CustomScanWindowViewModel(this);
        }

        public void Submit_Click(object sender, RoutedEventArgs e)
        {
            string input = ScanTextBox.Text;
            if (string.IsNullOrEmpty(input) || (!IsIp(input) && !IsUrl(input)))
            {
                ShowErrorMessage("Invalid input...", "Red");
                return;
            }

            if (IsIp(input))
            {
                ProcessSingleIp(input);
            }
            else if (IsUrl(input))
            {
                ProcessUrl(input);
            }

            ScanTextBox.Text = string.Empty;
        }

        private void ShowErrorMessage(string message, string color)
        {
            invalidTextBlock.IsVisible = true;
            invalidTextBlock.Text = message;
            invalidTextBlock.Foreground = color == "Red" ? Avalonia.Media.Brushes.Red : Avalonia.Media.Brushes.Green;
        }

        private void ProcessSingleIp(string input)
        {
            IpData data = new IpData { ip = input };
            string json = JsonConvert.SerializeObject(data);
            Communication.SendMSG(112, json);

            string respJson = Communication.GetMSG();
           
            var respStruct = JsonConvert.DeserializeObject<Structs.IpScanResponse>(respJson.Substring(7));
            if (respStruct.res == 1)
            {
                invalidTextBlock.IsVisible = false;
                ResultsScanWindow resultsScanWindow = new ResultsScanWindow(new[] { input });
                resultsScanWindow.Show();
            }
            else
            {
                ShowErrorMessage("Everything is clean!", "Green");
            }
        }

        private void ProcessUrl(string input)
        {
            List<string> ips = ExtractIPAddressesFromURL(input);
            List<string> results = new List<string>();
            foreach (string ip in ips)
            {
                IpData data = new IpData { ip = ip };
                string json = JsonConvert.SerializeObject(data);
                Communication.SendMSG(112, json);

                string respJson = Communication.GetMSG();
            
                var respStruct = JsonConvert.DeserializeObject<Structs.IpScanResponse>(respJson.Substring(7));
                if (respStruct.res == 1)
                {
                    results.Add(ip);
                }
            }

            if (results.Count > 0)
            {
                invalidTextBlock.IsVisible = false;
                ResultsScanWindow resultsScanWindow = new ResultsScanWindow(results.ToArray());
                resultsScanWindow.Show();
            }
            else
            {
                ShowErrorMessage("Everything is clean!", "Green");
            }
        }

        private bool IsIp(string str)
        {
            string pattern = @"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
            Regex regex = new Regex(pattern);
            return regex.IsMatch(str);
        }

        private bool IsUrl(string str)
        {
            Uri uriResult;
            return Uri.TryCreate(str, UriKind.Absolute, out uriResult) && 
                   (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
        }

        private List<string> ExtractIPAddressesFromURL(string url)
        {
            List<string> ipAddresses = new List<string>();
            Uri uri;
            if (Uri.TryCreate(url, UriKind.Absolute, out uri))
            {
                string host = uri.Host;
                IPAddress[] addresses = Dns.GetHostAddresses(host);
                foreach (IPAddress address in addresses)
                {
                    if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        ipAddresses.Add(address.ToString());
                    }
                }
            }
            return ipAddresses;
        }
    }
}
