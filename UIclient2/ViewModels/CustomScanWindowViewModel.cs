using Avalonia.Controls;
using ReactiveUI;
using System;
using System.Reactive;
using System.Threading.Tasks;
using System.Net;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using UIclient2.Views;
using Newtonsoft.Json;
using Avalonia.Threading;
using MsBox.Avalonia;
using MsBox.Avalonia.Dto;
using MsBox.Avalonia.Enums;
using MsBox.Avalonia.Models;
using System.IO;
using System.Linq;

namespace UIclient2.ViewModels
{
    public class YaraData
    {
        public string pathToYara { get; set; } = "python3 \"/home/noam/Desktop/implementations/yara_scanner/yara_main.py";
        public string pathToScan { get; set; }
        public string scanType { get; set; }
        public string recursive { get; set; }
    }

    public class HashData
    {
        public List<string> hashes { get; set; }
    }

    public class SaveHash
    {
       
        public string fileName;
        public string filepath;
        public string hash;
        public string DateAdded;
        public bool encrypted = true;
        public string source = "Noam's Computer";
        public string isolationStatus = "Free";
        }
    public class CustomScanWindowViewModel : ViewModelBase
    {
        public string pathToYara = "python3 \"/home/noam/Desktop/implementations/yara_scanner/yara_main.py";
        private CustomScanWindow _customScanWindow;

        public ReactiveCommand<Unit, Unit> HomeCommand { get; }
        public ReactiveCommand<Unit, Unit> SettingsCommand { get; }
        public ReactiveCommand<Unit, Unit> ArchivesCommand { get; }
        public ReactiveCommand<Unit, Unit> ScanCommand { get; }

       

        public CustomScanWindowViewModel(CustomScanWindow customScanWindow)
        {
            _customScanWindow = customScanWindow;

            HomeCommand = ReactiveCommand.Create(() => {
                MainWindow mainWindow = new MainWindow();
                mainWindow.Show();
                _customScanWindow.Close();
            });

            SettingsCommand = ReactiveCommand.Create(() => {
                SettingsWindow settingsWindow = new SettingsWindow();
                settingsWindow.Show();
                _customScanWindow.Close();
            });

            ArchivesCommand = ReactiveCommand.Create(() => {
                ArchivesWindow archivesWindow = new ArchivesWindow();
                archivesWindow.Show();
                _customScanWindow.Close();
            });


            ScanCommand = ReactiveCommand.Create(ScanFiles);

        }


        public async void ScanFiles()
        {
            var dialog = new DialogView();
            var viewModel = new DialogViewModel();
            dialog.DataContext = viewModel;
            var window = new Window
            {
                Title = "Select File or Directory",
                Content = dialog,
                SizeToContent = SizeToContent.WidthAndHeight
            };
            viewModel.SelectionMade += async (sender, result) =>
            {
                if (result == "file")
                {
                    var openFileDialog = new OpenFileDialog
                    {
                        Title = "Select File",
                        Directory = ".",
                        AllowMultiple = false,
                    };
                    string[] filePaths = await openFileDialog.ShowAsync(window);
                    if (filePaths != null && filePaths.Length > 0)
                    {
                        string[] yara_results = await Task.Run(() => yara_scan(filePaths[0], "--scan-file", ""));
                        Dictionary<string,string> hash_results = await Task.Run(() => HashScan(filePaths));
                        string[] final_results = CompareResults(yara_results, hash_results);
                        ResultsScanWindow resultsScanWindow = new ResultsScanWindow(final_results);
                        resultsScanWindow.Show();
                    }
                }
                else
                {
                    var openFolderDialog = new OpenFolderDialog
                    {
                        Title = "Select Folder",
                        Directory = ".",
                    };
                    string folderPath = await openFolderDialog.ShowAsync(window);
                    if (!string.IsNullOrEmpty(folderPath))
                    {
                        string[] yaraResults = await Task.Run(() => yara_scan(folderPath, "--scan-dir", "--recursive"));
                        string[] files = GetFilesInFolder(folderPath);
                        Dictionary<string, string> hashResults = await Task.Run(() => HashScan(files));
                        string[] final_results = CompareResults(yaraResults, hashResults);
                        ResultsScanWindow resultsScanWindow = new ResultsScanWindow(final_results);
                        resultsScanWindow.Show();
                    }
                }
                window.Close();
            };

            window.ShowDialog(_customScanWindow);
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
                string status = (entry.Value == 1) ? "Malicious" : "Clear";
                results.Add(fileName + " - " + status);
            }
            return results.ToArray();
        }

        private Dictionary<string, string> HashScan(string[] paths)
        {
            Dictionary<string, string> results = new Dictionary<string, string>();
            List<string> hashes = new List<string>();

            for (int i = 0; i < paths.Length; i++)
                hashes.Add(Communication.HashFile(paths[i]));

            HashData data = new HashData { hashes = hashes };
            string json = JsonConvert.SerializeObject(data);
            Communication.SendMSG(113, json);

            var respJson = Communication.GetMSG();
            var respStruct = JsonConvert.DeserializeObject<Structs.HashScanResponse>(respJson.Substring(7));

            for (int i = 0; i < respStruct.res.Count; i++)
            {
                results.Add(hashes[i], (respStruct.res[i] == 1) ? "Malicious" : "Clear");
            }
            return results;
        }



       



        private string[] CompareResults(string[] yaraResults, Dictionary<string, string> hashResults)
        {
            string[] results = new string[yaraResults.Length];

            for (int i = 0; i < yaraResults.Length; i++)
            {
                string hashFile = yaraResults[i].Split(" - ")[0];
                if (yaraResults[i].Contains("Malicious") && hashResults[Communication.HashFile(hashFile)] == "Clear")
                {
                    // Get the hash value from hashResults using the file name as the key
                    string hashValue = Communication.HashFile(hashFile);
                    SaveHash data = new SaveHash
                    {
                        fileName = "File",
                        filepath = yaraResults[i].Split(" - ")[0],
                        hash = hashValue,
                        DateAdded = DateTime.Now.ToString(), // Add the current date/time
                        encrypted = true,
                        source = "Noam's Computer",
                        isolationStatus = "Free"
                    };
                    // Save the hash data or perform other actions as needed
                    string json = JsonConvert.SerializeObject(data);
                    Communication.SendMSG(115, json);

                    var respJson = Communication.GetMSG();
                    var respStruct = JsonConvert.DeserializeObject<Structs.SaveHashResponse>(respJson.Substring(7));

                }
                // Check if both YARA and hash results indicate the file as malicious
                if (yaraResults[i].Contains("Malicious") && hashResults.FirstOrDefault().Value == "Malicious")
                {
                    results[i] = yaraResults[i]; // Keep the YARA result
                }
                // Check if either YARA or hash result indicates the file as malicious
                else if (yaraResults[i].Contains("Malicious") || hashResults.FirstOrDefault().Value == "Malicious")
                {
                    results[i] = yaraResults[i].Split(" - ")[0] + " - Malicious";
                }
                else
                {
                    results[i] = yaraResults[i].Split(" - ")[0] + " - Clear";
                }
            }

            return results;
        }



        private string[] GetFilesInFolder(string folderPath)
        {
            List<string> filePaths = new List<string>();

            if (Directory.Exists(folderPath))
            {
                filePaths.AddRange(Directory.GetFiles(folderPath));

                // Recursively search subfolders
                string[] subfolders = Directory.GetDirectories(folderPath);
                foreach (string subfolder in subfolders)
                {
                    filePaths.AddRange(GetFilesInFolder(subfolder));
                }
            }

            return filePaths.ToArray();
        }
    }
}
