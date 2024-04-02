using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Newtonsoft.Json;
using System.Collections.Generic;
using System;
using UIclient2.ViewModels;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace UIclient2;

public class TimeData
{
    public int time { get; set; }
}

public class FolderData
{
    public string folder { get; set; }
}
public partial class SettingsWindow : Window
{
    private string _currentFolderToScan;
    private int _time;
    public SettingsWindow()
    {
        InitializeComponent();
        DataContext = new SettingsWindowViewModel(this);      
        Communication.SendMSG(111, "");
        string responseJson = Communication.GetMSG();
        var responseStruct = JsonConvert.DeserializeObject<Structs.GetFolderResponse>(responseJson.Substring(7));
        _currentFolderToScan = responseStruct.folder;

        Communication.SendMSG(110, "");
        string respJson = Communication.GetMSG();
        _time = JsonConvert.DeserializeObject<Structs.GetTimeResponse>(respJson.Substring(7)).time;
        FrequencyTextBox.Watermark += _time.ToString();

    }
    public void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var openFolderDialog = new OpenFolderDialog
        {
            Title = "Select Folder",
            Directory = _currentFolderToScan,
        };

        var folderPath = openFolderDialog.ShowAsync(this);

        // Once the user has selected a folder, handle the result
        folderPath.ContinueWith(task =>
        {
            try
            {
                if (task.Status == TaskStatus.RanToCompletion && !string.IsNullOrEmpty(task.Result))
                {
                    string selectedFolder = task.Result;
                    FolderData data = new FolderData { folder = selectedFolder };
                    string json = JsonConvert.SerializeObject(data);
                    Communication.SendMSG(109, json);

                    string respJson = Communication.GetMSG();

                    var respStruct = JsonConvert.DeserializeObject<Structs.ChangeScanFolderResponse>(respJson.Substring(7));
                    if (respStruct.isWorked == 1)
                    {
                        _currentFolderToScan = selectedFolder;
                        ShowMessage("Successfully changed folder to scan :)\nWill be active after the next scan", "Green");
                    }

                }
                else
                {
                    // Handle the case where the user cancels or an error occurs
                    ShowMessage("Folder selection canceled or error occurred.", "Red");
                }
            }
            catch (Exception ex)
            {
                ShowMessage("Couldn't change the folder to scan :(\n" + ex.Message, "Red");
            }
        }, TaskScheduler.FromCurrentSynchronizationContext());
}

    public void Submit_Click(object sender, RoutedEventArgs e)
    {
        string input = FrequencyTextBox.Text;
        if(string.IsNullOrEmpty(input) || !IsNumber(input))
        {
            ShowMessage("Input must be a number!", "Red");
        }
        else
        {
            try
            {
                TimeData data = new TimeData { time = int.Parse(input) };
                string json = JsonConvert.SerializeObject(data);
                Communication.SendMSG(108, json);

                string respJson = Communication.GetMSG();
                var respStruct = JsonConvert.DeserializeObject<Structs.ChangeScanTimeResponse>(respJson.Substring(7));
                if (respStruct.isWorked == 1)
                {
                    ShowMessage("Successfully changed scan frequency :)\nWill be active after the next scan.", "Green");
                    FrequencyTextBox.Watermark = "Current Frequency: " + input;
                    FrequencyTextBox.Text = "";
                }
            }
            catch (Exception ex)
            {
                ShowMessage("Couldn't change scan frequency :(\n" + ex.Message, "Red");
            }
        }
    }

    private bool IsNumber(string s) {
        return double.TryParse(s, out _);
    }

    private void ShowMessage(string message, string color)
    {
        invalidTextBlock.IsVisible = true;
        invalidTextBlock.Text = message;
        invalidTextBlock.Foreground = color == "Red" ? Avalonia.Media.Brushes.Red : Avalonia.Media.Brushes.Green;

        var timer = new DispatcherTimer();
        timer.Interval = TimeSpan.FromSeconds(5);
        timer.Tick += (sender, e) =>
        {
            invalidTextBlock.IsVisible = false;
            timer.Stop();
        };
        timer.Start();
    }
}