using System.Collections.Generic;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using UIclient2.ViewModels;
using Newtonsoft.Json;
using System;
using System.Threading.Tasks;
using Avalonia.Threading;
using System.Security.Cryptography.X509Certificates;
using Avalonia.VisualTree;
using Avalonia.Controls.Templates;

namespace UIclient2.Views
{
    public class DriverData
    {
        public int pid { get; set; }
    }

    public class UpdateTableData
    {
        public int pid;
        public string dateTime;
        public string action;
    }
    public partial class ArchivesWindow : Window
    {
        public ArchivesWindow()
        {
            InitializeComponent();
            DataContext = new ArchivesWindowViewModel(this);
        }

        private void OpenMenu_Click(object sender, RoutedEventArgs e)
        {
            var button = (Button)sender;
            var menu = new ContextMenu();

            var menuItem1 = new MenuItem { Header = "Free" };
            menuItem1.Click += (s, args) => HandleMenuAction("Free", button);

            var menuItem2 = new MenuItem { Header = "Kill" };
            menuItem2.Click += (s, args) => HandleMenuAction("Kill", button);

            menu.Items.Add(menuItem1);
            menu.Items.Add(menuItem2);

            button.ContextMenu = menu;
            button.ContextMenu.Open(button);
        }

        private async void HandleMenuAction(string action, Button btn)
        {
            
            int pid = int.Parse(((KeyValuePair<string, string>)btn.DataContext).Value);
            try
            {
                await Task.Run(() =>
                {
                    int isWorked = 0;
                    if (action == "Free")
                    {
                        DriverData data = new DriverData { pid = pid };
                        string json = JsonConvert.SerializeObject(data);
                        Communication.SendMSG(105, json);
                        string respJson = Communication.GetMSG();
                        var respStruct = JsonConvert.DeserializeObject<Structs.FreeResponse>(respJson.Substring(7));
                        isWorked = respStruct.isWorked;
                    }
                    else if (action == "Kill")
                    {
                        DriverData data = new DriverData { pid = pid };
                        string json = JsonConvert.SerializeObject(data);
                        Communication.SendMSG(107, json);
                        string respJson = Communication.GetMSG();
                        var respStruct = JsonConvert.DeserializeObject<Structs.KillResponse>(respJson.Substring(7));
                        isWorked = respStruct.isWorked;
                    }
                    if(isWorked == 1)
                    {
                        btn.Content = action;
                        //send a request to the backend to remove those pids from the table
                        UpdateTableData updateTableData = new UpdateTableData { pid = pid, action = "remove", dateTime = DateTime.Now.ToString() };
                        string json2 = JsonConvert.SerializeObject(updateTableData);
                        Communication.SendMSG(103, json2);
                        string respJson2 = Communication.GetMSG();
                        var respStruct2 = JsonConvert.DeserializeObject<Structs.UpdateBlockedTableResponse>(respJson2.Substring(7));
                    }
                });
            }
            catch (Exception ex)
            {
            }
        }
    }
}
