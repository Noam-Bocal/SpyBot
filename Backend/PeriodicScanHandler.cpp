#include "PeriodicScanHandler.h"
#include <cstdlib>

int PeriodicScanHandler::_time = 20; // Default value for time
string PeriodicScanHandler::_folder = "/home/noam/Desktop/implementations/periodic scan files"; // Default folder path
std::mutex PeriodicScanHandler::_lock;

string PeriodicScanHandler::handleRequest(RequestInfo reqInfo) {
    if(reqInfo.id == PERIODIC_SCAN_FOLDER_REQUEST)
        return changeFolder(reqInfo);
    else if(reqInfo.id == PERIODIC_SCAN_TIME_REQUEST)
        return changeTime(reqInfo);
    else if(reqInfo.id == GET_CURRENT_SCAN_FOLDER_REQUEST)
        return getFolder(reqInfo);
    else if(reqInfo.id == GET_CURRENT_SCAN_FREQUENCY_REQUEST)
        return getTime(reqInfo);
    else
        return "Invalid request";
}

string PeriodicScanHandler::changeTime(const RequestInfo& reqInfo) {
    ChangeScanTimeRequest request = JsonRequestPacketDeserializer::desirializeChangeScanTimeRequest(reqInfo.buffer);
    _time = request.time;

    ChangeScanTimeResponse resp;
    resp.isWorked = 1;
    resp.status = PERIODIC_SCAN_TIME_RESPONSE;
    
    return JsonResponsePacketSerializer::serializeResponse(resp);
}

string PeriodicScanHandler::changeFolder(const RequestInfo& reqInfo) {
    ChangeScanFolderRequest request = JsonRequestPacketDeserializer::desirializeChangeScanFolderRequest(reqInfo.buffer);
    _folder = request.folder;

    ChangeScanFolderResponse resp{PERIODIC_SCAN_FOLDER_RESPONSE, 1};
    return JsonResponsePacketSerializer::serializeResponse(resp);
}

string PeriodicScanHandler::getTime(const RequestInfo &reqInfo)
{
    GetTimeResponse resp{GET_CURRENT_SCAN_FREQUENCY_RESPONSE, _time};
    return JsonResponsePacketSerializer::serializeResponse(resp);
}

std::string PeriodicScanHandler::getFolder(const RequestInfo &reqInfo)
{
    GetFolderResponse resp{GET_CURRENT_SCAN_FOLDER_RESPONSE, _folder};
    return JsonResponsePacketSerializer::serializeResponse(resp);
}

void PeriodicScanHandler::periodicScan() {
    while (true) {        
        try {
            std::this_thread::sleep_for(std::chrono::seconds(_time));
            sctScan();
            idtScan();
            /*std::map<std::string, int> res = Helper::yaraCommunicator("python3 \"/home/noam/Desktop/implementations/yara_scanner/yara_main.py\"", "--scan-dir", _folder, "--recursive");
            for (auto &item : res) {
                if (item.second == 1) { // found a virus
                    time_t now = time(0); 
                    char* dt = ctime(&now);  
                    dt[strcspn(dt, "\n")] = '\0';  // Trim newline
                    string message = item.first + " - MALICIOUS";
                    bool updateRes = Helper::updateVirusTables(item.first);
                    writeToScanResults(string(dt) + " - " + message);
                    popUp(message);
                }
            }*/

            //packetScan();
            //portsConnectionsScan();
        } catch (const std::exception& e) {
            std::cout << "Error aaa during periodic scan: " + string(e.what()) << std::endl;
        }
    }
}

void PeriodicScanHandler::packetScan() {
    FILE* pipe = popen("sudo /bin/python3 /home/noam/Desktop/implementations/network_scanner/net_scan.py", "r");
    if (!pipe)
        throw std::runtime_error("Failed to open pipe...");    
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        const char* pidStart = strstr(buffer, "(PID: ");
        if (pidStart) {
            pidStart += strlen("(PID: ");
            const char* pidEnd = strchr(pidStart, ')');
            if (pidEnd) {
                string pidString(pidStart, pidEnd - pidStart);
                int pid = std::stoi(pidString);
                blockPid(pid);
                time_t now = time(0); 
                char* dt = ctime(&now);  
                dt[strcspn(dt, "\n")] = '\0';  // Trim newline
                string message = std::to_string(pid) + " Found communicating with malicious IP";
                bool updateRes = Helper::updateVirusTables(std::to_string(pid));
                writeToScanResults(string(dt) + " - " + message);
                popUp(message);                                
            }
        }
    }
    pclose(pipe);
}

void PeriodicScanHandler::blockPid(int pid){
    int fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        //perror("Failed to open the device file");
    }

	int args[2] = {1, 0};
	int result = 0;
	//send the action and pid
	ioctl(fd, SPYBOT_IOC_SEND, args);
	//get the result from the driver(success - 1, fail - 0);
	ioctl(fd, SPYBOT_IOC_RECV, &result);
    close(fd);
}

void PeriodicScanHandler::sctScan(){
    int fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        //perror("Failed to open the device file");
    }

	int args[2] = {3, 0};
	int result = 0;
	//send the action and pid
	ioctl(fd, SPYBOT_IOC_SEND, args);
	//get the result from the driver(success - 1, fail - 0);
	ioctl(fd, SPYBOT_IOC_RECV, &result);
    close(fd);
	if(result != -1){
        popUp("sct alert: " + std::to_string(result));
    }
    else{
        popUp("sct ok.");
    }
}

void PeriodicScanHandler::idtScan(){
    int fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        //perror("Failed to open the device file");
    }

	int args[2] = {5, 0};
	int result = 0;
	//send the action and pid
	ioctl(fd, SPYBOT_IOC_SEND, args);
	//get the result from the driver(success - 1, fail - 0);
	ioctl(fd, SPYBOT_IOC_RECV, &result);
    close(fd);
	if(result != -1){
        popUp("idt alert: " + std::to_string(result));
    }
    else{
        popUp("idt ok.");
    }
}

void PeriodicScanHandler::portsConnectionsScan() {
    FILE* pipe = popen("sudo /bin/python3 /home/noam/Desktop/implementations/network_scanner/scanner.py", "r+");
    if (!pipe)
        throw std::runtime_error("Failed to open pipe...");
    
    char buffer[128];
while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        string line(buffer); // Convert char array to string

        size_t pos = line.find_first_of(' '); // Find the first space character
        if (pos != string::npos) {
            string protocol = line.substr(0, pos); // Extract the protocol
            cout << protocol << endl;

            // Extract IP address
            pos = line.find_first_of('-');
            if (pos != string::npos) {
                string ip = line.substr(pos + 2, line.size() - pos - 3); // Trim newline
                time_t now = time(nullptr);
                char* dt = ctime(&now);
                dt[strcspn(dt, "\n")] = '\0'; // Trim newline
                string message = "Computer " + ip + " found sending suspicious amount of packets to port " + protocol;
                bool updateRes = Helper::updateVirusTables(ip);
                writeToScanResults(string(dt) + " - " + message);
                popUp(message);
            }
        }
    }

    
    pclose(pipe);
}

void PeriodicScanHandler::writeToScanResults(const string& message) {
    std::lock_guard<std::mutex> guard(_lock);
    std::ofstream outputFile("/home/noam/Desktop/implementations/Backend/periodic_scan_results.txt", std::ios::app);
    if (!outputFile.is_open()) {
        throw std::runtime_error("Failed to open output file...");
    }
    outputFile << message << endl;
    outputFile.close();
}

void PeriodicScanHandler::popUp(const std::string& message) {
    if (!notify_init("MyApp")) {
        throw std::runtime_error("Failed to initialize libnotify");
    }

    NotifyNotification *notification = notify_notification_new("Linux Defender", message.c_str(), "");

    // Connect the callback function to the "closed" signal of the notification
    g_signal_connect(notification, "closed", G_CALLBACK(notificationClosed), nullptr);


    if (!notify_notification_show(notification, nullptr)) {
        throw std::runtime_error("Failed to show notification");
    }

    g_object_unref(notification);
    notify_uninit();
}



void PeriodicScanHandler::notificationClosed(NotifyNotification *notification, gpointer data) {
    std::cout << "Notification closed" << std::endl;
}