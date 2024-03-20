#include "PeriodicScanHandler.h"

int PeriodicScanHandler::_time = 60; // Default value for time
string PeriodicScanHandler::_folder = "/home/noam/implementations/periodic scan files"; // Default folder path
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
            std::this_thread::sleep_for(std::chrono::minutes(_time));
            std::map<std::string, int> res = Helper::yaraCommunicator("python3 \"/home/noam/implementations/yara_scanner/yara_main.py\"", "--scan-dir", _folder, "--recursive");
            for (auto &item : res) {
                if (item.second == 1) { // found a virus
                    time_t now = time(0); 
                    char* dt = ctime(&now);  
                    dt[strcspn(dt, "\n")] = '\0';  // Trim newline
                    string message = string(dt) + " - " + item.first + " - MALICIOUS";
                    writeToScanResults(message);
                    popUp(message);
                    bool updateRes = Helper::updateVirusTables(item.first);
                }
            }
            //packetScan();
            //portsConnectionsScan();
        } catch (const std::exception& e) {
            std::cout << "Error during periodic scan: " + string(e.what()) << std::endl;
        }
    }
}

void PeriodicScanHandler::packetScan() {
    FILE* pipe = popen("sudo -S /bin/python3 /home/noam/implementations/network_scanner/net_scan.py", "r+");
    if (!pipe)
        throw std::runtime_error("Failed to open pipe...");
    string sudoPassword = "123456\n"; //add a request to ask from the user
    fwrite(sudoPassword.c_str(), 1, sudoPassword.size(), pipe);
    fflush(pipe);
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        const char* pidStart = strstr(buffer, "(PID: ");
        if (pidStart) {
            pidStart += strlen("(PID: ");
            const char* pidEnd = strchr(pidStart, ')');
            if (pidEnd) {
                string pidString(pidStart, pidEnd - pidStart);
                int pid = std::stoi(pidString);
                time_t now = time(0); 
                char* dt = ctime(&now);  
                dt[strcspn(dt, "\n")] = '\0';  // Trim newline
                string message = string(dt) + " - " + std::to_string(pid) + " Found communicating with malicious IP";
                writeToScanResults(message);
                popUp(message);
                bool updateRes = Helper::updateVirusTables(std::to_string(pid));
            }
        }
    }
    pclose(pipe);
}

void PeriodicScanHandler::portsConnectionsScan() {
    FILE* pipe = popen("sudo -S /bin/python3 /home/noam/implementations/network_scanner/scanner.py", "r+");
    if (!pipe)
        throw std::runtime_error("Failed to open pipe...");

    string sudoPassword = "123456\n"; //add a request to ask from the user
    fwrite(sudoPassword.c_str(), 1, sudoPassword.size(), pipe);
    fflush(pipe);
    
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
                string message = string(dt) + " - Computer " + ip + " found sending suspicious amount of packets to port " + protocol;
                writeToScanResults(message);
                popUp(message);
                bool updateRes = Helper::updateVirusTables(ip);
            }
        }
    }
    pclose(pipe);
}

void PeriodicScanHandler::writeToScanResults(const string& message) {
    std::lock_guard<std::mutex> guard(_lock);
    std::ofstream outputFile("/home/noam/implementations/Backend/periodic_scan_results.txt", std::ios::app);
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