#include "Client.h"

Client::Client() : _clientSocket(-1)
{
}

Client::~Client()
{
    
}

void Client::connectToServer(std::string serverIP, int port)
{
    // Create a socket
    _clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (_clientSocket == -1)
    {
        throw std::runtime_error("Can't connect to backend");
    }

    // Set up the server address structure
    sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0)
    {
        close(_clientSocket); // Close the socket if an error occurs
        throw std::runtime_error("Invalid IP address");
    }

    // Connect to the server
    if (connect(_clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        close(_clientSocket); // Close the socket if an error occurs
        throw std::runtime_error("Can't connect to backend");
    }
}

void Client::startConversation()
{
    try {
        cout << "Welcome to SpyBot Server. Make your request by entering the corresponding code:\n"
            "0 - Exit\n"
            "100 - Start scanning\n"
            "101 - Get suspicious process list\n"
            "102 - Get suspended process list\n"
            "103 - Free process from block\n"
            "104 - Block process\n"
            "105 - Scan IP\n"
            "106 - Scan hash\n"
            "107 - Save IP\n"
            "108 - Save hash\n"
            "109 - Kill process\n";
        while (true)
        {
            cout << "\nEnter command: ";
            int code = 0;
            cin >> code;
            if (code == 0)
                break;

            while (code < 100 || code > 109)
            {
                cout << "Invalid command. Renter:" << endl;
                cin >> code;

                if (code == 0)
                    break;
            }
            string request_json;
            if (code == SCAN_REQUEST)
            {
                string path_to_scan = "";
                string scan_type = "";
                string recursive = "";
                string path_to_yara = "python3 \"/home/user/Desktop/implementations/yara_scanner/yara_main.py"; //change according to your system

                std::cout << "Enter scan type (file - 0, directory - 1): ";
                std::cin >> scan_type;
                scan_type = (scan_type == "0") ? "--scan-file" : "--scan-dir";

                std::cout << "Enter file or directory: ";
                std::getline(std::cin >> std::ws, path_to_scan);  // Use getline to handle spaces and non-ASCII characters

                if (scan_type == "--scan-dir") {
                    std::cout << "Do you want to scan directories inside this directory as well? (1- yes, 0- no): ";
                    std::cin >> recursive;
                    recursive = (recursive == "0") ? "" : "--recursive";
                    
                }

                ScanRequest scanReq{ path_to_yara, scan_type, path_to_scan, recursive };
                request_json = JsonRequestPacketSerializer::serializeResponse(scanReq);
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                ScanResponse resp = JsonResponsePacketDesirializer::deserializeScanResponse(resp_json.substr(7));
                for (auto& proc : resp.procInfo)
                {
                    cout << proc.first;
                    if (proc.second == 0)
                        cout << " - clear" << endl;
                    else
                        cout << " - malicious" << endl;
                }
            }


            else if (code == SUSPICIOUS_PROCESSES_LIST_REQUEST || code == SUSPENDED_PROCESSES_LIST_REQUEST)
            {
                request_json = JsonRequestPacketSerializer::serializeResponse(code); //a request that doesnt require any values
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                if (code == SUSPICIOUS_PROCESSES_LIST_REQUEST)
                {
                    SuspiciousListResponse resp = JsonResponsePacketDesirializer::deserializeSuspiciousListResponse(resp_json.substr(7));
                    for (auto& name : resp.procNames)
                        cout << name << endl;
                }
                else
                {
                    SuspendedListResponse resp = JsonResponsePacketDesirializer::deserializeSuspendedListResponse(resp_json.substr(7));
                    for (auto& name : resp.procNames)
                        cout << name << endl;
                }


            }
            else if (code == FREE_PROCESS_REQUEST)
            {
                int pid;
                cout << "Enter process id to free: " << endl; 
                cin >> pid;
                while (pid < 0)
                {
                    cout << "Invalid pid. Renter:";
                    cin >> pid;
                }
                FreeRequest freeReq{ pid };
                request_json = JsonRequestPacketSerializer::serializeResponse(freeReq);
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                FreeResponse resp = JsonResponsePacketDesirializer::deserializeFreeResponse(resp_json.substr(7));
                if (resp.isWorked == 1)
                    cout << "process " << pid << " is free" << endl;
                else
                    cout << "Couldnt free process " << pid << endl;
            }
            else if (code == BLOCK_PROCESS_REQUEST)
            {
                int pid;
                cout << "Enter process id to block: " << endl; //normaly he will see the list of process
                cin >> pid;
                BlockRequest blockReq{ pid };
                request_json = JsonRequestPacketSerializer::serializeResponse(blockReq);
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                BlockResponse resp = JsonResponsePacketDesirializer::deserializeBlockResponse(resp_json.substr(7));
                if (resp.isWorked == 1)
                    cout << "process " << pid << " is blocked" << endl;
                else
                    cout << "Couldnt block process " << pid << endl;
            }
            else if(code == KILL_PROCESS_REQUEST)
            {
                int pid;
                cout << "Enter process id to kill: " << endl;
                cin >> pid;
                KillRequest killReq{ pid };
                request_json = JsonRequestPacketSerializer::serializeResponse(killReq);
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                KillResponse resp = JsonResponsePacketDesirializer::deserializeKillResponse(resp_json.substr(7));
                if(resp.isWorked == 1)
                    cout << "process " << pid << " is terminated" << endl;
                else
                    cout << "Couldn't terminate process " << pid << endl;
            }
            else if (code == IP_SCAN_REQUEST)
            {
                string ip;
                cout << "Enter ip adress to scan: " << endl;
                cin >> ip;
                while (!Helper::isLegalIPAddress(ip))
                {
                    cout << "Illeagal IP address. Renter:";
                    cin >> ip;
                }
                IPScanRequest ipScanReq{ IP_SCAN_REQUEST, ip };
                request_json = JsonRequestPacketSerializer::serializeResponse(ipScanReq);
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                IpScanResponse resp = JsonResponsePacketDesirializer::deserializeIpScanResponse(resp_json.substr(7));
                if (resp.res == 0)
                    cout << ip << " Is clear" << endl;
                else
                    cout << ip << " Is malicioius" << endl;
            }
            else if (code == HASH_SCAN_REQUEST)
            {
                string filePath;
                cout << "Enter file path to scan its hash: " << endl;
                cin >> filePath;
                HashScanRequest hashCanReq;
                try {
                    hashCanReq = { HASH_SCAN_REQUEST ,HashHandler::hash_file(filePath) };
                }
                catch (std::runtime_error& e)
                {
                    cout << e.what() << endl;
                    continue; 
                }
                request_json = JsonRequestPacketSerializer::serializeResponse(hashCanReq);
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                HashScanResponse resp = JsonResponsePacketDesirializer::deserializeHashScanResponse(resp_json.substr(7));
                if (resp.res == 0)
                    cout << filePath << " Is clear" << endl;
                else
                    cout << filePath << " Is malicioius" << endl;
            }
            else if (code == SAVING_IP_REQUEST) {
                string ip;
                cout << "Enter ip adress to save: " << endl;
                cin >> ip;
                while (!Helper::isLegalIPAddress(ip))
                {
                    cout << "Illeagal IP address. Renter:";
                    cin >> ip;
                }
                IPSaveRequest ipSaveReq{ SAVING_IP_REQUEST,ip };
                request_json = JsonRequestPacketSerializer::serializeResponse(ipSaveReq);
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                SaveIpResponse resp = JsonResponsePacketDesirializer::deserializeSaveIpResponse(resp_json.substr(7));
                if (resp.isWorked == 1)
                    cout << "IP: " << ip << " was saved succefuly" << endl;
                else
                    cout << "couldn't save IP: " << ip << endl;
            }
            else if (code == SAVING_HASH_REQUEST)
            {
                string filePath, fileName;
                cout << "Enter hash to save: " << endl;
                cin >> filePath;
                cout << "Enter a name for the file: " << endl;
                cin >> fileName;
                HashSaveRequest hashSaveReq{ fileName, filePath, HashHandler::hash_file(filePath), Helper::getCurrentDate(), true, "Noam B PC", "suspended" };
                request_json = JsonRequestPacketSerializer::serializeResponse(hashSaveReq);
                Helper::sendData(_clientSocket, request_json);
                string resp_json = Helper::getAllTheSocket(_clientSocket);
                SaveHashResponse resp = JsonResponsePacketDesirializer::deserializeSaveHashResponse(resp_json.substr(7));
                if (resp.isWorked == 1)
                    cout << "Hash: " << fileName << " was saved succefuly" << endl;
                else
                    cout << "couldn't save file: " << fileName << endl;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        close(_clientSocket);
    }
}


