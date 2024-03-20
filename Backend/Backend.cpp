#include "Backend.h"
Backend::Backend(SqliteHelper* db) : _db(db){
    _BackendSocket = socket(AF_INET, SOCK_STREAM, 0);
    _ServerSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (_BackendSocket == -1 || _ServerSocket == -1)
        throw std::runtime_error("Backend::Backend() - socket");

    int enable = 1;
    if (setsockopt(_BackendSocket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        throw std::runtime_error("Backend::Backend() - setsockopt(SO_REUSEADDR) failed");


}

Backend::~Backend() {
    try {
        close(_BackendSocket);
        close(_ServerSocket);
    }
    catch (...) {}
}

void Backend::serve(int port) {
    struct sockaddr_in sa = { 0 };

    sa.sin_port = htons(port);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(_BackendSocket, (struct sockaddr*)&sa, sizeof(sa)) == -1)
        throw std::runtime_error("Backend::serve() - bind");

    if (listen(_BackendSocket, SOMAXCONN) == -1)
        throw std::runtime_error("Backend::serve() - listen");

    std::cout << "Listening on port " << port << std::endl;

    while (true) {
        std::cout << "Waiting for client connection request" << std::endl;
        acceptClient();
    }
}

void Backend::acceptClient() {
    int client_socket = accept(_BackendSocket, NULL, NULL);
    if (client_socket == -1)
        throw std::runtime_error("Backend::acceptClient() - accept");

    std::cout << "Client accepted" << std::endl;
    clientHandler(client_socket);
}

void Backend::clientHandler(int clientSocket) {
    try {
        while (true)
        {
            std::string packet = Helper::getAllTheSocket(clientSocket);
            RequestInfo info(packet);

            RequestHandler* requestHandler = new RequestHandler(_db);
            if (!requestHandler->isRequestRelevant(info)) {
                ErrorResponse errResponse{ "Request is not relevant." };
                Helper::sendData(clientSocket, JsonResponsePacketSerializer::serializeResponse(errResponse));
            }
            else {
                if (info.id >= 100 && info.id <= 107) //client - backend requests
                {
                    std::string result = requestHandler->handleRequest(info);
                    std::cout << "Data sent: " << result << std::endl;
                    Helper::sendData(clientSocket, result);
                }
                else if(info.id >= 108 && info.id <= 111)
                {
                    string result = PeriodicScanHandler::handleRequest(info);
                    cout << "Data sent: " << result << endl;
                    Helper::sendData(clientSocket, result);
                }
                else //client - server requests
                    handleServerRequest(clientSocket, packet);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Client existed: " << std::endl;
        close(clientSocket);
    }
}

void Backend::handleServerRequest(int clientSocket, std::string clientRequest)
{
    _ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { 0 };

    sa.sin_port = htons(9000);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(_ServerSocket, (struct sockaddr*)&sa, sizeof(sa)) == -1)
    {
        std::cerr << "Error connecting to the server" << std::endl;
        close(_ServerSocket);
        return;
    }

    try
    {
        Helper::sendData(_ServerSocket, clientRequest);
        std::string serverResponse = Helper::getAllTheSocket(_ServerSocket);
        Helper::sendData(clientSocket, serverResponse);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error handling server request: " << e.what() << std::endl;
    }
    close(_ServerSocket);
}