#include "Server.h"

Server::Server(SqliteHelper* db) {
    this->_db = db;
    _serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (_serverSocket == -1)
        throw std::runtime_error("Server::Server() - socket");

    //std::thread blocklist(system, "/bin/python3 /home/noam/implementations/Server/Blocklist.py");
    //blocklist.detach();
}

Server::~Server()
{
    try {
        close(_serverSocket);
    }
    catch(...) {}
}

void Server::serve(int port)
{
    struct sockaddr_in sa = { 0 };

    sa.sin_port = htons(port);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(_serverSocket, (struct sockaddr*)&sa, sizeof(sa)) == -1)
        throw std::runtime_error("Server::serve() - bind");

    if (listen(_serverSocket, SOMAXCONN) == -1)
        throw std::runtime_error("Server::serve() - listen");

    std::cout << "Listening on port " << port << std::endl;

    while (true) {
        std::cout << "Waiting for client connection request" << std::endl;
        acceptBackend();
    }
}

void Server::acceptBackend()
{
    int backend_socket = accept(_serverSocket, nullptr, nullptr);
    if (backend_socket == -1)
        throw std::runtime_error(__FUNCTION__);

    std::cout << "Client accepted" << std::endl;
    backendHandler(backend_socket);
}

void Server::backendHandler(int backendSocket)
{
    try {
        while (true) {
            std::string packet = Helper::getAllTheSocket(backendSocket);
            RequestInfo info(packet);

            RequestHandler* requestHandler = new RequestHandler(this->_db);
            if (!requestHandler->isRequestRelevant(info)) {
                ErrorResponse errResponse{ "Request is not relevant." };
                Helper::sendData(backendSocket, JsonResponsePacketSerializer::serializeResponse(errResponse));
            }
            else {
                std::string result = requestHandler->handleRequest(info);
                std::cout << "Data sent: " << result << std::endl;
                Helper::sendData(backendSocket, result);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        close(backendSocket);
    }
}