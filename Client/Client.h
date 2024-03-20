#pragma once

#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "JsonRequestPacketSerializer.h"
#include "JsonResponsePacketDesirializer.h"
#include "Helper.h"
#include "HashHandler.h"


class Client
{
public:
    Client();
    ~Client();

    void connectToServer(std::string serverIP, int port);
    void startConversation();

private:
    int _clientSocket;
};