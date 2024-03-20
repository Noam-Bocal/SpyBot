#pragma once
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define closesocket close
typedef int SOCKET;

#include "pch.h"
#include "Helper.h"
#include "RequestHandler.h"
#include "PeriodicScanHandler.h"
#include "SqliteHelper.h"


class Backend
{
public:
    Backend(SqliteHelper* db);
    ~Backend();
    void serve(int port);
    void periodicScan();
    void networkScan();
    void portScan();

private:
    void acceptClient();
    void clientHandler(SOCKET clientSocket);
    void handleServerRequest(SOCKET clientSocket, std::string clientRequest);

    SOCKET _BackendSocket;
    SOCKET _ServerSocket;

    PeriodicScanHandler* _periodicHandler;
    SqliteHelper* _db;
};