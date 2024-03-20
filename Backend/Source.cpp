#include "Backend.h"
#include "SqliteHelper.h"
#include "pch.h"
#include <iostream>
#include <exception>

int main()
{
    try
    {
        SqliteHelper* db = new SqliteHelper(DB_NAME);
        //std::thread autoScan(&PeriodicScanHandler::periodicScan);
        //autoScan.detach();
        Backend myBackend(db);
        myBackend.serve(8876);
    }
    catch (std::exception& e)
    {
        std::cout << "Error occurred: " << e.what() << std::endl;
    }
    return 0;
}