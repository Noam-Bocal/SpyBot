#include "SqliteHelper.h"
#include "Server.h"
#include <iostream>
#include <exception>

int main()
{
    try
    {
        SqliteHelper* db = new SqliteHelper(DB_NAME);
        Server myServer(db);

        myServer.serve(9000);
    }
    catch (std::exception& e)
    {
        std::cout << "Error occurred: " << e.what() << std::endl;
    }
    return 0;
}
