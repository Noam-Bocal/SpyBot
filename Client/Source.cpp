#include <iostream>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>
#include "Client.h"

int main()
{
    try
    {
        Client c1;
        c1.connectToServer("127.0.0.1", 8876);
        c1.startConversation();
    }
    catch (std::exception &e)
    {
        std::cerr << "Error occurred: " << e.what() << std::endl;
    }

    return 0;
}
