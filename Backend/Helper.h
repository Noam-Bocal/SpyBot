#pragma once

#include <iostream>
#include <stdexcept>
#include <cstring>
#include <bitset>
#include <sstream>
#include <regex>
#include <map>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include "sqlite3.h"
#include "pch.h"


#define NO_FLAGS 0
#define SIZE_OF_BYTE 8
#define VIRUSES_TABLE std::string("VirusTable")


enum ByteSizes { CODE_LEN_IN_BYTES = 2, DATA_LEN_IN_BYTES = 4 };

class Helper {
public:
    static char* getPartFromSocket(int sc, int bytesNum);
    static std::string getAllTheSocket(int sc);
    static void sendData(int sc, std::string message);

    static std::string convertToBinary(std::string str);
    static std::string convertToAscii(std::string str);
    
    static std::map<std::string, int> yaraCommunicator(const std::string path, const std::string scan_type, const std::string path_to_scan, const std::string recursive); 

    static bool updateVirusTables(std::string name);
};