#pragma once

#include <iostream>
#include <string>
#include <bitset>
#include <sstream>
#include <unistd.h>  // Add this for Unix socket compatibility
#include <sys/socket.h>
#include "pch.h"

#define NO_FLAGS 0
#define SIZE_OF_BYTE 8

enum ByteSizes { CODE_LEN_IN_BYTES = 2, DATA_LEN_IN_BYTES = 4 };

class Helper {
public:
    static char* getPartFromSocket(int sc, int bytesNum);  // Change SOCKET to int
    static std::string getAllTheSocket(int sc);  // Change SOCKET to int
    static void sendData(int sc, std::string message);  // Change SOCKET to int

    static std::string convertToBinary(std::string str);
    static std::string convertToAscii(std::string str);
    static std::string base64_encode(const unsigned char* data, size_t len);
    static std::string base64_decode(const std::string& encoded);
};