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
#include "pch.h"


#define NO_FLAGS 0
#define SIZE_OF_BYTE 8


enum ByteSizes { CODE_LEN_IN_BYTES = 2, DATA_LEN_IN_BYTES = 4 };


class Helper {
public:
	static char* getPartFromSocket(int sc, int bytesNum);
    static std::string getAllTheSocket(int sc);
    static void sendData(int sc, std::string message);

    static std::string convertToBinary(std::string str);
    static std::string convertToAscii(std::string str);
    static std::string base64_encode(const unsigned char* data, size_t len);
    static std::string base64_decode(const std::string& encoded);

	static bool isLegalIPAddress(const std::string& ipAddress);

	static string getCurrentDate();


};
