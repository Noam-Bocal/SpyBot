#include "Helper.h"

char* Helper::getPartFromSocket(int sc, int bytesNum)
{
    if (bytesNum == 0)
        return (char*)"";

    char* data = new char[bytesNum + 1];

    ssize_t res = recv(sc, data, bytesNum, NO_FLAGS);

    if (res == -1)
    {
        std::string s = "Error while receiving from socket: ";
        s += std::to_string(sc);
        throw std::runtime_error(s.c_str());
    }

    data[bytesNum] = '\0';
    return data;
}

void Helper::sendData(int sc, std::string message)
{
    std::string binStr = convertToBinary(message);
    const char* data = binStr.c_str();

    if (send(sc, data, binStr.size(), NO_FLAGS) == -1)
    {
        throw std::runtime_error("Error while sending message to client");
    }
}

std::string Helper::getAllTheSocket(int sc)
{
    std::string buffer = Helper::getPartFromSocket(sc, SIZE_OF_BYTE);
    std::string ascii = convertToAscii(buffer);
    if (ascii[0] == '\0')
        buffer = Helper::getPartFromSocket(sc, 3 * SIZE_OF_BYTE);
    else
        buffer += Helper::getPartFromSocket(sc, 2 * SIZE_OF_BYTE);

    // Getting the data length
    std::string dataLength = Helper::getPartFromSocket(sc, DATA_LEN_IN_BYTES * SIZE_OF_BYTE);
    buffer += dataLength;

    dataLength = convertToAscii(dataLength);

    // Getting the data from the packet
    buffer += Helper::getPartFromSocket(sc, SIZE_OF_BYTE * std::stoi(dataLength));
    return convertToAscii(buffer);
}

std::string Helper::convertToBinary(std::string str)
{
    std::string binString;
    for (auto element : str)
        binString += (std::bitset<8>(element)).to_string();
    return binString;
}

std::string Helper::convertToAscii(std::string str)
{
    std::string textualStr;
    std::stringstream sstream(str);

    while (sstream.good())
    {
        std::bitset<8> bits;
        sstream >> bits;
        char c = char(bits.to_ulong());
        textualStr += c;
    }
    return textualStr;
}

std::string Helper::base64_encode(const unsigned char* data, size_t len)
{
    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--) {
        // Read three characters from the input data into char_array_3
        char_array_3[i++] = *(data++);

        // If three characters are read, encode them into four base64 characters
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            // Append the base64-encoded characters to the result string
            for (i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];

            i = 0; // Reset the counter
        }
    }

    if (i) {
        // Handle the case when the last group has fewer than three characters
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        // Append the remaining base64-encoded characters to the result string
        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];

        // Add padding '=' characters if needed
        while (i++ < 3)
            encoded += '=';
    }

    return encoded;
}

std::string Helper::base64_decode(const std::string& encoded)
{
    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int in_len = static_cast<int>(encoded.size());
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string decoded;

    while (in_len-- && (encoded[in_] != '=') && (isalnum(encoded[in_]) || (encoded[in_] == '+') || (encoded[in_] == '/'))) {
        // Read four base64 characters into char_array_4
        char_array_4[i++] = encoded[in_]; in_++;

        // If four characters are read, decode them into three original characters
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            // Append the decoded characters to the result string
            for (i = 0; i < 3; i++)
                decoded += char_array_3[i];

            i = 0; // Reset the counter
        }
    }

    if (i) {
        // Handle the case when the last group has fewer than four characters
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        // Append the remaining decoded characters to the result string
        for (j = 0; j < i - 1; j++)
            decoded += char_array_3[j];
    }

    return decoded;
}

string Helper::getCurrentDate()
{
	time_t now = time(0);
    tm* ltm = localtime(&now);

    // Format the date as YYYY-MM-DD
    char buffer[11]; // Increase buffer size to accommodate null terminator
    strftime(buffer, sizeof(buffer), "%Y-%m-%d", ltm);

    return string(buffer);
}

bool Helper::isLegalIPAddress(const std::string& ipAddress) {
    // Split the IP address into tokens using '.' as the delimiter
    std::istringstream ss(ipAddress);
    std::string token;
    std::vector<int> parts;

    while (std::getline(ss, token, '.')) {
        try {
            int part = std::stoi(token);
            if (part < 0 || part > 255)
                return false;
            parts.push_back(part);
        }
        catch (const std::invalid_argument& e) {
            return false;
        }
        catch (const std::out_of_range& e) {
            return false;
        }
    }

    // Check if the IP address has exactly 4 parts
    if (parts.size() != 4) {
        return false;
    }

    // Check for leading zeros in each part
    for (const auto& part : parts) {
        std::string partStr = std::to_string(part);
        if (partStr.length() > 1 && partStr[0] == '0') {
            return false;
        }
    }

    // Check for consecutive dots
    size_t pos = ipAddress.find("..");
    if (pos != std::string::npos) {
        return false;
    }

    // Check for trailing dots
    if (ipAddress.back() == '.') {
        return false;
    }

    return true;
}

