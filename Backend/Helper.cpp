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

std::map<std::string, int> Helper::yaraCommunicator(const std::string path, const std::string arg_type, const std::string arg, const std::string arg2)
{
    std::string command = path + "\" " + arg_type + " \"" + arg + "\" " + arg2;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("couldn't open pipe");
    }

    char buffer[128];
    std::string output;

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
        output += buffer;


    pclose(pipe);

    std::map<std::string, int> result;
    std::regex pattern(R"(\s*'(.+?)'\s*:\s*(\d+)\s*,?)");
    auto words_begin = std::sregex_iterator(output.begin(), output.end(), pattern);
    auto words_end = std::sregex_iterator();

    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::smatch match = *i;
        std::string key = match[1];
        int value = std::stoi(match[2]);
        result[key] = value;
    }
    for (auto &item : result) {
        if (item.second == 1) { // found a virus
            bool updateRes = updateVirusTables(item.first);
        }
    }
    return result;
}

bool Helper::updateVirusTables(std::string name)
{
    sqlite3* db;
    std::time_t now = std::time(nullptr);
    std::tm* timeinfo = std::localtime(&now);
    char buffer[20];
    
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %I:%M %p", timeinfo);

    std::string dateTime(buffer);
    std::string query = "INSERT INTO " + VIRUSES_TABLE + "(Name, DateAdded) VALUES('" + name  + "', '" + dateTime + "');";
	char** errMessage = nullptr;
    sqlite3_open(DB_NAME, &db);
    return sqlite3_exec(db, query.c_str(), nullptr, nullptr, errMessage) == SQLITE_OK;
}
