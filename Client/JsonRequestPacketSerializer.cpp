#include "JsonRequestPacketSerializer.h"

string JsonRequestPacketSerializer::serializeResponse(json j, int code)
{
    string binJson = j.dump(); // Getting the json as a string
    std::vector<unsigned char>binData(binJson.begin(), binJson.end());
    std::ostringstream streamCode;
    std::ostringstream streamDataLen;

    streamCode << std::setw(CODE_LEN_IN_BYTES) << std::setfill('0') << std::to_string(code);

    streamDataLen << std::setw(DATA_LEN_IN_BYTES) << std::setfill('0') << binData.size();

    return streamCode.str() + streamDataLen.str() + j.dump();

}

string JsonRequestPacketSerializer::serializeResponse(ScanRequest scanReq)
{
    json j;
    j["pathToYara"] = Helper::base64_encode(reinterpret_cast<const unsigned char*>(scanReq.path_to_yara.c_str()), scanReq.path_to_yara.length());
    j["pathToScan"] = Helper::base64_encode(reinterpret_cast<const unsigned char*>(scanReq.path_to_scan.c_str()), scanReq.path_to_scan.length());
    j["scanType"] = scanReq.scan_type;
    j["recursive"] = scanReq.recursive;
    return JsonRequestPacketSerializer::serializeResponse(j, SCAN_REQUEST);
}

string JsonRequestPacketSerializer::serializeResponse(FreeRequest freeReq)
{
    json j{ {"pid", freeReq.pid} };
    return JsonRequestPacketSerializer::serializeResponse(j, FREE_PROCESS_REQUEST);

}

string JsonRequestPacketSerializer::serializeResponse(BlockRequest blockReq)
{
    json j{ {"pid", blockReq.pid} };
    return JsonRequestPacketSerializer::serializeResponse(j, BLOCK_PROCESS_REQUEST);
}

string JsonRequestPacketSerializer::serializeResponse(KillRequest killReq)
{
    json j{ {"pid", killReq.pid} };
    return JsonRequestPacketSerializer::serializeResponse(j, KILL_PROCESS_REQUEST);
}

string JsonRequestPacketSerializer::serializeResponse(IPScanRequest ipScanReq)
{
    json j{ {"ip", ipScanReq.ip}, {"status", ipScanReq.status} };
    return JsonRequestPacketSerializer::serializeResponse(j, ipScanReq.status);
}

string JsonRequestPacketSerializer::serializeResponse(HashScanRequest HashScanReq)
{
    json j;
    j["hash"] = Helper::base64_encode(reinterpret_cast<const unsigned char*>(HashScanReq.hash.c_str()), HashScanReq.hash.length());
    j["status"] = HashScanReq.status;
    return JsonRequestPacketSerializer::serializeResponse(j, HashScanReq.status);

}

string JsonRequestPacketSerializer::serializeResponse(IPSaveRequest IpSaveReq)
{
    json j{ {"ip", IpSaveReq.ip}, {"status", IpSaveReq.status}, {"DateAdded", Helper::getCurrentDate()}, {"source", "Noam B computer"} };
    return JsonRequestPacketSerializer::serializeResponse(j, IpSaveReq.status);
}

string JsonRequestPacketSerializer::serializeResponse(HashSaveRequest hashSaveReq)
{
    json j{
        {"fileName", hashSaveReq.fileName},
        {"filepath", hashSaveReq.filepath},
        {"hash", Helper::base64_encode(reinterpret_cast<const unsigned char*>(hashSaveReq.hash.c_str()), hashSaveReq.hash.length())},
        {"DateAdded", hashSaveReq.DateAdded},
        {"encrypted", hashSaveReq.encrypted},
        {"source", hashSaveReq.source},
        {"isolationStatus", hashSaveReq.isolationStatus}
    };
    return JsonRequestPacketSerializer::serializeResponse(j, SAVING_HASH_REQUEST);
}

//for requests without values
string JsonRequestPacketSerializer::serializeResponse(int code)
{
    std::ostringstream streamCode;
    std::ostringstream streamDataLen;

    streamCode << std::setw(CODE_LEN_IN_BYTES) << std::setfill('0') << std::to_string(code);

    streamDataLen << std::setw(DATA_LEN_IN_BYTES) << std::setfill('0') << 0;

    return streamCode.str() + streamDataLen.str();
}

