#include "JsonResponsePacketSerializer.h"

string JsonResponsePacketSerializer::serializeResponse(json j, int code)
{
    string binJson = j.dump(); // Getting the json as a string
    std::vector<unsigned char>binData(binJson.begin(), binJson.end());
    std::ostringstream streamCode;
    std::ostringstream streamDataLen;

    streamCode << std::setw(CODE_LEN_IN_BYTES) << std::setfill('0') << std::to_string(code);

    streamDataLen << std::setw(DATA_LEN_IN_BYTES) << std::setfill('0') << binData.size();

    return streamCode.str() + streamDataLen.str() + j.dump();
}

string JsonResponsePacketSerializer::serializeResponse(IpScanResponse ipScanResp) {
    json j;
    j["status"] = ipScanResp.status;
    j["res"] = ipScanResp.res;

    return JsonResponsePacketSerializer::serializeResponse(j, ipScanResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(HashScanResponse hashScanResp) {
    json j;
    j["status"] = hashScanResp.status;
    j["res"] = hashScanResp.res;

    return JsonResponsePacketSerializer::serializeResponse(j, hashScanResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(SaveIpResponse saveIpResp) {
    json j;
    j["status"] = saveIpResp.status;
    j["isWorked"] = saveIpResp.isWorked;

    return JsonResponsePacketSerializer::serializeResponse(j, saveIpResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(SaveHashResponse saveHashResp)
{
    json j;
    j["status"] = saveHashResp.status;
    j["isWorked"] = saveHashResp.isWorked;

    return JsonResponsePacketSerializer::serializeResponse(j, saveHashResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(ErrorResponse errResp)
{
    json j = { {"message", errResp.message} };
    return JsonResponsePacketSerializer::serializeResponse(j, ERROR);
}
