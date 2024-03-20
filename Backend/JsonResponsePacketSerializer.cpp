#include "JsonResponsePacketSerializer.h"

string JsonResponsePacketSerializer::serializeResponse(json j, int code)
{
    string binJson = j.dump(); // Getting the json as a string
    std::vector<unsigned char> binData(binJson.begin(), binJson.end());
    std::ostringstream streamCode;
    std::ostringstream streamDataLen;

    streamCode << std::setw(CODE_LEN_IN_BYTES) << std::setfill('0') << std::to_string(code);

    streamDataLen << std::setw(DATA_LEN_IN_BYTES) << std::setfill('0') << binData.size();

    return streamCode.str() + streamDataLen.str() + j.dump();

}

string JsonResponsePacketSerializer::serializeResponse(ScanResponse scanResp)
{
    json j;
    j["status"] = scanResp.status;
    j["procInfo"] = scanResp.procInfo;

    return JsonResponsePacketSerializer::serializeResponse(j, scanResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(SuspendedListResponse suspendedResp)
{
    json j;
    j["status"] = suspendedResp.status;
    j["procPids"] = suspendedResp.procPids;
    return JsonResponsePacketSerializer::serializeResponse(j, suspendedResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(SuspiciousListResponse suspiciousResp)
{
    json j;
    j["status"] = suspiciousResp.status;
    j["procNames"] = suspiciousResp.procNames;
    return JsonResponsePacketSerializer::serializeResponse(j, suspiciousResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(FreeResponse freeResp)
{
    json j = { {"status", freeResp.status}, {"isWorked", freeResp.isWorked}};
    return JsonResponsePacketSerializer::serializeResponse(j, freeResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(BlockResponse blockResp)
{
    json j = { {"status", blockResp.status}, {"isWorked", blockResp.isWorked} };
    return JsonResponsePacketSerializer::serializeResponse(j, blockResp.status);
}

string JsonResponsePacketSerializer::serializeResponse(KillResponse killResp)
{
    json j = { {"status", killResp.status}, {"isWorked", killResp.isWorked} };
    return JsonResponsePacketSerializer::serializeResponse(j, killResp.status);
}


string JsonResponsePacketSerializer::serializeResponse(ErrorResponse errResp)
{
    json j = { {"message", errResp.message} };
    return JsonResponsePacketSerializer::serializeResponse(j, ERROR);
}

std::string JsonResponsePacketSerializer::serializeResponse(ChangeScanFolderResponse changeFolderResp)
{
    json j = { {"status", changeFolderResp.status}, {"isWorked", changeFolderResp.isWorked} };
    return JsonResponsePacketSerializer::serializeResponse(j, changeFolderResp.status);
}

std::string JsonResponsePacketSerializer::serializeResponse(ChangeScanTimeResponse changeTimeResp)
{
    json j = { {"status", changeTimeResp.status}, {"isWorked", changeTimeResp.isWorked} };
    return JsonResponsePacketSerializer::serializeResponse(j, changeTimeResp.status);
}

std::string JsonResponsePacketSerializer::serializeResponse(UpdateBlockedTableResponse blockedTbaleResp)
{
    json j = { {"status", blockedTbaleResp.status}, {"isWorked", blockedTbaleResp.isWorked} };
    return JsonResponsePacketSerializer::serializeResponse(j, blockedTbaleResp.status);
}

std::string JsonResponsePacketSerializer::serializeResponse(UpdateVirusTableResponse virusTableResp)
{
    json j = { {"status", virusTableResp.status}, {"isWorked", virusTableResp.isWorked} };
    return JsonResponsePacketSerializer::serializeResponse(j, virusTableResp.status);    
}
std::string JsonResponsePacketSerializer::serializeResponse(GetTimeResponse timeResp)
{
    json j = {{"status", timeResp.status}, {"time", timeResp.time}};
    return JsonResponsePacketSerializer::serializeResponse(j, timeResp.status);
}

std::string JsonResponsePacketSerializer::serializeResponse(GetFolderResponse folderResp)
{
    json j = {{"status", folderResp.status}, {"folder", folderResp.folder}};
    return JsonResponsePacketSerializer::serializeResponse(j, folderResp.status);
}
