#include "RequestHandler.h"

RequestHandler::RequestHandler(SqliteHelper* db) : _db(db)
{ /**/ }

bool RequestHandler::isRequestRelevant(RequestInfo reqInfo)
{
    switch (reqInfo.id) {
    case IP_SCAN_REQUEST:
    case HASH_SCAN_REQUEST:
    case SAVING_IP_REQUEST:
    case SAVING_HASH_REQUEST:
        return true;

    default:
        return false;
    }
}

string RequestHandler::handleRequest(RequestInfo reqInfo)
{
    string result;
    if (reqInfo.id == IP_SCAN_REQUEST)
        result = IPScan(reqInfo);
    else if (reqInfo.id == HASH_SCAN_REQUEST)
        result = hashScan(reqInfo);
    else if (reqInfo.id == SAVING_IP_REQUEST)
        result = saveIp(reqInfo);
    else if (reqInfo.id == SAVING_HASH_REQUEST)
        result = saveHash(reqInfo);

    return result;
}

string RequestHandler::IPScan(RequestInfo reqInfo)
{
    IpScanResponse ipScanResponse;
    string ip = JsonRequestPacketDeserializer::deserializeIPScanRequest(reqInfo.buffer).IPAddress;
    ipScanResponse.status = IP_SCAN_RESPONSE;
    ipScanResponse.res = _db->IPisMalicious(ip);

    return JsonResponsePacketSerializer::serializeResponse(ipScanResponse);
}

string RequestHandler::hashScan(RequestInfo reqInfo)
{
    HashScanResponse hashScanResponse;
    std::list<string> hashes = JsonRequestPacketDeserializer::deserializeHashScanRequest(reqInfo.buffer).hashes;
    hashScanResponse.status = HASH_SCAN_RESPONSE;
    for(auto& hash : hashes)
        hashScanResponse.res.push_back(_db->HASHisMalicious(hash));
    return JsonResponsePacketSerializer::serializeResponse(hashScanResponse);
}

string RequestHandler::saveIp(RequestInfo reqInfo)
{
    SaveIpResponse saveIpResponse;
    SaveIpRequest saveIpRequest = JsonRequestPacketDeserializer::deserializeSaveIpRequest(reqInfo.buffer);

    string IPAddress = saveIpRequest.IPAddress;
    string DateAdded = saveIpRequest.DateAdded;
    string Source = saveIpRequest.Source;

    bool isWorked = _db->addIP(IPAddress, DateAdded, Source);
    saveIpResponse.status = SAVING_IP_RESPONSE;
    saveIpResponse.isWorked = isWorked;


    return JsonResponsePacketSerializer::serializeResponse(saveIpResponse);
}

string RequestHandler::saveHash(RequestInfo reqInfo)
{
    SaveHashResponse saveHashResponse;
    SaveHashRequest saveHashRequest = JsonRequestPacketDeserializer::deserializeSaveHashRequest(reqInfo.buffer);
    string FileName = saveHashRequest.FileName;
    string FilePath = saveHashRequest.FilePath;
    string FileHash_SHA256 = saveHashRequest.FileHash_SHA256;
    string DateAdded = saveHashRequest.DateAdded;
    bool Encrypted = saveHashRequest.Encrypted;
    string SourceDetection = saveHashRequest.SourceDetection;
    string IsolationStatus = saveHashRequest.IsolationStatus;

    bool isWorked = _db->addHASH(FileName, FilePath, FileHash_SHA256, DateAdded, Encrypted, SourceDetection, IsolationStatus);
    saveHashResponse.status = SAVING_HASH_RESPONSE;
    saveHashResponse.isWorked = isWorked;

    return JsonResponsePacketSerializer::serializeResponse(saveHashResponse);
}
