#include "JsonRequestPacketDeserializer.h"

IPScanRequest JsonRequestPacketDeserializer::deserializeIPScanRequest(vector<uint8_t> buffer)
{
	IPScanRequest iPScanRequest;
	json jsn = json::parse(buffer);
	iPScanRequest.IPAddress = jsn["ip"].get<string>();

	return iPScanRequest;
}

HashScanRequest JsonRequestPacketDeserializer::deserializeHashScanRequest(vector<uint8_t> buffer)
{
	HashScanRequest hashScanRequest;
	json jsn = json::parse(buffer);
	hashScanRequest.hashes = jsn["hashes"].get<std::list<string>>();

	return hashScanRequest;
}

SaveIpRequest JsonRequestPacketDeserializer::deserializeSaveIpRequest(vector<uint8_t> buffer)
{
	SaveIpRequest saveIpRequest;
	json jsn = json::parse(buffer);
	saveIpRequest.IPAddress = jsn["ip"].get<string>();
	saveIpRequest.DateAdded = jsn["DateAdded"].get<string>();
	saveIpRequest.Source = jsn["source"].get<string>();

	return saveIpRequest;
}

SaveHashRequest JsonRequestPacketDeserializer::deserializeSaveHashRequest(vector<uint8_t> buffer)
{
	SaveHashRequest saveHashRequest;
	json jsn = json::parse(buffer);
	saveHashRequest.DateAdded = jsn["DateAdded"].get<string>();
	saveHashRequest.Encrypted = jsn["encrypted"].get<bool>();
	saveHashRequest.FileHash_SHA256 = jsn["hash"].get<string>();
	saveHashRequest.FileName = jsn["fileName"].get<string>();
	saveHashRequest.FilePath = jsn["filepath"].get<string>();
	saveHashRequest.IsolationStatus = jsn["isolationStatus"].get<string>();
	saveHashRequest.SourceDetection = jsn["source"].get<string>();

	return saveHashRequest;
}
