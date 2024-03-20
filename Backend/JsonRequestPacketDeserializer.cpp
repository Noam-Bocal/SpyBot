#include "JsonRequestPacketDeserializer.h"
#include "Helper.h"

ScanRequest JsonRequestPacketDeserializer::deserializeScanRequest(vector<uint8_t> buffer)
{
	ScanRequest request;
	json jsn = json::parse(buffer);
	request.path_to_yara = jsn["pathToYara"].get<string>();
	request.path_to_scan = jsn["pathToScan"].get<string>();
	request.scan_type = jsn["scanType"].get<string>();
	request.recursive = jsn["recursive"].get<string>();
	return request;
}

FreeRequest JsonRequestPacketDeserializer::desrializeFreeRequest(vector<uint8_t> buffer)
{
	FreeRequest request;
	json jsn = json::parse(buffer);
	request.pid = jsn["pid"].get<int>();
	return request;
}

BlockRequest JsonRequestPacketDeserializer::desirializeBlockRequest(vector<uint8_t> buffer)
{
	BlockRequest request;
	json jsn = json::parse(buffer);
	request.pid = jsn["pid"].get<int>();
	return request;
}

KillRequest JsonRequestPacketDeserializer::desirializeKillRequest(vector<uint8_t> buffer)
{
	KillRequest request;
	json jsn = json::parse(buffer);
	request.pid = jsn["pid"].get<int>();
	return request;
}

ChangeScanTimeRequest JsonRequestPacketDeserializer::desirializeChangeScanTimeRequest(std::vector<uint8_t> buffer)
{
	ChangeScanTimeRequest request;
	json jsn = json::parse(buffer);
	request.time = jsn["time"].get<int>();
	return request;
}

ChangeScanFolderRequest JsonRequestPacketDeserializer::desirializeChangeScanFolderRequest(std::vector<uint8_t> buffer)
{
	ChangeScanFolderRequest request;
	json jsn = json::parse(buffer);
	request.folder = jsn["folder"].get<string>();
	return request;
}

UpdateBlockedTableRequest JsonRequestPacketDeserializer::deserializeUpdateBlockedTbaleRequest(std::vector<uint8_t> buffer)
{
	UpdateBlockedTableRequest request;
	json jsn = json::parse(buffer);
	request.pid = jsn["pid"].get<int>();
	request.dateTime = jsn["dateTime"].get<string>();
	request.action = jsn["action"].get<string>();
	return request;
}

UpdateVirusTableRequest JsonRequestPacketDeserializer::deserializeUpdateVirusTableRequest(std::vector<uint8_t> buffer)
{
	UpdateVirusTableRequest request;
	json jsn = json::parse(buffer);
	request.name = jsn["name"].get<string>();
	request.dateTime = jsn["dateTime"].get<string>();
	return request;
}


