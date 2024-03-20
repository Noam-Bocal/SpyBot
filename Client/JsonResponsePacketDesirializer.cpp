#include "JsonResponsePacketDesirializer.h"

ScanResponse JsonResponsePacketDesirializer::deserializeScanResponse(string buffer)
{
	ScanResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.procInfo = jsn["procInfo"].get<std::map<string, int>>();

	return response;
}

SuspiciousListResponse JsonResponsePacketDesirializer::deserializeSuspiciousListResponse(string buffer)
{
	SuspiciousListResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.procNames = jsn["procNames"].get<vector<string>>();
	return response;
}

SuspendedListResponse JsonResponsePacketDesirializer::deserializeSuspendedListResponse(string buffer)
{
	SuspendedListResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.procNames = jsn["procNames"].get<vector<string>>();
	return response;
}

FreeResponse JsonResponsePacketDesirializer::deserializeFreeResponse(string buffer)
{
	FreeResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.isWorked = jsn["isWorked"].get<int>();
	return response;
}

BlockResponse JsonResponsePacketDesirializer::deserializeBlockResponse(string buffer)
{
	BlockResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.isWorked = jsn["isWorked"].get<int>();
	return response;
}

KillResponse JsonResponsePacketDesirializer::deserializeKillResponse(string buffer)
{
	KillResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.isWorked = jsn["isWorked"].get<int>();
	return response;
}

IpScanResponse JsonResponsePacketDesirializer::deserializeIpScanResponse(string buffer)
{
	IpScanResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.res = jsn["res"].get<int>();
	return response;
}

HashScanResponse JsonResponsePacketDesirializer::deserializeHashScanResponse(string buffer)
{
	HashScanResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.res = jsn["res"].get<int>();
	return response;
}

SaveIpResponse JsonResponsePacketDesirializer::deserializeSaveIpResponse(string buffer)
{
	SaveIpResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.isWorked = jsn["isWorked"].get<int>();
	return response;
}

SaveHashResponse JsonResponsePacketDesirializer::deserializeSaveHashResponse(string buffer)
{
	SaveHashResponse response;
	json jsn = json::parse(buffer);
	response.status = jsn["status"].get<int>();
	response.isWorked = jsn["isWorked"].get<int>();
	return response;
}




