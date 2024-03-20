#pragma once
#include "Helper.h"
#include "json.hpp"
#include "pch.h"

using json = nlohmann::json;

struct ScanResponse {
	unsigned int status;
	std::map<string, int> procInfo;
};

struct SuspiciousListResponse {
	unsigned int status;
	vector<string> procNames;
};

struct SuspendedListResponse {
	unsigned int status;
	vector<string> procNames;
};

struct FreeResponse {
	unsigned int status;
	int isWorked;
};

struct BlockResponse {
	unsigned int status;
	int isWorked;
};

struct KillResponse {
	unsigned int status;
	int isWorked;
};

struct ErrorResponse {
	string message;
};

struct IpScanResponse {
	unsigned int status;
	int res; //o - clear, 1 - malicious
};

struct HashScanResponse
{
	unsigned int status;
	int res; //o - clear, 1 - malicious
};

struct SaveIpResponse{
	unsigned int status;
	int isWorked;
};

struct SaveHashResponse {
	unsigned int status;
	int isWorked;
};


class JsonResponsePacketDesirializer
{
public:
	static ScanResponse deserializeScanResponse(string buffer);
	static SuspiciousListResponse deserializeSuspiciousListResponse(string buffer);
	static SuspendedListResponse deserializeSuspendedListResponse(string buffer);
	static FreeResponse deserializeFreeResponse(string buffer);
	static BlockResponse deserializeBlockResponse(string buffer);
	static KillResponse deserializeKillResponse(string buffer);
	static IpScanResponse deserializeIpScanResponse(string buffer);
	static HashScanResponse deserializeHashScanResponse(string buffer);
	static SaveIpResponse deserializeSaveIpResponse(string buffer);
	static SaveHashResponse deserializeSaveHashResponse(string buffer);

};

