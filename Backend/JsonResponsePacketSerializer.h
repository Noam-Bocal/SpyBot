#pragma once
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "json.hpp"
#include "Helper.h"
#include "pch.h"
#include <list>

using json = nlohmann::json;

//client
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
	vector<string> procPids;
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

struct ChangeScanFolderResponse{
	unsigned int status;
	int isWorked;
};

struct ChangeScanTimeResponse{
	unsigned int status;
	int isWorked;
};

struct UpdateBlockedTableResponse
{
	unsigned int status;
	int isWorked;
};

struct UpdateVirusTableResponse{
	unsigned int status;
	int isWorked;
};

struct GetTimeResponse{
	unsigned int status;
	int time;
};

struct GetFolderResponse{
	unsigned int status;
	string folder;
};

struct ErrorResponse {
	string message;
};

class JsonResponsePacketSerializer
{
public:
	//client 
	static string serializeResponse(ScanResponse scanResp);
	static string serializeResponse(SuspendedListResponse suspendedResp);
	static string serializeResponse(SuspiciousListResponse suspiciousResp);
	static string serializeResponse(FreeResponse freeResp);
	static string serializeResponse(BlockResponse blockResp);
	static string serializeResponse(KillResponse killResp);
	static string serializeResponse(ChangeScanFolderResponse changeFolderResp);
	static string serializeResponse(ChangeScanTimeResponse changeTimeResp);
	static string serializeResponse(UpdateBlockedTableResponse blockedTbaleResp);
	static string serializeResponse(UpdateVirusTableResponse virusTableResp);
	static string serializeResponse(GetTimeResponse timeResp);
	static string serializeResponse(GetFolderResponse folderResp);


	//Error
	static string serializeResponse(ErrorResponse errResp);

private:
	static string serializeResponse(json j, int code);
};

