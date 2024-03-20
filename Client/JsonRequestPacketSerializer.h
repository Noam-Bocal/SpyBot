#pragma once
#include "Helper.h"
#include "json.hpp"
#include "pch.h"

using json = nlohmann::json;

struct ScanRequest {
	string path_to_yara;
	string scan_type;
	string path_to_scan;
	string recursive;
};

struct FreeRequest {
	int pid;
};

struct BlockRequest {
	int pid;
};

struct KillRequest {
	int pid;
};

struct IPScanRequest {
	unsigned int status;
	string ip;
};

struct HashScanRequest
{
	unsigned int status;
	string hash;
};

struct IPSaveRequest {
	unsigned int status;
	string ip;
};

struct HashSaveRequest {
	string fileName;
	string filepath;
	string hash;
	string DateAdded;
	bool encrypted;
	string source;
	string isolationStatus;
};

class JsonRequestPacketSerializer
{
private:
	static string serializeResponse(json j, int code);

public:
	static string serializeResponse(ScanRequest scanReq);
	static string serializeResponse(FreeRequest freeReq);
	static string serializeResponse(BlockRequest blockReq);
	static string serializeResponse(KillRequest killReq);
	static string serializeResponse(IPScanRequest IpScanReq);
	static string serializeResponse(HashScanRequest HashScanReq);
	static string serializeResponse(IPSaveRequest IpSaveReq);
	static string serializeResponse(HashSaveRequest hashSaveReq);
	static string serializeResponse(int code);
};

