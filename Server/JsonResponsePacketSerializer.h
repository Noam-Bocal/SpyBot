#pragma once
#include "json.hpp"
#include "pch.h"
#include "Helper.h"

using json = nlohmann::json;

struct IpScanResponse {
	unsigned int status;
	int res; //o - clear, 1 - malicious
};

struct HashScanResponse
{
	unsigned int status;
	std::list<int> res; //o - clear, 1 - malicious
};

struct SaveIpResponse {
	unsigned int status;
	int isWorked;
};

struct SaveHashResponse {
	unsigned int status;
	int isWorked;
};

struct ErrorResponse {
	string message;
};


class JsonResponsePacketSerializer
{
private:
	static string serializeResponse(json j, int code);

public:
	static string serializeResponse(IpScanResponse ipScanResp);
	static string serializeResponse(HashScanResponse hashScanResp);
	static string serializeResponse(SaveIpResponse saveIpResp);
	static string serializeResponse(SaveHashResponse saveHashResp);
	static string serializeResponse(ErrorResponse errResp);



};

