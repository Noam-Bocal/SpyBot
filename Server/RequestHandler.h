#pragma once
#include "pch.h"
#include "JsonResponsePacketSerializer.h"
#include "JsonRequestPacketDeserializer.h"
#include "SqliteHelper.h"

struct RequestInfo
{
	unsigned char id;
	vector<uint8_t> buffer;

	RequestInfo(string buff)
	{
		id = stoi(buff.substr(0, 3));
		string json_str = buff.substr(7);
		buffer = vector<uint8_t>(json_str.begin(), json_str.end());
	}
};



class RequestHandler
{
public:
	RequestHandler(SqliteHelper* db);
	bool isRequestRelevant(RequestInfo reqInfo);
	string handleRequest(RequestInfo reqInfo);

private:
	SqliteHelper* _db;

	string IPScan(RequestInfo reqInfo);
	string hashScan(RequestInfo reqInfo);
	string saveIp(RequestInfo reqInfo);
	string saveHash(RequestInfo reqInfo);
};

