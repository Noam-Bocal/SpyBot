#pragma once
#include "pch.h"
#include "JsonResponsePacketSerializer.h"
#include "JsonRequestPacketDeserializer.h"
#include "SqliteHelper.h"

//needed to communicate with driver
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SPYBOT_IOC_MAGIC 'k'
#define SPYBOT_IOC_SIGNAL _IOWR(SPYBOT_IOC_MAGIC, 1, int)

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
	virtual bool isRequestRelevant(RequestInfo reqInfo);
	virtual string handleRequest(RequestInfo reqInfo);
	int communicateWithDriver(int action, int target_pid);

private:
	SqliteHelper* _db;
	
	string scan(RequestInfo reqInfo);
	string getSuspiciousProcessesList(RequestInfo reqInfo);
	string getSuspendedProcessesList(RequestInfo reqInfo);
	string freeProcess(RequestInfo reqInfo);
	string blockProcess(RequestInfo reqInfo);
	string killProcess(RequestInfo reqInfo);
	string updateBlockedTable(RequestInfo reqInfo);
	string updateVirusTable(RequestInfo reqInfo);

};

