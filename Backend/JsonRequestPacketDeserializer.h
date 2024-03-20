#pragma once
#include "pch.h"
#include "json.hpp"

using json = nlohmann::json;

//client
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


struct ChangeScanTimeRequest{
	int time;
};

struct ChangeScanFolderRequest{
	string folder;
};

struct UpdateBlockedTableRequest{
	int pid;
	string dateTime;
	string action; //add, remove
}; 
struct UpdateVirusTableRequest{
	string name; //could be path of a file or a pid of a process
	string dateTime;
};

class JsonRequestPacketDeserializer
{
public:
	//client
	static ScanRequest deserializeScanRequest(vector<uint8_t> buffer);
	static FreeRequest desrializeFreeRequest(vector<uint8_t> buffer);
	static BlockRequest desirializeBlockRequest(vector<uint8_t> buffer);
	static KillRequest desirializeKillRequest(vector<uint8_t> buffer);
	static ChangeScanTimeRequest desirializeChangeScanTimeRequest(vector<uint8_t> buffer);
	static ChangeScanFolderRequest desirializeChangeScanFolderRequest(vector<uint8_t> buffer);
	static UpdateBlockedTableRequest deserializeUpdateBlockedTbaleRequest(vector<uint8_t> buffer);
	static UpdateVirusTableRequest deserializeUpdateVirusTableRequest(vector<uint8_t> buffer);
};

