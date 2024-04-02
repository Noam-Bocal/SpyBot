#include "RequestHandler.h"
RequestHandler::RequestHandler(SqliteHelper *db) : _db(db) {}

bool RequestHandler::isRequestRelevant(RequestInfo reqInfo)
{
	switch (reqInfo.id)
	{
	case SCAN_REQUEST:
	case SUSPENDED_PROCESSES_LIST_REQUEST:
	case SUSPICIOUS_PROCESSES_LIST_REQUEST:
	case FREE_PROCESS_REQUEST:
	case BLOCK_PROCESS_REQUEST:
	case IP_SCAN_REQUEST:
	case HASH_SCAN_REQUEST:
	case SAVING_HASH_REQUEST:
	case SAVING_IP_REQUEST:
	case KILL_PROCESS_REQUEST:
	case PERIODIC_SCAN_FOLDER_REQUEST:
	case PERIODIC_SCAN_TIME_REQUEST:
	case UPDATE_BLOCKED_TABLE_REQUEST:
	case UPDATE_VIRUS_LIST_REQUEST:
	case GET_CURRENT_SCAN_FOLDER_REQUEST:
	case GET_CURRENT_SCAN_FREQUENCY_REQUEST:
		return true;

	default:
		return false;

	}
}

string RequestHandler::handleRequest(RequestInfo reqInfo) {
	string result;
	if (reqInfo.id == SCAN_REQUEST)
		result = scan(reqInfo);
	else if (reqInfo.id == SUSPENDED_PROCESSES_LIST_REQUEST)
		result = getSuspendedProcessesList(reqInfo);
	else if (reqInfo.id == SUSPICIOUS_PROCESSES_LIST_REQUEST)
		result = getSuspiciousProcessesList(reqInfo);
	else if (reqInfo.id == FREE_PROCESS_REQUEST)
		result = freeProcess(reqInfo);
	else if (reqInfo.id == BLOCK_PROCESS_REQUEST)
		result = blockProcess(reqInfo);
	else if(reqInfo.id == KILL_PROCESS_REQUEST)
		result = killProcess(reqInfo);
	else if(reqInfo.id == UPDATE_BLOCKED_TABLE_REQUEST)
		result = updateBlockedTable(reqInfo);
	else if(reqInfo.id == UPDATE_VIRUS_LIST_REQUEST)
		result = updateVirusTable(reqInfo);
	return result;
}

string RequestHandler::scan(RequestInfo reqInfo)
{
	ScanRequest scanRequest = JsonRequestPacketDeserializer::deserializeScanRequest(reqInfo.buffer);
	std::map<string, int> res;
	try {
		res = Helper::yaraCommunicator("python3 \"/home/noam/Desktop/implementations/yara_scanner/yara_main.py", scanRequest.scan_type, scanRequest.path_to_scan, scanRequest.recursive);
	}
	catch (std::exception& e)
	{
		cout << e.what();
		exit(1);
	}
	ScanResponse scanResp;
	scanResp.status = SCAN_RESPONSE;
	scanResp.procInfo = res;
	return JsonResponsePacketSerializer::serializeResponse(scanResp);
}

string RequestHandler::getSuspendedProcessesList(RequestInfo reqInfo)
{
	SuspendedListResponse susResp;
	susResp.status = SUSPENDED_PROCESSES_LIST_REESPONSE;
	susResp.procPids = _db->getBlockedPorcesses();
	return JsonResponsePacketSerializer::serializeResponse(susResp);
}

string RequestHandler::getSuspiciousProcessesList(RequestInfo reqInfo)
{
	SuspiciousListResponse susResp;
	susResp.status = SUSPICIOUS_PROCESSES_LIST_RESPONSE;
	susResp.procNames = _db->getViruses();
	return JsonResponsePacketSerializer::serializeResponse(susResp);
}

string RequestHandler::freeProcess(RequestInfo reqInfo)
{
	FreeRequest freeRequest = JsonRequestPacketDeserializer::desrializeFreeRequest(reqInfo.buffer);

	FreeResponse freeResp { FREE_PROCESS_RESPONSE, communicateWithDriver(2, freeRequest.pid) };
	return JsonResponsePacketSerializer::serializeResponse(freeResp);
	
}

string RequestHandler::blockProcess(RequestInfo reqInfo)
{
	BlockRequest blockRequest = JsonRequestPacketDeserializer::desirializeBlockRequest(reqInfo.buffer);

	BlockResponse blockResp { BLOCK_PROCESS_RESPONSE, communicateWithDriver(1, blockRequest.pid) };
	return JsonResponsePacketSerializer::serializeResponse(blockResp);
}

string RequestHandler::killProcess(RequestInfo reqInfo)
{
	KillRequest killReq = JsonRequestPacketDeserializer::desirializeKillRequest(reqInfo.buffer);

	KillResponse killResp { KILL_PROCESS_RESPONSE, communicateWithDriver(0, killReq.pid) };
	return JsonResponsePacketSerializer::serializeResponse(killResp);
}

string RequestHandler::updateBlockedTable(RequestInfo reqInfo)
{
	UpdateBlockedTableRequest request = JsonRequestPacketDeserializer::deserializeUpdateBlockedTbaleRequest(reqInfo.buffer);
	UpdateBlockedTableResponse response;
	response.isWorked = _db->updateBlockedTable(request.action, request.pid, request.dateTime);
	response.status = UPDATE_BLOCKED_TABLE_RESPONSE;
	return JsonResponsePacketSerializer::serializeResponse(response);
}

string RequestHandler::updateVirusTable(RequestInfo reqInfo)
{
	UpdateVirusTableRequest request = JsonRequestPacketDeserializer::deserializeUpdateVirusTableRequest(reqInfo.buffer);
	UpdateVirusTableResponse response;
	response.isWorked = _db->updateViruses(request.name, request.dateTime);
	response.status = UPDATE_VIRUS_TABLE_RESPONSE;
	return JsonResponsePacketSerializer::serializeResponse(response);
}


int RequestHandler::communicateWithDriver(int action, int target_pid)
{
   int fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        //perror("Failed to open the device file");
    }

	int args[2] = {action, target_pid};
	int result = 0;
	//send the action and pid
	ioctl(fd, SPYBOT_IOC_SEND, args);
	//get the result from the driver(success - 1, fail - 0);
	ioctl(fd, SPYBOT_IOC_RECV, &result);
    close(fd);

	return result;
}



