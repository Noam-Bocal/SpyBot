#pragma once

#include <iostream>
#include <string.h>
#include <sstream>
#include <vector>

//client requests
#define SCAN_REQUEST 100 //{"type":"scan type (1, 2, 3 ...)"} 
#define SUSPICIOUS_PROCESSES_LIST_REQUEST 101 //{"status":"1"}
#define SUSPENDED_PROCESSES_LIST_REQUEST 102 // {"status":"1"}
#define FREE_PROCESS_REQUEST 103 //{"ID":"Procees ID that reference to the Process PID"}
#define BLOCK_PROCESS_REQUEST 104 //{"ID":"Procees ID that reference to the Process PID"}
#define KILL_PROCESS_REQUEST 109 //105 was taken :(

//client request to server
#define IP_SCAN_REQUEST 105 //{"IP":"(IP address)"}
#define HASH_SCAN_REQUEST 106 //{"HASH":"(HASH code)"}
#define SAVING_IP_REQUEST 107 // {"IP": "(IP address", "type" : "0-clear, 1-malcious"}
#define SAVING_HASH_REQUEST 108 // {"HASH":"(HASH code)", "type" : "0-clear, 1-malcious"}

//backend response
#define SCAN_RESPONSE 200 //{"processes names":"proc_1, proc_2, proc_3 ...", "processes status":"malicious \ clear \ warning ..."}
#define SUSPICIOUS_PROCESSES_LIST_RESPONSE 201 //{"process names":"proc_1, proc_2, proc_3 ..."}
#define SUSPENDED_PROCESSES_LIST_REESPONSE 202 //{"process names":"proc_1, proc_2, proc_3 ..."}
#define FREE_PROCESS_RESPONSE 203 //{"status":"1 (success) \ 0 (fail)"}
#define BLOCK_PROCESS_RESPONSE 204 //{"status":"1 (success) \ 0 (fail)"}

//server response

#define IP_SCAN_RESPONSE 205 //{"IP status":"malicious \ clear"}
#define HASH_SCAN_RESPONSE 206 //{"HASH status":"malicious \ clear"}
#define SAVING_IP_RESPONSE 207 //{"status":"1 (success) \ 0 (fail)"}
#define SAVING_HASH_RESPONSE 208 // {"status":"1 (success) \ 0 (fail)"}

#define ERROE 111

using std::string;
using std::cout;
using std::cin;
using std::endl;
using std::vector;