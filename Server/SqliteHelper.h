#pragma once
#include "sqlite3.h"
#include "pch.h"

#define IPS_TABLE "BlackListIPs"
#define HASHES_TABLE "BlackListHashes"

class SqliteHelper
{
public:
    SqliteHelper(const char* db);
    ~SqliteHelper();
    bool IPisMalicious(string ip);
    bool HASHisMalicious(string hash);
    bool addIP(string ip, string DateAdded, string Source);
    bool addHASH(string FileName, string FilePath, string FileHash_SHA256, string DateAdded, bool Encrypted, string SourceDetection, string IsolationStatus);
    
    
private:
    sqlite3* _db;

};
