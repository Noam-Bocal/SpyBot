#pragma once
#include "sqlite3.h"
#include "pch.h"

#define BLOCKED_TABLE string("BlockedTable")
#define VIRUSES_TABLE std::string("VirusTable")


class SqliteHelper
{
public:
    SqliteHelper(const char* db);
    ~SqliteHelper();

    vector<string> getBlockedPorcesses();
    vector<string> getViruses();

    bool updateBlockedTable(string action, int pid, string dateTime); //action - remove, add
    bool updateViruses(string name, string dateTime);
    
private:
    sqlite3* _db;
};

