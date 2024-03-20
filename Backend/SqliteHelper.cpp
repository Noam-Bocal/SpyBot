#include "SqliteHelper.h"

SqliteHelper::SqliteHelper(const char *db)
{
    string query_1 = "", query_2 = "";

	if (sqlite3_open(db, &_db) != SQLITE_OK) {
		_db = nullptr;
		std::cout << "Failed to open DB\n";
		exit(1);
	}
	// Iniate Relevant SQL Tables
	char** errMessage = nullptr;

	query_1 = query_1 + "CREATE TABLE IF NOT EXISTS " + BLOCKED_TABLE + " (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, PID INTEGER NOT NULL, DateAdded TEXT);";
	query_2 = query_2 + "CREATE TABLE IF NOT EXISTS " + VIRUSES_TABLE + " (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, Name TEXT NOT NULL, DateAdded TEXT);";

	sqlite3_exec(_db, query_1.c_str(), nullptr, nullptr, errMessage);
	sqlite3_exec(_db, query_2.c_str(), nullptr, nullptr, errMessage);
}

SqliteHelper::~SqliteHelper() {
	sqlite3_close(_db);
	_db = nullptr;
}

vector<string> SqliteHelper::getViruses()
{
    vector<string> procNames;
    string query = "SELECT Name FROM " + VIRUSES_TABLE + ";";
    char** errMessage = nullptr;

    sqlite3_exec(_db, query.c_str(), [](void* data, int argc, char** argv, char** azColName) {
        for (int i = 0; i < argc; i++) 
            static_cast<vector<string>*>(data)->push_back(argv[i]);
        return 0;
    }, &procNames, errMessage);

    return procNames;
}

vector<string> SqliteHelper::getBlockedPorcesses()
{
	vector<string> pids;
	string query = "SELECT PID FROM " + BLOCKED_TABLE + ";";
	char** errMessage = nullptr;

	sqlite3_exec(_db, query.c_str(), [](void* data, int argc, char** argv, char** azColName){
		for(int i=0; i < argc; i++)
			static_cast<vector<string>*>(data)->push_back(argv[i]);
		return 0;
	}, &pids, errMessage);

	return pids;
}

bool SqliteHelper::updateBlockedTable(string action, int pid, string dateTime)
{
    string query = "";
    char** errMessage = nullptr;

    if (action == "add")
        query = "INSERT INTO " + BLOCKED_TABLE + "(PID, DateAdded) VALUES(" + std::to_string(pid) + ", '" + dateTime + "');";
    else
        query = "DELETE FROM " + BLOCKED_TABLE + " WHERE PID = " + std::to_string(pid) + ";";
    return sqlite3_exec(_db, query.c_str(), nullptr, nullptr, errMessage) == SQLITE_OK;
}

bool SqliteHelper::updateViruses(string name, string dateTime)
{
	string query = "INSERT INTO " + VIRUSES_TABLE + "(Name, DateAdded) VALUES('" + name  + "', '" + dateTime + "');";
	char** errMessage = nullptr;
    return sqlite3_exec(_db, query.c_str(), nullptr, nullptr, errMessage) == SQLITE_OK;
}

