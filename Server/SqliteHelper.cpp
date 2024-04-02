#include "SqliteHelper.h"

SqliteHelper::SqliteHelper(const char* db) {
	string query_1 = "", query_2 = "";

	if (sqlite3_open(db, &_db) != SQLITE_OK) {
		_db = nullptr;
		std::cout << "Failed to open DB\n";
		exit(1);
	}
	// Iniate Relevant SQL Tables
	char** errMessage = nullptr;

	query_1 = query_1 + "CREATE TABLE IF NOT EXISTS " + IPS_TABLE + " (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, IPAddress TEXT NOT NULL, DateAdded TEXT, Source TEXT DEFAULT 'Blocklist.de' NOT NULL);";
	query_2 = query_2 + "CREATE TABLE IF NOT EXISTS " + HASHES_TABLE + " (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, FileName TEXT NOT NULL, FilePath TEXT, FileHash_SHA256 TEXT NOT NULL, DateAdded TEXT, Encrypted BOOLEAN NOT NULL, SourceDetection TEXT, IsolationStatus TEXT);";

	sqlite3_exec(_db, query_1.c_str(), nullptr, nullptr, errMessage);
	sqlite3_exec(_db, query_2.c_str(), nullptr, nullptr, errMessage);
}

SqliteHelper::~SqliteHelper() {
	sqlite3_close(_db);
	_db = nullptr;
}

bool SqliteHelper::IPisMalicious(string ip) {
	string query = "";
	query = query + "SELECT COUNT(*) FROM " + IPS_TABLE + " WHERE IPAddress = '" + ip + "'; ";

	char** errMessage = nullptr;
	int ans;
	sqlite3_exec(_db, query.c_str(), [](void* data, int argc, char** argv, char** azColName) {
		if (argc != 0) {
			int* existRes = static_cast<int*>(data);
			*existRes = atoi(argv[0]);
		}
		return 0;
		}, &ans, errMessage);

	return ans >= 1;
}


bool SqliteHelper::HASHisMalicious(string hash) {
	string query = "";
	query = query + "SELECT COUNT(*) FROM " + HASHES_TABLE + " WHERE FileHash_SHA256 = '" + hash + "'; ";

	char** errMessage = nullptr;
	int ans;
	sqlite3_exec(_db, query.c_str(), [](void* data, int argc, char** argv, char** azColName) {
		if (argc != 0) {
			int* existRes = static_cast<int*>(data);
			*existRes = atoi(argv[0]);
		}
		return 0;
		}, &ans, errMessage);

	return ans >= 1;
}

bool SqliteHelper::addIP(string ip, string DateAdded, string Source) {
	string query = "";
	query = "INSERT INTO " + string(IPS_TABLE) + "(IPAddress, DateAdded, Source) VALUES('" + ip + "', '" + DateAdded + "', '" + Source + "');";
	char** errMessage = nullptr;
	return sqlite3_exec(_db, query.c_str(), nullptr, nullptr, errMessage) == SQLITE_OK;
}

bool SqliteHelper::addHASH(string FileName, string FilePath, string FileHash_SHA256, string DateAdded, bool Encrypted, string SourceDetection, string IsolationStatus) {
	 string encryptedStr = Encrypted ? "True" : "False";

	std::string query = std::string("INSERT INTO ") + HASHES_TABLE + std::string("(FileName, FilePath, FileHash_SHA256, DateAdded, Encrypted, SourceDetection, IsolationStatus) VALUES(?, ?, ?, ?, ?, ?, ?);");
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(_db, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, FileName.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, FilePath.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, FileHash_SHA256.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, DateAdded.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, encryptedStr.c_str(), -1, SQLITE_STATIC); // Use encryptedStr
        sqlite3_bind_text(stmt, 6, SourceDetection.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, IsolationStatus.c_str(), -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return true;
        }
    }
    
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    
    return false;
}

