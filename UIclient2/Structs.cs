using System.Collections.Generic;
using System.Numerics;

namespace UIclient2
{
    class Structs
    {
        public struct ScanRequest
        {
            public string path_to_yara;
            public string scan_type;
            public string path_to_scan;
            public string recursive;
        }

        public struct FreeRequest
        {
            public int pid;
        }

        public struct BlockRequest
        {
            public int pid;
        }

        public struct KillRequest
        {
            int pid;
        }

        public struct IPScanRequest
        {
            public string ip;
        }

        public struct HashScanRequest
        {
            public List<string> hashes;
        }

        public struct IPSaveRequest
        {
            public string ip;
        }

        public struct HashSaveRequest
        {
            public string file_name;
            public string file_path;
            public string hash;
            public string date_added;
            public bool encrypted;
            public string source;
            public string isolationStatus;
        }
        public struct ScanResponse
        {
            public int status;
            public Dictionary<string, int> procInfo;
        }
        public struct SuspiciousListResponse
        {
            public int status;
            public List<string> procNames;
        }
        public struct SuspendedListResponse
        {
            public int status;
            public List<string> procPids;
        }

        public struct FreeResponse
        {
            public int status;
            public int isWorked;
        }
        public struct BlockResponse
        {
            public int status;
            public int isWorked;
        }
        public struct KillResponse
        {
            public int status;
            public int isWorked;
        }
        public struct IpScanResponse
        {
            public int status;
            public int res;
        }
        public struct HashScanResponse
        {
            public int status;
            public List<int> res;
        }
        public struct SaveIpResponse
        {
            public int status;
            public int isWorked;
        }
        public struct SaveHashResponse
        {
            public int status;
            public int isWorked;
        }

        public struct ChangeScanTimeResponse{
            public int status;
            public int isWorked;
        }

        public struct ChangeScanFolderResponse
        {
            public int status;
            public int isWorked;
        }

        public struct UpdateBlockedTableResponse
        {
            public int status;
            public int isWorked;
        }

        public struct UpdateVirusTableResponse
        {
            public int status;
            public int isWorked;
        }

        public struct GetFolderResponse
        {
            public int status;
            public string folder;
        }

        public struct GetTimeResponse
        {
            public int status;
            public int time;
        }

    }

}

