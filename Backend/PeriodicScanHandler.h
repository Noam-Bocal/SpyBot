#pragma once
#include "RequestHandler.h"
#include "PeriodicScanHandler.h"
#include "JsonResponsePacketSerializer.h"
#include "JsonRequestPacketDeserializer.h"
#include <libnotify/notify.h>
#include "Helper.h"


class PeriodicScanHandler {
public:
    static string handleRequest(RequestInfo reqInfo);
    static void periodicScan();

private:
    static int _time;
    static string _folder;
    static std::mutex _lock;

    static string changeTime(const RequestInfo& reqInfo);
    static string changeFolder(const RequestInfo& reqInfo);

    static string getTime(const RequestInfo& reqInfo);
    static string getFolder(const RequestInfo& reqInfo);

    static void packetScan(); //scans for packets that speak with malicous ips
    static void portsConnectionsScan(); //scans if a computer on the same netwrok sends many conenction requests in a short time
    static void openPortsScan(); //scans for open ports on the computer
    static void blockPid(int pid); // block pid
    static void sctScan(); //scan hooks in the sct 
    static void idtScan(); //scan hooks in the idt

    static void writeToScanResults(const string& message);

    static void popUp(const string& message); //functiom that will open pop up if there was a match

    static void notificationClosed(NotifyNotification *notification, gpointer data);
};
