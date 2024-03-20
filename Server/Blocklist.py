from requests import get
from sqlite3 import connect
from datetime import date
import schedule
from time import sleep

IPS_TABLE = "BlackListIPs"
INSERT_QUERY = "INSERT INTO " + IPS_TABLE + " (IPAddress, DateAdded) VALUES ('%s', '%s');"
SELECT_QUERY = "SELECT * FROM " + IPS_TABLE + " WHERE IPAddress='%s';"
SOURCE = "https://lists.blocklist.de/lists/all.txt"
DB_NAME = "ServerData.db"
UPDATE_TIME = "00:00"


def getIP():
    IPlist = get(SOURCE).text.split('\n')
    for ip in IPlist:
        yield ip


def isExists(ip, crsr):
    crsr.execute(SELECT_QUERY % ip)
    ans = crsr.fetchall()
    return len(ans) != 0


def blocklistTask():
    connection = connect(DB_NAME)
    crsr = connection.cursor()
    DateAdded = date.today()

    for ip in getIP():
        if not isExists(ip, crsr):
            crsr.executescript(INSERT_QUERY % (ip, DateAdded))

    connection.close()


def main():
    schedule.every().day.at(UPDATE_TIME).do(blocklistTask)
    while True:
        schedule.run_pending()
        sleep(1)


if __name__ == "__main__":
    main()
