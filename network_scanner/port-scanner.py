import socket
import datetime
import os 

#The folder name of the folder that contains the log files.
LOG_FOLDER = "port-scanner.logs/"

#Get the current time to set the name of the log file.
log_name = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S").replace(" ", "&") + ".log"
log = []

#The ports for scanning.
ports = { 21: "FTP",
	      22: "SSH",
	      23: "Telnet",
	      25: "SMTP"}

os.mkdir(LOG_FOLDER)

#Scanning the ports and checks for each port from the dict if its open, 
#then it add all the open ports to the log file.
for key, value in ports.items():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	result = sock.connect_ex(('127.0.0.1', key))

#Check if the port is open
	if result == 0:
		log.append(value + "\n")

	sock.close()

#Open the log file and write the results of the scan
with open(LOG_FOLDER + log_name, "w") as file:
	file.write(''.join(log))
