from scapy.all import sniff, TCP, IP, UDP, ICMP
import sqlite3
import psutil

IPS_TABLE = "BlackListIPs"
SELECT_QUERY = f"SELECT * FROM {IPS_TABLE} WHERE IPAddress=?"
DB_NAME = "/home/noam/implementations/Server/ServerData.db"

def filter(packet):
    return TCP in packet or UDP in packet or ICMP in packet or packet.haslayer(IP)

def print_packet(packet):
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
        if is_malicious_ip(src) or is_malicious_ip(dst):
            print(f"Malicious packet detected: {src} > {dst}")
            identify_process(src)
        else:
            print(f"Packet detected: {src} > {dst}")

def is_malicious_ip(ip):
    connection = sqlite3.connect(DB_NAME)
    try:
        with connection:
            cursor = connection.cursor()
            return ip_exists(ip, cursor)
    finally:
        connection.close()

def ip_exists(ip, cursor):
    cursor.execute(SELECT_QUERY, (ip,))
    return cursor.fetchone() is not None

def identify_process(ip):
    try:
        # Get the process using the IP address
        connections = psutil.net_connections(kind='inet')
        process = next((conn for conn in connections if conn.laddr.ip == ip), None)

        if process:
            process_name = psutil.Process(process.pid).name()
            print(f"Process identified: {process_name} (PID: {process.pid}) associated with IP: {ip}")
        else:
            print(f"Process not found for IP: {ip}")

    except (psutil.NoSuchProcess, psutil.AccessDenied, StopIteration):
        pass

def main():
    sniff(lfilter=filter, prn=print_packet, timeout=10)

if __name__ == "__main__":
    main()
