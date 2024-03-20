from scapy.all import sniff, TCP, IP, Ether
import time
import subprocess

MAX_CONNS = 50  # For each connection
MAX_TIME = 10  # Time in seconds

Telnet = {23}
FTP = {21}
SSH = {22, 2222}
RDP = {3389}

LOCMAC = "00:00:00:00:00:00"

# Ports counter for each connection
Ports = {"Telnet": {}, "FTP": {}, "SSH": {}, "RDP": {}}


def get_mac_address():
    try:
        command = "ifconfig | grep -o -E '([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2})'"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print("Error:", result.stderr.strip())
    except Exception as e:
        print("Error:", e)


def packet_callback(packet):
    global LOCMAC, Ports
    proto = ""

    if Ether in packet and packet[Ether].dst == LOCMAC and TCP in packet and IP in packet:
        dport = packet[TCP].dport

        if dport in Telnet:
            proto = "Telnet"
        elif dport in FTP:
            proto = "FTP"
        elif dport in SSH:
            proto = "SSH"
        elif dport in RDP:
            proto = "RDP"

        if proto and packet[IP].src in Ports[proto]:
            Ports[proto][packet[IP].src] += 1
        elif proto:
            Ports[proto][packet[IP].src] = 0


def main():
    global LOCMAC, Ports
    LOCMAC = get_mac_address()
    sniff_duration = MAX_TIME

    packets = sniff(prn=packet_callback, timeout=sniff_duration)

    suspicious_connections = []

    for port, data in Ports.items():
        for ip, conn in data.items():
            if conn >= MAX_CONNS:
                suspicious_connections.append(f"{port} - {ip}")

    if suspicious_connections:
        print("\n".join(suspicious_connections))

    # Reset all connection counters
    Ports = {port: {ip: 0 for ip in data} for port, data in Ports.items()}


if __name__ == "__main__":
    main()
