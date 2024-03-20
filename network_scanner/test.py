import socket
import threading

HOST = "172.29.67.87"
PORT = 3389
NUM_CONNECTIONS = 60

def connect_to_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        print("Connection established")
    except Exception as e:
        print(f"Connection failed: {e}")
    finally:
        s.close()

# Start multiple threads to establish connections
threads = []
for _ in range(NUM_CONNECTIONS):
    t = threading.Thread(target=connect_to_port)
    t.start()
    threads.append(t)

# Wait for all threads to finish
for t in threads:
    t.join()
