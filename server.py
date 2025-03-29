"""
server.py

The server runs this Python file, waits for connections from client.py(s)
"""
import logging
import socket
import threading
import time
import json

logging.basicConfig(
    level=logging.DEBUG,  # Set the logging level
    format="[SERVER] [%(asctime)s.%(msecs)03d | %(created)f] [%(filename)s@%(funcName)s@%(lineno)d] [%(levelname)s] %(message)s",
	datefmt='%d/%b/%y | %I:%M:%S%p',
    handlers=[logging.FileHandler("log.log"), logging.StreamHandler()],
)
HOST = "0.0.0.0"
TCP_PORT = 6969
UDP_PORT = TCP_PORT+1 # To keep the program simple the UDP can be by standard 1 integer off the TCP
SERVERNAME = "Alpha"

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # ALlow reusing the same host
serverSocket.bind((HOST, TCP_PORT))
serverSocket.listen()
logging.info(f"\nClients only need your hostname and TCP Port\nServer listening on\n{HOST} @ {TCP_PORT} (UDP is {UDP_PORT})\n\nOR\n\n{socket.gethostbyname(socket.gethostname())} @ {TCP_PORT} (UDP is{UDP_PORT})")
def handleClient(clientSocket, addr):
    clientSocket.sendall(b'Hey')
    clientSocket.close()
    return

def udpOnlineCheck():
  """UDP server to respond to online checks."""
  udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_socket.bind((HOST, UDP_PORT))
  logging.info(f"UDP Online Check Server running on {HOST}:{UDP_PORT}")

  while True:
      try:
          data, addr = udp_socket.recvfrom(1024)  # Receive UDP message
          if data == b"PING":
              test_dict = {"serverName": "X", "serverVersion": "0.0.1"}
              JSON = json.dumps(test_dict).encode('utf-8')
              udp_socket.sendto(JSON, addr)  # Send response
              logging.info(f"Responded to PING from {addr}")
      except Exception as e:
          logging.error(f"UDP error: {e}")
    

# Start UDP server in a separate process
udp_process = threading.Thread(target=udpOnlineCheck, daemon=True)
udp_process.start()

while True:
    client_socket, addr = serverSocket.accept()
    logging.info(f"New TCP connection from {addr}")
    new_client = threading.Thread(target=handleClient, args=(client_socket, addr), daemon=True)
    new_client.start()