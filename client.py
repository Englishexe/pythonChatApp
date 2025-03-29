"""
client.py

The client runs this Python file, connects to a server.py


data_parts = []
while True:
    chunk, addr = udp_socket.recvfrom(4096)  # Read 4KB at a time
    data_parts.append(chunk)
    
    if len(chunk) < 4096:  # If we received less than 4KB, it's the last part
        break

full_data = b''.join(data_parts)  # Reassemble message

"""

import socket
import time
import logging
import json

logging.basicConfig(
    level=logging.DEBUG,  # Set the logging level
    format="[CLIENT] [%(asctime)s.%(msecs)03d | %(created)f] [%(filename)s@%(funcName)s@%(lineno)d] [%(levelname)s] %(message)s",
	datefmt='%d/%b/%y | %I:%M:%S%p',
    handlers=[logging.FileHandler("log.log"), logging.StreamHandler()],
)

host = "0.0.0.0"
port = 6969

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def enterServerAddress() -> str:
  """
  Ask the user for a server address with light error catching

  returns a string
  """
  print("Leave blank for localhost")
  serverAddress = input("Server address:")
  if serverAddress == "" or serverAddress == " ":
    serverAddress = "0.0.0.0"
    try:
      socket.inet_aton(serverAddress)
    except(socket.error):
      serverAddress = "0.0.0.0"
      logging.critical("Invalid server address given, defaulting to localhost.")
  return serverAddress

def enterServerPort() -> int:
  """
  Ask the user for a server port with light error catching

  returns an integer
  """
  print("Leave blank for port 6969")
  serverPort = input("Server Port:")
  if serverPort == "" or serverPort == " ":
    serverPort == 6969
  try:
    serverPort = int(serverPort)
  except(TypeError):
    serverPort = 6969
    logging.critical("Invalid server port given, defaulting to 6969.")
  return serverPort
#sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def isServerOnline(host, port, timeout=2):
  """
  The function will deal with changing the port to a pythonChatApp UDP port
  Check if the server is online AND if it registers as a pythonChatApp server
  Also checks if the client (this) and server share the same MAJOR version
  Warns if the server is a lower MINOR version
  """
  temporaryClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  temporaryClientSocket.settimeout(timeout)  # Set timeout for response
  logging.info(f"Checking {host}, {port}")
  try:
    # Send an empty "ping" message
    temporaryClientSocket.sendto(b"PING", (host, port+1))

    # Wait for response
    data, _ = temporaryClientSocket.recvfrom(1024)

    # {"serverName": "X", "serverVersion": "0.0.1", ""}
    data = json.loads(data.decode('utf-8'))

    if data['serverVersion'].split(".")[0] == "0":
      logging.info("MAJOR OK")
    if data['serverVersion'].split(".")[1] == "0":
      logging.info("MINOR OK")
    if data['serverVersion'].split(".")[2] == "1":
      logging.info("PATCH OK")
    if data == b"PONG":
        logging.info("Server confirmed")
        return True
  except socket.timeout:
    return False
  except Exception as e:
    print(f"Error: {e}")
    return False
  finally:
    temporaryClientSocket.close()

isServerOnline(host, port)
clientSocket.connect((host, port))
time.sleep(0.1)
print(socket.gethostname())
clientSocket.close()