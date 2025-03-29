"""
server.py

The server runs this Python file, waits for connections from client.py(s)
"""
import logging
import socket
import threading
import time
import json
import select 
import os
import base64
logging.basicConfig(
    level=logging.DEBUG,  # Set the logging level
    format="[SERVER] [%(asctime)s.%(msecs)03d | %(created)f] [%(filename)s@%(funcName)s@%(lineno)d] [%(levelname)s] %(message)s",
	datefmt='%d/%b/%y | %I:%M:%S%p',
    handlers=[logging.FileHandler("log.log"), logging.StreamHandler()],
)
VERSION = "0.0.1"
HOST = "0.0.0.0"
TCP_PORT = 6969
UDP_PORT = TCP_PORT+1 # To keep the program simple the UDP can be by standard 1 integer off the TCP
SERVERNAME = "Alpha"

os.chdir("serverData")

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # ALlow reusing the same host
serverSocket.bind((HOST, TCP_PORT))
serverSocket.listen()
logging.info(f"\nClients only need your hostname and TCP Port\nServer listening on\n{HOST} @ {TCP_PORT} (UDP is {UDP_PORT})\n\nOR\n\n{socket.gethostbyname(socket.gethostname())} @ {TCP_PORT} (UDP is{UDP_PORT})")

def isSocketOpen(sock):
    try:
        # Peek at data without removing it from the buffer
        data = sock.recv(1, socket.MSG_PEEK)
        return bool(data)  # If data is received, the socket is open
    except socket.error:
        return False  # If an error occurs, the socket is closed

def dictToBin(dict):
  return json.dumps(dict).encode('utf-8')

def toDict(bin):
   return json.loads(bin.decode('utf-8'))

def getUserInfo(username):
  username = base64.urlsafe_b64encode(bytes(username, encoding='ascii'))
  if not username in os.listdir():
     return False
  with open(username, "r") as f:
     return f.read()

def createUser(username, password, email=None):
  username = base64.urlsafe_b64encode(bytes(username, encoding='ascii'))
  if username in os.listdir():
      return False
  with open(username, "w") as f:
    f.write(str({"password": password, "email": email}))
    return True

def handleClient(clientSocket, addr):
    signedIn = False
    anonymous = False
    username = None
    password = None
    email = None
    while True:
      if not isSocketOpen(clientSocket):
        return False
      ready, _, _ = select.select([clientSocket], [], [], 0)
      if ready:
          data = toDict(clientSocket.recv(1024))
          logging.info(f"[RAW DATA] ({addr}) {data}")
          if data["type"] == "credentials":
            if not signedIn:
              if data["credentialsType"] == "login":
                anonymous, username, password = False, data["username"], data["password"]
                userInfo = getUserInfo(username)
                if not userInfo:
                  clientSocket.sendall(dictToBin({"type": "fail", "message": f"{addr} tried to log in as a user that either doesn't exist or using the wrong password."}))
                elif not password == userInfo["password"]:
                  clientSocket.sendall(dictToBin({"type": "fail", "message": f"{addr} tried to log in as a user that either doesn't exist or using the wrong password."}))
                else:
                  clientSocket.sendall(dictToBin({"type": "confirm"}))
                  signedIn = True
              elif data["credentialsType"] == "signup":
                anonymous, username, password, email = False, data["username"], data["password"], data["email"]
                if not createUser(username, password, email):
                  clientSocket.sendall(dictToBin({"type": "fail", "message": f"{addr} tried to signup as a user that already exists"}))
                else:
                  clientSocket.sendall(dictToBin({"type": "confirm"}))
                  signedIn = True
              elif data["credentialsType"] == "anon":
                signedIn, anonymous, username, password, email = True, True, None, None, None
                clientSocket.sendall(dictToBin({"type": "confirm"}))
                signedIn = True
            else:
               clientSocket.sendall(dictToBin({"type": "fail", "message": f"{addr} is already logged in"}))
               logging.warning(f"{addr} tried to re-login")
          else:
             logging.warning(f"Malformed message from {addr},\n{data}")

    return

def udpOnlineCheck():
  """UDP server to respond to online checks."""
  udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_socket.bind((HOST, UDP_PORT))
  logging.info(f"UDP Online Check Server running on {HOST}:{UDP_PORT}")

  while True:
      try:
          data, addr = udp_socket.recvfrom(1024)  # Receive UDP message

          data = json.loads(data.decode('utf-8'))

          if data:
              test_dict = {"serverName": SERVERNAME, "serverVersion": VERSION}
              JSON = json.dumps(test_dict).encode('utf-8')
              udp_socket.sendto(JSON, addr)  # Send response
              logging.info(f"Responded to udpOnlineCheck from {addr}({data["clientName"]})")
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