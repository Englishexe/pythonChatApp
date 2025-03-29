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
import select
import getpass
import hashlib
import re

logging.basicConfig(
    level=logging.DEBUG,  # Set the logging level
    format="[CLIENT] [%(asctime)s.%(msecs)03d | %(created)f] [%(filename)s@%(funcName)s@%(lineno)d] [%(levelname)s] %(message)s",
	datefmt='%d/%b/%y | %I:%M:%S%p',
    handlers=[logging.FileHandler("log.log"), logging.StreamHandler()],
)
VERSION = "0.0.1"
HOST = "0.0.0.0"
PORT = 6969
CLIENTNAME = socket.gethostname()

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
    serverPort = 6969
  try:
    serverPort = int(serverPort)
  except(ValueError):
    serverPort = 6969
    logging.critical("Invalid server port given, defaulting to 6969.")
  return serverPort
#sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def isServerOnline(HOST, PORT, timeout=2):
  """
  The function will deal with changing the port to a pythonChatApp UDP port
  Check if the server is online AND checks if the client (this) and server share the same MAJOR version
  If the server has a lower MINOR version connection isn't allowed
  """
  temporaryClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  temporaryClientSocket.settimeout(timeout)  # Set timeout for response
  logging.info(f"Checking {HOST}, {PORT}")
  try:
    dict = {"clientName": CLIENTNAME, "clientVersion": VERSION}
    dict = json.dumps(dict).encode('utf-8')
    temporaryClientSocket.sendto(dict, (HOST, PORT+1))
    
    data, _ = temporaryClientSocket.recvfrom(1024)
    # {"serverName": "X", "serverVersion": "0.0.1"}
    data = json.loads(data.decode('utf-8'))

    if not int(data['serverVersion'].split(".")[0]) == int(VERSION.split(".")[0]):
      logging.critical(f"Server is incompatible with client. (S: {data['serverVersion']}, C: {VERSION})\nServer is {int(data['serverVersion'].split(".")[0]) - int(VERSION.split(".")[0])} MAJOR versions ahead. (- if behind)")
      return False
    elif not int(data['serverVersion'].split(".")[1]) <= int(VERSION.split(".")[1]):
      logging.critical(f"Server is incompatible with client. (S: {data['serverVersion']}, C: {VERSION})\nServer is {int(data['serverVersion'].split(".")[1]) - int(VERSION.split(".")[1])} MINOR versions ahead. (- if behind)")
      return False
    else:
      logging.info(f"Server is online and compatible with client. (S: {data['serverVersion']}, C: {VERSION})\nServer is {int(data['serverVersion'].split(".")[0]) - int(VERSION.split(".")[0])} MAJOR versions ahead\nServer is {int(data['serverVersion'].split(".")[0]) - int(VERSION.split(".")[0])} MINOR versions ahead\nServer is {int(data['serverVersion'].split(".")[2]) - int(VERSION.split(".")[2])} PATCH versions ahead")
      return True
  
  except socket.timeout:
    logging.warning(f"Server didn't respond, this likely means the server is not online or accessible.")
    return False
  except Exception as e:
    logging.warning(f"Error: {e}")
    return False
  finally:
    temporaryClientSocket.close()

def getCredentials():
  username = input("Username:")
  password = hashlib.md5(getpass.getpass(prompt="Password:").encode()).hexdigest()
  return username, password

def getSignupCredentials():
  while True:
    username = input("Username:")
    password = hashlib.md5(getpass.getpass(prompt="Password:").encode()).hexdigest()
    confirmPassword = hashlib.md5(getpass.getpass(prompt="Confirm Password:").encode()).hexdigest()
    if not password == confirmPassword:
      print("Passwords do not match.")
    else:
      break
  email = input("(OPTIONAL) Email:")
  if email == "" or email == " " or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
    email = None
  return username, password, email

def dictToBin(dict):
  return json.dumps(dict).encode('utf-8')

def binToDict(bin):
   return json.loads(bin.decode('utf-8'))

def waitForResponse(sock, timeout=10):
  startTimeStamp = time.time()
  while startTimeStamp < time.time()+timeout:
    ready, _, _ = select.select([sock], [], [], 0)
    if ready:
      return True
  else:
    return False


def clientStart(clientSocket):
  
  while True:
    username = "anon"
    password = ""
    print("""1. Login\n2. signup\n3. Anon""")
    userChoice = input(">")
    if userChoice == "1":
      username, password = getCredentials()
      dict = {"type": "credentials", "credentialsType": "login", "username": username, "password": password}
      clientSocket.sendall(dictToBin(dict))
      waitForResponse(clientSocket)
      data = binToDict(clientSocket.recv(1024))
      if data["type"] == "confirm":
        break
      else:
        print(f"Fail: f{data["message"]}")
    elif userChoice == "2":
      username, password, email = getSignupCredentials()
      dict = {"type": "credentials", "credentialsType": "signup", "username": username, "password": password, "email": email}
      clientSocket.sendall(dictToBin(dict))
      waitForResponse(clientSocket)
      data = binToDict(clientSocket.recv(1024))
      if data["type"] == "confirm":
        break
      else:
        print(f"Fail: f{data["message"]}")
    elif userChoice == "3":
      print("Anon users have limited permissions")
      dict = {"type": "credentials", "credentialsType": "anon"}
      clientSocket.sendall(dictToBin(dict))
      waitForResponse(clientSocket)
      data = binToDict(clientSocket.recv(1024))
      if data["type"] == "confirm":
        break
      else:
        print(f"Server reported a failure with the following message:\n{data["message"]}")
    else:
      None
  logging.info(f"Logged in as {username}")
  # ready, _, _ = select.select([clientSocket], [], [], 0)

HOST = enterServerAddress()
PORT = enterServerPort()
if isServerOnline(HOST, PORT):
  clientSocket.connect((HOST, PORT))

  clientStart(clientSocket)
  time.sleep(0.1)
  print()
  clientSocket.close()
else:
  exit()