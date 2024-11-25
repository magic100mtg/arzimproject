import json
import socket

server_socket = socket.socket()
server_socket.bind(("0.0.0.0", 8820))
server_socket.listen()
print("Server is up and running")
(client_socket, client_address) = server_socket.accept()
print("Client connected")

length = client_socket.recv(4).decode()
if not length:
    print("Failed to receive the length prefix.")
    client_socket.close()
    server_socket.close()
    exit()

data = client_socket.recv(int(length)).decode()


with open('sniffs_serv.json', 'w') as file:
        json.dump(data, file)
        
with open("sniffs_serv.json", 'r') as file:
    data = json.load(file)
print("Received data:", data)

client_socket.close()
server_socket.close()