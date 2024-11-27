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

total_length = int(length)
data = b""
while len(data) < total_length:
    chunk = client_socket.recv(total_length - len(data))
    if not chunk:
        print("Connection closed before all data was received.")
        client_socket.close()
        server_socket.close()
        exit()
    data += chunk
decoded_data = data.decode()

with open('sniffs_serv.json', 'w') as file:
        json.dump(decoded_data, file)

parsed_data = json.loads(decoded_data)
print("Received data:")
for idx, summary in enumerate(parsed_data['summary'], start=1):
    print(f"{idx}. {summary}")

client_socket.close()
server_socket.close()