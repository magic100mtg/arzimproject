import json
import socket
import threading

#CR: filename

def hendel(client_socket, client_address): # CR: english
    print(f"Client connected from {client_address}")
    length = client_socket.recv(4).decode() # CR: still using the number as a string instead of bytes
    if not length:
        print("Failed to receive the length prefix.")
        client_socket.close()
        exit()

    total_length = int(length)
    data = b""
    while len(data) < total_length: # CR: should be a function, this is something you will do a lot (maybe even put it in a different file, the client will want to do this too)
        chunk = client_socket.recv(total_length - len(data))
        if not chunk:
            print("Connection closed before all data was received.")
            client_socket.close()
            exit()
        data += chunk

    with open('{client_address}_sniffs_serv.json', 'wb') as file: # CR: not formatted, this also deletes the clients data upon each new request from the same address
        file.write(data) # CR: save to some dictionary variable, not just write to a file, and it will probably be a DB in the future.
    
    decoded_data = data.decode()
    parsed_data = json.loads(decoded_data)
    print("Received data:")
    for idx, summary in enumerate(parsed_data['summary'], start=1):
        print(f"{idx}. {summary}")
    client_socket.close()

def main():
    server_socket = socket.socket()
    server_socket.bind(("0.0.0.0", 8820)) # CR: port should probably be cli argument, not hardcoded, with default value. read up on Argparser library for python.
    server_socket.listen()
    print("Server is up and running")
    while(True):
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=hendel, args=(client_socket, client_address))
        client_thread.start()
    server_socket.close()
    
if __name__ == "__main__":
    main()
