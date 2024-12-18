import json
import socket
import threading
import network 
#CR: filename


def hendel(client_socket, client_address): # CR: english

    print(f"Client connected from {client_address}")
    if (network.getheder(client_socket) == "deiff"):
        data = network.getdata(client_socket)
        with open(f'sniffs/{client_address}_sniffs_serv.json', 'ab') as file:
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
