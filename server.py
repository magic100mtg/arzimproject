import json
import socket
import threading
import network 
import analyze
#CR: filename
def anlsist(parsed_data):
    analyze.detect_suspicious(parsed_data)

def hendel(client_socket, client_address): # CR: english
    

    print(f"Client connected from {client_address}")
    data = network.getdata(client_socket)
    decoded_data = data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    
    if (parsed_data["header"] == "headersniff"):
        with open(f'sniffs/{client_address}_sniffs_serv.json', 'ab') as file:
            file.write(data) # CR: save to some dictionary variable, not just write to a file, and it will probably be a DB in the future.
        #print("Received data:")
        #for idx, summary in enumerate(parsed_data['summary'], start=1):
        #    print(f"{idx}. {summary}")
        client_socket.close() #if hie finds out that it need to send req just send them her.
    json_string = json.dumps(parsed_data["data"])
    recomdisehns = anlsist(json_string)
    print(recomdisehns)

def main():
    ip = "0.0.0.0"
    port  = 8820
    server_socket = socket.socket()
    server_socket.bind((ip, port))
    server_socket.listen()
    print("Server is up and running")
    while(True):
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=hendel, args=(client_socket, client_address))
        client_thread.start()
    server_socket.close()
    
if __name__ == "__main__":
    main()
