import json
import socket
import threading
import network as ne
import analyze
#CR: filename
def anlsist(parsed_data):
    analyze.detect_suspicious(parsed_data)

def hendel(client_socket: socket.socket, client_address): # CR: english
    
    print(f"Client connected from {client_address}")

    data = ne.getdata(client_socket)
    parsed_data = json.loads(data.decode('utf-8'))
    parsed_data = ne.AES_decrypt(parsed_data, iv_and_aes_kay)
    
    if (parsed_data["header"] == "headersniff"):
        with open(f'sniffs/{client_address}_sniffs_serv.json', 'ab') as file:
            file.write(data) # CR: save to some dictionary variable, not just write to a file, and it will probably be a DB in the future.

        #recomdisehns = anlsist(parsed_data["data"])
        recomdisehns = parsed_data["data"]
        if(recomdisehns == True):
            sec_socket = socket.socket()
            sec_socket.connect(("127.0.0.1", 8840))
            recomdisehns = ne.AES_encrypt(recomdisehns, iv_and_aes_kay)
            ne.sendata(sec_socket, recomdisehns, "headerreq")
            sec_socket.close()
        print(recomdisehns)
        client_socket.close() #if hie finds out that it need to send req just send them her.

    #json_string = json.dumps(parsed_data["data"])
    elif(parsed_data["header"] == "headerreq"):
        with open(f'sniffs/{client_address}_sniffs_serv.json', 'ab') as file:
            file.read()
        recomdisehns = anlsist(file)
        recomdisehns = ne.AES_encrypt(recomdisehns, iv_and_aes_kay)
        ne.sendata(client_socket, recomdisehns, "headerreq")
        print(recomdisehns)

def main():
    ip = "0.0.0.0"
    port  = 8820
    server_socket = socket.socket()
    server_socket.bind((ip, port))
    server_socket.listen()
    print("Server is up and running")

    ne.RSA_start()
    pubkey_client = ne.getdata(server_socket)
    ne.send_pubkey(server_socket)

    aes_key, iv = ne.AES_start()
    iv_and_aes_key = {"aes_key": aes_key, "iv": iv}
    data = json.dumps(iv_and_aes_key).encode('utf-8')

    tosend_encrypt_aes_key = ne.RSA_encrypt(data, pubkey_client)
    ne.sendata(server_socket, tosend_encrypt_aes_key)






    while(True):
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=hendel, args=(client_socket, client_address))
        client_thread.start()
    server_socket.close()
    
if __name__ == "__main__":
    main()
