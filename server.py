import json
import socket
import threading
import network as ne
import analyze
import base64

#CR: filename

class Server:
    enclient = ne.encrypted_client()
    pubkey_client = enclient.RSA_get_pubkey()

    def __init__(self):
        s="s"
    
    def anlsist(self, parsed_data):
        analyze.detect_suspicious(parsed_data)

    def hendel(self, client_socket: socket.socket, client_address): # CR: english
        print(f"Client connected from {client_address}")
        encryptit = ne.encrypt()
        enserver = ne.encrypted_server()
        iv_and_aes_key_bytes = json.dumps(enserver.iv_and_aes_key_b64).encode('utf-8')
        tosend_encrypt_AES_key = encryptit.RSA_encrypt(iv_and_aes_key_bytes, self.pubkey_client)
        tosend_encrypt_AES_key_b64 = (base64.b64encode(tosend_encrypt_AES_key)).decode('utf-8')
        ne.sendata(client_socket, tosend_encrypt_AES_key_b64)
        print("all good")
        parsed_data = enserver.reciv_AES_encrypt(client_socket)
        print(parsed_data)
        if (parsed_data['header'] == "headersniff"): # type: ignore
            #with open(f'sniffs/{client_address}_sniffs_serv.json', 'ab') as file:
            #    file.write(parsed_data["data"]) # CR: save to some dictionary variable, not just write to a file, and it will probably be a DB in the future.

            #recomdisehns = anlsist(parsed_data["data"])
            recomdisehns = parsed_data["data"] # type: ignore
            print(recomdisehns)
            if(recomdisehns == True):
                sec_socket = socket.socket()
                sec_socket.connect(("127.0.0.1", 8840))
                enserver.send_AES_encrypt(sec_socket, recomdisehns, "headerreq")
                sec_socket.close()
            print(recomdisehns)
            client_socket.close() #if hie finds out that it need to send req just send them her.

        #json_string = json.dumps(parsed_data["data"])
        elif(parsed_data["header"] == "headerreq"): # type: ignore
            with open(f'sniffs/{client_address}_sniffs_serv.json', 'ab') as file:
                file.read()
            recomdisehns = "d" #anlsist(file)
            enserver.send_AES_encrypt(client_socket, recomdisehns, "headerreq")
            print(recomdisehns)

def main():

    ip = "0.0.0.0"
    port  = 8820
    server_socket = socket.socket()
    server_socket.bind((ip, port))
    server_socket.listen()
    print("Server is up and running")
    Server1 = Server()

    #while(True):
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(target=Server1.hendel, args=(client_socket, client_address))
    client_thread.start()
    #server_socket.close()
    
if __name__ == "__main__":
    main()
