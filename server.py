import json
import socket
import threading
import network as ne
import analyze
#CR: filename

class Server:
    with open("enc_rsa_pubkey.pem", "rb") as key_file:  
            pubkey_client = key_file.read()

    def __init__(self):
        s="s"
    

    def anlsist(self, parsed_data):
        analyze.detect_suspicious(parsed_data)

    def hendel(self, client_socket: socket.socket, client_address): # CR: english
        print(f"Client connected from {client_address}")
        encryptit = ne.encrypt()
        
        enserver = ne.encryptedserver()

        tosend_encrypt_AES_key = encryptit.RSA_encrypt(enserver.iv_and_aes_key, self.pubkey_client)
        ne.sendata(client_socket, tosend_encrypt_AES_key)

        parsed_data = enserver.reciv_encrypt(client_socket)



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
    Server1 = Server()

    while(True):
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=Server1.hendel, args=(client_socket, client_address))
        client_thread.start()
    server_socket.close()
    
if __name__ == "__main__":
    main()
