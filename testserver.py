import json
import socket
import threading
import network as ne
import analyze
import base64


    
def hendel(client_socket, client_address):
    enclient = ne.encrypted_client()
    pubkey_client = enclient.RSA_get_pubkey()
    print(f"Client connected from {client_address}")
    encryptit = ne.encrypt()
    enserver = ne.encrypted_server()
    iv_and_aes_key_bytes = json.dumps(enserver.iv_and_aes_key_b64).encode('utf-8')
    tosend_encrypt_AES_key = encryptit.RSA_encrypt(iv_and_aes_key_bytes, pubkey_client)
    tosend_encrypt_AES_key_b64 = (base64.b64encode(tosend_encrypt_AES_key)).decode('utf-8')
    ne.sendata(client_socket, tosend_encrypt_AES_key_b64)

ip = "0.0.0.0"
port  = 8821
server_socket = socket.socket()
server_socket.bind((ip, port))
server_socket.listen()
print("Server is up and running")
client_socket, client_address = server_socket.accept()
client_thread = threading.Thread(target=hendel, args=(client_socket, client_address))
client_thread.start()
