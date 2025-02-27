import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import base64


def start_RSA(): #do on your dvice
    enclient = encrypted_client()
    enclient.RSA_start()
    enserver = encrypted_server()
    enserver.RSA_start()
    

def recvall(sock : socket.socket, length : int) -> dict:
    data = b""
    while len(data) < length: 
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before all data was received.")
        data += chunk
    in_json = json.loads(data.decode('utf-8'))
    return in_json

def sendata(sock: socket.socket, data:str, header = "deiff"):
    print(header)
    if header in ('headersniff', "deiff", "pubkey"):
        to_send = (json.dumps({"header": header, "data": data})).encode('utf-8')
        length = (len(to_send)).to_bytes(4, 'big')
        sock.send(length + to_send)
    elif(header == "headerreq"):
        to_send = (json.dumps({"header": header, "data": None})).encode('utf-8')
        length = (len(to_send)).to_bytes(4, 'big')
        sock.send(length + to_send)
    else:
        print("invaled header")
        #sock.send(length + data)

def getdata(sock):
    length = int.from_bytes(recvall(sock, 4), 'big')
    return recvall(sock, length)

def getheader(sock):
    return "h"

class encrypt:
    def __init__(self): 
        self.enc_rsa_pubkey = "enc_rsa_pubkey.pem"
        self.enc_rsa_privatekey = "enc_rsa_privatekey.pem"
    
    def RSA_get_pubkey(self):
        with open(self.enc_rsa_pubkey, "rb") as key_file:  
            pubkey = key_file.read()
        return pubkey
    
    def RSA_get_privet(self):
        with open(self.enc_rsa_privatekey, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())
        return private_key
    
    def AES_start(self):
        aes_key = get_random_bytes(16)
        iv = get_random_bytes(16)
        return aes_key, iv

    def AES_encrypt(self, data:str, iv_and_aes_kay) -> str:
        AES_cipher = AES.new(base64.b64decode(iv_and_aes_kay["aes_key"]), AES.MODE_CBC, base64.b64decode(iv_and_aes_kay["iv"]))
        msg = pad(data.encode("utf-8"), 16)
        ciphertext = AES_cipher.encrypt(msg)
        ciphertext_in_str = ciphertext.decode("utf-8")
        return ciphertext_in_str

    def AES_decrypt(self, encrypt_data, iv_and_aes_kay):
        AES_cipher = AES.new(base64.b64decode(iv_and_aes_kay["aes_key"]), AES.MODE_CBC, base64.b64decode(iv_and_aes_kay["iv"]))
        pad_data = AES_cipher.decrypt(encrypt_data)
        return unpad(pad_data, 16)

    def RSA_start(self):
        rsakey = RSA.generate(2048) 
        rsakey_data = rsakey.export_key() 
        rsakey_pub_data = rsakey.public_key().export_key() 
        with open(self.enc_rsa_privatekey, "wb") as key_file: 
            key_file.write(rsakey_data) 
        with open(self.enc_rsa_pubkey, "wb") as key_file:  
            key_file.write(rsakey_pub_data)

    #def send_pubkey(self, sock):
    #    sendata(sock = sock, data = encrypt.RSA_get_pubkey(self), header = "pubkey")

    def RSA_encrypt(self, data, publickey):
        rsa_key = RSA.import_key(publickey)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        enc_msg = rsa_cipher.encrypt(data)
        return enc_msg

    def RSA_decrypt(self, enc_msg):
        rsa_cipher = PKCS1_OAEP.new(encrypt.RSA_get_privet(self))
        msg = rsa_cipher.decrypt(enc_msg)
        return msg


class encrypted_server(encrypt):
    def __init__(self):
          # Create an instance of Encrypt class
        self.aes_key, self.iv = self.AES_start()

        self.iv_and_aes_key_b64 = {"aes_key": base64.b64encode(self.aes_key).decode(), "iv": base64.b64encode(self.iv).decode()}
        super().__init__()  # Call parent constructor
        self.enc_rsa_pubkey = "enc_rsa_pubkey_server.pem"
        self.enc_rsa_privatekey = "enc_rsa_privatekey_server.pem"

    def send_AES_encrypt(self , sock, data:str, header = "deiff"):
        ciphertext = self.AES_encrypt(data, self.iv_and_aes_key_b64)
        sendata(sock, ciphertext, header)
    
    def reciv_AES_encrypt(self, sock):
        data = getdata(sock)
        decrypt_data =  self.AES_decrypt(data, self.iv_and_aes_key_b64)
        parsed_data = json.loads(decrypt_data.decode('utf-8'))
        return parsed_data
        
class encrypted_client(encrypt):
    def __init__(self):

        super().__init__()  # Call parent constructor
        self.enc_rsa_pubkey = "enc_rsa_pubkey_client.pem"
        self.enc_rsa_privatekey = "enc_rsa_privatekey_client.pem"


    def set_ARS_key(self, aes_key:bytes, iv:bytes):
        self.ARS_key = {"aes_key": base64.b64encode(aes_key).decode(), "iv": base64.b64encode(iv).decode()}
    
    def send_encrypt(self , sock, data:str, header = "deiff"):
        ciphertext = self.AES_encrypt(data, self.ARS_key)
        sendata(sock, ciphertext, header)
    
    def reciv_encrypt(self, sock):
        data = getdata(sock)
        decrypt_data =  self.AES_decrypt(data, self.ARS_key)
        parsed_data = json.loads(decrypt_data.decode('utf-8'))
        return parsed_data
    
    
    


    


        



