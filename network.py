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
    

def recvall(sock : socket.socket, length : int) -> bytes:
    data = b""
    while len(data) < length:
        try:
            chunk = sock.recv(length - len(data))
            if not chunk:
                sock.close()
                raise ConnectionError("Connection closed before all data was received.")
        except ConnectionError as e:
            print(f"Error: {e}")
            return b""
        data += chunk
    return data

def getdata(sock) -> dict | None:
    length_data = recvall(sock, 4)
    if not length_data:
        print("Client closed connection before sending data length.")
        return None

    try:
        length = int.from_bytes(length_data, 'big')
        if length <= 0:
            print("Invalid data length received.")
            return None

        data = recvall(sock, length)
        if not data:
            print("Client closed connection before sending full data.")
            return None

        return json.loads(data.decode('utf-8'))
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Invalid JSON data received: {e}")
        return None

# def sendata(sock: socket.socket, data: str, header = "deiff"):
#     if header in ("headersniff", "deiff", "pubkey"):
#         to_send = (json.dumps({"header": header, "data": data})).encode('utf-8')
#         length = (len(to_send)).to_bytes(4, 'big')
#         sock.sendall(length + to_send)
#     elif(header == "headerreq"):
#         to_send = (json.dumps({"header": header, "data": None})).encode('utf-8')
#         length = (len(to_send)).to_bytes(4, 'big')
#         sock.sendall(length + to_send)
#     else:
#         print("invalid header")
#         to_send = (json.dumps({"header": "invalid", "data": None})).encode('utf-8')
#         length = (len(to_send)).to_bytes(4, 'big')
#         sock.sendall(length + to_send)

def sendata(sock: socket.socket, data: str, header="deiff"):
    # Define allowed headers including the new ones.
    allowed_headers = (
        "headersniff", "deiff", "pubkey", "headerreq",
        "login", "measurement_update", "get_all_measurements",
        "request_recommendations", "response"
    )
    
    if header in allowed_headers:
        # For headerreq, always send data as None
        if header == "headerreq":
            message = {"header": header, "data": None}
        else:
            message = {"header": header, "data": data}
        to_send = json.dumps(message).encode('utf-8')
        length = len(to_send).to_bytes(4, 'big')
        sock.sendall(length + to_send)
    else:
        print("invalid header")
        to_send = json.dumps({"header": "invalid", "data": None}).encode('utf-8')
        length = len(to_send).to_bytes(4, 'big')
        sock.sendall(length + to_send)



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
        data_encode = data.encode("utf-8")
        msg = pad(data_encode, 16)
        ciphertext = AES_cipher.encrypt(msg)
        ciphertext_in_str = base64.b64encode(ciphertext).decode("utf-8")
        return ciphertext_in_str

    def AES_decrypt(self, encrypt_data, iv_and_aes_kay):
        if isinstance(encrypt_data, str):
            encrypt_data = base64.b64decode(encrypt_data)  # המרת סטרינג לבייטים

        AES_cipher = AES.new(
        base64.b64decode(iv_and_aes_kay["aes_key"]),
        AES.MODE_CBC,
        base64.b64decode(iv_and_aes_kay["iv"])
        )

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

    def RSA_encrypt(self, data: bytes, publickey):
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
        self.aes_key = get_random_bytes(16) 
        self.iv = get_random_bytes(16)
        #self.aes_key, self.iv = self.AES_start()

        self.iv_and_aes_key_b64 = {"aes_key": base64.b64encode(self.aes_key).decode('utf-8'), "iv": base64.b64encode(self.iv).decode('utf-8')}
        super().__init__()  # Call parent constructor
        self.enc_rsa_pubkey = "enc_rsa_pubkey_server.pem"
        self.enc_rsa_privatekey = "enc_rsa_privatekey_server.pem"

    def send_AES_encrypt(self , sock, data: str, header = "deiff"):
        message = json.dumps({"header": header, "data": data})
        ciphertext = self.AES_encrypt(message, self.iv_and_aes_key_b64)
        sendata(sock, ciphertext, header)
    
    def reciv_AES_encrypt(self, sock):
        received_json = getdata(sock)
    
        if not received_json or "data" not in received_json:
            print("No valid data received. Closing connection.")
            return None

        encrypted_data = received_json["data"]
    
        if encrypted_data is None:
            print("Error: Encrypted data is None.")
            return None

        try:
            decrypted_message = self.AES_decrypt(encrypted_data, self.iv_and_aes_key_b64)
            if not decrypted_message: 
                print("Error: Decryption failed and returned None or empty.")
                return None

            try:
                parsed_message = json.loads(decrypted_message.decode('utf-8'))
                return parsed_message
            except json.JSONDecodeError:
                print(f"Error: Decryption result is not valid JSON. Data: {decrypted_message}")
                return None

        except Exception as e:
            print(f"Unexpected error during decryption: {e}")
            return None

        
class encrypted_client(encrypt):
    def __init__(self):

        super().__init__()  # Call parent constructor
        self.enc_rsa_pubkey = "enc_rsa_pubkey_client.pem"
        self.enc_rsa_privatekey = "enc_rsa_privatekey_client.pem"


    def set_ARS_key(self, aes_key:bytes, iv:bytes):
        self.ARS_key = {"aes_key": base64.b64encode(aes_key).decode(), "iv": base64.b64encode(iv).decode()}
    
    def send_encrypt(self , sock:socket.socket, data , header = "deiff"): #data need to be Json
        message = json.dumps({"header": header, "data": data})
        ciphertext = self.AES_encrypt(message, self.ARS_key)
        sendata(sock, ciphertext, header)
    
    def reciv_encrypt(self, sock):
        received_json = getdata(sock)
    
        if not received_json or "data" not in received_json:
            print("No valid data received. Closing connection.")
            return None

        encrypted_data = received_json["data"]
    
        if encrypted_data is None:
            print("Error: Encrypted data is None.")
            return None

        try:
            decrypted_message = self.AES_decrypt(encrypted_data, self.ARS_key)
            if not decrypted_message: 
                print("Error: Decryption failed and returned None or empty.")
                return None

            try:
                parsed_message = json.loads(decrypted_message.decode('utf-8'))
                return parsed_message
            except json.JSONDecodeError:
                print(f"Error: Decryption result is not valid JSON. Data: {decrypted_message}")
                return None

        except Exception as e:
            print(f"Unexpected error during decryption: {e}")
            return None
    
    
    


    


        



