import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


def recvall(sock, length) -> bytes:

    data = b""
    while len(data) < length: 
        chunk = sock.recv(length - len(data))
        if not chunk:
            print("Connection closed before all data was received.")
            sock.close()
            exit()
        data += chunk
    return data

def sendata(sock, data = None, header = "deiff"):

    if header == ('headersniff' or "deiff" or "pubkey"):
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


def AES_start():
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    return aes_key, iv

def AES_encrypt(data, iv_and_aes_kay):

    AES_cipher = AES.new(iv_and_aes_kay["aes_key"], AES.MODE_CBC, iv_and_aes_kay["iv"])
    msg = pad(data, 16)
    ciphertext = AES_cipher.encrypt(msg)
    return ciphertext, msg

def AES_decrypt(encrypt_data, iv_and_aes_kay):
    AES_cipher = AES.new(iv_and_aes_kay["aes_key"], AES.MODE_CBC, iv_and_aes_kay["iv"])
    pad_data = AES_cipher.decrypt(encrypt_data)
    return unpad(pad_data, 16)



def RSA_start():
    rsakey = RSA.generate(2048) 
    rsakey_data = rsakey.export_key() 
    rsakey_pub_data = rsakey.public_key().export_key() 
    with open("enc_rsa_privatekey", "wb") as key_file: 
     key_file.write(rsakey_data) 
    with open("enc_rsa_pubkey.pem", "wb") as key_file:  
     key_file.write(rsakey_pub_data)

def RSA_get_pubkey():
    with open("enc_rsa_pubkey.pem", "rb") as key_file:  
     pubkey = key_file.read
    return pubkey

def send_pubkey(sock):
    sendata(sock = sock, data = RSA_get_pubkey(), header = "pubkey")




def RSA_encrypt(data, publickey):
    rsa_cipher = PKCS1_OAEP.new(publickey.public_key())
    enc_msg = rsa_cipher.encrypt(data)
    return enc_msg


def RSA_decrypt(enc_msg):
    with open("enc_rsa_privatekey.pem", "rb") as key_file:
        private_key = RSA.import_key(key_file.read())
    rsa_cipher = PKCS1_OAEP.new(private_key)
    msg = rsa_cipher.encrypt(enc_msg)
    return msg



    



