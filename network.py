import socket
import json
def recvall(sock, length):
    data = b""
    while len(data) < length: 
        chunk = sock.recv(length - len(data))
        if not chunk:
            print("Connection closed before all data was received.")
            sock.close()
            exit()
        data += chunk
    return data

def sendata(sock, data, header = "deiff"):
    if header == ('headersniff' or "headerreq" or "deiff"):
        to_send = json.dumps({"header": header, "data": data}).encode('utf-8')
        length = (len(to_send)).to_bytes(4, 'big')
        #header = header.encode('utf-8') # need to do to only one bit
        sock.send(length + to_send)
    else:
        print("invaled header")
        sock.send(length + data)
    
def getdata(sock):
    length = int.from_bytes(recvall(sock, 4), 'big')
    return recvall(sock, length)

def getheader(sock):
    return "h"