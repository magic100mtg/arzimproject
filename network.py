import socket
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

def sendata(sock: socket.socket, data, heder = "deiff"):
    length = (len(data)).to_bytes(4, 'big')
    if heder == ('hederreq' or "hederreq"):
        heder = heder.encode('utf-8') # need to do to only one bit
        sock.send(length + heder + data)
    else:
        print("invaled heder")
        sock.send(length + data)
    
def getdata(sock):
    length = int.from_bytes(recvall(sock, 4), 'big')
    return recvall(sock, length)

def getheder(sock):
    length = int.from_bytes(recvall(sock, 4), 'big')
    heder = recvall(sock, 1).decode('utf-8')
    return heder

