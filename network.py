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

def sendata(sock: socket.socket, data):
    length = (len(data)).to_bytes(4, 'big')
    sock.send((length + data))

def getdata(sock):
    length = int.from_bytes(recvall(sock, 4), 'big')
    return recvall(sock, length)
