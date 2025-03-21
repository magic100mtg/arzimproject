import threading

import network as ne
import socket
def cool(mtsock):
    enc_aes_key_received = ne.getdata(my_socket)["data"]
    print(enc_aes_key_received)

my_socket = socket.socket()
my_socket.connect(("127.0.0.1", 8821))
sendsniff = threading.Thread(target=cool, args=(my_socket,))
sendsniff.start()
