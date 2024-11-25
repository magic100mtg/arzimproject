from collections import Counter
from scapy.all import *
import json
import socket

snif = 10
for i in range(snif):
    packets = [sniff()]
#packets = sniff(count = 10)
packet_summary = [str(pkt.summary()) for pkt in packets]
json_data = {"summary": packet_summary}

print(packets.summary())
with open("sniffs.json", "w") as file:
    json.dump(json_data, file)

my_socket = socket.socket()
my_socket.connect(("127.0.0.1", 8820))

with open("sniffs.json", 'r') as file:
    pac = file.read()  
    length = str(len(pac)).zfill(4)
    my_socket.send((length + pac).encode())

print("File sent successfully!")
my_socket.close()

#with open("sniffs.json", 'r') as file:
#    data = json.load(file)
#print("Received data:", data)
