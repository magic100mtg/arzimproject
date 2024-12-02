from collections import Counter
from scapy.all import *
import json
import socket

# CR: filename

snif = 10
#for i in range(snif):
#    packets = [sniff()]
packets = sniff(count = snif)
#packet_summary = [str(pkt.summary()) for pkt in packets]
packet_summary = [str(pkt.summary()) for pkt in packets]
json_data = {"summary": packet_summary}

print(packet_summary)
with open("sniffs.json", "w") as file:
    json.dump(json_data, file)

my_socket = socket.socket()
my_socket.connect(("127.0.0.1", 8820))

with open("sniffs.json", 'r') as file: # CR: why the dumping and reading instead of just sending it as is?
    pac = file.read()
    length = str(len(pac)).zfill(4)
    my_socket.send((length + pac).encode())

print("File sent successfully!")
my_socket.close()

#with open("sniffs.json", 'r') as file:
#    data = json.load(file)
#print("Received data:", data)


# CR: if __name__ == "__main__"
