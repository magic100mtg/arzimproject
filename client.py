from collections import Counter
from scapy.all import *
import json
import socket
import network as ne

def main():
    snif = 10
    packets = sniff(count = snif)

    packet_summary = [str(pkt.summary()) for pkt in packets]
    json_data = (json.dumps({"summary": packet_summary})).encode()

    print(packet_summary)
    my_socket = socket.socket()
    my_socket.connect(("127.0.0.1", 8820))

    ne.sendata(my_socket ,json_data)

    print("File sent successfully!")
    my_socket.close()

if __name__ == "__main__":
    main()