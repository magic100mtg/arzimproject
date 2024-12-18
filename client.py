from collections import Counter
from scapy.all import *
import json
import socket
import network as ne
def sendsniffpack(my_socket, heder):
    snif = 10
    packets = sniff(count = snif)
    packet_summary = [str(pkt.summary()) for pkt in packets]
    json_data = (json.dumps({"summary": packet_summary})).encode()
    print(packet_summary)
    ne.sendata(my_socket ,json_data, heder)
    print("File sent successfully!")

def askforrecomdishens(my_socket, heder):
    s="a"


def main():
    heder = ""
    hedersniff = "hedersniff"
    hederreq = "hederreq"
    my_socket = socket.socket()
    my_socket.connect(("127.0.0.1", 8820))
    if heder == hedersniff:
        sendsniffpack(my_socket, heder) #call onl wit te eder, need to pass it?
    if heder == hederreq:
        askforrecomdishens(my_socket, heder)
    my_socket.close()

if __name__ == "__main__":
    main()