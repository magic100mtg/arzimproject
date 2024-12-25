from collections import Counter
from scapy.all import *
import json
import socket
import network as ne
import sos as sos
from scapy.layers.inet import IP, TCP, UDP


def extract_packet_info(pkt):
    if IP in pkt:
            src_ip = pkt[IP].src
            if TCP in pkt:
                dst_port = pkt[TCP].dport
                protocol = "TCP"
            elif UDP in pkt:
                dst_port = pkt[UDP].dport
                protocol = "UDP"
            else:
                return None
                
            return {
                "src_ip": src_ip,
                "dst_port": dst_port,
                "protocol": protocol
            }

def sendsniffpack(my_socket):
    snif = 100
    packets = sniff(count=snif, filter="ip")
    packet_data = []

    for pkt in packets:
        info = extract_packet_info(pkt)
        packet_data.append(info)
    print(packet_data)

    #json_data = json.dumps(packet_data).encode()
    ne.sendata(my_socket, packet_data, "headersniff")
    print("File sent successfully!")

    #snif = 1000
    #packets = sniff(count = snif)
    packet_summary = [str(pkt.summary()) for pkt in packets]
    #json_data = (json.dumps({"summary": packet_summary, "header": "deiff"})).encode()
    #print(packet_summary)
    #ne.sendata(my_socket ,packet_summary, "headersniff")
    #print("File sent successfully!")

def askforrecomdishens(my_socket, data):
    sos.block_ip_windows(data.decode())


def main():

    my_socket = socket.socket()
    my_socket.connect(("127.0.0.1", 8820))
    #data = ne.getdata(my_socket)
    sendsniffpack(my_socket)
    #if data["header"] == "headersniff":
    #     sendsniffpack(my_socket) #call onl wit te eder, need to pass it?
    #if data["header"] == "headerreq":
    #     askforrecomdishens(my_socket, data)
    my_socket.close()

if __name__ == "__main__":
    main()