from collections import Counter
from scapy.all import sniff
import json
import socket
import network as ne
import block_ip as block_ip
from scapy.layers.inet import IP, TCP, UDP
import threading


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
    #print(packet_data)
    packet_data = ne.AES_encrypt(packet_data, iv_and_aes_kay)
    ne.sendata(my_socket, packet_data, "headersniff")
    print("File sent successfully!")
    

    

def liesenforrecomdishens(my_socket):
    ip = "0.0.0.0"
    port  = 8840
    listen_socket = socket.socket() 
    listen_socket.bind((ip, port))
    listen_socket.listen()
    server_socket, server_address = listen_socket.accept()
    print(f"Client connected from {server_address}")
    data = ne.getdata(server_socket)
    parsed_data = json.loads(data.decode('utf-8'))
    do_req(parsed_data)
    print(parsed_data)
    
def do_req(recomdisehns):
    block_ip.block_ip_windows(recomdisehns)
    

def main():
    my_socket = socket.socket()
    my_socket.connect(("127.0.0.1", 8820))
    
    ne.RSA_start()
    ne.send_pubkey(my_socket)

    encrypt_aes_key = ne.getdata(my_socket)
    iv_and_aes_key = ne.RSA_decrypt(encrypt_aes_key)
    

    while(True):
        sendsniff = threading.Thread(target=sendsniffpack, args=(my_socket,))
        sendsniff.start()
        lisentoreq = threading.Thread(target=liesenforrecomdishens, args=(my_socket,))
        lisentoreq.start()

    
    #data = ne.getdata(my_socket)
    sendsniffpack(my_socket)
    ###askforrecomdishens(my_socket)
    #if data["header"] == "headersniff":
    #     sendsniffpack(my_socket) #call onl wit te eder, need to pass it?
    #if data["header"] == "headerreq":
    #     askforrecomdishens(my_socket, data)
    my_socket.close()

if __name__ == "__main__":
    main()
    