from collections import Counter
from scapy.all import sniff
import json
import socket
import network as ne
import block_ip as block_ip
from scapy.layers.inet import IP, TCP, UDP
import threading
import base64




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
    enclient = ne.encrypted_client()
    enc_aes_key_received = ne.getdata(my_socket)["data"]
    print(enc_aes_key_received)
    aes_key_iv = json.loads((enclient.RSA_decrypt(base64.b64decode(enc_aes_key_received))).decode("utf-8"))
    print(aes_key_iv)
    aes_key = base64.b64decode(aes_key_iv["aes_key"])
    iv = base64.b64decode(aes_key_iv["iv"])
    print(iv, len(iv), aes_key, len(aes_key))
    enclient.set_ARS_key(aes_key, iv)

    snif = 100
    packets = sniff(count=snif, filter="ip")
    packet_data = []

    for pkt in packets:
        info = extract_packet_info(pkt)
        packet_data.append(info)
    
    print(packet_data)
    #to_send = json.dumps(packet_data)
    
    enclient.send_encrypt(my_socket, packet_data, "headersniff")
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
    do_req(data)
    print(data)
    
def do_req(recomdisehns):
    block_ip.block_ip_windows(recomdisehns)
    

def main():
    
    my_socket = socket.socket()
    my_socket.connect(("127.0.0.1", 8820))
    
    #while(True):
    sendsniff = threading.Thread(target=sendsniffpack, args=(my_socket,))
    sendsniff.start()
    #lisentoreq = threading.Thread(target=liesenforrecomdishens, args=(my_socket,))
    #lisentoreq.start()

    
    #data = ne.getdata(my_socket)
    #sendsniffpack(my_socket)
    ###askforrecomdishens(my_socket)
    #if data["header"] == "headersniff":
    #     sendsniffpack(my_socket) #call onl wit te eder, need to pass it?
    #if data["header"] == "headerreq":
    #     askforrecomdishens(my_socket, data)

if __name__ == "__main__":
    main()
    