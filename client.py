# from collections import Counter
# from scapy.all import sniff
# import json
# import socket
# import network as ne
# import block_ip as block_ip
# from scapy.layers.inet import IP, TCP, UDP
# import threading
# import base64




# def extract_packet_info(pkt):
#     if IP in pkt:
#             src_ip = pkt[IP].src
#             if TCP in pkt:
#                 dst_port = pkt[TCP].dport
#                 protocol = "TCP"
#             elif UDP in pkt:
#                 dst_port = pkt[UDP].dport
#                 protocol = "UDP"
#             else:
#                 return None
                
#             return {
#                 "src_ip": src_ip,
#                 "dst_port": dst_port,
#                 "protocol": protocol
#             }

# def sendsniffpack(my_socket):
#     enclient = ne.encrypted_client()
#     parsed_data = ne.getdata(my_socket)
#     if parsed_data is None:
#         print("No valid data received. Closing connection.")
#         my_socket.close()
#         return
#     enc_aes_key_received = parsed_data["data"]
#     print(enc_aes_key_received)
#     aes_key_iv = json.loads((enclient.RSA_decrypt(base64.b64decode(enc_aes_key_received))).decode("utf-8"))
#     print(aes_key_iv)
#     aes_key = base64.b64decode(aes_key_iv["aes_key"])
#     iv = base64.b64decode(aes_key_iv["iv"])
#     print(iv, len(iv), aes_key, len(aes_key))
#     enclient.set_ARS_key(aes_key, iv)

#     snif = 100
#     packets = sniff(count=snif, filter="ip")
#     packet_data = []

#     for pkt in packets:
#         info = extract_packet_info(pkt)
#         packet_data.append(info)
    
#     print(packet_data)
#     #to_send = json.dumps(packet_data)
    
#     enclient.send_encrypt(my_socket, packet_data, "headersniff")
#     print("File sent successfully!")
    

    

# def liesenforrecomdishens(my_socket):
#     ip = "0.0.0.0"
#     port  = 8840
#     listen_socket = socket.socket() 
#     listen_socket.bind((ip, port))
#     listen_socket.listen()
#     server_socket, server_address = listen_socket.accept()
#     print(f"Client connected from {server_address}")

#     data = ne.getdata(server_socket)
#     do_req(data)
#     print(data)
    
# def do_req(recomdisehns):
#     block_ip.block_ip_windows(recomdisehns)
    

# def main():
    
#     my_socket = socket.socket()
#     my_socket.connect(("127.0.0.1", 8820))
    
#     #while(True):
#     sendsniff = threading.Thread(target=sendsniffpack, args=(my_socket,))
#     sendsniff.start()
#     #lisentoreq = threading.Thread(target=liesenforrecomdishens, args=(my_socket,))
#     #lisentoreq.start()

    
#     #data = ne.getdata(my_socket)
#     #sendsniffpack(my_socket)
#     ###askforrecomdishens(my_socket)
#     #if data["header"] == "headersniff":
#     #     sendsniffpack(my_socket) #call onl wit te eder, need to pass it?
#     #if data["header"] == "headerreq":
#     #     askforrecomdishens(my_socket, data)

# if __name__ == "__main__":
#     main()

import socket
import json
import base64
import threading
import time
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import network as ne  # Your network module with encryption routines


def extract_packet_info(pkt):
    """
    Extracts relevant details from a packet:
      - src_ip, dst_ip, protocol, dst_port, flags
    """
    if IP in pkt:
        info = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": None,
            "dst_port": None,
            "flags": None
        }
        if TCP in pkt:
            info["protocol"] = "TCP"
            info["dst_port"] = pkt[TCP].dport
            info["flags"]    = str(pkt[TCP].flags)
        elif UDP in pkt:
            info["protocol"] = "UDP"
            info["dst_port"] = pkt[UDP].dport
        return info
    return None

def perform_handshake(client_socket, enclient: ne.encrypted_client):
    """
    Receive the AES key/IV from the server and initialize the encryption.
    """
    handshake = ne.getdata(client_socket)
    if not handshake or "data" not in handshake:
        print("[-] No AES key received. Closing connection.")
        client_socket.close()
        return False
    enc_aes = handshake["data"]
    # Decrypt the AES info using the client's RSA private key
    aes_info = json.loads(enclient.RSA_decrypt(base64.b64decode(enc_aes)).decode("utf-8"))
    aes_key = base64.b64decode(aes_info["aes_key"])
    iv = base64.b64decode(aes_info["iv"])
    enclient.set_ARS_key(aes_key, iv)
    print("[INFO] AES key established.")
    return True

def login(client_socket, enclient: ne.encrypted_client):
    """
    Log in using the 'login' header.
    """
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    login_msg = {
            "username": username,
            "password": password
    }

    enclient.send_encrypt(client_socket, login_msg, "login")
    response = enclient.reciv_encrypt(client_socket)
    if not response:
            print("[-] No valid response received from server.")
            client_socket.close()
            return None, None
    response_data = response.get("data")
    if response_data.get("status") == "success":
        token = response_data.get("token")
        print("[INFO] Login successful. Token:", token)
        return username, token
    else:
        print("[-] Login failed:", response_data.get("message"))
        client_socket.close()
        return None, None

def send_measurement_update(client_socket, enclient: ne.encrypted_client, username, token):
    """
    Capture measurement data using scapy and send it as a measurement update.
    """
    print("[INFO] Sniffing network packets for measurement data...")
    packets = sniff(count=100, filter="ip")
    measurement_data = [extract_packet_info(p) for p in packets if extract_packet_info(p)]
    print("[INFO] Measurement data captured:", measurement_data)
    
    meas_msg = {
            "username": username,
            "token": token,
            "measurement": measurement_data
    }
    print(meas_msg)
    enclient.send_encrypt(client_socket, meas_msg, "measurement_update")
    response = enclient.reciv_encrypt(client_socket)
    print("[INFO] Server response for measurement update:")
    print(response)

def request_recommendations(client_socket, enclient: ne.encrypted_client, username, token):
    """
    Request recommendations on demand using the 'request_recommendations' header.
    """
    rec_msg = {
            "username": username,
            "token": token
    }
    enclient.send_encrypt(client_socket, rec_msg, "request_recommendations")
    response = enclient.reciv_encrypt(client_socket)
    print("[INFO] Server recommendations:")
    print(response)

def main():
    server_ip = "127.0.0.1"
    server_port = 8820
    client_socket = socket.socket()
    try:
        client_socket.connect((server_ip, server_port))
        enclient = ne.encrypted_client()
        
        # Step 1: Handshake to receive AES key/IV.
        if not perform_handshake(client_socket, enclient):
            return
        
        # Step 2: Login to obtain a token.
        username, token = login(client_socket, enclient)
        if not username or not token:
            return
        # Step 3: Start a thread to periodically send measurement updates (data captured via scapy).
        def measurement_loop():
            while True:
                send_measurement_update(client_socket, enclient, username, token)
                time.sleep(10)  # Adjust the interval as needed
        
        meas_thread = threading.Thread(target=measurement_loop, daemon=True)
        meas_thread.start()
        
        # Step 4: Allow the user to request recommendations on demand.
        while True:
            cmd = input("Type 'rec' to request recommendations, or 'exit' to quit: ").strip().lower()
            if cmd == "rec":
                request_recommendations(client_socket, enclient, username, token)
            elif cmd == "exit":
                break
        
    except Exception as e:
        print("[-] Error:", e)
    finally:
        client_socket.close()
        print("[INFO] Connection closed.")

if __name__ == "__main__":
    main()

    