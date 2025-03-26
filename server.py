# import json
# import socket
# import threading
# import network as ne
# import analyze
# import base64

# #CR: filename

# class Server:
#     enclient = ne.encrypted_client()
#     pubkey_client = enclient.RSA_get_pubkey()

#     def __init__(self):
#         s="s"
    
#     def anlsist(self, parsed_data):
#         analyze.detect_suspicious(parsed_data)

#     def hendel(self, client_socket: socket.socket, client_address): # CR: english
#         print(f"Client connected from {client_address}")
#         encryptit = ne.encrypt()
#         enserver = ne.encrypted_server()
#         iv_and_aes_key_bytes = json.dumps(enserver.iv_and_aes_key_b64).encode('utf-8')
#         tosend_encrypt_AES_key = encryptit.RSA_encrypt(iv_and_aes_key_bytes, self.pubkey_client)
#         tosend_encrypt_AES_key_b64 = (base64.b64encode(tosend_encrypt_AES_key)).decode('utf-8')
#         ne.sendata(client_socket, tosend_encrypt_AES_key_b64)
#         print("all good")
#         parsed_data = enserver.reciv_AES_encrypt(client_socket)
#         print(parsed_data)
    
#         if (parsed_data['header'] == "headersniff"): # type: ignore
#             #with open(f'sniffs/{client_address}_sniffs_serv.json', 'ab') as file:
#             #    file.write(parsed_data["data"]) # CR: save to some dictionary variable, not just write to a file, and it will probably be a DB in the future.

#             #recomdisehns = anlsist(parsed_data["data"])
#             print("hiiiiiiii")
#             recomdisehns = parsed_data["data"] # type: ignore
#             print(recomdisehns)
#             if(recomdisehns == True):
#                 enserver.send_AES_encrypt(client_socket, recomdisehns, "headerreq")
#             print(recomdisehns)
#             client_socket.close() #if hie finds out that it need to send req just send them her.

#         #json_string = json.dumps(parsed_data["data"])
#         elif(parsed_data["header"] == "headerreq"): # type: ignore
#             with open(f'sniffs/{client_address}_sniffs_serv.json', 'ab') as file:
#                 file.read()
#             recomdisehns = "d" #anlsist(file)
#             enserver.send_AES_encrypt(client_socket, recomdisehns, "headerreq")
#             print(recomdisehns)

# def main():

#     ip = "0.0.0.0"
#     port  = 8820
#     server_socket = socket.socket()
#     server_socket.bind((ip, port))
#     server_socket.listen()
#     print("Server is up and running")
#     Server1 = Server()

#     #while(True):
#     client_socket, client_address = server_socket.accept()
#     client_thread = threading.Thread(target=Server1.hendel, args=(client_socket, client_address))
#     client_thread.start()
#     #server_socket.close()
    
# if __name__ == "__main__":
#     main()

import socket
import threading
import json
import base64
import sqlite3
import authentication as db  # Your DB module (with add_user_data, get_user_data, authenticate_user, etc.)
import network as ne  # Your network module with encryption routines
import analyze  # Module containing the detect_suspicious function

class DBServer:
    def __init__(self, ip="0.0.0.0", port=8820):
        self.ip = ip
        self.port = port
        # Initialize the client encryption to retrieve its public RSA key.
        enclient = ne.encrypted_client()
        self.client_pubkey = enclient.RSA_get_pubkey()

    def anlsist(self, measurement_data):
        """
        Analyze the given measurement data (a sequence of packets) 
        and return a list of recommended IP addresses.
        """
        recommendations = analyze.detect_suspicious(measurement_data)
        return recommendations

    def handle_client(self, client_socket: socket.socket, client_address):
        print(f"[+] Client connected from {client_address}")
        try:
            # Initialize encryption on the server side.
            encryptit = ne.encrypt()
            enserver = ne.encrypted_server()
            # Send the AES key/IV encrypted with the client's RSA public key.
            aes_info = json.dumps(enserver.iv_and_aes_key_b64).encode('utf-8')
            encrypted_aes_info = encryptit.RSA_encrypt(aes_info, self.client_pubkey)
            encrypted_aes_info_b64 = base64.b64encode(encrypted_aes_info).decode('utf-8')
            ne.sendata(client_socket, encrypted_aes_info_b64)
            
            # Receive the client's request.
            while True:
                parsed_message = enserver.reciv_AES_encrypt(client_socket)
                if not parsed_message:
                    print("[-] No valid data received from client.")
                    client_socket.close()
                    return
                
                print("[=] Received:", parsed_message)
                header = parsed_message.get("header")
                data = parsed_message.get("data")
                response = {}
                
                # --- Handle Commands ---
                if header == "login":
                    username = data.get("username")
                    password = data.get("password")
                    if db.authenticate_user(username, password):
                        # Retrieve the user's admin status.
                        conn = sqlite3.connect(db.DB_NAME)
                        cursor = conn.cursor()
                        cursor.execute("SELECT is_admin FROM users WHERE username=?", (username,))
                        row = cursor.fetchone()
                        conn.close()
                        is_admin = bool(row[0]) if row else False
                        token = db.create_jwt(username, is_admin)
                        response = {"status": "success", "token": token}
                    else:
                        response = {"status": "error", "message": "Invalid credentials."}
                
                elif header == "measurement_update":
                    # Expected data: username, token, and measurement (a list of packet info)
                    username = data.get("username")
                    token = data.get("token")
                    measurement = data.get("measurement")
                    payload = db.verify_jwt(token)
                    if payload and payload.get("username") == username:
                        # Store the measurement in the DB (as a JSON string).
                        db.add_user_data(username, json.dumps(measurement))
                        # Analyze this measurement update.
                        ##recommendations = self.anlsist(measurement)
                        recommendations = "good"
                        response = {"status": "success", 
                                    "message": "Measurement stored.", 
                                    "recommendations": recommendations}
                    else:
                        response = {"status": "error", "message": "Authentication failed."}
                
                elif header == "get_all_measurements":
                    # Expected data: username and token.
                    username = data.get("username")
                    token = data.get("token")
                    payload = db.verify_jwt(token)
                    if payload and payload.get("username") == username:
                        all_data = db.get_user_data(username)
                        measurements = []
                        if all_data:
                            for key, value in all_data.items():
                                try:
                                    # Assuming each stored value is a JSON string of measurement data.
                                    measurement = json.loads(value)
                                    if isinstance(measurement, list):
                                        measurements.extend(measurement)
                                    else:
                                        measurements.append(measurement)
                                except Exception as e:
                                    print("Error decoding measurement from DB:", e)
                        response = {"status": "success", "measurements": measurements}
                    else:
                        response = {"status": "error", "message": "Authentication failed."}
                
                elif header == "request_recommendations":
                    # Expected data: username and token.
                    username = data.get("username")
                    token = data.get("token")
                    payload = db.verify_jwt(token)
                    if payload and payload.get("username") == username:
                        # Retrieve all measurement data from DB.
                        all_data = db.get_user_data(username)
                        measurements = []
                        if all_data:
                            for key, value in all_data.items():
                                try:
                                    measurement = json.loads(value)
                                    if isinstance(measurement, list):
                                        measurements.extend(measurement)
                                    else:
                                        measurements.append(measurement)
                                except Exception as e:
                                    print("Error decoding measurement from DB:", e)
                        # Analyze all measurements to generate recommendations.
                        recommendations = self.anlsist(measurements)
                        response = {"status": "success", "recommendations": recommendations}
                    else:
                        response = {"status": "error", "message": "Authentication failed."}
                
                else:
                    response = {"status": "error", "message": "Unknown command."}
                
                # Send back the response.
                enserver.send_AES_encrypt(client_socket, response, "response")
        except Exception as e:
            print("[-] Error handling client:", e)
        finally:
            client_socket.close()
            print(f"[i] Connection with {client_address} closed.")
    
    def start(self):
        server_socket = socket.socket()
        server_socket.bind((self.ip, self.port))
        server_socket.listen()
        print(f"[i] Server listening on {self.ip}:{self.port}")
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()

if __name__ == "__main__":

    server = DBServer()
    server.start()

