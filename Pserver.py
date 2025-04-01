
import os
import sys
import base64
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization


# AES encryption function
def encrypt_message(message, key):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()

# AES decryption function
def decrypt_message(iv_base64, ciphertext_base64, key):
    iv = base64.b64decode(iv_base64)
    ciphertext = base64.b64decode(ciphertext_base64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return message.decode()

# Handles communication with each client in a separate thread
def handle_client(conn, addr, aes_key):
    print(f"Handling client {addr} in a separate thread")

    #need to receive the connecting client's public RSA key before sneding the AES Key 
    serialized_public_key = conn.recv(1024)                                          #NEW 324/2025
    print(f"Serialized RSA_public Key received : {serialized_public_key}") #debugging#NEW 324/2025

    #Deseralize the key bytes back to PEM format for use with encoding
    RSA_public_key = load_pem_public_key(serialized_public_key)
    print("Serialized RSA_public key converted to key instance")

    #encrypt AES Key with public key
    encrypted_AES = RSA_public_key.encrypt(aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )    
    
    # Send encrypted AES key to client
    conn.send(encrypted_AES)
    print(f"RSA_public key has encrypted AES Key, sending to Server, encrypted AES key is: ", {encrypted_AES})
    
    
    #conn.send(base64.b64encode(aes_key))  # Ensure AES key is Base64 encoded before sending - added KAK 3/19/2025



    while True:
        try:
            data = conn.recv(1024)
            print(data)
            if not data:
                break

            iv_base64, ciphertext_base64 = data.decode().split(":", 1)
            decrypted_message = decrypt_message(iv_base64, ciphertext_base64, aes_key)

            print(f"Message from {addr}: {decrypted_message}")

            # Respond with encrypted acknowledgment
            response = f"Server received: {decrypted_message}"
            iv_resp, ciphertext_resp = encrypt_message(response, aes_key)
            conn.send(f"{iv_resp}:{ciphertext_resp}".encode())
            
            #send to all clients
            broadcast(data, conn)                   # sends the received encrypted message (data) to all clients. 

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            break

    conn.close()
    print(f"Connection with {addr} closed.")

def broadcast(encrypted_message, conn):                      # conn is a socket object passed to boradcast function. 
    print("Broadcasting")
    for client in clientList:                                # client is a socket object in clientList
        if client != conn:
            try:
                print("Broadcast Message Start")
                client.send(encrypted_message)
            except:
                client.close()
                remove(client)                              #removes client from clientList if there is an error.

def remove(conn):
    if conn in clientList:
        clientList.remove(conn)

# Server function to handle multiple clients
def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)  # Allow multiple clients
    print(f"Server started on {host}:{port}")
    

    # 🔹 Generate AES key **once** before accepting clients
    aes_key = os.urandom(32)
    print(f"Generated AES key: {aes_key.hex()}")

    while True:
        conn, addr = server_socket.accept()
        clientList.append(conn)                                                        #adds a new conn (socket object) to a list of clients. 
        clients = len(clientList)
        print(f"New connection from {addr}, {clients} connected")
                            

        # Start a new thread for each client
        client_thread = threading.Thread(target=handle_client, args=(conn, addr, aes_key))  #conn is a socket object, addr is the IP, aes_key is the key that needs to be passed to the client. 
        client_thread.start()
        


if __name__ == "__main__":
    #start_server("0.0.0.0", 65432)
    host_name = socket.gethostname()
    ip_addr = socket.gethostbyname(host_name)
    while len(sys.argv) != 2:
        print("USE PORT: 65432 \nSyntax: <script> <Port #>")
        exit() 
    port = int(sys.argv[1])
    print(f"HOST NAME:{host_name} - IP ADDRESS:{ip_addr}:{port}")
    clientList = []                            #added KAK 3/19/2025
    
    start_server(ip_addr, port)