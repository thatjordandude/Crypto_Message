
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

    # Receive the client's public RSA key before sending the AES Key
    serialized_public_key = conn.recv(1024)
    print(f"Received RSA public key from {addr}")

    # Deserialize the received key
    RSA_public_key = load_pem_public_key(serialized_public_key)

    # Encrypt AES Key with public key
    encrypted_AES = RSA_public_key.encrypt(
        aes_key, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send the encrypted AES key to the client
    conn.send(encrypted_AES)
    print(f"Sent AES key to {addr}")

    while True:
        try:
            data = conn.recv(1024)
            if not data:
                print(f"Client {addr} sent an empty message. Disconnecting...")
                break

            # Debugging output
            print(f"Received encrypted message from {addr}: {repr(data)}")

            # Decrypt the message
            iv_base64, ciphertext_base64 = data.decode().split(":", 1)
            decrypted_message = decrypt_message(iv_base64, ciphertext_base64, aes_key)

            print(f"Message from {addr}: {decrypted_message}")

            # Broadcast to all other clients
            broadcast(data, conn, aes_key)

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            break

    # Cleanup
    remove(conn)
    conn.close()
    print(f"Connection with {addr} closed.")


def broadcast(encrypted_message, conn, aes_key):
    print("Broadcasting")

    try:
        # Extract IV and Ciphertext from sender's encrypted message
        iv_base64, ciphertext_base64 = encrypted_message.decode().split(":", 1)
        
        # ecrypt the received message
        decrypted_message = decrypt_message(iv_base64, ciphertext_base64, aes_key)

        for client in clientList:
            if client != conn:  # Avoid sending back to the sender
                try:
                    # Encrypt again with a new IV
                    new_iv_base64, new_ciphertext_base64 = encrypt_message(decrypted_message, aes_key)
                    
                    # Send the newly encrypted message to the client
                    client.send(f"{new_iv_base64}:{new_ciphertext_base64}".encode())

                except Exception as e:
                    print(f"Error sending to a client: {e}")
                    remove(client)  # Remove the client from the list if it failed


    except Exception as e:
        print(f" Error in broadcasting: {e}")


def remove(conn):
    if conn in clientList:
        clientList.remove(conn)

# Server function to handle multiple clients
def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server started on {host}:{port}")

    # Generate AES key once
    aes_key = os.urandom(32)
    print(f"Generated AES key: {aes_key.hex()}")

    while True:
        conn, addr = server_socket.accept()
        clientList.append(conn)  # Add new client to the list
        print(f"New connection from {addr}, total clients: {len(clientList)}")

        # Start a new thread for each client
        client_thread = threading.Thread(target=handle_client, args=(conn, addr, aes_key))
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