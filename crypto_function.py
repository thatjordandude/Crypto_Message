import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64
import os
import sys

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server started on {self.host}:{self.port}")
        while True:
            client_socket, client_address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()

    def handle_client(self, client_socket, client_address):
        print(f"Accepted connection from {client_address}")
        try:
            # Send public key to client
            client_socket.send(self.public_key.export_key())

            # Receive client's public key
            client_public_key = RSA.import_key(client_socket.recv(2048))

            # Generate and encrypt AES key with client's public key
            aes_key = os.urandom(16)
            cipher_rsa = PKCS1_OAEP.new(client_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            client_socket.send(encrypted_aes_key)

            self.clients[client_socket] = aes_key

            while True:
                # Receive and decrypt message
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:
                    break
                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=encrypted_message[:16])
                decrypted_message = cipher_aes.decrypt(encrypted_message[16:])
                print(f"Received: {decrypted_message.decode()}")

                # Encrypt and send response
                response = "Message received".encode()
                cipher_aes = AES.new(aes_key, AES.MODE_EAX)
                nonce = cipher_aes.nonce
                ciphertext, tag = cipher_aes.encrypt_and_digest(response)
                client_socket.send(nonce + ciphertext + tag)

        except ConnectionResetError:
            print(f"Client {client_address} disconnected abruptly.")
        except Exception as e:
             print(f"Error handling client {client_address}: {e}")
        finally:
            self.remove_client(client_socket)
            print(f"Connection with {client_address} closed")

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            del self.clients[client_socket]
            client_socket.close()

class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.aes_key = None

    def start(self):
        self.client_socket.connect((self.host, self.port))

        # Receive server's public key
        server_public_key = RSA.import_key(self.client_socket.recv(2048))

        # Send client's public key
        self.client_socket.send(self.public_key.export_key())

        # Receive and decrypt AES key
        encrypted_aes_key = self.client_socket.recv(256)
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        self.aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        while True:
            message = input("Enter message: ")
            cipher_aes = AES.new(self.aes_key, AES.MODE_EAX)
            nonce = cipher_aes.nonce
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
            self.client_socket.send(nonce + ciphertext + tag)

            # Receive and decrypt response
            encrypted_response = self.client_socket.recv(1024)
            cipher_aes = AES.new(self.aes_key, AES.MODE_EAX, nonce=encrypted_response[:16])
            decrypted_response = cipher_aes.decrypt(encrypted_response[16:])
            print("Server response:", decrypted_response.decode())

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 12345

    server = ChatServer(host, port)
    client = ChatClient(host, port)

    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()

    client.start()