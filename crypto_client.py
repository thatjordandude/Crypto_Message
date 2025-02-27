import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os

PRE_GENERATED_KEY = b"J7F41fME8FWOIM8UTzMF6GiZW5rFKxIeU3CjFHvArOa7vtIxZRkupW2XXn7r5Fb+"[:32]  # 256-bit key (32 bytes)

# AES encryption function
def encrypt_message(message, key):
    iv = os.urandom(16)  # Random 16 bytes for IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of block size (AES block size is 16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    # Encrypt the message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return both IV and ciphertext, encoded in base64
    return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()

# AES decryption function
def decrypt_message(iv_base64, ciphertext_base64, key):
    iv = base64.b64decode(iv_base64)
    ciphertext = base64.b64decode(ciphertext_base64)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted message
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
    return message.decode()

# Client function
def start_client(host, port, key):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    while True:
        # Input message to be sent to the server
        message = input("Enter message: ")
        
        if message.lower() == "exit":
            break
        
        # Encrypt the message
        iv_base64, ciphertext_base64 = encrypt_message(message, key)
        
        # Send encrypted message to the server
        client_socket.send(f"{iv_base64}:{ciphertext_base64}".encode())
        
        # Receive the response from the server
        response = client_socket.recv(1024).decode()

        print(f"Response from server: {response}")  # Add this debug line

        try:
            iv_base64, ciphertext_base64 = response.split(":", 1)
            
            # Decrypt the server's response
            decrypted_response = decrypt_message(iv_base64, ciphertext_base64, key)
            print(f"Server response: {decrypted_response}")
        except ValueError as e:
            print(f"Error: {e}")
            print("Received response was:", response)  # Debug: Print the response to see what was received
    
    client_socket.close()

if __name__ == "__main__":
    start_client('10.0.0.103', 65432, PRE_GENERATED_KEY)
