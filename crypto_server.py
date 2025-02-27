import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os


PRE_GENERATED_KEY = b"J7F41fME8FWOIM8UTzMF6GiZW5rFKxIeU3CjFHvArOa7vtIxZRkupW2XXn7r5Fb+"[:32]  # ENTER KEY HERE 32 bytes!

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

# Server function
def start_server(host, port, key):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server started on {host}:{port}")
    
    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    while True:
        # Receive encrypted message from client
        data = conn.recv(1024)
        if not data:
            break
        
        iv_base64, ciphertext_base64 = data.decode().split(":", 1)
        print(f"Encrypted message received: {ciphertext_base64}")
        
        # Decrypt the message
        decrypted_message = decrypt_message(iv_base64, ciphertext_base64, key)
        print(f"Decrypted message: {decrypted_message}")
        
        # Respond with an encrypted message
        response = f"Server received: {decrypted_message}"
        iv_base64, ciphertext_base64 = encrypt_message(response, key)
        conn.send(f"{iv_base64}:{ciphertext_base64}".encode())

    conn.close()

if __name__ == "__main__":
    start_server('10.0.0.103', 65432, PRE_GENERATED_KEY)
