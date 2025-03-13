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

#This cannot be hard coded and needs to be generated. 
#PRE_GENERATED_KEY = b"J7F41fME8FWOIM8UTzMF6GiZW5rFKxIeU3CjFHvArOa7vtIxZRkupW2XXn7r5Fb+"[:32]  # ENTER KEY HERE 32 bytes!

# AES encryption function
def encrypt_message(message, key):
    iv = os.urandom(16)  # Random 16 bytes for IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of block size (AES block size is 16 bytes)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
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
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
    return message.decode()

# Server function
#def start_server(host, port, key):
def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5) # Changed from 1 to 5
    print(f"Server started on {host}:{port}")
    
    #while True: # Loop here to accept multiple socets/connetions
    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}\n")

    # Send public key to Client
    conn.send(serialized_public_key)
    #print(f"Serialized RSA_public key sent {serialized_public_key}\n")

    # Receive AES Key from client, decrypt with RSA private key.
    AES_encrypted_key = conn.recv(1024)
    aes_key = private_key.decrypt(AES_encrypted_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    #print(f"Received encrypted AES key: {AES_encrypted_key}\n\nDecrypted key is:\n{aes_key}")				# for debugging

    # good to communicate with AES Symmetric key. 

    while True:
        # Receive encrypted message from client
        data = conn.recv(1024)
        if not data:
            break
        
        iv_base64, ciphertext_base64 = data.decode().split(":", 1)
        #print(f"Encrypted message received: {ciphertext_base64}")
        
        # Decrypt the message
        decrypted_message = decrypt_message(iv_base64, ciphertext_base64, aes_key)
        print(f"Decrypted message: {decrypted_message}")
        
        # Respond with an encrypted message
        response = f"Server received: {decrypted_message}"
        iv_base64, ciphertext_base64 = encrypt_message(response, aes_key)
        conn.send(f"{iv_base64}:{ciphertext_base64}".encode())

    conn.close()

if __name__ == "__main__":
    #start_server('192.168.1.54', 65432, PRE_GENERATED_KEY)
    host_name = socket.gethostname()
    ip_addr = socket.gethostbyname(host_name)
    while len(sys.argv) != 2:
        print("USE PORT: 65432 \nSyntax: <script> <Port #>")
        exit() 
    port = int(sys.argv[1])
    print(f"HOST NAME:{host_name} - IP ADDRESS:{ip_addr}:{port}")

# Below generates an instance of RSAPrivateKey
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Generates RSA PUBLIC KEY instance from PRIVATE KEY. 
    public_key = private_key.public_key()

#Serializes key to allow transfer of key instance by converting to bytes.
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 				#PEM is base 64 encoding.
        format=serialization.PublicFormat.SubjectPublicKeyInfo	        #SubjectPublicKeyInfo is default format. 
    )

    start_server(ip_addr, port)


# I think I need to switch what we do here. The server should generate the Symmetric Key. Each additionl client should generate their own Pbulic key and send to the server to hve the server send out the symmetric key. The clients then decode the symmetric key with their Private RSA Key. 

