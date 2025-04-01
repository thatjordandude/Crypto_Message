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

client_public_keys = {}  # Dictionary to store client public keys
client_connections = {}  # O track client connections for fun


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
    
    #while True: # Loop here to accept multiple sockets/connetions
    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}\n")


    #load or gen RSA keys for the server 
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Send public key to Client    
    # Moved from bottom to here
    serialized_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    conn.send(serialized_public_key)
    print(f"Serialized RSA_public key sent {serialized_public_key}\n")

    # Receive AES Key from client, decrypt with RSA private key.
    encrypted_aes_key = conn.recv(2048)
    aes_key = private_key.decrypt(encrypted_aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    print(f"AES key decrypted: {aes_key.hex()}")				# for debugging
    serialized_public_key = conn.recv(2048)  
    client_public_key = serialization.load_pem_public_key(serialized_public_key)

    encrypted_aes_key = client_public_key.encrypt(aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    # good to communicate with AES Symmetric key. 

    while True:
        
        
        #Recieve public keys upon connection
        
        print(f"Connected by {addr}")

        #  Receive client's public key
        serialized_public_key = conn.recv(2048)  # Buffer size can be increased as needed
        client_public_key = serialization.load_pem_public_key(serialized_public_key)

        # Store client's public key and connection info
        client_public_keys[addr] = client_public_key
        client_connections[addr] = conn

        print(f"Stored public key for client {addr}")
        
        #Handle Public Key Requests
        while True:
            # Receive request
            request = conn.recv(1024).decode()
            
            if request.startswith("GET_KEY"):
                # Format: GET_KEY <target_client_addr>
                _, target_ip, target_port = request.split()
                target_addr = (target_ip, int(target_port))
                
                if target_addr in client_public_keys:
                    # Send serialized public key back
                    target_pub_key = client_public_keys[target_addr]
                    serialized_key = target_pub_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    conn.sendall(serialized_key)
                    print(f"Sent public key of {target_addr} to {addr}")
                else:
                    conn.sendall(b"ERROR: Client not found")
            
            elif request == "EXIT":
                break

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
    #added Cleanup When Client Disconnects
    client_public_keys.pop(addr, None)
    client_connections.pop(addr, None)
    print(f"Client {addr} disconnected")
    


if __name__ == "__main__":
    #start_server('192.168.1.54', 65432, PRE_GENERATED_KEY)
    host_name = socket.gethostname()
    ip_addr = socket.gethostbyname(host_name)
    while len(sys.argv) != 2:
        print("USE PORT: 65432 \nSyntax: <script> <Port #>")
        exit() 
    port = int(sys.argv[1])
    print(f"HOST NAME:{host_name} - IP ADDRESS:{ip_addr}:{port}")




    start_server(ip_addr, port)


# 
