import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
import base64
import os
import sys #NEW
from cryptography.hazmat.primitives import serialization #new


# AES encryption function
def encrypt_message(message, aes_key):
    iv = os.urandom(16)  # Random 16 bytes for IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of block size (AES block size is 16 bytes)
    #print(f"AES KEY IS: {aes_key}")
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    # Encrypt the message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return both IV and ciphertext, encoded in base64
    return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()

# AES decryption function
def decrypt_message(iv_base64, ciphertext_base64, aes_key):
    iv = base64.b64decode(iv_base64)
    ciphertext = base64.b64decode(ciphertext_base64)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted message
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
    return message.decode()

# Client function
#def start_client(host, port, key):
def start_client(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    #Generate RSA keys 
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    
    # Serialize public key and yeet to the server
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(serialized_public_key)
    
    #Recieve servers encypted AES keys for use
    encrypted_aes_key = client_socket.recv(2048)
    aes_key = private_key.decrypt(encrypted_aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
    
    #Generate AES 32 byte Key
    
    print(f"AES key decrypted: {aes_key.hex()}") #changed from "encryped to dencypted"			#for debugging
     
   

    # Receive public key from Server
    serialized_public_key = client_socket.recv(1024)
    print(f"Serialized RSA_public Key received : {serialized_public_key}")				#for debugging

    #Deseralize the key bytes back to PEM format for use with encoding
    RSA_public_key = load_pem_public_key(serialized_public_key)
    print("Serialized RSA_public key converted to key instance")

    # encrypt AES Key with server generated RSA public key - encryption seems to need padding??
    encrypted_AES = RSA_public_key.encrypt(aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )       

    # send encrypted key AES Key to server !!! issue with encrypted_AES.encode()
    client_socket.send(encrypted_AES) #.encode()) <- eliminating this seemed to work
    print(f"RSA_public key has encrypted AES Key, sending to Server, encrypted AES key is: ", {encrypted_AES})

    # # good to communicate with AES Symmetric key. 
    print("welcome gamer, type \"exit\" to end session")
    while True:
        # Input message to be sent to the server
        print(f"AES Key is: {aes_key}")					# debugging
        message = input("Enter message: ")
        
        if message.lower() == "exit":
            break
        
        # Encrypt the message
        iv_base64, ciphertext_base64 = encrypt_message(message, aes_key)
        
        # Send encrypted message to the server
        client_socket.send(f"{iv_base64}:{ciphertext_base64}".encode())
        
        # Receive the response from the server
        response = client_socket.recv(1024).decode()

        iv_base64, ciphertext_base64 = response.split(":", 1)
        decrypted_response = decrypt_message(iv_base64, ciphertext_base64, aes_key)
        print(f"Server response: {decrypted_response}")  # Debug line?

        try:
            iv_base64, ciphertext_base64 = response.split(":", 1)
            
            # Decrypt the server's response   
            decrypted_response = decrypt_message(iv_base64, ciphertext_base64, aes_key)
            #print(f"Server response: {decrypted_response}")			# Add this debug line
        except ValueError as e:
            print(f"Error: {e}")
            print("Received response was:", response)  # Debug: Print the response to see what was received
    
    client_socket.close()

if __name__ == "__main__":


    while len(sys.argv) != 3:
        print("USE IP: 192.168.1.54 & PORT: 65432 \nSyntax: <script> <IP address> <Port #>")
        exit() 
    ip_Addr = str(sys.argv[1])
    port = int(sys.argv[2])
    start_client(ip_Addr, port)


