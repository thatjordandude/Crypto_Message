import os
import sys
import base64
import socket
import select
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization

# AES encryption function
def encrypt_message(message, aes_key):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()

# AES decryption function
def decrypt_message(iv_base64, ciphertext_base64, aes_key):
    iv = base64.b64decode(iv_base64)
    ciphertext = base64.b64decode(ciphertext_base64)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return message.decode()

def sendMsg(aes_key, client_socket):     #added client_socket     #Nothing sending messages to the server here....
    while True:
        client_msg = input("Enter message: ")                      #Message to send
        if client_msg.lower() == "exit":
            print("Bye!")
            sys.exit("Goodbye" + ip_Addr)   # hard exit of program, Not sure if this is a 'nice' way to accomplish this
        iv_base64, ciphertext_base64 = encrypt_message(client_msg, aes_key)
        client_socket.send(f"{iv_base64}:{ciphertext_base64}".encode())
        
# Client function
def start_client(host, port):
    #client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    #THIS IS WHERE RSA KEY EXCHANGE NEEDS TO HAPPEN
    
    # Send public key to server                                                                     #NEW 3/24/25
    client_socket.send(rsa_pub_key)  #changed from conn.send to client_socket.send                  #NEW 3/24/25
    print(f"Serialized RSA_public key sent\n{rsa_pub_key}\n")                                       #NEW 3/24/25
    
    # Receive AES Key from server, decrypt with RSA private key. added 3/19/25                      #NEW 3/24/25
    AES_encrypted_key = client_socket.recv(1024)  #changed from conn.recv to client_socket.recv     #NEW 3/24/25
    print(f"AES engrypted key received\n{AES_encrypted_key}")    #debugging                          #NEW 3/24/25
    aes_key = private_key.decrypt(AES_encrypted_key, padding.OAEP(                                  #NEW 3/24/25
        mgf=padding.MGF1(algorithm=hashes.SHA256()),                                                #NEW 3/24/25
        algorithm=hashes.SHA256(),                                                                  #NEW 3/24/25
        label=None                                                                                  #NEW 3/24/25
        )                                                                                           #NEW 3/24/25
    )                                                                                               

    if len(aes_key) != 32:
        print("❌ Error: Failed to receive a valid AES key from the server.")
        client_socket.close()
        return
        
    # aes_key = base64.b64decode(client_socket.recv(64))  # Receive and decode the AES key properly, this can likely be shortened from 1024 to 32
    print(f"Decrypted AES Key\n{aes_key}") #debugging [class is bytes]
    client_thread = threading.Thread(target=sendMsg, daemon=True, args=(aes_key, client_socket))   #[aes_key] i believe this is correct
    client_thread.start()# starts a thread to receive input from user

    # if len(aes_key) != 32:
        # print("❌ Error: Failed to receive a valid AES key from the server.")
        # client_socket.close()
        # return

    print(f"✅ Received AES key: {aes_key.hex()}")  # Debugging
    print("🔄 Entering message loop. Type your message below:")
    
    socket = [client_socket]
    # Start sending messages
    while True:
        #message = input("Enter message: ")
        #if message.lower() == "exit":
        #    break
        
        #socket = [client_socket]
        read_socket, write_socket, error_socket = select.select(socket, [], [])
        
        for sock in read_socket:
            if sock == client_socket:
                encrypted_message = sock.recv(1024).decode()
                print(f" Debug: Received from server -> {repr(encrypted_message)}") #added 3/25
                try:
                    iv_base64, ciphertext_base64 = encrypted_message.split(":", 1)
                    #Decrypt the server's response   
                    decrypted_response = decrypt_message(iv_base64, ciphertext_base64, aes_key)
                    print(f"🔹 Server response: {decrypted_response}")
                    
                except ValueError as e:
                        print(f"❌ Error: {e}")
                        print("🔴 Received response was:", repr(encrypted_message)) #added 3/25
                        print("Received response was:", decrypted_response)  
                        print("The server might have sent an error message. Ignoring...")
                        return # Prevent further execution if an error occurs
            else: # LINES 88-96 LIKELY NOT NEEDED. 
                message = input("Enter message: ")                      #Message to send
                if client_msg.lower() == "exit":
                    print("Bye!")
                    sys.exit("Goodbye" + ip_Addr)    # hard exit of program, Not sure if this is a 'nice' way to accomplish this
                    
                #client_socket.send(message)
                iv_base64, ciphertext_base64 = encrypt_message(message, aes_key)
                client_socket.send(f"{iv_base64}:{ciphertext_base64}".encode())
                
        # Encrypt the message
        #iv_base64, ciphertext_base64 = encrypt_message(message, aes_key)
        
        # Send encrypted message to the server
        #client_socket.send(f"{iv_base64}:{ciphertext_base64}".encode())
        
        # Receive the response from the server
        #response = client_socket.recv(1024).decode()

        # try:
            # iv_base64, ciphertext_base64 = response.split(":", 1)
            
            # # Decrypt the server's response   
            # decrypted_response = decrypt_message(iv_base64, ciphertext_base64, aes_key)
            # print(f"🔹 Server response: {decrypted_response}")
        # except ValueError as e:
            # print(f"❌ Error: {e}")
            # print("Received response was:", response)  
    
    client_socket.close()
    
def rsa_keypair():  #added 3/24/25
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
    return serialized_public_key, private_key




if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("USE IP: 192.168.1.54 & PORT: 65432 \nSyntax: <script> <IP address> <Port #>")
        exit() 
    ip_Addr = str(sys.argv[1])
    port = int(sys.argv[2])
    #client_thread = threading.Thread(target=sendMsg, daemon=True, args=(aes_key))
    #client_thread.start()# starts a thread to receive input from user
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rsa_pub_key, private_key = rsa_keypair()   #NEW 3/24/25
    start_client(ip_Addr, port)




