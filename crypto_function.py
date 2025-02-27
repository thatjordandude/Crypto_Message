from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

# Generate a random AES key
def generate_key():
    return os.urandom(32)  # 32 bytes = 256-bit AES key

# Encrypt the message using AES-CBC
def encrypt_message(message, key):
    iv = os.urandom(16)  # Random 16 bytes for IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of block size (AES block size is 16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    # Encrypt the message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return both IV and ciphertext, encoded in base64 to transmit as text
    return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()

# Decrypt the message using AES-CBC
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
