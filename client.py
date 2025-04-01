import argparse
import base64
import datetime
import hashlib
import os
import socket
import sys
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


from Crypto import Random
from Crypto.Cipher import AES
from termcolor import colored


class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size    
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[: AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size :])).decode("utf-8")

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[: -ord(s[len(s) - 1 :])]


class Send(threading.Thread):
    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name

    def run(self):
        #send public key to server 
        self.sock.sendall(b"PUBLIC_KEY:" + self.public_key)
        # Generate AES session key
        aes_key = get_random_bytes(32)

        # Encrypt AES key with peer's public key
        cipher_rsa = PKCS1_OAEP.new(self.receive_thread.peer_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Send encrypted AES key
        self.sock.sendall(b"AES_KEY:" + encrypted_aes_key)

        # Initialize AES cipher object
        self.enc = AESCipher(aes_key)
        print(colored("AES session key securely exchanged.", "green"))
        while True:
            print("{}: ".format(self.name), end="")
            sys.stdout.flush()
            message = sys.stdin.readline()[:-1]
            
            if message == "QUIT":
                self.sock.sendall(
                    "Server: {} has left the chat.".format(self.name).encode("utf-8")
                )
                break
            else:
                message = self.enc.encrypt("{}: {}".format(self.name, message))
                self.sock.sendall(message)
        self.sock.close()
        os._exit(0)


class Receive(threading.Thread):
    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name
        self.messages = None

    def run(self):
        while True:
            message = self.sock.recv(1024)
            #recieve peers public key
            if message.startswith(b"PUBLIC_KEY:"):
                peer_pub_key_data = message[len(b"PUBLIC_KEY:"):]
                self.peer_public_key = RSA.import_key(peer_pub_key_data)
                print(colored("Received peer's public key.", "yellow"))
            elif message.startswith(b"AES_KEY:"):
                encrypted_aes_key = message[len(b"AES_KEY:"):]
                cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.client.private_key))
                aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                self.enc = AESCipher(aes_key)
                print(colored("Received and decrypted AES session key.", "green"))

            elif message:
                try:
                    message = str(self.enc.decrypt(message))
                except:
                    message = message.decode("utf-8")
                print("\r{}\n{}: ".format(colored(message, "red"), self.name), end="")
            else:
                print("\nlost connection...")
                self.sock.close()
                os._exit(0)


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = None
        self.messages = None

    def start(self):
        #run key function
        self.generate_rsa_keys()
        
        self.sock.connect((self.host, self.port))
        self.name = input("Your name: ")
        send = Send(self.sock, self.name)
        receive = Receive(self.sock, self.name)
        send.start()
        receive.start()
        self.sock.sendall("Server: {} has joined".format(self.name).encode("utf-8"))
        return receive
        #gen rsa keys
    def generate_rsa_keys(self):
        self.rsa_key = RSA.generate(2048)
        self.private_key = self.rsa_key.export_key()
        self.public_key = self.rsa_key.publickey().export_key()


def main(host, port):
    client = Client(host, port)
    client.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument(
        "-p", metavar="PORT", type=int, default=1060, help="TCP port (default 1060)"
    )
    args = parser.parse_args()
    secret_key = input('type your key: ')
    enc = AESCipher(secret_key)
    main(args.host, args.p)
