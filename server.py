import argparse
import os
import socket
import threading

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = []

    def broadcast(self, message, source_client):
        for client in self.clients:
            if client != source_client:
                client.send(message)

    def handle_client(self, client_socket, client_address):
        print(f"New connection from {client_address}")
        self.clients.append(client_socket)
        try:
            while True:
                message = client_socket.recv(4096)
                if not message:
                    break
                self.broadcast(message, client_socket)
        except ConnectionResetError:
            print(f"Connection lost with {client_address}")
        finally:
            self.clients.remove(client_socket)
            client_socket.close()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen()
        print(f"Server listening on {self.host}:{self.port}")
        try:
            while True:
                client_socket, client_address = server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_handler.start()
        except KeyboardInterrupt:
            print("Server shutting down.")
        finally:
            server_socket.close()

if __name__ == "__main__":
    HOST = "127.0.0.1"  # Localhost
    PORT = 65432        # Port to listen on
    server = Server(HOST, PORT)
    server.start()