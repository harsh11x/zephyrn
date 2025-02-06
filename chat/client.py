# client.py
import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('13.127.3.82', 12345))  # Replace with Device 1's IP address

while True:
    message = input("Client: ")
    client_socket.send(message.encode())
    data = client_socket.recv(1024)
    print(f"Server: {data.decode()}")
