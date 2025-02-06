import socket
import threading

# Function to continuously receive messages from the server
def receive_messages(server_socket):
    while True:
        try:
            message = server_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"Server: {message}")
        except:
            break
    server_socket.close()

# Client setup
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_ip = input("Enter the server IP address: ")
client.connect((server_ip, 12345))

# Start a thread to handle incoming messages from the server
receive_thread = threading.Thread(target=receive_messages, args=(client,))
receive_thread.start()

# Continuously send messages to the server
while True:
    message = input("You: ")
    client.send(message.encode('utf-8'))
