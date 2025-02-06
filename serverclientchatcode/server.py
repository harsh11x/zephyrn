import socket
import threading

# Function to handle each client's messages
def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"Client: {message}")
        except:
            break
    client_socket.close()

# Server setup
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 12345))  # Binds to all available network interfaces, on port 12345
server.listen(5)
print("Server started and listening...")

while True:
    client_socket, addr = server.accept()
    print(f"Connection established with {addr}")
    
    # Start a thread to handle the client
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()

    # Continuously send messages to the client
    while True:
        message = input("You: ")
        client_socket.send(message.encode('utf-8'))
