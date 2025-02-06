import socket
import threading
from tkinter import Tk, Label, Button, Text, Entry, messagebox
import string
import random

# Extended character set for encryption (letters, digits, punctuation, and space)
CHAR_SET = string.ascii_letters + string.digits + string.punctuation + " "
CHAR_SET_LEN = len(CHAR_SET)

# Vigenère Cipher Functions
def create_vigenere_table():
    table = []
    for i in range(CHAR_SET_LEN):
        row = CHAR_SET[i:] + CHAR_SET[:i]  # Cyclic table shift for Vigenère cipher
        table.append(row)
    return table

def vigenere_encrypt(plaintext, key):
    table = create_vigenere_table()
    expanded_key = (key * ((len(plaintext) // len(key)) + 1))[:len(plaintext)]
    ciphertext = []
    for i in range(len(plaintext)):
        if plaintext[i] in CHAR_SET:
            row = CHAR_SET.index(expanded_key[i])
            col = CHAR_SET.index(plaintext[i])
            ciphertext.append(table[row][col])
        else:
            ciphertext.append(plaintext[i])  # Non-CHAR_SET chars are kept as is
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key):
    table = create_vigenere_table()
    expanded_key = (key * ((len(ciphertext) // len(key)) + 1))[:len(ciphertext)]
    plaintext = []

    try:
        for i in range(len(ciphertext)):
            if ciphertext[i] in CHAR_SET:
                row = CHAR_SET.index(expanded_key[i])
                col = table[row].index(ciphertext[i])
                plaintext.append(CHAR_SET[col])
            else:
                plaintext.append(ciphertext[i])  # Non-CHAR_SET chars are kept as is
    except Exception as e:
        print(f"Decryption Error: {str(e)}")
        return None

    return ''.join(plaintext)

# Chat Server with GUI
class ChatServerGUI:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port
        self.server_socket = None
        self.connections = []
        self.client_sockets = []
        self.keys = {}
        self.server_running = False

        # Create the Tkinter window
        self.window = Tk()
        self.window.title("Chat Server")
        self.window.geometry("700x700")

        # Server Info Label
        self.server_info_label = Label(self.window, text=f"Server started at {self.host}, Port {self.port}")
        self.server_info_label.pack()

        # Key Input
        self.key_label = Label(self.window, text="Enter Key (or generate):")
        self.key_label.pack()
        self.key_entry = Entry(self.window, width=40)
        self.key_entry.pack()

        self.generate_button = Button(self.window, text="Generate Key", command=self.generate_key)
        self.generate_button.pack()

        # Chat Display
        self.chat_box = Text(self.window, width=80, height=20, state="disabled")
        self.chat_box.pack()

        # Server Message Input
        self.server_message_label = Label(self.window, text="Server Message:")
        self.server_message_label.pack()
        self.server_message_box = Entry(self.window, width=50)
        self.server_message_box.pack()

        self.send_button = Button(self.window, text="Send Message", command=self.send_server_message)
        self.send_button.pack()

        # Decrypt Input Box
        self.decrypt_label = Label(self.window, text="Enter Text to Decrypt:")
        self.decrypt_label.pack()
        self.decrypt_input_box = Entry(self.window, width=50)
        self.decrypt_input_box.pack()

        # Decrypt Button and Output
        self.decrypt_button = Button(self.window, text="Decrypt Text", command=self.decrypt_text)
        self.decrypt_button.pack()

        self.decrypt_output_label = Label(self.window, text="Decrypted Output:")
        self.decrypt_output_label.pack()
        self.decrypt_output_box = Text(self.window, width=80, height=5, state="disabled")
        self.decrypt_output_box.pack()

        # Start/Stop Server
        self.start_button = Button(self.window, text="Start Server", command=self.start_server)
        self.start_button.pack()
        self.stop_button = Button(self.window, text="Stop Server", command=self.stop_server)
        self.stop_button.pack()

        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

    def start_server(self):
        if self.server_running:
            self.stop_server()

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.connections = []
        self.client_sockets = []
        self.keys = {}
        self.server_running = True

        self.chat_box.config(state="normal")
        self.chat_box.insert("end", f"Server started at {self.host}, Port {self.port}\n")
        self.chat_box.config(state="disabled")

        threading.Thread(target=self.accept_clients, daemon=True).start()

    def accept_clients(self):
        while self.server_running:
            client_socket, client_address = self.server_socket.accept()
            self.connections.append(client_socket)
            self.client_sockets.append(client_socket)
            threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()

    def handle_client(self, client_socket, client_address):
        try:
            key = None
            while self.server_running:
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                if key is None:
                    key = data.strip()
                    self.keys[client_socket] = key
                    continue

                decrypted_message = vigenere_decrypt(data, key)
                self.chat_box.config(state="normal")
                self.chat_box.insert("end", f"Message from {client_address} (Decrypted): {decrypted_message}\n")
                self.chat_box.config(state="disabled")

                for conn in self.client_sockets:
                    if conn != client_socket:
                        encrypted_message = vigenere_encrypt(decrypted_message, self.keys[conn])
                        conn.sendall(encrypted_message.encode())
        finally:
            client_socket.close()
            if client_socket in self.connections:
                self.connections.remove(client_socket)
            if client_socket in self.client_sockets:
                self.client_sockets.remove(client_socket)

    def send_server_message(self):
        message = self.server_message_box.get()
        if not message:
            messagebox.showerror("Error", "Please enter a message.")
            return
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Please enter or generate a key.")
            return
        encrypted_message = vigenere_encrypt(message, key)
        for conn in self.client_sockets:
            conn.sendall(encrypted_message.encode())

        self.chat_box.config(state="normal")
        self.chat_box.insert("end", f"Server: {message}\n")
        self.chat_box.config(state="disabled")
        self.server_message_box.delete(0, "end")

    def decrypt_text(self):
        key = self.key_entry.get().strip()
        text_to_decrypt = self.decrypt_input_box.get().strip()

        if not key:
            messagebox.showerror("Error", "Please enter a key to decrypt the text.")
            return

        if not text_to_decrypt:
            messagebox.showerror("Error", "Please enter text to decrypt.")
            return

        try:
            decrypted_text = vigenere_decrypt(text_to_decrypt, key)
            self.decrypt_output_box.config(state="normal")
            self.decrypt_output_box.delete(1.0, "end")
            self.decrypt_output_box.insert("end", decrypted_text)
            self.decrypt_output_box.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during decryption:\n{str(e)}")

    def generate_key(self):
        key_length = random.randint(15, 20)
        key = ''.join(random.choice(CHAR_SET) for _ in range(key_length))
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, key)

    def stop_server(self):
        self.server_running = False
        for conn in self.client_sockets:
            conn.close()
        if self.server_socket:
            self.server_socket.close()
        self.chat_box.config(state="normal")
        self.chat_box.insert("end", "Server stopped.\n")
        self.chat_box.config(state="disabled")

    def on_closing(self):
        self.stop_server()
        self.window.quit()

# Run the Server
if __name__ == "__main__":
    chat_server = ChatServerGUI()
    chat_server.window.mainloop()
