import socket
import threading
from tkinter import Tk, Label, Button, Text, Entry, messagebox
import string

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

# Chat Client with GUI
class ChatClientGUI:
    def __init__(self):
        self.client_socket = None
        self.key = None
        self.connected = False

        # Create the Tkinter window
        self.window = Tk()
        self.window.title("Chat Client")
        self.window.geometry("700x700")

        # Server Info Input
        self.server_info_label = Label(self.window, text="Enter Server IP and Port:")
        self.server_info_label.pack()
        
        self.ip_label = Label(self.window, text="Server IP:")
        self.ip_label.pack()
        self.ip_entry = Entry(self.window, width=40)
        self.ip_entry.pack()
        
        self.port_label = Label(self.window, text="Server Port:")
        self.port_label.pack()
        self.port_entry = Entry(self.window, width=40)
        self.port_entry.pack()

        # Key Input
        self.key_label = Label(self.window, text="Enter Key:")
        self.key_label.pack()
        self.key_entry = Entry(self.window, width=40)
        self.key_entry.pack()

        # Connect Button
        self.connect_button = Button(self.window, text="Connect to Server", command=self.connect_to_server)
        self.connect_button.pack()

        # Chat Display
        self.chat_box = Text(self.window, width=80, height=20, state="disabled")
        self.chat_box.pack()

        # Client Message Input
        self.client_message_label = Label(self.window, text="Your Message:")
        self.client_message_label.pack()
        self.client_message_box = Entry(self.window, width=50)
        self.client_message_box.pack()

        self.send_button = Button(self.window, text="Send Message", command=self.send_message)
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

        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

    def connect_to_server(self):
        if self.connected:
            messagebox.showerror("Error", "Already connected to the server.")
            return

        server_ip = self.ip_entry.get().strip()
        server_port = self.port_entry.get().strip()
        self.key = self.key_entry.get().strip()

        if not server_ip or not server_port or not self.key:
            messagebox.showerror("Error", "Please enter all required fields.")
            return

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_ip, int(server_port)))
            self.client_socket.sendall(self.key.encode())
            self.connected = True

            self.chat_box.config(state="normal")
            self.chat_box.insert("end", "Connected to server.\n")
            self.chat_box.config(state="disabled")

            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to the server: {str(e)}")

    def receive_messages(self):
        while self.connected:
            try:
                data = self.client_socket.recv(1024).decode()
                if not data:
                    break
                decrypted_message = vigenere_decrypt(data, self.key)
                self.chat_box.config(state="normal")
                self.chat_box.insert("end", f"Message (Decrypted): {decrypted_message}\n")
                self.chat_box.config(state="disabled")
            except Exception as e:
                print(f"Receive Error: {str(e)}")
                break

    def send_message(self):
        message = self.client_message_box.get().strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message.")
            return

        try:
            encrypted_message = vigenere_encrypt(message, self.key)
            self.client_socket.sendall(encrypted_message.encode())
            self.chat_box.config(state="normal")
            self.chat_box.insert("end", f"You: {message}\n")
            self.chat_box.config(state="disabled")
            self.client_message_box.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Send Error", f"An error occurred while sending the message: {str(e)}")

    def decrypt_text(self):
        text_to_decrypt = self.decrypt_input_box.get().strip()

        if not self.key:
            messagebox.showerror("Error", "Please enter a key to decrypt the text.")
            return

        if not text_to_decrypt:
            messagebox.showerror("Error", "Please enter text to decrypt.")
            return

        try:
            decrypted_text = vigenere_decrypt(text_to_decrypt, self.key)
            self.decrypt_output_box.config(state="normal")
            self.decrypt_output_box.delete(1.0, "end")
            self.decrypt_output_box.insert("end", decrypted_text)
            self.decrypt_output_box.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during decryption:\n{str(e)}")

    def on_closing(self):
        self.connected = False
        if self.client_socket:
            self.client_socket.close()
        self.window.quit()

# Run the Client
if __name__ == "__main__":
    chat_client = ChatClientGUI()
    chat_client.window.mainloop()
