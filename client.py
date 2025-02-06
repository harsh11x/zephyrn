import socket
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
import string
import secrets
import base64
import hashlib

class ZephyrSecuritiesChatClient:
    def __init__(self):
        # Create the main window
        self.window = tk.Tk()
        self.window.title("Zephyr Securities - Encrypted Chat Client")
        self.window.geometry("800x700")

        # Connection variables
        self.client_socket = None
        self.client_running = False

        # Create UI Components
        self.create_ui()

    def create_ui(self):
        # Connection Frame
        connection_frame = tk.LabelFrame(self.window, text="Connection Settings")
        connection_frame.pack(padx=10, pady=10, fill="x")

        # IP Address Input
        tk.Label(connection_frame, text="Server IP:").pack(side="left", padx=5)
        self.ip_entry = tk.Entry(connection_frame, width=15)
        self.ip_entry.pack(side="left", padx=5)
        self.ip_entry.insert(0, "127.0.0.1")

        # Port Input
        tk.Label(connection_frame, text="Port:").pack(side="left", padx=5)
        self.port_entry = tk.Entry(connection_frame, width=5)
        self.port_entry.pack(side="left", padx=5)
        self.port_entry.insert(0, "12345")

        # Key Frame
        key_frame = tk.LabelFrame(self.window, text="Encryption Key")
        key_frame.pack(padx=10, pady=10, fill="x")

        # Key Options
        tk.Label(key_frame, text="Key Method:").pack(side="left", padx=5)
        self.key_method = tk.StringVar(value="manual")
        
        manual_radio = tk.Radiobutton(key_frame, text="Manual Key", 
                                      variable=self.key_method, 
                                      value="manual", 
                                      command=self.toggle_key_input)
        manual_radio.pack(side="left")

        generate_radio = tk.Radiobutton(key_frame, text="Generate Key", 
                                        variable=self.key_method, 
                                        value="generate", 
                                        command=self.toggle_key_input)
        generate_radio.pack(side="left")

        # Key Entry
        self.key_entry = tk.Entry(key_frame, width=40, show="")
        self.key_entry.pack(side="left", padx=5)

        # Generate Key Button
        self.generate_key_button = tk.Button(key_frame, text="Generate Key", command=self.generate_secure_key)
        self.generate_key_button.pack(side="left", padx=5)

        # Chat Display
        tk.Label(self.window, text="Chat Messages:").pack()
        self.chat_box = tk.Text(self.window, width=80, height=20, state="disabled")
        self.chat_box.pack(padx=10, pady=10)

        # Message Input Frame
        message_frame = tk.Frame(self.window)
        message_frame.pack(fill="x", padx=10)

        tk.Label(message_frame, text="Message:").pack(side="left")
        self.message_entry = tk.Entry(message_frame, width=50)
        self.message_entry.pack(side="left", expand=True, fill="x", padx=5)

        # Send Button
        send_button = tk.Button(message_frame, text="Send", command=self.send_message)
        send_button.pack(side="right", padx=5)

        # Connection Buttons
        button_frame = tk.Frame(self.window)
        button_frame.pack(pady=10)

        connect_button = tk.Button(button_frame, text="Connect", command=self.connect_to_server)
        connect_button.pack(side="left", padx=5)

        disconnect_button = tk.Button(button_frame, text="Disconnect", command=self.disconnect)
        disconnect_button.pack(side="left", padx=5)

        # Ensure proper cleanup on window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

    def toggle_key_input(self):
        """Toggle key input based on selected method"""
        if self.key_method.get() == "manual":
            self.key_entry.config(state="normal")
            self.generate_key_button.config(state="disabled")
        else:
            self.key_entry.config(state="disabled")
            self.generate_key_button.config(state="normal")
            self.generate_secure_key()

    def generate_secure_key(self):
        """Generate a cryptographically secure random key"""
        # Generate a 32-byte (256-bit) random key and encode it
        raw_key = secrets.token_bytes(32)
        base64_key = base64.b64encode(raw_key).decode('utf-8')
        
        # Update key entry with generated key
        self.key_entry.config(state="normal")  # Ensure it's editable
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, base64_key)
        self.key_entry.config(state="disabled")

    def connect_to_server(self):
        """Establish connection to the server"""
        # Validate inputs
        try:
            host = self.ip_entry.get().strip()
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid IP or Port")
            return

        # Get encryption key
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Please provide an encryption key")
            return

        try:
            # Establish socket connection
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            self.client_running = True

            # Start message receiving thread
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            self.update_chat_box("Connected to server successfully!")
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def send_message(self):
        """Send an encrypted message to the server"""
        if not self.client_running:
            messagebox.showerror("Error", "Not connected to server")
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        key = self.key_entry.get().strip()
        try:
            encrypted_msg = self.encrypt_message(message, key)
            self.client_socket.send(encrypted_msg.encode('utf-8'))
            self.update_chat_box(f"You: {message}")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def receive_messages(self):
        """Continuously receive and decrypt messages"""
        key = self.key_entry.get().strip()
        while self.client_running:
            try:
                data = self.client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                decrypted_msg = self.decrypt_message(data, key)
                if decrypted_msg:
                    self.update_chat_box(f"Server: {decrypted_msg}")
            except Exception as e:
                print(f"Receive error: {e}")
                break

    def encrypt_message(self, message, key):
        """Enhanced message encryption using SHA-256 and XOR"""
        # Convert key to fixed-length hash
        key_hash = hashlib.sha256(key.encode()).digest()
        
        # XOR encryption
        encrypted = bytearray()
        for i, char in enumerate(message.encode()):
            encrypted.append(char ^ key_hash[i % len(key_hash)])
        
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_message(self, encrypted_message, key):
        """Enhanced message decryption using SHA-256 and XOR"""
        try:
            # Convert key to fixed-length hash
            key_hash = hashlib.sha256(key.encode()).digest()
            
            # Decode base64 and XOR decryption
            decoded = base64.b64decode(encrypted_message)
            decrypted = bytearray()
            for i, char in enumerate(decoded):
                decrypted.append(char ^ key_hash[i % len(key_hash)])
            
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def disconnect(self):
        """Disconnect from the server"""
        if self.client_running:
            self.client_running = False
            if self.client_socket:
                self.client_socket.close()
            self.update_chat_box("Disconnected from server")

    def update_chat_box(self, message):
        """Update chat box with new message"""
        self.chat_box.config(state="normal")
        self.chat_box.insert(tk.END, message + "\n")
        self.chat_box.see(tk.END)
        self.chat_box.config(state="disabled")

    def on_closing(self):
        """Handle window closing"""
        self.disconnect()
        self.window.quit()

    def run(self):
        """Start the chat client"""
        self.window.mainloop()

# Run the client
if __name__ == "__main__":
    client = ZephyrSecuritiesChatClient()
    client.run()