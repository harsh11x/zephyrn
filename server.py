import socket
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import secrets
import base64
import hashlib
import string

class ZephyrSecuritiesChatServer:
    def __init__(self):
        # Create the main window with a modern look
        self.window = tk.Tk()
        self.window.title("Zephyr Securities - Encrypted Chat Server")
        self.window.geometry("1000x800")
        self.window.configure(bg='#2c3e50')  # Dark background

        # Styling
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Modern theme
        self.style.configure('TLabel', foreground='white', background='#2c3e50', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10, 'bold'))
        self.style.configure('TFrame', background='#2c3e50')
        self.style.configure('TLabelframe', background='#34495e', foreground='white')
        self.style.configure('TLabelframe.Label', foreground='white', background='#34495e')

        # Server configuration
        self.host = '0.0.0.0'
        self.port = 12345
        self.server_socket = None
        self.connections = []
        self.server_running = False

        # Create UI Components
        self.create_ui()

    def create_ui(self):
        # Main container with padding
        main_container = ttk.Frame(self.window, padding="20 20 20 20", style='TFrame')
        main_container.pack(fill=tk.BOTH, expand=True)

        # Server Configuration Frame
        config_frame = ttk.LabelFrame(main_container, text="Server Configuration", style='TLabelframe')
        config_frame.pack(fill="x", pady=(0, 10))

        # Port Input
        ttk.Label(config_frame, text="Port:", style='TLabel').pack(side="left", padx=5)
        self.port_entry = ttk.Entry(config_frame, width=10)
        self.port_entry.pack(side="left", padx=5)
        self.port_entry.insert(0, str(self.port))

        # Key Frame with improved layout
        key_frame = ttk.LabelFrame(main_container, text="Encryption Key", style='TLabelframe')
        key_frame.pack(fill="x", pady=(0, 10))

        # Key Method Selection
        key_method_container = ttk.Frame(key_frame, style='TFrame')
        key_method_container.pack(fill="x")

        ttk.Label(key_method_container, text="Key Method:", style='TLabel').pack(side="left", padx=5)
        self.key_method = tk.StringVar(value="generate")
        
        manual_radio = ttk.Radiobutton(key_method_container, text="Manual Key", 
                                       variable=self.key_method, 
                                       value="manual", 
                                       command=self.toggle_key_input)
        manual_radio.pack(side="left")

        generate_radio = ttk.Radiobutton(key_method_container, text="Generate Key", 
                                         variable=self.key_method, 
                                         value="generate", 
                                         command=self.toggle_key_input)
        generate_radio.pack(side="left")

        # Key Entry and Generation
        key_input_container = ttk.Frame(key_frame, style='TFrame')
        key_input_container.pack(fill="x", pady=(5,0))

        self.key_entry = ttk.Entry(key_input_container, width=50, show="")
        self.key_entry.pack(side="left", padx=5, expand=True, fill="x")

        self.generate_key_button = ttk.Button(key_input_container, text="Generate Key", command=self.generate_secure_key)
        self.generate_key_button.pack(side="right", padx=5)

        # Server Log Display
        log_label = ttk.Label(main_container, text="Server Log:", style='TLabel')
        log_label.pack()

        log_frame = ttk.Frame(main_container)
        log_frame.pack(padx=10, pady=5, expand=True, fill="both")

        self.log_box = tk.Text(log_frame, width=80, height=20, 
                                bg='#34495e', fg='white', 
                                insertbackground='white',
                                font=('Consolas', 10))
        self.log_box.pack(side="left", expand=True, fill="both")

        # Scrollbar for log
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_box.yview)
        log_scrollbar.pack(side="right", fill="y")
        self.log_box.configure(yscrollcommand=log_scrollbar.set)
        self.log_box.config(state="disabled")

        # Message Broadcast Frame
        message_frame = ttk.Frame(main_container)
        message_frame.pack(fill="x", padx=10, pady=(10,0))

        ttk.Label(message_frame, text="Broadcast Message:", style='TLabel').pack(side="left")
        self.message_entry = ttk.Entry(message_frame, width=50)
        self.message_entry.pack(side="left", expand=True, fill="x", padx=5)

        # Send Button with color
        send_button = ttk.Button(message_frame, text="Broadcast", command=self.broadcast_message, 
                                 style='Accent.TButton')
        send_button.pack(side="right", padx=5)

        # Server Control Buttons
        button_frame = ttk.Frame(main_container)
        button_frame.pack(pady=10)

        # Styled buttons
        start_button = ttk.Button(button_frame, text="Start Server", command=self.start_server)
        start_button.pack(side="left", padx=5)

        stop_button = ttk.Button(button_frame, text="Stop Server", command=self.stop_server)
        stop_button.pack(side="left", padx=5)

        # Decryption Frame
        decrypt_frame = ttk.LabelFrame(main_container, text="Decryption", style='TLabelframe')
        decrypt_frame.pack(fill="x", padx=10, pady=(0,10))

        ttk.Label(decrypt_frame, text="Text to Decrypt:", style='TLabel').pack(side="left")
        self.decrypt_entry = ttk.Entry(decrypt_frame, width=40)
        self.decrypt_entry.pack(side="left", padx=5, expand=True, fill="x")

        decrypt_button = ttk.Button(decrypt_frame, text="Decrypt", command=self.manual_decrypt)
        decrypt_button.pack(side="right", padx=5)

        self.decrypt_output = tk.Text(decrypt_frame, height=3, width=80, 
                                      bg='#34495e', fg='white', 
                                      insertbackground='white',
                                      font=('Consolas', 10),
                                      state="disabled")
        self.decrypt_output.pack(pady=5, padx=10, fill="x")

        # Ensure proper cleanup on window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Custom styling
        self.style.configure('Accent.TButton', background='#3498db', foreground='white')

        # Start with generated key
        self.generate_secure_key()

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

    def start_server(self):
        """Start the server"""
        if self.server_running:
            messagebox.showerror("Error", "Server is already running")
            return

        # Get port and validate
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return

        # Get encryption key
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Please provide an encryption key")
            return

        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, port))
            self.server_socket.listen(5)
            self.server_running = True

            # Determine the actual IP address
            try:
                # Create a temporary socket to get the local IP
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                temp_socket.connect(("8.8.8.8", 80))  # Doesn't actually send data
                local_ip = temp_socket.getsockname()[0]
                temp_socket.close()
            except Exception:
                local_ip = '127.0.0.1'  # Fallback to localhost if detection fails

            # Start accepting connections in a separate thread
            accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            accept_thread.start()

            # Update log with IP and port information
            self.update_log(f"Server started on {local_ip}:{port}")
            self.update_log(f"Listening on all interfaces (0.0.0.0)")
        except Exception as e:
            messagebox.showerror("Server Start Error", str(e))

    def accept_connections(self):
        """Accept incoming client connections"""
        while self.server_running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.update_log(f"Connection from {client_address}")
                
                # Store connection with server's key
                key = self.key_entry.get().strip()
                self.connections.append((client_socket, client_address))
                
                # Start a thread to handle this client
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, client_address, key), 
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.server_running:
                    self.update_log(f"Accept connection error: {e}")
                break

    def handle_client(self, client_socket, client_address, key):
        """Handle individual client communication"""
        try:
            while self.server_running:
                # Receive encrypted message
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break

                # Decrypt and log message
                decrypted_msg = self.decrypt_message(data, key)
                if decrypted_msg:
                    self.update_log(f"Received from {client_address}: {decrypted_msg}")
        except Exception as e:
            self.update_log(f"Client {client_address} disconnected: {e}")
        finally:
            # Remove client from connections and close socket
            self.connections = [
                conn for conn in self.connections 
                if conn[0] != client_socket
            ]
            client_socket.close()

    def broadcast_message(self):
        """Send a message to all connected clients"""
        if not self.connections:
            messagebox.showinfo("Info", "No clients connected")
            return

        message = self.message_entry.get().strip()
        if not message:
            messagebox.showwarning("Warning", "Message is empty")
            return

        key = self.key_entry.get().strip()
        try:
            # Encrypt message
            encrypted_msg = self.encrypt_message(message, key)
            
            # Broadcast to all connected clients
            for client_socket, _ in self.connections:
                client_socket.send(encrypted_msg.encode('utf-8'))

            # Log the broadcast
            self.update_log(f"Broadcast: {message}")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Broadcast Error", str(e))

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
            self.update_log(f"Decryption error: {e}")
            return None

    def manual_decrypt(self):
        """Manual decryption for testing"""
        encrypted_text = self.decrypt_entry.get().strip()
        key = self.key_entry.get().strip()

        if not encrypted_text or not key:
            messagebox.showwarning("Warning", "Provide encrypted text and key")
            return

        decrypted_text = self.decrypt_message(encrypted_text, key)
        
        # Update decryption output
        self.decrypt_output.config(state="normal")
        self.decrypt_output.delete(1.0, tk.END)
        self.decrypt_output.insert(tk.END, decrypted_text or "Decryption failed")
        self.decrypt_output.config(state="disabled")

    def update_log(self, message):
        """Update server log"""
        self.log_box.config(state="normal")
        self.log_box.insert(tk.END, message + "\n")
        self.log_box.see(tk.END)
        self.log_box.config(state="disabled")

    def stop_server(self):
        """Stop the server and close all connections"""
        if not self.server_running:
            return

        self.server_running = False
        
        # Close all client connections
        for client_socket, _ in self.connections:
            client_socket.close()
        self.connections.clear()

        # Close server socket
        if self.server_socket:
            self.server_socket.close()

        self.update_log("Server stopped")

    def on_closing(self):
        """Handle window closing"""
        self.stop_server()
        self.window.quit()

    def run(self):
        """Start the server application"""
        self.window.mainloop()

# Run the server
if __name__ == "__main__":
    server = ZephyrSecuritiesChatServer()
    server.run()