import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import queue
import os
import secrets
import time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct

class ModernStyledApp:
    def __init__(self, root):
        self.root = root
        self._setup_root()
        self.password_queue = queue.Queue()
        self._create_widgets()

    def _setup_root(self):
        """Configure root window with modern styling."""
        self.root.title("Zephyrn Securities")
        self.root.geometry("800x600")
        self.root.configure(bg='#1e1e2e')
        self.root.option_add("*Font", "Segoe 10")

        # Custom style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self._configure_styles()

    def _configure_styles(self):
        """Create custom styles for modern look."""
        # Button styles
        self.style.configure('TButton',
                             background='#11111b',
                             foreground='white',
                             font=('Segoe UI', 12, 'bold'),
                             borderwidth=0,
                             relief='flat')
        self.style.map('TButton',
                       background=[('active', '#313244'), ('pressed', '#45475a')])

        # Progress bar style
        self.style.configure('Custom.Horizontal.TProgressbar',
                             background='white',
                             troughcolor='black')

    def _create_widgets(self):
        """Create modern, sleek UI components."""
        # Main container
        main_frame = tk.Frame(self.root, bg='#1e1e2e')
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        # Title
        title_label = tk.Label(main_frame,
                               text="Zephyrn Securities",
                               font=('Segoe UI', 24, 'bold'),
                               bg='#1e1e2e',
                               fg='#89b4fa')
        title_label.pack(pady=(0, 30))

        # Button frame
        button_frame = tk.Frame(main_frame, bg='#1e1e2e')
        button_frame.pack(fill='x', pady=10)

        # Encrypt Button
        self.encrypt_btn = ttk.Button(button_frame,
                                      text="🔒 Encrypt File",
                                      command=self._start_encryption,
                                      style='TButton')
        self.encrypt_btn.pack(side=tk.LEFT, expand=True, padx=10, fill='x')

        # Decrypt Button
        self.decrypt_btn = ttk.Button(button_frame,
                                      text="🔓 Decrypt File",
                                      command=self._start_decryption,
                                      style='TButton')
        self.decrypt_btn.pack(side=tk.RIGHT, expand=True, padx=10, fill='x')

        # Progress Section
        progress_frame = tk.Frame(main_frame, bg='#1e1e2e')
        progress_frame.pack(fill='x', pady=20)

        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame,
                                            variable=self.progress_var,
                                            style='Custom.Horizontal.TProgressbar',
                                            length=760,
                                            mode='determinate')
        self.progress_bar.pack(fill='x')

        # Percentage Label
        self.percentage_label = tk.Label(progress_frame,
                                         text="0%",
                                         bg='#1e1e2e',
                                         fg='white',
                                         font=('Segoe UI', 10))
        self.percentage_label.pack(pady=(10, 0))

        # Status Label
        self.status_label = tk.Label(main_frame,
                                     text="Ready to Encrypt/Decrypt",
                                     bg='#1e1e2e',
                                     fg='#cdd6f4',
                                     font=('Segoe UI', 10))
        self.status_label.pack(pady=10)

    def _get_secure_password(self):
        """Enhanced password input dialog."""
        # Create a modern, floating password dialog
        password_window = tk.Toplevel(self.root)
        password_window.title("Secure Password")
        password_window.geometry("400x250")
        password_window.configure(bg='#11111b')
        password_window.overrideredirect(True)

        # Center the window
        self._center_window(password_window)

        # Password frame
        password_frame = tk.Frame(password_window, bg='#11111b')
        password_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        # Title
        title = tk.Label(password_frame,
                         text="Enter Encryption Password",
                         bg='#11111b',
                         fg='#89b4fa',
                         font=('Segoe UI', 14, 'bold'))
        title.pack(pady=(0, 20))

        # Password Entry
        password_var = tk.StringVar()
        password_entry = tk.Entry(password_frame,
                                  textvariable=password_var,
                                  show="•",
                                  font=('Segoe UI', 14),
                                  bg='#181825',
                                  fg='white',
                                  insertbackground='white',
                                  borderwidth=0)
        password_entry.pack(fill='x', pady=10)

        # Submit Button
        def on_submit():
            password = password_var.get()
            if len(password) < 8:
                messagebox.showwarning("Weak Password", "Password must be at least 8 characters")
                return

            self.password_queue.put(password)
            password_window.destroy()

        submit_btn = ttk.Button(password_frame,
                                text="Submit",
                                command=on_submit,
                                style='TButton')
        submit_btn.pack(pady=20)

        password_entry.bind('<Return>', lambda e: on_submit())

        password_window.transient(self.root)
        self.root.wait_window(password_window)

        try:
            return self.password_queue.get(block=False)
        except queue.Empty:
            return None

    def _center_window(self, window):
        """Center the window on the screen."""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (self.root.winfo_width() // 2) - (width // 2) + self.root.winfo_x()
        y = (self.root.winfo_height() // 2) - (height // 2) + self.root.winfo_y()
        window.geometry(f'{width}x{height}+{x}+{y}')

    def _start_encryption(self):
        """Initiate encryption in a separate thread."""
        def encryption_thread():
            try:
                input_path = filedialog.askopenfilename(title="Select File to Encrypt")
                if not input_path:
                    return

                password = self._get_secure_password()
                if not password:
                    return

                start_time = time.time()
                output_path = self._encrypt_file(input_path, password)
                elapsed_time = time.time() - start_time

                if output_path:
                    messagebox.showinfo("Success",
                                        f"File Encrypted Successfully: {output_path}\nTime Taken: {elapsed_time:.2f} seconds")
            except Exception as e:
                messagebox.showerror("Encryption Error", str(e))
            finally:
                self.progress_var.set(0)
                self.percentage_label.config(text="0%")

        threading.Thread(target=encryption_thread, daemon=True).start()

    def _start_decryption(self):
        """Initiate decryption in a separate thread."""
        def decryption_thread():
            try:
                input_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.enc")])
                if not input_path:
                    return

                password = self._get_secure_password()
                if not password:
                    return

                # Verify password before decryption
                if not self._verify_password(input_path, password):
                    messagebox.showerror("Decryption Error", "Wrong Password! Try Again.")
                    return

                start_time = time.time()
                output_path = self._decrypt_file(input_path, password)
                elapsed_time = time.time() - start_time

                if output_path:
                    messagebox.showinfo("Success",
                                        f"File Decrypted Successfully: {output_path}\nTime Taken: {elapsed_time:.2f} seconds")
            except Exception as e:
                messagebox.showerror("Decryption Error", str(e))
            finally:
                self.progress_var.set(0)
                self.percentage_label.config(text="0%")

        threading.Thread(target=decryption_thread, daemon=True).start()

    def _encrypt_file(self, input_path, password):
        """Robust file encryption with .enc extension."""
        try:
            # Get the original file extension
            original_extension = os.path.splitext(input_path)[1]

            # Remove the original extension and append .enc
            base_name = os.path.splitext(input_path)[0]
            output_path = base_name + '.enc'

            salt = secrets.token_bytes(16)
            iv = secrets.token_bytes(16)
            key = self._derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write salt and IV
                outfile.write(salt)
                outfile.write(iv)

                # Write the length of the original extension
                outfile.write(struct.pack('>I', len(original_extension)))

                # Write the original extension
                outfile.write(original_extension.encode())

                # Encrypt the file content
                file_size = os.path.getsize(input_path)
                bytes_processed = 0

                while chunk := infile.read(1024 * 1024):
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                    bytes_processed += len(chunk)
                    progress = (bytes_processed / file_size) * 100
                    self.progress_var.set(progress)
                    self.percentage_label.config(text=f"{progress:.2f}%")
                    self.root.update_idletasks()

                final_chunk = encryptor.finalize()
                outfile.write(final_chunk)

            return output_path
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return None

    def _decrypt_file(self, input_path, password):
        """Decrypt a file that was previously encrypted with the .enc extension."""
        try:
            with open(input_path, 'rb') as infile:
                # Read salt and IV
                salt = infile.read(16)
                iv = infile.read(16)

                # Read the length of the original extension
                extension_length = struct.unpack('>I', infile.read(4))[0]

                # Read the original extension
                original_extension = infile.read(extension_length).decode()

                # Derive the key
                key = self._derive_key(password, salt)

                # Initialize the cipher
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                # Remove the .enc extension and restore the original extension
                base_name = os.path.splitext(input_path)[0]
                output_path = base_name + original_extension

                # Decrypt the file content
                file_size = os.path.getsize(input_path) - 32 - 4 - extension_length  # Exclude salt, IV, and extension metadata
                bytes_processed = 0

                with open(output_path, 'wb') as outfile:
                    while chunk := infile.read(1024 * 1024):
                        decrypted_chunk = decryptor.update(chunk)
                        outfile.write(decrypted_chunk)
                        bytes_processed += len(chunk)
                        progress = (bytes_processed / file_size) * 100
                        self.progress_var.set(progress)
                        self.percentage_label.config(text=f"{progress:.2f}%")
                        self.root.update_idletasks()

                    final_chunk = decryptor.finalize()
                    outfile.write(final_chunk)

            return output_path
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return None

    def _verify_password(self, input_path, password):
        """Verify the password for decrypting the file."""
        try:
            with open(input_path, 'rb') as infile:
                salt = infile.read(16)
                key = self._derive_key(password, salt)
            return key is not None
        except Exception:
            return False

    def _derive_key(self, password, salt):
        """Derive a secure key using Scrypt KDF."""
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        key = kdf.derive(password.encode())
        return key

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernStyledApp(root)
    root.mainloop()
