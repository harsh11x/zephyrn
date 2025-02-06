import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import queue
import os
import secrets
import time
import traceback

try:
    import numpy as np
    import pyopencl as cl
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants for UI
BG_COLOR = '#1e1e2e'
FG_COLOR = '#cdd6f4'
BUTTON_BG = '#11111b'
BUTTON_ACTIVE_BG = '#313244'
BUTTON_PRESSED_BG = '#45475a'
TITLE_FONT = ('Segoe UI', 24, 'bold')
LABEL_FONT = ('Segoe UI', 10)
BUTTON_FONT = ('Segoe UI', 12, 'bold')

class ModernStyledApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Zephyrn Securities")
        self.root.geometry("800x650")
        self.root.configure(bg=BG_COLOR)
        self.root.option_add("*Font", "Segoe 10")

        self.password_queue = queue.Queue()
        self.gpu_devices = self._detect_gpu_devices()
        self._create_widgets()

    def _detect_gpu_devices(self):
        """Detect available GPU devices."""
        devices = []
        if not GPU_AVAILABLE:
            print("PyOpenCL is not installed. Please install it with: pip install pyopencl")
            return devices

        try:
            platforms = cl.get_platforms()
            for platform in platforms:
                try:
                    platform_devices = platform.get_devices(cl.device_type.GPU)
                    devices.extend(platform_devices)
                except cl.LogicError:
                    continue  # No GPU devices found in this platform

            if not devices:
                print("No OpenCL GPU devices found.")
        except Exception as e:
            print("Error detecting GPU devices:", e)

        return devices

    def _create_widgets(self):
        """Create the main application widgets."""
        main_frame = tk.Frame(self.root, bg=BG_COLOR)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        title_label = tk.Label(main_frame, text="Zephyrn Securities", font=TITLE_FONT, bg=BG_COLOR, fg=FG_COLOR)
        title_label.pack(pady=(0, 30))

        self._create_gpu_info(main_frame)
        self._create_buttons(main_frame)
        self._create_progress_bar(main_frame)
        self._create_status_labels(main_frame)

    def _create_gpu_info(self, parent):
        """Create GPU information display."""
        gpu_frame = tk.Frame(parent, bg=BG_COLOR)
        gpu_frame.pack(fill='x', pady=10)

        gpu_devices_names = ", ".join([d.name for d in self.gpu_devices]) if self.gpu_devices else "No GPU Detected"
        gpu_label = tk.Label(gpu_frame, text=f"GPU Devices: {gpu_devices_names}", bg=BG_COLOR, fg=FG_COLOR, font=LABEL_FONT)
        gpu_label.pack()

    def _create_buttons(self, parent):
        """Create action buttons for encryption and decryption."""
        button_frame = tk.Frame(parent, bg=BG_COLOR)
        button_frame.pack(fill='x', pady=10)

        self.encrypt_btn = ttk.Button(button_frame, text="🔒 Encrypt File", command=self._start_encryption, style='TButton')
        self.encrypt_btn.pack(side=tk.LEFT, expand=True, padx=10, fill='x')

        self.decrypt_btn = ttk.Button(button_frame, text="🔓 Decrypt File", command=self._start_decryption, style='TButton')
        self.decrypt_btn.pack(side=tk.RIGHT, expand=True, padx=10, fill='x')

    def _create_progress_bar(self, parent):
        """Create a progress bar for file operations."""
        progress_frame = tk.Frame(parent, bg=BG_COLOR)
        progress_frame.pack(fill='x', pady=20)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, length=760, mode='determinate')
        self.progress_bar.pack(fill='x')

        self.percentage_label = tk.Label(progress_frame, text="0%", bg=BG_COLOR, fg='white', font=LABEL_FONT)
        self.percentage_label.pack(pady=(10, 0))

    def _create_status_labels(self, parent):
        """Create status labels for displaying messages."""
        self.status_label = tk.Label(parent, text="Ready to Encrypt/Decrypt", bg=BG_COLOR, fg=FG_COLOR, font=LABEL_FONT)
        self.status_label.pack(pady=10)

        self.time_label = tk.Label(parent, text="Time Taken: 0 seconds", bg=BG_COLOR, fg=FG_COLOR, font=LABEL_FONT)
        self.time_label.pack(pady=(10, 0))

    def _get_secure_password(self):
        """Prompt the user for a secure password."""
        password_window = tk.Toplevel(self.root)
        password_window.title("Secure Password")
        password_window.geometry("400x250")
        password_window.configure(bg=BUTTON_BG)
        password_window.overrideredirect(True)

        self._center_window(password_window)

        password_frame = tk.Frame(password_window, bg=BUTTON_BG)
        password_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        title = tk.Label(password_frame, text="Enter Encryption Password", bg=BUTTON_BG, fg=FG_COLOR, font=('Segoe UI', 14, 'bold'))
        title.pack(pady=(0, 20))

        password_var = tk.StringVar()
        password_entry = tk.Entry(password_frame, textvariable=password_var, show="•", font=('Segoe UI', 14), bg='#181825', fg='white', insertbackground='white', borderwidth=0)
        password_entry.pack(fill='x', pady=10)

        def on_submit():
            password = password_var.get()
            if len(password) < 8:
                messagebox.showwarning("Weak Password", "Password must be at least 8 characters")
                return
            self.password_queue.put(password)
            password_window.destroy()

        submit_btn = ttk.Button(password_frame, text="Submit", command=on_submit, style='TButton')
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

    def _gpu_process_chunk(self, chunk, key, iv, operation):
        """Encrypt or decrypt a chunk using GPU."""
        if not GPU_AVAILABLE or not self.gpu_devices:
            return None

        try:
            device = self.gpu_devices[0]
            context = cl.Context([device])
            queue = cl.CommandQueue(context)

            chunk_np = np.frombuffer(chunk, dtype=np.uint8)
            key_np = np.frombuffer(key, dtype=np.uint8)
            iv_np = np.frombuffer(iv, dtype=np.uint8)

            chunk_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=chunk_np)
            key_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=key_np)
            iv_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=iv_np)
            output_buf = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, chunk_np.nbytes)

            kernel_source = f"""
            __kernel void {operation}_chunk(__global const uchar* input, 
                                              __global const uchar* key, 
                                              __global const uchar* iv, 
                                              __global uchar* output) {{
                int gid = get_global_id(0);
                output[gid] = input[gid] ^ key[gid % 32] ^ iv[gid % 16];
            }}
            """

            program = cl.Program(context, kernel_source).build()
            global_size = (len(chunk_np),)
            program.__getattr__(f"{operation}_chunk")(queue, global_size, None, chunk_buf, key_buf, iv_buf, output_buf)

            output_np = np.empty_like(chunk_np)
            cl.enqueue_copy(queue, output_np, output_buf)

            return output_np.tobytes()
        except Exception as e:
            print(f"GPU {operation.capitalize()} Error: {e}")
            return None

    def _encrypt_file(self, input_path, password):
        """Encrypt the specified file using the provided password."""
        start_time = time.time()
        try:
            output_path = input_path + '.enc'
            salt = secrets.token_bytes(16)
            iv = secrets.token_bytes(16)
            key = self._derive_key(password, salt)

            use_gpu = GPU_AVAILABLE and self.gpu_devices
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                outfile.write(salt)
                outfile.write(iv)

                file_size = os.path.getsize(input_path)
                bytes_processed = 0

                while chunk := infile.read(1024 * 1024):
                    if use_gpu:
                        encrypted_chunk = self._gpu_process_chunk(chunk, key, iv, 'encrypt')
                    
                    if not use_gpu or encrypted_chunk is None:
                        encrypted_chunk = encryptor.update(chunk)
                    
                    outfile.write(encrypted_chunk)
                    bytes_processed += len(chunk)
                    self._update_progress(bytes_processed, file_size)

                final_chunk = encryptor.finalize()
                outfile.write(final_chunk)

            elapsed_time = time.time() - start_time
            self.time_label.config(text=f"Time Taken: {elapsed_time:.2f} seconds")
            return output_path
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return None

    def _decrypt_file(self, input_path, password):
        """Decrypt the specified file using the provided password."""
        start_time = time.time()
        try:
            output_path = input_path[:-4]  # Remove .enc extension
            with open(input_path, 'rb') as infile:
                salt = infile.read(16)
                iv = infile.read(16)
                key = self._derive_key(password, salt)

                use_gpu = GPU_AVAILABLE and self.gpu_devices
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                with open(output_path, 'wb') as outfile:
                    file_size = os.path.getsize(input_path)
                    bytes_processed = 0

                    while chunk := infile.read(1024 * 1024):
                        if use_gpu:
                            decrypted_chunk = self._gpu_process_chunk(chunk, key, iv, 'decrypt')

                        if not use_gpu or decrypted_chunk is None:
                            decrypted_chunk = decryptor.update(chunk)

                        outfile.write(decrypted_chunk)
                        bytes_processed += len(chunk)
                        self._update_progress(bytes_processed, file_size)

                    final_chunk = decryptor.finalize()
                    outfile.write(final_chunk)

            elapsed_time = time.time() - start_time
            self.time_label.config(text=f"Time Taken: {elapsed_time:.2f} seconds")
            return output_path
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return None

    def _update_progress(self, bytes_processed, file_size):
        """Update the progress bar and percentage label."""
        progress = (bytes_processed / file_size) * 100
        self.progress_var.set(progress)
        self.percentage_label.config(text=f"{progress:.2f}%")
        self.root.update_idletasks()

    def _derive_key(self, password, salt):
        """Derive a key from the password using Scrypt."""
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        return kdf.derive(password.encode())

    def _start_encryption(self):
        """Start the encryption process in a new thread."""
        input_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if input_path:
            password = self._get_secure_password()
            if password:
                threading.Thread(target=self._encrypt_file, args=(input_path, password)).start()

    def _start_decryption(self):
        """Start the decryption process in a new thread."""
        input_path = filedialog.askopenfilename(title="Select a file to decrypt")
        if input_path:
            password = self._get_secure_password()
            if password:
                threading.Thread(target=self._decrypt_file, args=(input_path, password)).start()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = ModernStyledApp(root)
        root.mainloop()
    except Exception as e:
        print("An error occurred :", e)
        traceback.print_exc()