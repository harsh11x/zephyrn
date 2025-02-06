import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import queue
import os
import secrets
import time
import sys
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
import hashlib

class ModernStyledApp:
    def __init__(self, root):
        self.root = root
        self._setup_root()
        self.password_queue = queue.Queue()
        self.gpu_devices = self._detect_gpu_devices()
        self._create_widgets()

    def _detect_gpu_devices(self):
        devices = []
        if not GPU_AVAILABLE:
            print("PyOpenCL is not installed. Please install it with: pip install pyopencl")
            return devices

        try:
            platforms = cl.get_platforms()
            print(f"Total OpenCL Platforms Detected: {len(platforms)}")

            for i, platform in enumerate(platforms):
                print(f"\nPlatform {i}:")
                print(f"  Name: {platform.name}")
                print(f"  Vendor: {platform.vendor}")
                print(f"  Version: {platform.version}")

                try:
                    platform_devices = platform.get_devices(cl.device_type.GPU)
                    for j, device in enumerate(platform_devices):
                        print(f"\n  Device {j}:")
                        print(f"    Name: {device.name}")
                        print(f"    Type: {cl.device_type.to_string(device.type)}")
                        print(f"    Max Compute Units: {device.max_compute_units}")
                        print(f"    Global Memory: {device.global_mem_size / (1024**3):.2f} GB")
                        devices.append(device)
                except cl.LogicError as device_error:
                    print(f"  No GPU devices found in this platform: {device_error}")
                except Exception as inner_error:
                    print(f"  Error detecting devices: {inner_error}")

            if not devices:
                print("No OpenCL GPU devices found. Ensure NVIDIA OpenCL drivers are installed.")
                try:
                    import subprocess
                    result = subprocess.run(['nvidia-smi'], capture_output=True, text=True)
                    print("\nNVIDIA-SMI Output:")
                    print(result.stdout)
                except Exception:
                    print("nvidia-smi command not available. Check NVIDIA driver installation.")

        except Exception as e:
            print("Comprehensive GPU Detection Error:")
            print(traceback.format_exc())

        return devices

    def _setup_root(self):
        self.root.title("Zephyrn Securities")
        self.root.geometry("800x650")
        self.root.configure(bg='#1e1e2e')
        self.root.option_add("*Font", "Segoe 10")

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self._configure_styles()

    def _configure_styles(self):
        self.style.configure('TButton',
                             background='#11111b',
                             foreground='white',
                             font=('Segoe UI', 12, 'bold'),
                             borderwidth=0,
                             relief='flat')
        self.style.map('TButton',
                       background=[('active', '#313244'), ('pressed', '#45475a')])

        self.style.configure('Custom.Horizontal.TProgressbar',
                             background='white',
                             troughcolor='black')

    def _create_widgets(self):
        main_frame = tk.Frame(self.root, bg='#1e1e2e')
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        title_label = tk.Label(main_frame,
                               text="Zephyrn Securities",
                               font=('Segoe UI', 24, 'bold'),
                               bg='#1e1e2e',
                               fg='#89b4fa')
        title_label.pack(pady=(0, 30))

        gpu_frame = tk.Frame(main_frame, bg='#1e1e2e')
        gpu_frame.pack(fill='x', pady=10)

        gpu_devices_names = ", ".join([d.name for d in self.gpu_devices]) if self.gpu_devices else "No GPU Detected"
        gpu_label_text = f"GPU Devices: {gpu_devices_names}"
        gpu_label = tk.Label(gpu_frame,
                             text=gpu_label_text,
                             bg='#1e1e2e',
                             fg='#cdd6f4',  # Corrected color code
                             font=('Segoe UI', 10))
        gpu_label.pack()

        button_frame = tk.Frame(main_frame, bg='#1e1e2e')
        button_frame.pack(fill='x', pady=10)

        self.encrypt_btn = ttk.Button(button_frame,
                                      text="🔒 Encrypt File",
                                      command=self._start_encryption,
                                      style='TButton')
        self.encrypt_btn.pack(side=tk.LEFT, expand=True, padx=10, fill='x')

        self.decrypt_btn = ttk.Button(button_frame,
                                      text="🔓 Decrypt File",
                                      command=self._start_decryption,
                                      style='TButton')
        self.decrypt_btn.pack(side=tk.RIGHT, expand=True, padx=10, fill='x')

        progress_frame = tk.Frame(main_frame, bg='#1e1e2e')
        progress_frame.pack(fill='x', pady=20)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame,
                                            variable=self.progress_var,
                                            style='Custom.Horizontal.TProgressbar',
                                            length=760,
                                            mode='determinate')
        self.progress_bar.pack(fill='x')

        self.percentage_label = tk.Label(progress_frame,
                                         text="0%",
                                         bg='#1e1e2e',
                                         fg='white',
                                         font=('Segoe UI', 10))
        self.percentage_label.pack(pady=(10, 0))

        self.status_label = tk.Label(main_frame,
                                     text="Ready to Encrypt/Decrypt",
                                     bg='#1e1e2e',
                                     fg='#cdd6f4',
                                     font=('Segoe UI', 10))
        self.status_label.pack(pady=10)

        self.time_label = tk.Label(main_frame,
                                   text="Time Taken: 0 seconds",
                                   bg='#1e1e2e',
                                   fg='#cdd6f4',
                                   font=('Segoe UI', 10))
        self.time_label.pack(pady=(10, 0))

    def _get_secure_password(self):
        password_window = tk.Toplevel(self.root)
        password_window.title("Secure Password")
        password_window.geometry("400x250")
        password_window.configure(bg='#11111b')
        password_window.overrideredirect(True)

        self._center_window(password_window)

        password_frame = tk.Frame(password_window, bg='#11111b')
        password_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        title = tk.Label(password_frame,
                         text="Enter Encryption Password",
                         bg='#11111b',
                         fg='#89b4fa',
                         font=('Segoe UI', 14, 'bold'))
        title.pack(pady=(0, 20))

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
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (self.root.winfo_width() // 2) - (width // 2) + self.root.winfo_x()
        y = (self.root.winfo_height() // 2) - (height // 2) + self.root.winfo_y()
        window.geometry(f'{width}x{height}+{x}+{y}')

    def _gpu_encrypt_chunk(self, chunk, key, iv):
        if not GPU_AVAILABLE or not self.gpu_devices:
            return None

        try:
            devices = self.gpu_devices  # ()
           # gpu_devices[0]
            context = cl.Context([devices])
            queue = cl.CommandQueue(context)

            chunk_np = np.frombuffer(chunk, dtype=np.uint8)
            key_np = np.frombuffer(key, dtype=np.uint8)
            iv_np = np.frombuffer(iv, dtype=np.uint8)

            chunk_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=chunk_np)
            key_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=key_np)
            iv_buf = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=iv_np)
            output_buf = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, chunk_np.nbytes)

            kernel_source = """
            __kernel void encrypt_chunk(__global const uchar* input, 
                                        __global const uchar* key, 
                                        __global const uchar* iv, 
                                        __global uchar* output) {
                int gid = get_global_id(0);
                output[gid] = input[gid] ^ key[gid % 32] ^ iv[gid % 16];
            }
            """

            program = cl.Program(context, kernel_source).build()

            global_size = (len(chunk_np),)
            local_size = None

            program.encrypt_chunk(queue, global_size, local_size, 
                                  chunk_buf, key_buf, iv_buf, output_buf)

            output_np = np.empty_like(chunk_np)
            cl.enqueue_copy(queue, output_np, output_buf)

            return output_np.tobytes()
        except Exception as e:
            print(f"GPU Encryption Error: {e}")
            return None

    def _encrypt_file(self, input_path, password):
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
                        encrypted_chunk = self._gpu_encrypt_chunk(chunk, key, iv)
                    
                    if not use_gpu or encrypted_chunk is None:
                        encrypted_chunk = encryptor.update(chunk)
                    
                    outfile.write(encrypted_chunk)
                    bytes_processed += len(chunk)
                    progress = (bytes_processed / file_size) * 100
                    self.progress_var.set(progress)
                    self.percentage_label.config(text=f"{progress:.2f}%")
                    self.root.update_idletasks()

                final_chunk = encryptor.finalize()
                outfile.write(final_chunk)

            elapsed_time = time.time() - start_time
            self.time_label.config(text=f"Time Taken: {elapsed_time:.2f} seconds")
            return output_path
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return None

    def _gpu_decrypt_chunk(self, chunk, key, iv):
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

            kernel_source = """
            __kernel void decrypt_chunk(__global const uchar* input, 
                                        __global const uchar* key, 
                                        __global const uchar* iv, 
                                        __global uchar* output) {
                int gid = get_global_id(0);
                output[gid] = input[gid] ^ key[gid % 32] ^ iv[gid % 16];
            }
            """

            program = cl.Program(context, kernel_source).build()

            global_size = (len(chunk_np),)
            local_size = None

            program.decrypt_chunk(queue, global_size, local_size, 
                                  chunk_buf, key_buf, iv_buf, output_buf)

            output_np = np.empty_like(chunk_np)
            cl.enqueue_copy(queue, output_np, output_buf)

            return output_np.tobytes()
        except Exception as e:
            print(f"GPU Decryption Error: {e}")
            return None

    def _decrypt_file(self, input_path, password):
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
                            decrypted_chunk = self._gpu_decrypt_chunk(chunk, key, iv)

                        if not use_gpu or decrypted_chunk is None:
                            decrypted_chunk = decryptor.update(chunk)

                        outfile.write(decrypted_chunk)
                        bytes_processed += len(chunk)
                        progress = (bytes_processed / file_size) * 100
                        self.progress_var.set(progress)
                        self.percentage_label.config(text=f"{progress:.2f}%")
                        self.root.update_idletasks()

                    final_chunk = decryptor.finalize()
                    outfile.write(final_chunk)

            elapsed_time = time.time() - start_time
            self.time_label.config(text=f"Time Taken: {elapsed_time:.2f} seconds")
            return output_path
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return None

    def _derive_key(self, password, salt):
        """Derive a key from the password using Scrypt."""
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def _start_encryption(self):
        input_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if input_path:
            password = self._get_secure_password()
            if password:
                threading.Thread(target=self._encrypt_file, args=(input_path, password)).start()

    def _start_decryption(self):
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
        print("An error occurred:", e)
        traceback.print_exc()