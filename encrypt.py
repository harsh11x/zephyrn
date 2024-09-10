import os
from tkinter import Tk, Label, Button, filedialog, messagebox, simpledialog
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import threading

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption Tool")
        self.root.geometry("400x250")
        
        self.label = Label(root, text="Select a file to encrypt", font=("Helvetica", 14))
        self.label.pack(pady=20)
        
        self.choose_button = Button(root, text="Choose File", command=self.choose_file, font=("Helvetica", 12))
        self.choose_button.pack(pady=10)
        
        self.encrypt_button = Button(root, text="Encrypt", command=self.start_encryption, state="disabled", font=("Helvetica", 12))
        self.encrypt_button.pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="indeterminate")
        
        self.file_path = None

    def choose_file(self):
        self.file_path = filedialog.askopenfilename(title="Select File")
        if self.file_path:
            self.label.config(text=f"File: {os.path.basename(self.file_path)} selected")
            self.encrypt_button.config(state="normal")

    def generate_key(self, password):
        hasher = SHA256.new(password.encode('utf-8'))
        return hasher.digest()

    def encrypt_file(self):
        try:
            chunk_size = 64 * 1024
            output_file = self.file_path + ".enc"
            file_size = str(os.path.getsize(self.file_path)).zfill(16)
            iv = Random.new().read(16)
            
            with open(self.file_path, 'rb') as infile:
                with open(output_file, 'wb') as outfile:
                    outfile.write(file_size.encode('utf-8'))
                    outfile.write(iv)
                    encryptor = AES.new(self.key, AES.MODE_CBC, iv)
                    
                    while chunk := infile.read(chunk_size):
                        if len(chunk) % 16 != 0:
                            chunk += b' ' * (16 - len(chunk) % 16)
                        outfile.write(encryptor.encrypt(chunk))
            messagebox.showinfo("Success", f"File '{os.path.basename(self.file_path)}' encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during encryption: {e}")
        finally:
            self.stop_progress()

    def start_encryption(self):
        password = simpledialog.askstring("Password", "Enter encryption password:", show="*")
        if not password:
            messagebox.showwarning("No Password", "Password is required to encrypt the file.")
            return
        self.key = self.generate_key(password)
        
        self.progress_bar.pack(pady=10)
        self.progress_bar.start()
        
        self.disable_buttons()
        encryption_thread = threading.Thread(target=self.encrypt_file)
        encryption_thread.start()

    def disable_buttons(self):
        self.choose_button.config(state="disabled")
        self.encrypt_button.config(state="disabled")

    def stop_progress(self):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.choose_button.config(state="normal")

if __name__ == "__main__":
    root = Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
