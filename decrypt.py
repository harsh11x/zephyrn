import os
from tkinter import Tk, Label, Button, filedialog, messagebox, simpledialog
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import threading

class FileDecryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Decryption Tool")
        self.root.geometry("400x250")
        
        self.label = Label(root, text="Select an encrypted file (.enc) to decrypt", font=("Helvetica", 14))
        self.label.pack(pady=20)
        
        self.choose_button = Button(root, text="Choose File", command=self.choose_file, font=("Helvetica", 12))
        self.choose_button.pack(pady=10)
        
        self.decrypt_button = Button(root, text="Decrypt", command=self.start_decryption, state="disabled", font=("Helvetica", 12))
        self.decrypt_button.pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="indeterminate")
        
        self.file_path = None

    def choose_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")], title="Select Encrypted File")
        if self.file_path:
            self.label.config(text=f"File: {os.path.basename(self.file_path)} selected")
            self.decrypt_button.config(state="normal")

    def generate_key(self, password):
        hasher = SHA256.new(password.encode('utf-8'))
        return hasher.digest()

    def decrypt_file(self):
        try:
            chunk_size = 64 * 1024
            output_file = os.path.splitext(self.file_path)[0]  # Remove ".enc" from the filename
            
            with open(self.file_path, 'rb') as infile:
                file_size = int(infile.read(16))
                iv = infile.read(16)
                decryptor = AES.new(self.key, AES.MODE_CBC, iv)
                
                with open(output_file, 'wb') as outfile:
                    while chunk := infile.read(chunk_size):
                        outfile.write(decryptor.decrypt(chunk))
                    outfile.truncate(file_size)
            
            messagebox.showinfo("Success", f"File '{os.path.basename(self.file_path)}' decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during decryption: {e}")
        finally:
            self.stop_progress()

    def start_decryption(self):
        password = simpledialog.askstring("Password", "Enter decryption password:", show="*")
        if not password:
            messagebox.showwarning("No Password", "Password is required to decrypt the file.")
            return
        self.key = self.generate_key(password)
        
        self.progress_bar.pack(pady=10)
        self.progress_bar.start()
        
        self.disable_buttons()
        decryption_thread = threading.Thread(target=self.decrypt_file)
        decryption_thread.start()

    def disable_buttons(self):
        self.choose_button.config(state="disabled")
        self.decrypt_button.config(state="disabled")

    def stop_progress(self):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.choose_button.config(state="normal")

if __name__ == "__main__":
    root = Tk()
    app = FileDecryptorApp(root)
    root.mainloop()
