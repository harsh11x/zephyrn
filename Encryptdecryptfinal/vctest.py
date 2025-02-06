import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip

# Extended character set for encryption
CHAR_SET = string.ascii_letters + string.digits + string.punctuation + " "
CHAR_SET_LEN = len(CHAR_SET)

# Function to generate a random key (15-20 characters)
def generate_unique_code():
    code_length = random.randint(15, 20)
    code = ''.join(random.choices(CHAR_SET, k=code_length))
    return code

# Function to create a dynamic Vigenère table
def create_vigenere_table():
    table = []
    for i in range(CHAR_SET_LEN):
        row = CHAR_SET[i:] + CHAR_SET[:i]
        table.append(row)
    return table

# Function for Vigenère encryption
def vigenere_encrypt_layer(plaintext, key):
    table = create_vigenere_table()
    expanded_key = (key * ((len(plaintext) // len(key)) + 1))[:len(plaintext)]
    ciphertext = []
    for i, char in enumerate(plaintext):
        if char in CHAR_SET:
            row = CHAR_SET.index(expanded_key[i])
            col = CHAR_SET.index(char)
            ciphertext.append(table[row][col])
        else:
            ciphertext.append(char)
    return ''.join(ciphertext)

# Function for Vigenère decryption
def vigenere_decrypt_layer(ciphertext, key):
    table = create_vigenere_table()
    expanded_key = (key * ((len(ciphertext) // len(key)) + 1))[:len(ciphertext)]
    plaintext = []
    for i, char in enumerate(ciphertext):
        if char in CHAR_SET:
            row = CHAR_SET.index(expanded_key[i])
            col = table[row].index(char)
            plaintext.append(CHAR_SET[col])
        else:
            plaintext.append(char)
    return ''.join(plaintext)

# Function for Caesar cipher encryption
def caesar_encrypt_layer(text, shift):
    return ''.join(CHAR_SET[(CHAR_SET.index(c) + shift) % CHAR_SET_LEN] if c in CHAR_SET else c for c in text)

# Function for Caesar cipher decryption
def caesar_decrypt_layer(text, shift):
    return ''.join(CHAR_SET[(CHAR_SET.index(c) - shift) % CHAR_SET_LEN] if c in CHAR_SET else c for c in text)

# Multi-layer encryption function
def multi_layer_encrypt(plaintext, key):
    vigenere_encrypted = vigenere_encrypt_layer(plaintext, key)
    shift = sum(ord(char) for char in key) % CHAR_SET_LEN
    return caesar_encrypt_layer(vigenere_encrypted, shift)

# Multi-layer decryption function
def multi_layer_decrypt(ciphertext, key):
    shift = sum(ord(char) for char in key) % CHAR_SET_LEN
    caesar_decrypted = caesar_decrypt_layer(ciphertext, shift)
    return vigenere_decrypt_layer(caesar_decrypted, key)

class ZephyrnSecurities(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # Window Configuration
        self.title("Zephyrn Securities")
        self.geometry("700x650")
        self.configure(bg='#121725')  # Darker background for better contrast
        
        # Remove default window decorations for a custom look
        self.overrideredirect(True)
        
        # Create a main container with shadow effect
        self.create_main_container()
        
        # Variables
        self.key_var = tk.StringVar()
        self.key_option_var = tk.StringVar(value="Generate")
        self.result_var = tk.StringVar()
        
        # Create UI components
        self.create_custom_titlebar()
        self.create_widgets()
        
        # Make window movable
        self.bind_window_movement()
    
    def create_main_container(self):
        # Create a container with shadow effect
        self.container = tk.Frame(self, bg='#121725', bd=0, relief=tk.FLAT)
        self.container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create a inner frame with clear background
        self.main_frame = tk.Frame(
            self.container, 
            bg='#1E2636',  # Slightly lighter, more neutral blue
            bd=2, 
            relief=tk.RAISED
        )
        self.main_frame.pack(fill=tk.BOTH, expand=True)
    
    def create_custom_titlebar(self):
        # Custom Titlebar
        self.titlebar = tk.Frame(
            self.main_frame, 
            bg='#263859', 
            height=40
        )
        self.titlebar.pack(fill=tk.X, side=tk.TOP)
        self.titlebar.pack_propagate(False)
        
        # App Title
        title_label = tk.Label(
            self.titlebar, 
            text="Zephyrn Securities", 
            font=('Segoe UI', 12, 'bold'),
            fg='#FFFFFF',  # Pure white for better readability
            bg='#263859'
        )
        title_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Close Button
        close_button = tk.Button(
            self.titlebar, 
            text='✕', 
            command=self.quit,
            bg='#263859', 
            fg='#FF6B6B',  # Softer red for close button
            font=('Arial', 12, 'bold'),
            bd=0,
            activebackground='#FF6B6B',
            activeforeground='white'
        )
        close_button.pack(side=tk.RIGHT, padx=10, pady=5)
    
    def create_widgets(self):
        # Content Frame
        content_frame = tk.Frame(
            self.main_frame, 
            bg='#1E2636'
        )
        content_frame.pack(
            fill=tk.BOTH, 
            expand=True, 
            padx=20, 
            pady=20
        )
        
        # Key Section
        key_frame = tk.Frame(content_frame, bg='#1E2636')
        key_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            key_frame, 
            text="Secret Key:", 
            bg='#1E2636', 
            fg='#FFFFFF'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.key_entry = tk.Entry(
            key_frame, 
            textvariable=self.key_var, 
            width=50,
            bg='#2C3E50',  # Dark background
            fg='#FFFFFF',  # White text
            insertbackground='#FFFFFF',  # White cursor
            font=('Consolas', 10)
        )
        self.key_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        
        # Key Generation Options
        key_option_frame = tk.Frame(key_frame, bg='#1E2636')
        key_option_frame.pack(side=tk.RIGHT)
        
        self.generate_radio = tk.Radiobutton(
            key_option_frame, 
            text="Generate", 
            variable=self.key_option_var, 
            value="Generate", 
            command=self.toggle_key_entry,
            bg='#1E2636',  # Match background
            fg='#FFFFFF',  # White text
            selectcolor='#263859'  # Dark blue when selected
        )
        self.generate_radio.pack(side=tk.LEFT, padx=5)
        
        self.manual_radio = tk.Radiobutton(
            key_option_frame, 
            text="Manual", 
            variable=self.key_option_var, 
            value="Manual", 
            command=self.toggle_key_entry,
            bg='#1E2636',  # Match background
            fg='#FFFFFF',  # White text
            selectcolor='#263859'  # Dark blue when selected
        )
        self.manual_radio.pack(side=tk.LEFT)
        
        # Text Input Section
        text_input_frame = tk.Frame(content_frame, bg='#1E2636')
        text_input_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            text_input_frame, 
            text="Text:", 
            bg='#1E2636', 
            fg='#FFFFFF'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.text_entry = tk.Entry(
            text_input_frame, 
            width=50,
            bg='#2C3E50',  # Dark background
            fg='#FFFFFF',  # White text
            insertbackground='#FFFFFF',  # White cursor
            font=('Consolas', 10)
        )
        self.text_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        # Action Buttons
        action_frame = tk.Frame(content_frame, bg='#1E2636')
        action_frame.pack(fill=tk.X, pady=20)
        
        encrypt_button = tk.Button(
            action_frame, 
            text="Encrypt", 
            command=self.encrypt_text,
            bg='#263859',  # Deep blue
            fg='#FFFFFF',  # White text
            font=('Segoe UI', 10, 'bold')
        )
        encrypt_button.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        
        decrypt_button = tk.Button(
            action_frame, 
            text="Decrypt", 
            command=self.decrypt_text,
            bg='#263859',  # Deep blue
            fg='#FFFFFF',  # White text
            font=('Segoe UI', 10, 'bold')
        )
        decrypt_button.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        
        # Result Display
        result_frame = tk.Frame(content_frame, bg='#1E2636')
        result_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            result_frame, 
            text="Result:", 
            bg='#1E2636', 
            fg='#FFFFFF'
        ).pack(side=tk.TOP, anchor=tk.W)
        
        self.result_text = tk.Text(
            result_frame, 
            height=5, 
            bg='#2C3E50',  # Dark background
            fg='#FFFFFF',  # White text
            insertbackground='#FFFFFF',  # White cursor
            font=('Consolas', 10),
            wrap=tk.WORD  # Wrap text
        )
        self.result_text.pack(fill=tk.X, pady=5)
        
        # Bottom Action Buttons
        bottom_frame = tk.Frame(content_frame, bg='#1E2636')
        bottom_frame.pack(fill=tk.X, pady=10)
        
        copy_button = tk.Button(
            bottom_frame, 
            text="Copy Result", 
            command=self.copy_result,
            bg='#263859',  # Deep blue
            fg='#FFFFFF',  # White text
            font=('Segoe UI', 10, 'bold')
        )
        copy_button.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        
        paste_button = tk.Button(
            bottom_frame, 
            text="Paste", 
            command=self.paste_text,
            bg='#263859',  # Deep blue
            fg='#FFFFFF',  # White text
            font=('Segoe UI', 10, 'bold')
        )
        paste_button.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
    
    def bind_window_movement(self):
        # Allow moving the window by dragging the titlebar
        def start_move(event):
            self.x = event.x
            self.y = event.y

        def stop_move(event):
            self.x = None
            self.y = None

        def do_move(event):
            deltax = event.x - self.x
            deltay = event.y - self.y
            x = self.winfo_x() + deltax
            y = self.winfo_y() + deltay
            self.geometry(f"+{x}+{y}")

        self.titlebar.bind("<ButtonPress-1>", start_move)
        self.titlebar.bind("<ButtonRelease-1>", stop_move)
        self.titlebar.bind("<B1-Motion>", do_move)
    
    def generate_key(self):
        random_key = generate_unique_code()
        self.key_var.set(random_key)
        messagebox.showinfo("Key Generated", "A new unique encryption key has been generated!")
    
    def encrypt_text(self):
        try:
            key = self.key_var.get()
            if not key:
                messagebox.showwarning("Missing Key", "Please enter or generate a key!")
                return
            
            plaintext = self.text_entry.get()
            if not plaintext:
                messagebox.showwarning("Empty Input", "Please enter text to encrypt!")
                return
            
            encrypted_text = multi_layer_encrypt(plaintext, key)
            
            # Clear previous result and insert new encrypted text
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert(tk.END, encrypted_text)
            
            messagebox.showinfo("Encryption", "Text successfully encrypted!")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
    
    def decrypt_text(self):
        try:
            key = self.key_var.get()
            if not key:
                messagebox.showwarning("Missing Key", "Please enter or generate a key!")
                return
            
            ciphertext = self.text_entry.get()
            if not ciphertext:
                messagebox.showwarning("Empty Input", "Please enter text to decrypt!")
                return
            
            decrypted_text = multi_layer_decrypt(ciphertext, key)
            
            # Clear previous result and insert new decrypted text
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert(tk.END, decrypted_text)
            
            messagebox.showinfo("Decryption", "Text successfully decrypted!")
        except Exception as e:
            messagebox.showerror("Decryption Error", "Decryption failed. Verify your key and ciphertext.")
    
    
    def copy_result(self):
        result = self.result_text.get('1.0', tk.END).strip()
        if result:
            pyperclip.copy(result)
            messagebox.showinfo("Copied", "Result copied to clipboard")
    
    def paste_text(self):
        clipboard_content = pyperclip.paste()
        self.text_entry.delete(0, tk.END)
        self.text_entry.insert(0, clipboard_content)
    
    def toggle_key_entry(self):
        # Toggle key entry method
        if self.key_option_var.get() == "Generate":
            # Generate a random key
            random_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            self.key_var.set(random_key)
            self.key_entry.config(state='readonly')
        else:
            self.key_entry.config(state='normal')

def main():
    app = ZephyrnSecurities()
    app.mainloop()

if __name__ == "__main__":
    main()