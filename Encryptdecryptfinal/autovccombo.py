import tkinter as tk
from tkinter import ttk
import random
import string

# Extended character set for encryption
CHAR_SET = string.ascii_letters + string.digits + string.punctuation + " "
CHAR_SET_LEN = len(CHAR_SET)

# Function to generate a random key (7-10 characters)
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

# Encryption button action
def encrypt_text():
    key = key_var.get()
    plaintext = plaintext_entry.get()
    encrypted_text = multi_layer_encrypt(plaintext, key)
    result_var.set(encrypted_text)

# Decryption button action
def decrypt_text():
    key = key_var.get()
    ciphertext = plaintext_entry.get()
    decrypted_text = multi_layer_decrypt(ciphertext, key)
    result_var.set(decrypted_text)

# Clipboard copy functions
def copy_result_text():
    result_text = result_var.get()
    root.clipboard_clear()
    root.clipboard_append(result_text)
    root.update()

def paste_text():
    clipboard_content = root.clipboard_get()
    plaintext_entry.delete(0, tk.END)
    plaintext_entry.insert(0, clipboard_content)

# Generate random key
def generate_key():
    random_key = generate_unique_code()
    key_var.set(random_key)

# Toggle key entry mode
def toggle_key_entry():
    if key_option_var.get() == "Generate":
        generate_key()
        key_entry.config(state='readonly')
    else:
        key_entry.config(state='normal')

# GUI setup
root = tk.Tk()
root.title("Multi-Layer Encryption Tool")

key_var = tk.StringVar()
key_option_var = tk.StringVar(value="Generate")
result_var = tk.StringVar()

# Key selection widgets
ttk.Label(root, text="Secret Key:").grid(column=0, row=0, padx=10, pady=5, sticky=tk.W)
key_entry = ttk.Entry(root, textvariable=key_var, width=30)
key_entry.grid(column=1, row=0, padx=10, pady=5, sticky=tk.W)

key_option_frame = ttk.Frame(root)
key_option_frame.grid(column=2, row=0, padx=10, pady=5, sticky=tk.W)
ttk.Radiobutton(key_option_frame, text="Generate", variable=key_option_var, value="Generate", command=toggle_key_entry).pack(side=tk.LEFT)
ttk.Radiobutton(key_option_frame, text="Manual", variable=key_option_var, value="Manual", command=toggle_key_entry).pack(side=tk.LEFT)

# Generate and Copy Key buttons
ttk.Button(root, text="Generate Key", command=generate_key).grid(column=3, row=0, padx=10, pady=5)
ttk.Button(root, text="Copy Key", command=lambda: root.clipboard_append(key_var.get())).grid(column=4, row=0, padx=10, pady=5)

# Input text field
ttk.Label(root, text="Text (Plaintext/Ciphertext):").grid(column=0, row=1, padx=10, pady=5, sticky=tk.W)
plaintext_entry = ttk.Entry(root, width=50)
plaintext_entry.grid(column=1, row=1, padx=10, pady=5)

# Encrypt and Decrypt buttons
ttk.Button(root, text="Encrypt", command=encrypt_text).grid(column=1, row=2, padx=10, pady=5, sticky=tk.W)
ttk.Button(root, text="Decrypt", command=decrypt_text).grid(column=1, row=2, padx=100, pady=5, sticky=tk.W)

# Result display
ttk.Label(root, text="Result:").grid(column=0, row=3, padx=10, pady=5, sticky=tk.W)
ttk.Label(root, textvariable=result_var, wraplength=400).grid(column=1, row=3, padx=10, pady=5)

# Copy and Paste buttons
ttk.Button(root, text="Copy Result", command=copy_result_text).grid(column=1, row=4, padx=10, pady=5)
ttk.Button(root, text="Paste Text", command=paste_text).grid(column=1, row=5, padx=10, pady=5)

root.mainloop()
