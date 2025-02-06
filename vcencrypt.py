import tkinter as tk
from tkinter import ttk

# Function to create Vigenère table
def create_vigenere_table():
    table = []
    for i in range(26):
        row = [(chr((i + j) % 26 + 65)) for j in range(26)]
        table.append(row)
    return table

# Function to encrypt a message using the Vigenère cipher
def vigenere_encrypt(plaintext, key):
    table = create_vigenere_table()
    key = key.upper()
    expanded_key = (key * ((len(plaintext) // len(key)) + 1))[:len(plaintext)]
    ciphertext = []
    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            row = ord(expanded_key[i]) - 65
            col = ord(plaintext[i].upper()) - 65
            ciphertext.append(table[row][col])
        else:
            ciphertext.append(plaintext[i])
    return ''.join(ciphertext)

# Function to handle encryption button click
def encrypt_text():
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    encrypted_text = vigenere_encrypt(plaintext, key)
    encrypted_text_var.set(encrypted_text)

# Function to copy the encrypted text to the clipboard
def copy_encrypted_text():
    encrypted_text = encrypted_text_var.get()
    root.clipboard_clear()
    root.clipboard_append(encrypted_text)
    root.update()  # Keep the clipboard contents

# Function to paste text into the plaintext and key entry fields
def paste_text():
    clipboard_content = root.clipboard_get()
    clipboard_lines = clipboard_content.splitlines()
    if len(clipboard_lines) >= 2:
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, clipboard_lines[0])
        key_entry.delete(0, tk.END)
        key_entry.insert(0, clipboard_lines[1])

# Set up the GUI window
root = tk.Tk()
root.title("Vigenère Cipher Encryption")

# Create and place widgets
ttk.Label(root, text="Plaintext:").grid(column=0, row=0, padx=10, pady=5, sticky=tk.W)
plaintext_entry = ttk.Entry(root, width=50)
plaintext_entry.grid(column=1, row=0, padx=10, pady=5)

ttk.Label(root, text="Key:").grid(column=0, row=1, padx=10, pady=5, sticky=tk.W)
key_entry = ttk.Entry(root, width=50)
key_entry.grid(column=1, row=1, padx=10, pady=5)

encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.grid(column=1, row=2, padx=10, pady=5, sticky=tk.W)

ttk.Label(root, text="Encrypted Text:").grid(column=0, row=3, padx=10, pady=5, sticky=tk.W)
encrypted_text_var = tk.StringVar()
encrypted_text_label = ttk.Label(root, textvariable=encrypted_text_var, wraplength=400)
encrypted_text_label.grid(column=1, row=3, padx=10, pady=5)

copy_button = ttk.Button(root, text="Copy", command=copy_encrypted_text)
copy_button.grid(column=1, row=4, padx=10, pady=5, sticky=tk.W)

paste_button = ttk.Button(root, text="Paste", command=paste_text)
paste_button.grid(column=1, row=5, padx=10, pady=5, sticky=tk.W)

# Run the GUI event loop
root.mainloop()
