import tkinter as tk
from tkinter import ttk

# Function to create Vigenère table
def create_vigenere_table():
    table = []
    for i in range(26):
        row = [(chr((i + j) % 26 + 65)) for j in range(26)]
        table.append(row)
    return table

# Function to decrypt a message using the Vigenère cipher
def vigenere_decrypt(ciphertext, key):
    table = create_vigenere_table()
    key = key.upper()
    expanded_key = (key * ((len(ciphertext) // len(key)) + 1))[:len(ciphertext)]
    plaintext = []
    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():
            row = ord(expanded_key[i]) - 65
            col = table[row].index(ciphertext[i].upper())
            plaintext.append(chr(col + 65))
        else:
            plaintext.append(ciphertext[i])
    return ''.join(plaintext)

# Function to handle decryption button click
def decrypt_text():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()
    decrypted_text = vigenere_decrypt(ciphertext, key)
    decrypted_text_var.set(decrypted_text)

# Function to copy the decrypted text to the clipboard
def copy_decrypted_text():
    decrypted_text = decrypted_text_var.get()
    root.clipboard_clear()
    root.clipboard_append(decrypted_text)
    root.update()  # Keep the clipboard contents

# Function to paste text into the ciphertext and key entry fields
def paste_text():
    clipboard_content = root.clipboard_get()
    clipboard_lines = clipboard_content.splitlines()
    if clipboard_lines:
        if len(clipboard_lines) > 0:
            ciphertext_entry.delete(0, tk.END)
            ciphertext_entry.insert(0, clipboard_lines[0])
        if len(clipboard_lines) > 1:
            key_entry.delete(0, tk.END)
            key_entry.insert(0, clipboard_lines[1])

# Set up the GUI window
root = tk.Tk()
root.title("Vigenère Cipher Decryption")

# Create and place widgets
ttk.Label(root, text="Ciphertext:").grid(column=0, row=0, padx=10, pady=5, sticky=tk.W)
ciphertext_entry = ttk.Entry(root, width=50)
ciphertext_entry.grid(column=1, row=0, padx=10, pady=5)

ttk.Label(root, text="Key:").grid(column=0, row=1, padx=10, pady=5, sticky=tk.W)
key_entry = ttk.Entry(root, width=50)
key_entry.grid(column=1, row=1, padx=10, pady=5)

decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.grid(column=1, row=2, padx=10, pady=5, sticky=tk.W)

ttk.Label(root, text="Decrypted Text:").grid(column=0, row=3, padx=10, pady=5, sticky=tk.W)
decrypted_text_var = tk.StringVar()
decrypted_text_label = ttk.Label(root, textvariable=decrypted_text_var, wraplength=400)
decrypted_text_label.grid(column=1, row=3, padx=10, pady=5)

copy_button = ttk.Button(root, text="Copy", command=copy_decrypted_text)
copy_button.grid(column=1, row=4, padx=10, pady=5, sticky=tk.W)

paste_button = ttk.Button(root, text="Paste", command=paste_text)
paste_button.grid(column=1, row=5, padx=10, pady=5, sticky=tk.W)

# Run the GUI event loop
root.mainloop()
