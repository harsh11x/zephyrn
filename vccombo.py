import tkinter as tk
from tkinter import ttk
import random
import string

# Function to generate a random key (7-10 characters)
def generate_unique_code():
    code_length = random.randint(7, 10)
    code = ''.join(random.choices(string.ascii_letters, k=code_length))
    return code

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

# Function to handle encryption button click
def encrypt_text():
    key = key_var.get()
    plaintext = plaintext_entry.get()
    encrypted_text = vigenere_encrypt(plaintext, key)
    result_var.set(encrypted_text)

# Function to handle decryption button click
def decrypt_text():
    key = key_var.get()
    ciphertext = plaintext_entry.get()
    decrypted_text = vigenere_decrypt(ciphertext, key)
    result_var.set(decrypted_text)

# Function to copy the result text to the clipboard
def copy_result_text():
    result_text = result_var.get()
    root.clipboard_clear()
    root.clipboard_append(result_text)
    root.update()  # Keep the clipboard contents

# Function to paste text into the plaintext entry field
def paste_text():
    clipboard_content = root.clipboard_get()
    plaintext_entry.delete(0, tk.END)
    plaintext_entry.insert(0, clipboard_content)

# Function to generate a random key and display it
def generate_key():
    random_key = generate_unique_code()
    key_var.set(random_key)

# Function to copy the key to the clipboard
def copy_key():
    key = key_var.get()
    root.clipboard_clear()
    root.clipboard_append(key)
    root.update()  # Keep the clipboard contents

# Function to toggle key entry based on user selection
def toggle_key_entry():
    if key_option_var.get() == "Generate":
        generate_key()
        key_entry.config(state='readonly')
    else:
        key_entry.config(state='normal')

# Set up the GUI window
root = tk.Tk()
root.title("Vigenère Cipher with Key Options")

# Key selection: option to generate or manually enter key
ttk.Label(root, text="Secret Key:").grid(column=0, row=0, padx=10, pady=5, sticky=tk.W)

key_var = tk.StringVar()
key_option_var = tk.StringVar(value="Generate")

# Option for key generation or manual entry
key_option_frame = ttk.Frame(root)
key_option_frame.grid(column=0, row=0, padx=10, pady=5, sticky=tk.W)

key_generate_radio = ttk.Radiobutton(key_option_frame, text="Generate Automatically", variable=key_option_var, value="Generate", command=toggle_key_entry)
key_generate_radio.pack(side=tk.LEFT)

key_manual_radio = ttk.Radiobutton(key_option_frame, text="Enter Manually", variable=key_option_var, value="Manual", command=toggle_key_entry)
key_manual_radio.pack(side=tk.LEFT)

key_entry = ttk.Entry(root, textvariable=key_var, width=30)
key_entry.grid(column=1, row=0, padx=10, pady=5, sticky=tk.W)

# Generate Key Button
generate_button = ttk.Button(root, text="Generate Key", command=generate_key)
generate_button.grid(column=2, row=0, padx=10, pady=5)

# Copy Key Button
copy_key_button = ttk.Button(root, text="Copy Key", command=copy_key)
copy_key_button.grid(column=3, row=0, padx=10, pady=5)

# Create and place widgets
ttk.Label(root, text="Text (Plaintext/Ciphertext):").grid(column=0, row=1, padx=10, pady=5, sticky=tk.W)
plaintext_entry = ttk.Entry(root, width=50)
plaintext_entry.grid(column=1, row=1, padx=10, pady=5)

# Encrypt and Decrypt Buttons
encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.grid(column=1, row=2, padx=10, pady=5, sticky=tk.W)

decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.grid(column=1, row=2, padx=100, pady=5, sticky=tk.W)

# Result and Copy Button
ttk.Label(root, text="Result (Encrypted/Decrypted):").grid(column=0, row=3, padx=10, pady=5, sticky=tk.W)
result_var = tk.StringVar()
result_label = ttk.Label(root, textvariable=result_var, wraplength=400)
result_label.grid(column=1, row=3, padx=10, pady=5)

copy_button = ttk.Button(root, text="Copy", command=copy_result_text)
copy_button.grid(column=1, row=4, padx=10, pady=5, sticky=tk.W)

paste_button = ttk.Button(root, text="Paste", command=paste_text)
paste_button.grid(column=1, row=5, padx=10, pady=5, sticky=tk.W)

# Run the GUI event loop
root.mainloop()
