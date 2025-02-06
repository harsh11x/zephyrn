import tkinter as tk
from tkinter import messagebox
import subprocess

def open_script(script_name):
    try:
        subprocess.run(['python', script_name])
    except Exception as e:
        messagebox.showerror("Error", f"Could not open script: {e}")

def on_choice():
    choice = var.get()
    if choice == 'files':
        open_script('combo.py')
    elif choice == 'chat':
        open_script('autovccombo.py')
    root.destroy()  # Close the GUI window after opening the script

# Create the main window
root = tk.Tk()
root.title("Encryption/Decryption Choice")

# Create a label
label = tk.Label(root, text="Do you want to encrypt/decrypt chat or files?")
label.pack(pady=10)

# Create a variable to hold the choice
var = tk.StringVar(value='files')

# Create radio buttons for the choices
files_radio = tk.Radiobutton(root, text="Encrypt/Decrypt Files", variable=var, value='files')
files_radio.pack(anchor=tk.W, padx=20)

chat_radio = tk.Radiobutton(root, text="Encrypt/Decrypt Chat", variable=var, value='chat')
chat_radio.pack(anchor=tk.W, padx=20)

# Create a button to submit the choice
submit_button = tk.Button(root, text="Submit", command=on_choice)
submit_button.pack(pady=20)

# Start the main loop
root.mainloop()
