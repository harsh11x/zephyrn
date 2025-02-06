import random
import numpy as np
import os
from collections import namedtuple
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox

class Photon:
    def __init__(self, polarization):
        self.polarization = polarization
        
    def measure(self, basis):
        if self.polarization[1] == basis:
            return self.polarization[0]
        else:
            return random.randint(0, 1)

class QuantumChannel:
    def __init__(self, error_rate=0.0):
        self.error_rate = error_rate
    
    def transmit(self, photons):
        transmitted_photons = []
        for photon in photons:
            if random.random() < self.error_rate:
                new_pol = (1 - photon.polarization[0], photon.polarization[1])
                transmitted_photons.append(Photon(new_pol))
            else:
                transmitted_photons.append(photon)
        return transmitted_photons

class QuantumCryptography:
    def __init__(self, key_length=1024):
        self.key_length = key_length
        self.channel = QuantumChannel(error_rate=0.01)
    
    def generate_photons(self, bits, bases):
        return [Photon((bit, basis)) for bit, basis in zip(bits, bases)]
    
    def measure_photons(self, photons, bases):
        return [photon.measure(basis) for photon, basis in zip(photons, bases)]
    
    def generate_key(self):
        alice_bits = [random.randint(0, 1) for _ in range(self.key_length)]
        alice_bases = [random.randint(0, 1) for _ in range(self.key_length)]
        
        photons = self.generate_photons(alice_bits, alice_bases)
        received_photons = self.channel.transmit(photons)
        
        bob_bases = [random.randint(0, 1) for _ in range(self.key_length)]
        bob_bits = self.measure_photons(received_photons, bob_bases)
        
        key_bits = []
        for i in range(self.key_length):
            if alice_bases[i] == bob_bases[i]:
                key_bits.append(alice_bits[i])
                
        return key_bits

class QuantumFileEncryption:
    def __init__(self):
        self.qkd = QuantumCryptography(key_length=2048)
        
    def generate_shared_key(self):
        return self.qkd.generate_key()
    
    def _bytes_to_bits(self, data):
        return ''.join(format(byte, '08b') for byte in data)
    
    def _bits_to_bytes(self, bits):
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    
    def encrypt_file(self, input_path, output_path, key=None):
        if key is None:
            key = self.generate_shared_key()
        
        with open(input_path, 'rb') as f:
            file_data = f.read()
        
        data_bits = self._bytes_to_bits(file_data)
        padded_key = key * (len(data_bits) // len(key) + 1)
        padded_key = padded_key[:len(data_bits)]
        
        encrypted_bits = ''.join(str(int(a) ^ int(b)) 
                               for a, b in zip(data_bits, padded_key))
        
        encrypted_bytes = self._bits_to_bytes(encrypted_bits)
        with open(output_path, 'wb') as f:
            f.write(encrypted_bytes)
        
        return key
    
    def decrypt_file(self, input_path, output_path, key):
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()
        
        encrypted_bits = self._bytes_to_bits(encrypted_data)
        padded_key = key * (len(encrypted_bits) // len(key) + 1)
        padded_key = padded_key[:len(encrypted_bits)]
        
        decrypted_bits = ''.join(str(int(a) ^ int(b)) 
                                for a, b in zip(encrypted_bits, padded_key))
        
        decrypted_bytes = self._bits_to_bytes(decrypted_bits)
        with open(output_path, 'wb') as f:
            f.write(decrypted_bytes)

class QuantumFileEncryptionGUI:
    def __init__(self):
        self.qfe = QuantumFileEncryption()
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the main window
        
    def select_file(self, title, file_types=(("All files", "*.*"),)):
        """Opens a file selection dialog and returns the selected file path"""
        file_path = filedialog.askopenfilename(
            title=title,
            filetypes=file_types
        )
        return file_path if file_path else None
    
    def save_file(self, title, default_extension, file_types=(("All files", "*.*"),)):
        """Opens a file save dialog and returns the selected path"""
        file_path = filedialog.asksaveasfilename(
            title=title,
            defaultextension=default_extension,
            filetypes=file_types
        )
        return file_path if file_path else None
    
    def save_key_to_file(self, key, output_path):
        """Save the encryption key to a file"""
        try:
            with open(output_path, 'w') as f:
                f.write(''.join(str(bit) for bit in key))
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save key: {str(e)}")
            return False
    
    def encrypt_workflow(self):
        # Select input file
        input_file = self.select_file("Select file to encrypt")
        if not input_file:
            return
        
        # Select output file
        output_file = self.save_file("Save encrypted file as", ".encrypted",
                                   [("Encrypted files", "*.encrypted"),
                                    ("All files", "*.*")])
        if not output_file:
            return
        
        try:
            # Encrypt the file
            print("\nGenerating quantum key and encrypting file...")
            key = self.qfe.encrypt_file(input_file, output_file)
            
            # Save the key
            key_file = self.save_file("Save encryption key as", ".key",
                                    [("Key files", "*.key"),
                                     ("Text files", "*.txt"),
                                     ("All files", "*.*")])
            if key_file:
                self.save_key_to_file(key, key_file)
                messagebox.showinfo("Success", 
                    f"File encrypted successfully!\nKey saved to: {key_file}")
            else:
                key_str = ''.join(str(bit) for bit in key)
                messagebox.showinfo("Success", 
                    f"File encrypted successfully!\nKey: {key_str}\n\nPlease save this key!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_workflow(self):
        # Select encrypted file
        input_file = self.select_file("Select encrypted file",
                                    [("Encrypted files", "*.encrypted"),
                                     ("All files", "*.*")])
        if not input_file:
            return
        
        # Select output file
        output_file = self.save_file("Save decrypted file as", "",
                                   [("All files", "*.*")])
        if not output_file:
            return
        
        # Get the key (either from file or manual input)
        key_file = self.select_file("Select key file",
                                  [("Key files", "*.key"),
                                   ("Text files", "*.txt"),
                                   ("All files", "*.*")])
        
        try:
            if key_file:
                with open(key_file, 'r') as f:
                    key_input = f.read().strip()
            else:
                key_input = tk.simpledialog.askstring("Key Required", 
                    "Please enter the encryption key (binary string):")
                if not key_input:
                    return
            
            # Convert key string to list of bits
            key = [int(bit) for bit in key_input]
            
            # Decrypt the file
            print("\nDecrypting file...")
            self.qfe.decrypt_file(input_file, output_file, key)
            messagebox.showinfo("Success", "File decrypted successfully!")
            
        except ValueError:
            messagebox.showerror("Error", "Invalid key format. Key should contain only 0s and 1s.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def main():
    gui = QuantumFileEncryptionGUI()
    
    while True:
        print("\nQuantum File Encryption System")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            gui.encrypt_workflow()
        elif choice == '2':
            gui.decrypt_workflow()
        elif choice == '3':
            print("\nExiting program. Goodbye!")
            break
        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()