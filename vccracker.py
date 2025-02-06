import tkinter as tk
from tkinter import messagebox
import string
from collections import Counter

# Frequencies of English letters in the alphabet
ENGLISH_FREQ = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 
                0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 
                0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.001, 
                0.020, 0.001]

LETTERS = string.ascii_uppercase

def find_repeated_sequences_spacings(text):
    spacings = {}
    for seq_len in range(3, 6):  # Look for sequences of length 3 to 5
        for i in range(len(text) - seq_len):
            seq = text[i:i + seq_len]
            for j in range(i + seq_len, len(text) - seq_len):
                if text[j:j + seq_len] == seq:
                    if seq not in spacings:
                        spacings[seq] = []
                    spacings[seq].append(j - i)
    return spacings

def kasiski_examination(text):
    spacings = find_repeated_sequences_spacings(text)
    spacing_values = []
    for seq in spacings:
        spacing_values.extend(spacings[seq])
    return gcd_of_list(spacing_values)

def gcd_of_list(numbers):
    from math import gcd
    if len(numbers) == 0:
        return None
    gcd_value = numbers[0]
    for num in numbers[1:]:
        gcd_value = gcd(gcd_value, num)
    return gcd_value

def shift_text(text, shift):
    shifted_text = []
    for letter in text:
        if letter in LETTERS:
            shifted_text.append(LETTERS[(LETTERS.index(letter) - shift) % len(LETTERS)])
        else:
            shifted_text.append(letter)
    return ''.join(shifted_text)

def get_letter_frequency(text):
    letter_counts = Counter(text)
    total_letters = sum(letter_counts.values())
    freq = {letter: letter_counts.get(letter, 0) / total_letters for letter in LETTERS}
    return freq

def frequency_match_score(text):
    text_freq = list(get_letter_frequency(text).values())
    score = sum([abs(text_freq[i] - ENGLISH_FREQ[i]) for i in range(len(LETTERS))])
    return score

def guess_key_length(ciphertext):
    guessed_key_length = kasiski_examination(ciphertext)
    return guessed_key_length if guessed_key_length else 1

def decrypt_with_key(ciphertext, key):
    key_length = len(key)
    decrypted_text = []
    key_index = 0
    for symbol in ciphertext:
        num = LETTERS.find(symbol)
        if num != -1:
            num -= LETTERS.find(key[key_index])
            num %= len(LETTERS)
            decrypted_text.append(LETTERS[num])
            key_index = (key_index + 1) % key_length
        else:
            decrypted_text.append(symbol)
    return ''.join(decrypted_text)

def vigenere_cipher_crack(ciphertext):
    ciphertext = ''.join([char.upper() for char in ciphertext if char in LETTERS])
    key_length = guess_key_length(ciphertext)
    
    key = []
    for i in range(key_length):
        nth_letters = ciphertext[i::key_length]
        scores = []
        for shift in range(len(LETTERS)):
            shifted_text = shift_text(nth_letters, shift)
            score = frequency_match_score(shifted_text)
            scores.append((shift, score))
        best_shift = min(scores, key=lambda x: x[1])[0]
        key.append(LETTERS[best_shift])
    
    key = ''.join(key)
    decrypted_text = decrypt_with_key(ciphertext, key)
    return decrypted_text, key

# GUI setup
def crack_vigenere():
    encrypted_text = encrypted_text_entry.get("1.0", tk.END).strip()
    
    if not encrypted_text:
        messagebox.showerror("Error", "Please enter the encrypted text.")
        return
    
    decrypted_text, guessed_key = vigenere_cipher_crack(encrypted_text)
    
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"Guessed Key: {guessed_key}\n")
    result_text.insert(tk.END, f"Decrypted Text: {decrypted_text}")

# Setting up the main window
root = tk.Tk()
root.title("Vigenère Cipher Cracker")

# Creating the layout
tk.Label(root, text="Enter Encrypted Text:").pack(pady=5)
encrypted_text_entry = tk.Text(root, height=10, width=50)
encrypted_text_entry.pack(pady=5)

crack_button = tk.Button(root, text="Crack", command=crack_vigenere)
crack_button.pack(pady=10)

result_text = tk.Text(root, height=10, width=50)
result_text.pack(pady=5)

# Running the application
root.mainloop()
