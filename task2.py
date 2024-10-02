import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
import os

BLOCK_SIZE_DES = 8  # Block size for DES and 3DES
BLOCK_SIZE_AES = 16  # Block size for AES


# Function to handle file encryption
def encrypt_file(filepath, key, algorithm):
    with open(filepath, 'rb') as file:
        plaintext = file.read()

    # Padding and encryption
    if algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_ECB)
        padded_plaintext = pad(plaintext, DES.block_size)
    elif algorithm == '3DES':
        cipher = DES3.new(key, DES3.MODE_ECB)
        padded_plaintext = pad(plaintext, DES3.block_size)
    elif algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_ECB)
        padded_plaintext = pad(plaintext, AES.block_size)

    ciphertext = cipher.encrypt(padded_plaintext)

    # Save encrypted file
    encrypted_filepath = filepath + f'.{algorithm.lower()}'
    with open(encrypted_filepath, 'wb') as file:
        file.write(ciphertext)


def decrypt_file(filepath, key, algorithm):
    with open(filepath, 'rb') as file:
        ciphertext = file.read()

    # Decryption
    try:
        if algorithm == 'DES':
            cipher = DES.new(key, DES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        elif algorithm == '3DES':
            cipher = DES3.new(key, DES3.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
        elif algorithm == 'AES':
            cipher = AES.new(key, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Save decrypted file (removing the .des, .des3, or .aes extension)
        decrypted_filepath = filepath.replace(f'.{algorithm.lower()}', '')
        with open(decrypted_filepath, 'wb') as file:
            file.write(plaintext)
    except ValueError as e:
        messagebox.showerror("Decryption failed", "Decryption failed: " + str(e))


# Function to encrypt or decrypt folders
def process_folder(folder_path, key, algorithm, mode):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            if mode == 'encrypt':
                encrypt_file(filepath, key, algorithm)
            elif mode == 'decrypt' and file.endswith(f'.{algorithm.lower()}'):
                decrypt_file(filepath, key, algorithm)


# GUI setup
def browse_file():
    filepath = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filepath)


def browse_folder():
    folderpath = filedialog.askdirectory()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, folderpath)


def encrypt():
    key = key_entry.get().encode('utf-8')
    filepath = file_entry.get()
    algorithm = algorithm_choice.get()

    if not key or not filepath:
        messagebox.showerror("Input Error", "Please provide both key and file/folder path.")
        return

    # Key length validation
    if algorithm == 'DES' and len(key) != 8:
        messagebox.showerror("Key Error", "DES key must be 8 bytes long.")
        return
    elif algorithm == '3DES' and len(key) != 16 and len(key) != 24:
        messagebox.showerror("Key Error", "3DES key must be either 16 or 24 bytes long.")
        return
    elif algorithm == 'AES' and len(key) not in [16, 24, 32]:
        messagebox.showerror("Key Error", "AES key must be 16, 24, or 32 bytes long.")
        return

    if os.path.isfile(filepath):
        encrypt_file(filepath, key, algorithm)
    elif os.path.isdir(filepath):
        process_folder(filepath, key, algorithm, 'encrypt')

    messagebox.showinfo("Success", "Encryption completed!")


def decrypt():
    key = key_entry.get().encode('utf-8')
    filepath = file_entry.get()
    algorithm = algorithm_choice.get()

    if not key or not filepath:
        messagebox.showerror("Input Error", "Please provide both key and file/folder path.")
        return

    # Key length validation
    if algorithm == 'DES' and len(key) != 8:
        messagebox.showerror("Key Error", "DES key must be 8 bytes long.")
        return
    elif algorithm == '3DES' and len(key) != 16 and len(key) != 24:
        messagebox.showerror("Key Error", "3DES key must be either 16 or 24 bytes long.")
        return
    elif algorithm == 'AES' and len(key) not in [16, 24, 32]:
        messagebox.showerror("Key Error", "AES key must be 16, 24, or 32 bytes long.")
        return

    if os.path.isfile(filepath):
        decrypt_file(filepath, key, algorithm)
    elif os.path.isdir(filepath):
        process_folder(filepath, key, algorithm, 'decrypt')

    messagebox.showinfo("Success", "Decryption completed!")


# GUI creation
root = tk.Tk()
root.title("File/Folder Encryption & Decryption")

# File/Folder selection
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=0, column=1, padx=10, pady=10)

browse_file_button = tk.Button(root, text="Browse File", command=browse_file)
browse_file_button.grid(row=0, column=2, padx=10, pady=10)

browse_folder_button = tk.Button(root, text="Browse Folder", command=browse_folder)
browse_folder_button.grid(row=0, column=3, padx=10, pady=10)

# Key entry
tk.Label(root, text="Key:").grid(row=1, column=0, padx=10, pady=10)
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=1, column=1, padx=10, pady=10)

# Algorithm selection
tk.Label(root, text="Algorithm:").grid(row=2, column=0, padx=10, pady=10)
algorithm_choice = tk.StringVar(value='DES')
algorithm_menu = tk.OptionMenu(root, algorithm_choice, 'DES', '3DES', 'AES')
algorithm_menu.grid(row=2, column=1, padx=10, pady=10)

# Encrypt and Decrypt buttons
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=3, column=1, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=3, column=2, padx=10, pady=10)

root.mainloop()
