import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# Constants for block sizes
BLOCK_SIZE_DES = 8  # Block size for DES (in bytes)
BLOCK_SIZE_AES = 16  # Block size for AES (in bytes)


# Function to generate a key based on the algorithm
def generate_key(algorithm):
    if algorithm == 'DES':
        key = get_random_bytes(8)  # 8 bytes for DES
    elif algorithm == '3DES':
        key = get_random_bytes(24)  # 24 bytes for 3DES
    elif algorithm == 'AES':
        key = get_random_bytes(32)  # 32 bytes for AES
    return key.hex()  # Return the key in hex form


# Function to validate key length
def validate_key_length(key, algorithm):
    try:
        key_bytes = bytes.fromhex(key)  # Attempt to convert hex key to bytes
    except ValueError:
        return "Invalid key format. Key must be a valid hexadecimal string."

    length = len(key_bytes)
    if algorithm == 'DES' and length != 8:
        return "DES key must be 8 bytes long."
    elif algorithm == '3DES' and length not in [16, 24]:
        return "3DES key must be either 16 or 24 bytes long."
    elif algorithm == 'AES' and length not in [16, 24, 32]:
        return "AES key must be 16, 24, or 32 bytes long."

    return None  # If no errors, return None


# Function to handle file encryption
def encrypt_file(filepath, key, algorithm):
    try:
        # Convert hex key back to bytes
        key = bytes.fromhex(key)

        # File opening
        with open(filepath, 'rb') as file:
            plaintext = file.read()

        # Padding and encryption (every algorithm in ECB mode)
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
        encrypted_filepath = f"{filepath}.{algorithm.lower()}"
        with open(encrypted_filepath, 'wb') as file:
            # Saving encrypted file
            file.write(ciphertext)

        os.remove(filepath)  # Delete the original file
        status_label.config(text=f"Encrypted file saved as {encrypted_filepath}.", fg="green")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt {filepath}: {str(e)}")


def decrypt_file(filepath, key, algorithm):
    try:
        # Convert hex key back to bytes
        key = bytes.fromhex(key)

        with open(filepath, 'rb') as file:
            # Encrypted file opening
            ciphertext = file.read()

        # Decryption (every algorithm in ECB mode)
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
            # Saving decrypted file
            file.write(plaintext)

        os.remove(filepath)  # Delete the encrypted file after successful decryption
        status_label.config(text=f"Decrypted file saved as {decrypted_filepath}.", fg="green")

    except Exception as e:
        messagebox.showerror("Decryption failed", "Decryption failed: " + str(e))


# Function to encrypt or decrypt folders (recursively)
def process_folder(folder_path, key, algorithm, mode):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            if mode == 'encrypt':
                encrypt_file(filepath, key, algorithm)
            elif mode == 'decrypt' and file.endswith(f'.{algorithm.lower()}'):
                decrypt_file(filepath, key, algorithm)

        # After processing files, attempt to remove the files and directories
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            try:
                os.rmdir(dir_path)  # Try to remove the directory
            except OSError:
                pass  # If the directory is not empty, we ignore the error

    # Finally, attempt to remove the root folder if encrypting
    if mode == 'encrypt':
        try:
            os.rmdir(folder_path)  # Attempt to remove the original folder
        except OSError:
            pass  # Ignore if the folder is not empty


# GUI setup
def browse_file():
    filepath = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filepath)


def browse_folder():
    folderpath = filedialog.askdirectory()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, folderpath)


def generate():
    algorithm = algorithm_choice.get()
    if not algorithm:
        status_label.config(text="Please select an algorithm before generating a key.", fg="red")
        return
    key = generate_key(algorithm)
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key)
    status_label.config(text="Key generated successfully.", fg="green")


def encrypt():
    key = key_entry.get()
    filepath = file_entry.get()
    algorithm = algorithm_choice.get()

    if not key or not filepath:
        status_label.config(text="Please provide both key and file/folder path.", fg="red")
        return

    key_error = validate_key_length(key, algorithm)
    if key_error:
        status_label.config(text=key_error, fg="red")
        return

    if os.path.isfile(filepath):
        encrypt_file(filepath, key, algorithm)
    elif os.path.isdir(filepath):
        process_folder(filepath, key, algorithm, 'encrypt')

    status_label.config(text="Encryption completed!", fg="green")


def decrypt():
    key = key_entry.get()
    filepath = file_entry.get()
    algorithm = algorithm_choice.get()

    if not key or not filepath:
        status_label.config(text="Please provide both key and file/folder path.", fg="red")
        return

    key_error = validate_key_length(key, algorithm)
    if key_error:
        status_label.config(text=key_error, fg="red")
        return

    if os.path.isfile(filepath):
        decrypt_file(filepath, key, algorithm)
    elif os.path.isdir(filepath):
        process_folder(filepath, key, algorithm, 'decrypt')

    status_label.config(text="Decryption completed!", fg="green")


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

generate_key_button = tk.Button(root, text="Generate Key", command=generate)
generate_key_button.grid(row=1, column=2, padx=10, pady=10)

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

# Status label to show messages
status_label = tk.Label(root, text="", fg="blue")
status_label.grid(row=4, column=1, columnspan=3, padx=10, pady=10)

# Start the GUI loop
root.mainloop()
