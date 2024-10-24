import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
import os
import string
import random

# Constants for block sizes
BLOCK_SIZE_DES = 8  # Block size for DES (in bytes)
BLOCK_SIZE_AES = 16  # Block size for AES (in bytes)
SALT_SIZE = 16  # Size of the salt in bytes
HMAC_SIZE = 32  # HMAC size (SHA256 produces a 32-byte HMAC)


# Function to derive a key from the password using PBKDF2
# The derived key length depends on the algorithm (DES, 3DES, AES)
def derive_key(password, salt, algorithm):
    if algorithm == 'DES':
        key = PBKDF2(password, salt, dkLen=8, count=1000000)  # 8 bytes for DES
    if algorithm == '3DES':
        key = PBKDF2(password, salt, dkLen=24, count=1000000)  # 24 bytes for DES
    if algorithm == 'AES':
        key = PBKDF2(password, salt, dkLen=32, count=1000000)  # 32 bytes for DES
    return key


# Function to add HMAC to the data for integrity checking
# The HMAC is computed using SHA256 and appended to the encrypted data
def add_hmac(data, key):
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(data)
    return data + hmac.digest()  # Return the data concatenated with HMAC


# Function to verify HMAC during decryption
# This ensures that the data has not been tampered with
def verify_hmac(data, key):
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(data[:-HMAC_SIZE])  # Exclude the HMAC itself from the check
    try:
        hmac.verify(data[-HMAC_SIZE:])  # Verify the HMAC at the end of the data
        return data[:-HMAC_SIZE]  # If valid, return the data without the HMAC
    except ValueError:
        raise Exception("Data integrity check failed (HMAC mismatch).")


"""
# Function to generate a key based on the algorithm
def generate_key(algorithm):
    key = None
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
"""


# Secure file encryption function
# The function reads the file, derives the key, encrypts the file, and saves the encrypted result
def encrypt_file(filepath, password, algorithm):
    try:
        """
        # Convert hex key back to bytes
        key = bytes.fromhex(key)
        """
        # File opening
        with open(filepath, 'rb') as file:
            plaintext = file.read()  # Read the file content

        # Generate a random salt and derive a key from the password and salt
        salt = get_random_bytes(SALT_SIZE)
        key = derive_key(password, salt, algorithm)

        # Generate a random IV and initialize the cipher based on the selected algorithm
        if algorithm == 'DES':
            iv = get_random_bytes(DES.block_size)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_plaintext = pad(plaintext, DES.block_size)
        elif algorithm == '3DES':
            iv = get_random_bytes(DES3.block_size)
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            padded_plaintext = pad(plaintext, DES3.block_size)
        elif algorithm == 'AES':
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = pad(plaintext, AES.block_size)

        """
        ciphertext = iv + cipher.encrypt(padded_plaintext)
        """

        # Encrypt the padded plaintext
        ciphertext = cipher.encrypt(padded_plaintext)

        # Combine the IV and ciphertext, and add HMAC for integrity checking
        data_to_protect = iv + ciphertext
        final_data = add_hmac(data_to_protect, key)

        # Save the salt and final encrypted data (salt + IV + ciphertext + HMAC)
        encrypted_filepath = f"{filepath}.{algorithm.lower()}"
        with open(encrypted_filepath, 'wb') as file:
            file.write(salt + final_data)

        os.remove(filepath)  # Delete the original file
        status_label.config(text=f"Encrypted file saved as {encrypted_filepath}.", fg="green")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt {filepath}: {str(e)}")


# Secure file decryption function
# This function reads the encrypted file, verifies integrity using HMAC, and decrypts the content
def decrypt_file(filepath, password, algorithm):
    try:
        """
        # Convert hex key back to bytes
        key = bytes.fromhex(key)
        """

        with open(filepath, 'rb') as file:
            """
            # Read the IV (first block) and ciphertext (rest)
            iv = file.read(BLOCK_SIZE_DES if algorithm == 'DES' else BLOCK_SIZE_AES)
            ciphertext = file.read()
            """
            # Extract the salt and the rest of the data (IV + ciphertext + HMAC)
            salt = file.read(SALT_SIZE)
            encrypted_data = file.read()

        # Derive the key using the same password and extracted salt
        key = derive_key(password, salt, algorithm)

        # Verify the HMAC to ensure data integrity
        verified_data = verify_hmac(encrypted_data, key)

        # Extract the IV and ciphertext from the verified data
        iv = verified_data[:BLOCK_SIZE_AES if algorithm == 'AES' else BLOCK_SIZE_DES]
        ciphertext = verified_data[BLOCK_SIZE_AES if algorithm == 'AES' else BLOCK_SIZE_DES:]

        # Decrypt the ciphertext using the correct algorithm
        if algorithm == 'DES':
            cipher = DES.new(key, DES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        elif algorithm == '3DES':
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
        elif algorithm == 'AES':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Save decrypted file (removing the .des, .des3, or .aes extension)
        decrypted_filepath = filepath.replace(f'.{algorithm.lower()}', '')
        with open(decrypted_filepath, 'wb') as file:
            # Saving decrypted file
            file.write(plaintext)

        os.remove(filepath)  # Delete the encrypted file after successful decryption
        status_label.config(text=f"Decrypted file saved as {decrypted_filepath}.", fg="green")

    except ValueError as e:
        if "Padding is incorrect" in str(e):
            messagebox.showerror("Decryption failed", "Incorrect password. Decryption failed due to invalid padding.")
        elif "MAC check failed" in str(e):
            messagebox.showerror("Decryption failed", "Incorrect password. HMAC verification failed.")
        else:
            messagebox.showerror("Decryption failed", "Decryption failed: " + str(e))

    except Exception as e:
        messagebox.showerror("Decryption failed", "Decryption failed: " + str(e))


# Helper function to generate a random password
# The password consists of a mix of letters, digits, and special characters
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password


# Updated generate function for generating a password and displaying the derived key
def generate():
    algorithm = algorithm_choice.get()
    if not algorithm:
        status_label.config(text="Please select an algorithm before generating a key.", fg="red")
        return
    """
    key = generate_key(algorithm)
    """

    # Generate a random password
    password = generate_random_password()

    # Derive the encryption key from the password and a dummy salt for display purposes
    salt = get_random_bytes(SALT_SIZE)  # Dummy salt used just to display the derived key
    key = derive_key(password, salt, algorithm)

    # Display the generated password in the key entry field
    key_entry.delete(0, tk.END)
    key_entry.insert(0, password)

    # Optionally, display the derived key
    # derived_key_label.config(text=f"Derived Key: {key.hex()}")

    status_label.config(text="Password and key generated successfully.", fg="green")


# Function to handle folder encryption and decryption
def process_folder(folder_path, password, algorithm, mode):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            if mode == 'encrypt':
                encrypt_file(filepath, password, algorithm)
            elif mode == 'decrypt' and file.endswith(f'.{algorithm.lower()}'):
                decrypt_file(filepath, password, algorithm)

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


# Function to handle file/folder encryption
def encrypt():
    password = key_entry.get()  # Get the entered password
    filepath = file_entry.get()  # Get the selected file/folder path
    algorithm = algorithm_choice.get()  # Get the selected algorithm

    if not password or not filepath:
        status_label.config(text="Please provide both password and file/folder path.", fg="red")
        return

    """
    key_error = validate_key_length(key, algorithm)
    if key_error:
        status_label.config(text=key_error, fg="red")
        return
    """

    if os.path.isfile(filepath):
        encrypt_file(filepath, password, algorithm)
    elif os.path.isdir(filepath):
        process_folder(filepath, password, algorithm, 'encrypt')

    status_label.config(text="Encryption completed!", fg="green")


# Function to handle file/folder decryption
def decrypt():
    password = key_entry.get()  # Get the entered password
    filepath = file_entry.get()  # Get the selected file/folder path
    algorithm = algorithm_choice.get()  # Get the selected algorithm

    if not password or not filepath:
        status_label.config(text="Please provide both password and file/folder path.", fg="red")
        return

    """
    key_error = validate_key_length(key, algorithm)
    if key_error:
        status_label.config(text=key_error, fg="red")
        return
    """

    if os.path.isfile(filepath):
        decrypt_file(filepath, password, algorithm)
    elif os.path.isdir(filepath):
        process_folder(filepath, password, algorithm, 'decrypt')

    status_label.config(text="Decryption completed!", fg="green")


# Function to browse and select a file from the file system
def browse_file():
    filepath = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])  # Open file dialog to select a file
    file_entry.delete(0, tk.END)  # Clear the file entry field
    file_entry.insert(0, filepath)  # Insert the selected file path into the entry field


# Function to browse and select a folder from the file system
def browse_folder():
    folder_path = filedialog.askdirectory()  # Open folder dialog to select a folder
    file_entry.delete(0, tk.END)  # Clear the file entry field
    file_entry.insert(0, folder_path)  # Insert the selected folder path into the entry field


# GUI setup
root = tk.Tk()  # Create the main application window
root.title("File/Folder Encryption & Decryption")  # Set the window title

# File/Folder selection entry field
file_entry = tk.Entry(root, width=50)  # Input field to display the selected file/folder path
file_entry.grid(row=0, column=1, padx=10, pady=10)

# Buttons to browse for files and folders
browse_file_button = tk.Button(root, text="Browse File", command=browse_file)
browse_file_button.grid(row=0, column=2, padx=10, pady=10)

browse_folder_button = tk.Button(root, text="Browse Folder", command=browse_folder)
browse_folder_button.grid(row=0, column=3, padx=10, pady=10)

# Password entry label and field
tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)
key_entry = tk.Entry(root, width=50)  # Input field for entering or generating the password
key_entry.grid(row=1, column=1, padx=10, pady=10)

# Button to generate a random password
generate_key_button = tk.Button(root, text="Generate Password", command=generate)
generate_key_button.grid(row=1, column=2, padx=10, pady=10)

# Algorithm selection dropdown menu
tk.Label(root, text="Algorithm:").grid(row=2, column=0, padx=10, pady=10)
algorithm_choice = tk.StringVar(value='DES')  # Default algorithm is set to DES
algorithm_menu = tk.OptionMenu(root, algorithm_choice, 'DES', '3DES', 'AES')
algorithm_menu.grid(row=2, column=1, padx=10, pady=10)

# Buttons for encryption and decryption
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=3, column=1, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=3, column=2, padx=10, pady=10)

# Status label to display messages to the user
status_label = tk.Label(root, text="", fg="blue")
status_label.grid(row=4, column=1, columnspan=3, padx=10, pady=10)

# Derived key display label (optional, for educational purposes)
derived_key_label = tk.Label(root, text="")
derived_key_label.grid(row=5, column=1, columnspan=3, padx=10, pady=10)

# Start the GUI loop
root.mainloop()
