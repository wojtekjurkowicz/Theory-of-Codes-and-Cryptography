import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from hashlib import sha256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Constant for AES block size
BLOCK_SIZE_AES = 16  # Block size for AES encryption


# === Cryptographic Functions ===
def derive_aes_key_from_password(password):
    """
    Derive a 256-bit AES key (K2) from a user-provided password using SHA-256.
    This key is used to encrypt/decrypt the RSA private key.
    """
    return sha256(password.encode()).digest()


def generate_key():
    """
    Generate a 32-byte AES key (K1) for encrypting files/folders.
    Returns the key as a hex string.
    """
    key = get_random_bytes(32)  # 32 bytes for AES
    return key.hex()  # Return the key in hex form


def generate_rsa_keypair():
    """
    Generate a 2048-bit RSA key pair (Pub, Priv).
    Returns the private and public keys.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def save_rsa_keys(public_key, pub_filepath="public.pem"):
    with open(pub_filepath, 'wb') as pub_file:
        pub_file.write(public_key)


def save_encrypted_rsa_private_key(private_key, password, priv_filepath="private_enc.pem"):
    k2 = derive_aes_key_from_password(password)
    cipher = AES.new(k2, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)

    with open(priv_filepath, 'wb') as priv_file:
        priv_file.write(cipher.nonce + tag + ciphertext)


def load_encrypted_rsa_private_key(password, priv_filepath="private_enc.pem"):
    try:
        with open(priv_filepath, 'rb') as priv_file:
            content = priv_file.read()

        nonce = content[:16]
        tag = content[16:32]
        ciphertext = content[32:]
        k2 = derive_aes_key_from_password(password)

        cipher = AES.new(k2, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except FileNotFoundError:
        raise FileNotFoundError("Encrypted private key file not found.")
    except Exception as e:
        raise Exception(f"Failed to load private key: {str(e)}")


# AES Key Encryption/Decryption with RSA
def encrypt_aes_key_rsa(aes_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(aes_key)


def decrypt_aes_key_rsa(encrypted_aes_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_aes_key)


# Function to handle file encryption
def encrypt_file(filepath, aes_key, rsa_public_key=None):
    try:
        # Convert hex key back to bytes
        key = bytes.fromhex(aes_key)

        # File opening
        with open(filepath, 'rb') as file:
            plaintext = file.read()

        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        encrypted_filepath = f"{filepath}.enc"

        with open(encrypted_filepath, 'wb') as enc_file:
            # Saving encrypted file
            enc_file.write(cipher.nonce + tag + ciphertext)

        if rsa_public_key:
            encrypted_key = encrypt_aes_key_rsa(key, rsa_public_key)
            with open(f"{encrypted_filepath}.key", 'wb') as key_file:
                key_file.write(encrypted_key)

        os.remove(filepath)  # Delete the original file
        status_label.config(text=f"Encrypted file saved as {encrypted_filepath}.", fg="green")
    except FileNotFoundError:
        messagebox.showerror("Error", f"File not found: {filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt {filepath}: {str(e)}")


def decrypt_file(filepath, rsa_private_key):
    try:
        # Load the RSA-encrypted AES key
        key_filepath = f"{filepath}.key"
        with open(key_filepath, 'rb') as key_file:
            encrypted_key = key_file.read()

        # Decrypt the AES key using the RSA private key
        aes_key = decrypt_aes_key_rsa(encrypted_key, rsa_private_key)

        # Load the encrypted file
        with open(filepath, 'rb') as file:
            content = file.read()

        # Extract nonce, tag, and ciphertext
        nonce = content[:16]
        tag = content[16:32]
        ciphertext = content[32:]

        # Decrypt the file contents
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Save the decrypted file
        decrypted_filepath = filepath.replace('.enc', '')
        with open(decrypted_filepath, 'wb') as dec_file:
            dec_file.write(plaintext)

        # Delete the original encrypted file and key file
        os.remove(filepath)
        os.remove(key_filepath)  # Delete the .key file
        status_label.config(text=f"Decrypted file saved as {decrypted_filepath}.", fg="green")
    except FileNotFoundError:
        messagebox.showerror("Error", f"Key file or encrypted file not found: {filepath}")
    except Exception as e:
        messagebox.showerror("Decryption failed", f"Decryption failed: {str(e)}")


# Folder Encryption/Decryption
def process_folder(folder_path, aes_key, mode, rsa_public_key=None, rsa_private_key=None):
    try:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                filepath = os.path.join(root, file)
                if mode == 'encrypt':
                    encrypt_file(filepath, aes_key, rsa_public_key=rsa_public_key)
                elif mode == 'decrypt' and file.endswith('.enc'):
                    decrypt_file(filepath, rsa_private_key=rsa_private_key)
        status_label.config(text=f"Folder {mode}ion completed successfully!", fg="green")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to process folder: {str(e)}")


# Input Validation Functions
def validate_file_path(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"The path '{filepath}' does not exist.")
    if os.path.isdir(filepath):
        raise IsADirectoryError(f"The path '{filepath}' is a directory.")


def validate_password(password):
    if not password or len(password.strip()) == 0:
        raise ValueError("Password cannot be empty.")


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
    try:
        key = generate_key()
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key)
        status_label.config(text="Key generated successfully.", fg="green")
    except Exception as e:
        status_label.config(text=f"Key generation failed: {str(e)}", fg="red")


def generate_rsa():
    try:
        password = simpledialog.askstring("Password", "Enter a password to protect your private key:", show='*')
        validate_password(password)

        private_key, public_key = generate_rsa_keypair()
        save_rsa_keys(public_key)
        save_encrypted_rsa_private_key(private_key, password)
        status_label.config(text="RSA keys generated and private key encrypted.", fg="green")
    except ValueError as e:
        status_label.config(text=str(e), fg="red")
    except Exception as e:
        status_label.config(text=f"RSA key generation failed: {str(e)}", fg="red")


def encrypt():
    try:
        aes_key = key_entry.get()
        filepath = file_entry.get()
        validate_file_path(filepath)

        public_key = RSA.import_key(open("public.pem", "rb").read())
        if os.path.isfile(filepath):
            encrypt_file(filepath, aes_key, rsa_public_key=public_key)
        elif os.path.isdir(filepath):
            process_folder(filepath, aes_key=aes_key, mode='encrypt', rsa_public_key=public_key)
    except Exception as e:
        status_label.config(text=f"Encryption failed: {str(e)}", fg="red")


def decrypt():
    try:
        filepath = file_entry.get()
        validate_file_path(filepath)

        password = simpledialog.askstring("Password", "Enter the password to decrypt the private key:", show='*')
        validate_password(password)

        private_key = load_encrypted_rsa_private_key(password)
        rsa_private_key = RSA.import_key(private_key)

        if os.path.isfile(filepath):
            decrypt_file(filepath, rsa_private_key)
        elif os.path.isdir(filepath):
            process_folder(filepath, aes_key=None, mode='decrypt', rsa_private_key=rsa_private_key)
    except ValueError as e:
        status_label.config(text=str(e), fg="red")
    except Exception as e:
        status_label.config(text=f"Decryption failed: {str(e)}", fg="red")


# GUI Setup
root = tk.Tk()
root.title("File/Folder Encryption & Decryption")

tk.Label(root, text="File/Folder Path:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=0, column=1, padx=10, pady=10, columnspan=2)

browse_file_button = tk.Button(root, text="Browse File", command=browse_file)
browse_file_button.grid(row=0, column=3, padx=10, pady=10)

browse_folder_button = tk.Button(root, text="Browse Folder", command=browse_folder)
browse_folder_button.grid(row=0, column=4, padx=10, pady=10)

tk.Label(root, text="Encryption Key:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=1, column=1, padx=10, pady=10, columnspan=2)

generate_key_button = tk.Button(root, text="Generate Key", command=generate)
generate_key_button.grid(row=1, column=3, padx=10, pady=10)

generate_rsa_button = tk.Button(root, text="Generate RSA Keys", command=generate_rsa)
generate_rsa_button.grid(row=1, column=4, padx=10, pady=10)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=2, column=1, padx=10, pady=20)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=2, column=2, padx=10, pady=20)

status_label = tk.Label(root, text="", fg="blue")
status_label.grid(row=3, column=0, columnspan=5, padx=10, pady=10)

root.mainloop()
