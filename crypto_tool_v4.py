import os
import tkinter as tk
import json
from tkinter import filedialog, messagebox, simpledialog
from hashlib import sha256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2

# Constants
BLOCK_SIZE_AES = 16


# === Cryptographic Functions ===

def hash_license_to_key(license_number):
    """
    Derive an AES key from a license number using SHA-256.
    This ensures the license number generates a consistent encryption key.
    """
    return sha256(license_number.encode()).digest()


def protect_app_private_key(private_key, license_number, filepath="app_private_enc.pem"):
    """
    Encrypt the application's private key using an AES key derived from the license number.
    Ensures the private key is securely stored.
    """
    app_key = hash_license_to_key(license_number)  # Derive encryption key
    cipher = AES.new(app_key, AES.MODE_EAX)  # Create AES cipher
    ciphertext, tag = cipher.encrypt_and_digest(private_key)  # Encrypt private key

    with open(filepath, 'wb') as file:
        file.write(cipher.nonce + tag + ciphertext)  # Save encrypted private key


def load_app_private_key(license_number, filepath="app_private_enc.pem"):
    """
    Decrypt the application's private key using the AES key derived from the license number.
    Handles missing or corrupted key files gracefully.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError("The application's private key file is missing. Please generate the keys first.")

    try:
        app_key = hash_license_to_key(license_number)  # Derive decryption key
        with open(filepath, 'rb') as file:
            content = file.read()

        # Extract nonce, tag, and ciphertext
        nonce = content[:16]
        tag = content[16:32]
        ciphertext = content[32:]
        cipher = AES.new(app_key, AES.MODE_EAX, nonce=nonce)  # Create AES cipher
        return cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify
    except ValueError as e:
        raise ValueError(f"Decryption failed: {str(e)} (Ensure license number is correct.)")


def generate_app_private_key(license_number, priv_filepath="app_private_enc.pem", pub_filepath="app_public.pem"):
    """
    Generate the application's RSA key pair, encrypt the private key using the license number,
    and save the public key to a file.
    """
    key = RSA.generate(2048)  # Generate RSA key pair
    private_key = key.export_key()  # Export private key
    public_key = key.publickey().export_key()  # Export public key
    protect_app_private_key(private_key, license_number, priv_filepath)  # Secure private key
    with open(pub_filepath, 'wb') as file:
        file.write(public_key)  # Save public key
    messagebox.showinfo("Success", "Application private and public keys generated successfully.")


# === Certificate Management ===

def generate_certificate(user_identity, user_public_key, app_private_key, cert_filepath):
    """
    Generate a user certificate containing identity, public key, and a signature.
    Signs the hash of the public key using the app's private key.
    """
    try:
        if isinstance(user_public_key, bytes):
            user_public_key = RSA.import_key(user_public_key)  # Ensure correct key format

        public_key_hash = SHA256.new(user_public_key.export_key())  # Hash the public key
        signature = pkcs1_15.new(app_private_key).sign(public_key_hash)  # Sign the hash

        certificate = {
            "identity": user_identity,
            "public_key": user_public_key.export_key().decode('utf-8'),
            "signature": signature.hex()  # Store signature as hex string
        }

        with open(cert_filepath, 'w') as file:
            json.dump(certificate, file, indent=4)  # Save certificate as JSON
    except Exception as e:
        raise Exception(f"Error during certificate generation: {str(e)}")


def load_encrypted_private_key(filepath, password):
    """
    Load and decrypt a private key that is protected with a password.
    """
    try:
        with open(filepath, 'rb') as file:
            content = file.read()

        # Extract salt, nonce, tag, and ciphertext
        salt = content[:16]
        nonce = content[16:32]
        tag = content[32:48]
        ciphertext = content[48:]

        private_key_aes_key = PBKDF2(password, salt, dkLen=32)  # Derive AES key
        cipher = AES.new(private_key_aes_key, AES.MODE_EAX, nonce=nonce)  # Create AES cipher
        private_key = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt private key

        return RSA.import_key(private_key)  # Import RSA key
    except ValueError:
        raise ValueError("Incorrect password or corrupted private key file.")


def validate_certificate(certificate_path, app_public_key):
    """
    Validate a certificate by checking the signature using the app's public key.
    """
    try:
        with open(certificate_path, 'r') as file:
            certificate = json.load(file)

        user_public_key = RSA.import_key(certificate["public_key"].encode('utf-8'))
        signature = bytes.fromhex(certificate["signature"])

        public_key_hash = SHA256.new(user_public_key.export_key())  # Hash the public key
        pkcs1_15.new(app_public_key).verify(public_key_hash, signature)  # Verify signature

        return True  # Certificate is valid
    except (ValueError, TypeError) as e:
        raise ValueError(f"Certificate validation failed: {str(e)}")


# === File Encryption and Decryption ===

def encrypt_for_users(filepath, selected_certificates, app_public_key):
    """
    Encrypt a file for multiple users using their public keys from certificates.
    """
    try:
        aes_key = get_random_bytes(32)  # Generate AES key (K)
        headers = []

        for cert_path in selected_certificates:
            # Load and validate certificate
            with open(cert_path, 'r') as file:
                certificate = json.load(file)

            user_identity = certificate.get("identity")
            user_public_key = RSA.import_key(certificate["public_key"].encode('utf-8'))
            validate_certificate(cert_path, app_public_key)

            # Encrypt AES key with user's public key
            encrypted_key = PKCS1_OAEP.new(user_public_key).encrypt(aes_key)
            headers.append({"identity": user_identity, "encrypted_key": encrypted_key.hex()})

        # Encrypt the file content with AES key
        with open(filepath, 'rb') as file:
            plaintext = file.read()

        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        encrypted_filepath = f"{filepath}.enc"
        with open(encrypted_filepath, 'wb') as enc_file:
            enc_file.write(cipher.nonce + tag + ciphertext)

        # Save encryption headers
        header_filepath = f"{encrypted_filepath}.headers"
        with open(header_filepath, 'w') as header_file:
            json.dump(headers, header_file, indent=4)

        os.remove(filepath)  # Delete original file after encryption
    except Exception as e:
        raise Exception(f"Error during file encryption: {str(e)}")


def decrypt_for_user(filepath, user_private_key, user_identity):
    """
    Decrypt a file for a user by recovering the AES key (K) from the headers.
    """
    try:
        header_filepath = f"{filepath}.headers"
        with open(header_filepath, 'r') as header_file:
            headers = json.load(header_file)

        # Find header matching user's identity
        matching_header = next((h for h in headers if h["identity"] == user_identity), None)
        if not matching_header:
            raise ValueError(f"No encryption header found for user: {user_identity}")

        # Decrypt the AES key using the user's private key
        encrypted_key = bytes.fromhex(matching_header["encrypted_key"])
        aes_key = PKCS1_OAEP.new(user_private_key).decrypt(encrypted_key)

        # Decrypt the file content with AES key
        with open(filepath, 'rb') as file:
            content = file.read()

        nonce = content[:16]
        tag = content[16:32]
        ciphertext = content[32:]

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Save decrypted file
        decrypted_filepath = filepath.replace('.enc', '')
        with open(decrypted_filepath, 'wb') as dec_file:
            dec_file.write(plaintext)

        os.remove(filepath)  # Delete encrypted file
        os.remove(header_filepath)  # Delete headers
    except Exception as e:
        raise Exception(f"Error during file decryption: {str(e)}")


# === GUI Integration ===
def generate_app_keys_gui():
    """GUI function to generate the application's RSA keys."""
    license_number = simpledialog.askstring("License Number", "Enter the license number:")
    if not license_number:
        messagebox.showerror("Error", "License number is required.")
        return

    generate_app_private_key(license_number)


def generate_certificate_gui():
    """GUI for generating user certificates. Ensures the application's private key exists."""
    try:
        # Ask for user identity
        user_identity = simpledialog.askstring("Identity", "Enter user identity:")
        if not user_identity:
            messagebox.showerror("Error", "User identity cannot be empty.")
            return

        # Ask for license number
        license_number = simpledialog.askstring("License Number", "Enter the license number to access app keys:")
        if not license_number:
            messagebox.showerror("Error", "License number cannot be empty.")
            return

        # Load the application's private key
        app_private_key_data = load_app_private_key(license_number)
        app_private_key = RSA.import_key(app_private_key_data)

        # Ask for a password to protect the user's private key
        private_key_password = simpledialog.askstring("Password", "Enter a password to protect your private key:",
                                                      show='*')
        if not private_key_password:
            messagebox.showerror("Error", "Password is required to protect the private key.")
            return

        # Generate a new RSA key pair for the user
        user_key_pair = RSA.generate(2048)
        user_private_key = user_key_pair.export_key()
        user_public_key = user_key_pair.publickey()

        # Encrypt the private key with the password
        salt = get_random_bytes(16)
        private_key_aes_key = PBKDF2(private_key_password, salt, dkLen=32)
        cipher = AES.new(private_key_aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(user_private_key)

        # Create directories for keys if they don't exist
        os.makedirs("public_keys", exist_ok=True)
        os.makedirs("private_keys", exist_ok=True)

        # Save the user's encrypted private key to the private_keys folder
        private_key_filepath = os.path.join("private_keys", f"{user_identity}_private.enc")
        with open(private_key_filepath, 'wb') as priv_file:
            priv_file.write(salt + cipher.nonce + tag + ciphertext)

        # Save the user's public key (certificate) to the public_keys folder
        cert_filepath = os.path.join("public_keys", f"{user_identity}_cert.json")
        generate_certificate(user_identity, user_public_key, app_private_key, cert_filepath)

        messagebox.showinfo(
            "Certificate",
            f"Certificate and private key generated for {user_identity}.\n"
            f"Encrypted Private Key saved at: {private_key_filepath}\n"
            f"Certificate saved at: {cert_filepath}"
        )
    except FileNotFoundError as e:
        messagebox.showerror("Error", f"Key file not found: {str(e)}")
    except ValueError as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")


def encrypt_gui():
    """GUI for encrypting files for multiple users."""
    try:
        filepath = filedialog.askopenfilename(title="Select File to Encrypt")
        if not filepath:
            messagebox.showerror("Error", "No file selected.")
            return

        cert_paths = filedialog.askopenfilenames(title="Select User Certificates (JSON Certificate Files)")
        if not cert_paths:
            messagebox.showerror("Error", "No certificates selected.")
            return

        # Load the application's public key
        try:
            app_public_key = RSA.import_key(open("app_public.pem", "rb").read())
        except FileNotFoundError:
            messagebox.showerror("Error", "Application public key not found. Generate app keys first.")
            return

        # Encrypt the file
        encrypt_for_users(filepath, cert_paths, app_public_key)
        messagebox.showinfo("Encryption", f"File encrypted successfully.")
    except ValueError as e:
        messagebox.showerror("Error", f"Invalid file selected: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")


def decrypt_gui():
    """GUI for decrypting files."""
    try:
        # Select the encrypted file
        filepath = filedialog.askopenfilename(title="Select Encrypted File")
        if not filepath:
            messagebox.showerror("Error", "No file selected.")
            return

        # Select the user's private key file
        private_key_filepath = filedialog.askopenfilename(title="Select Your Encrypted Private Key")
        if not private_key_filepath:
            messagebox.showerror("Error", "No private key selected.")
            return

        # Prompt for the user identity
        user_identity = simpledialog.askstring("Identity", "Enter your user identity:")
        if not user_identity:
            messagebox.showerror("Error", "User identity is required.")
            return

        # Prompt for the private key password
        private_key_password = simpledialog.askstring("Password", "Enter your private key password:", show='*')
        if not private_key_password:
            messagebox.showerror("Error", "Password is required to access the private key.")
            return

        # Load and decrypt the private key
        user_private_key = load_encrypted_private_key(private_key_filepath, private_key_password)

        # Decrypt the file
        decrypt_for_user(filepath, user_private_key, user_identity)
    except FileNotFoundError as e:
        messagebox.showerror("Error", f"File not found: {str(e)}")
    except ValueError as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")


# === Main GUI ===
root = tk.Tk()
root.title("Certificate-Based File Encryption")

# Set the window dimensions (width x height)
root.geometry("400x300")  # You can adjust these values as needed

# Add buttons and padding
tk.Label(root, text="Certificate-Based File Encryption Tool", font=("Helvetica", 16)).pack(pady=20)
tk.Button(root, text="Generate App Keys", command=generate_app_keys_gui, width=25).pack(pady=10)
tk.Button(root, text="Generate Certificate", command=generate_certificate_gui, width=25).pack(pady=10)
tk.Button(root, text="Encrypt File", command=encrypt_gui, width=25).pack(pady=10)
tk.Button(root, text="Decrypt File", command=decrypt_gui, width=25).pack(pady=10)

root.mainloop()
