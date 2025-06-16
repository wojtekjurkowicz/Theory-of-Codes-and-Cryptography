from tkinter import filedialog, Tk, Entry, Label, Button, OptionMenu, StringVar
import os
import numpy as np
import threading
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

# Constants for block sizes
BLOCK_SIZE_DES = 8  # Block size for DES (in bytes)
BLOCK_SIZE_AES = 16  # Block size for AES (in bytes)


# Helper Functions for McEliece

def generate_random_matrix(rows, cols):
    return np.random.randint(0, 2, (rows, cols))


def is_full_rank(matrix):
    return np.linalg.matrix_rank(matrix) == min(matrix.shape)


def generate_full_rank_matrix(rows, cols):
    """
    Generate a full-rank binary matrix over GF(2).
    """
    while True:
        matrix = np.random.randint(0, 2, (rows, cols))
        if np.linalg.matrix_rank(matrix) == rows:  # Ensure the matrix is full-rank
            try:
                _ = mod2_inverse(matrix)  # Check if matrix is invertible in GF(2)
                return matrix
            except ValueError:
                pass  # If not invertible, retry


def mod2_inverse(matrix):
    """
    Compute inverse of a square matrix over GF(2).
    """
    n = matrix.shape[0]
    augmented = np.concatenate((matrix, np.eye(n, dtype=int)), axis=1) % 2

    for i in range(n):
        if augmented[i, i] == 0:
            for j in range(i + 1, n):
                if augmented[j, i] == 1:
                    augmented[[i, j]] = augmented[[j, i]]
                    break
            else:
                raise ValueError("Matrix is not invertible in GF(2)")

        # Normalize row i
        augmented[i] = augmented[i] % 2
        for j in range(n):
            if i != j and augmented[j, i] == 1:
                augmented[j] = (augmented[j] + augmented[i]) % 2

    return augmented[:, n:] % 2


def key_generation(n, k, t):
    """
    Generate McEliece public and private keys.
    - n: Code length
    - k: Message length (must be >= 128)
    - t: Error weight
    """
    if k < 128:
        raise ValueError("k must be at least 128 to accommodate the AES key.")

    P_random = generate_random_matrix(k, n - k)
    G = np.concatenate((np.eye(k, dtype=int), P_random), axis=1)
    P = np.eye(n, dtype=int)
    np.random.shuffle(P)
    S = generate_full_rank_matrix(k, k)
    G_prime = (S @ G @ P) % 2
    private_key = (S.tolist(), G.tolist(), P.tolist())
    return G_prime, private_key


def mceliece_encrypt(public_key, message, t):
    k, n = public_key.shape  # Rows (k) and columns (n) of the public key
    if len(message) != k:
        raise ValueError(f"Message length {len(message)} and public key row size {k} mismatch.")

    # Reshape message to ensure it's a row vector
    message = message.reshape(1, -1)  # Shape (1, k)

    # Encode the message
    encoded_message = (message @ public_key) % 2  # Result is shape (1, n)
    encoded_message = encoded_message.flatten()  # Convert to 1D array for further processing

    # Generate the error vector
    error_vector = np.zeros(n, dtype=int)
    error_indices = np.random.choice(range(n), t, replace=False)
    error_vector[error_indices] = 1

    # Compute the ciphertext
    ciphertext = (encoded_message + error_vector) % 2
    return ciphertext


def mceliece_decrypt(ciphertext, private_key):
    S, G, P = map(np.array, private_key)

    # Step 1: Invert S and P matrices over GF(2)
    try:
        S_inv = mod2_inverse(S)  # Invert S
        P_inv = mod2_inverse(P)  # Invert P
    except ValueError as e:
        raise ValueError(f"Matrix inversion failed in GF(2): {e}")

    # Permute the ciphertext using P_inv
    permuted_ciphertext = (ciphertext @ P_inv) % 2
    print(f"Permuted ciphertext: {permuted_ciphertext}")

    # Decode the message using the generator matrix G
    decoded_message = decode(permuted_ciphertext, G, max_errors=8)
    if decoded_message is None:
        raise ValueError("Decoding failed: Unable to reconstruct the message.")

    # Recover the original message using S_inv
    original_message = (decoded_message @ S_inv) % 2
    print(f"Recovered symmetric key bits: {original_message}")

    return original_message


def precompute_syndrome_table(generator_matrix, max_errors):
    """
    Precompute a syndrome table for error patterns up to max_errors bits.
    Returns a dictionary mapping syndrome -> error pattern.
    """
    k, n = generator_matrix.shape
    syndrome_table = {}

    from itertools import combinations

    # Generate error patterns for weights 1 to max_errors
    for weight in range(1, max_errors + 1):
        for positions in combinations(range(n), weight):
            error_vector = np.zeros(n, dtype=int)
            for pos in positions:
                error_vector[pos] = 1

            # Compute syndrome
            syndrome = tuple((error_vector @ generator_matrix.T) % 2)
            syndrome_table[syndrome] = error_vector

    return syndrome_table


def decode(received_vector, generator_matrix, max_errors=8):
    """
    Decode received_vector using syndrome decoding and a precomputed syndrome table.
    """
    k, n = generator_matrix.shape

    # Precompute the syndrome table
    syndrome_table = precompute_syndrome_table(generator_matrix, max_errors)

    # Compute the syndrome of the received vector
    syndrome = tuple((received_vector @ generator_matrix.T) % 2)

    # If syndrome is zero, no errors
    if all(s == 0 for s in syndrome):
        return received_vector[:k]

    # Lookup syndrome in the precomputed table
    if syndrome in syndrome_table:
        error_vector = syndrome_table[syndrome]
        corrected_vector = (received_vector + error_vector) % 2
        return corrected_vector[:k]

    print("Error correction failed: Unable to decode the message.")
    return None


def save_key_to_file(key, filepath):
    import json
    with open(filepath, "w") as file:
        if isinstance(key, np.ndarray):
            json.dump(key.tolist(), file)
        elif isinstance(key, tuple):
            key_as_list = [k.tolist() if isinstance(k, np.ndarray) else k for k in key]
            json.dump(key_as_list, file)
        else:
            json.dump(key, file)


def load_key_from_file(filepath):
    import json
    with open(filepath, "r") as file:
        return json.load(file)  # Load the key as a JSON list


# GUI Functions
def generate():
    algorithm = algorithm_choice.get()
    if algorithm == "McEliece":
        n = 256  # Codeword length
        k = 128  # Message length
        t = 8  # Error weight

        public_key, private_key = key_generation(n, k, t)

        # Save the public key
        save_key_to_file(public_key.tolist(), "public_key.txt")

        # Save the private key (ensure it's properly formatted)
        save_key_to_file(private_key, "private_key.txt")

        status_label.config(text="McEliece keys generated and saved.", fg="green")
    else:
        key = get_random_bytes(32 if algorithm == 'AES' else (24 if algorithm == '3DES' else 8))
        key_entry.delete(0, 'end')
        key_entry.insert(0, key.hex())
        status_label.config(text="Key generated successfully.", fg="green")


def encrypt():
    filepath = file_entry.get()
    algorithm = algorithm_choice.get()
    if algorithm == "McEliece":
        symmetric_key = get_random_bytes(16)  # AES key (16 bytes)
        public_key = np.array(load_key_from_file("public_key.txt"))

        # Convert symmetric key to bits
        symmetric_key_bits = np.unpackbits(np.frombuffer(symmetric_key, dtype=np.uint8))
        k, n = public_key.shape  # Rows (k) and columns (n) of public key

        # Ensure k is large enough
        if k < 128:
            raise ValueError("Public key message length (k) must be at least 128 bits.")

        # Adjust symmetric_key_bits to match the public_key's row size
        if len(symmetric_key_bits) > k:
            symmetric_key_bits = symmetric_key_bits[:k]  # Truncate if larger
        else:
            symmetric_key_bits = np.pad(symmetric_key_bits, (0, k - len(symmetric_key_bits)), 'constant')

        # Encrypt the symmetric key using McEliece
        encrypted_symmetric_key = mceliece_encrypt(public_key, symmetric_key_bits, 8)

        # Encrypt the file using AES with the original symmetric key
        with open(filepath, "rb") as file:
            plaintext = file.read()
        cipher = AES.new(symmetric_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE_AES))

        # Save the encrypted symmetric key and ciphertext to the output file
        encrypted_filepath = filepath + ".mceliece"
        with open(encrypted_filepath, "wb") as file:
            file.write(np.packbits(encrypted_symmetric_key).tobytes() + ciphertext)

        status_label.config(text="File encrypted with McEliece.", fg="green")

def decrypt():
    def decryption_task():
        filepath = file_entry.get().strip()
        algorithm = algorithm_choice.get()
        if algorithm == "McEliece":
            try:
                # Load private key
                private_key = [np.array(k) for k in load_key_from_file("private_key.txt")]

                # Read encrypted file
                with open(filepath, "rb") as file:
                    encrypted_content = file.read()

                # Extract encrypted symmetric key and ciphertext
                encrypted_key_length = private_key[2].shape[1]
                key_byte_length = (encrypted_key_length + 7) // 8
                encrypted_symmetric_key = np.unpackbits(
                    np.frombuffer(encrypted_content[:key_byte_length], dtype=np.uint8)
                )[:encrypted_key_length]
                ciphertext = encrypted_content[key_byte_length:]

                # Decrypt the symmetric key using McEliece
                symmetric_key_bits = mceliece_decrypt(encrypted_symmetric_key, private_key)

                # Ensure key is 128 bits long
                symmetric_key_bits = np.pad(symmetric_key_bits, (0, 128 - len(symmetric_key_bits)), 'constant')[:128]
                symmetric_key_bytes = np.packbits(symmetric_key_bits).tobytes()

                # Debugging: Compare hashes
                reconstructed_hash = sha256(symmetric_key_bytes).hexdigest()
                print(f"Reconstructed symmetric key hash: {reconstructed_hash}")

                # AES decryption
                cipher = AES.new(symmetric_key_bytes, AES.MODE_ECB)
                decrypted_data = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE_AES)

                # Save the decrypted data to a file
                output_filepath = os.path.splitext(filepath)[0]
                with open(output_filepath, "wb") as file:
                    file.write(decrypted_data)

                status_label.config(text=f"File decrypted to: {output_filepath}", fg="green")
            except Exception as e:
                status_label.config(text=f"Error during decryption: {str(e)}", fg="red")

    # Run decryption in a separate thread
    threading.Thread(target=decryption_task).start()


# GUI Setup
root = Tk()
root.title("Encryption Tool with McEliece")

file_entry = Entry(root, width=50)
file_entry.grid(row=0, column=1, padx=10, pady=10)

Label(root, text="File:").grid(row=0, column=0, padx=10, pady=10)
Button(root, text="Browse",
       command=lambda: (file_entry.delete(0, 'end'), file_entry.insert(0, filedialog.askopenfilename()))).grid(row=0,
                                                                                                               column=2,
                                                                                                               padx=10,
                                                                                                               pady=10)

Label(root, text="Key:").grid(row=1, column=0, padx=10, pady=10)
key_entry = Entry(root, width=50)
key_entry.grid(row=1, column=1, padx=10, pady=10)

Button(root, text="Generate Key", command=generate).grid(row=1, column=2, padx=10, pady=10)

Label(root, text="Algorithm:").grid(row=2, column=0, padx=10, pady=10)
algorithm_choice = StringVar(value="AES")
OptionMenu(root, algorithm_choice, "AES", "3DES", "DES", "McEliece").grid(row=2, column=1, padx=10, pady=10)

Button(root, text="Encrypt", command=encrypt).grid(row=3, column=0, padx=10, pady=10)
Button(root, text="Decrypt", command=decrypt).grid(row=3, column=1, padx=10, pady=10)

status_label = Label(root, text="", fg="blue")
status_label.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()
