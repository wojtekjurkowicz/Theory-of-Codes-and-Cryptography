import numpy as np


# Helper Functions
def generate_random_matrix(rows, cols):
    return np.random.randint(0, 2, (rows, cols))


def is_full_rank(matrix):
    return np.linalg.matrix_rank(matrix) == min(matrix.shape)


def generate_full_rank_matrix(rows, cols):
    while True:
        matrix = generate_random_matrix(rows, cols)
        if is_full_rank(matrix):
            return matrix


def generate_parity_check_matrix(generator_matrix):
    k, n = generator_matrix.shape
    identity_matrix = np.eye(k, dtype=int)
    parity_matrix = np.concatenate((generator_matrix[:, k:], identity_matrix), axis=1)
    return parity_matrix


# Key Generation
def key_generation(n, k, t):
    # Generate random parity matrix P (k x (n-k))
    P_random = generate_random_matrix(k, n - k)

    # Construct G in standard form: [I_k | P]
    G = np.concatenate((np.eye(k, dtype=int), P_random), axis=1)

    # Generate random permutation matrix P
    P = np.eye(n, dtype=int)
    np.random.shuffle(P)

    # Generate random invertible matrix S
    S = generate_full_rank_matrix(k, k)

    # Calculate public key G' = S * G * P
    G_prime = (S @ G @ P) % 2

    # Private key: S, G, P
    private_key = (S, G, P)

    return G_prime, private_key


# Encryption
def encrypt(public_key, message, t):
    # Encode message with public key
    encoded_message = (message @ public_key) % 2

    # Generate random error vector with weight t
    error_vector = np.zeros(public_key.shape[1], dtype=int)
    error_indices = np.random.choice(range(public_key.shape[1]), t, replace=False)
    error_vector[error_indices] = 1

    # Add error to encoded message
    ciphertext = (encoded_message + error_vector) % 2

    return ciphertext


# Decryption
def decrypt(ciphertext, private_key):
    S, G, P = private_key

    # Calculate inverse of S
    S_inv = np.linalg.inv(S).astype(int) % 2

    # Undo permutation
    P_inv = np.linalg.inv(P).astype(int)
    permuted_ciphertext = (ciphertext @ P_inv) % 2

    # Decode using generator matrix G
    # Assuming we have an efficient decoding function for G (omitted here for simplicity)
    decoded_message = decode(permuted_ciphertext, G)

    # Undo transformation with S
    original_message = (decoded_message @ S_inv) % 2

    return original_message


def decode(received_vector, generator_matrix):
    """
    Decodes the received vector by correcting errors and extracting the original message.

    Args:
        received_vector: Received vector (size n).
        generator_matrix: Generator matrix G in standard form [I_k | P].

    Returns:
        Decoded message vector (size k).
    """
    k, n = generator_matrix.shape
    # Correct errors (omitted for simplicity; assuming error-free decoding)
    # In a real-world implementation, apply error-correcting algorithms here.

    # Extract the first k elements of the received vector (assumes standard form)
    decoded_message = received_vector[:k]
    return decoded_message


n = 7  # Code length
k = 4  # Message length
t = 2  # Error-correcting capability

# Key generation
public_key, private_key = key_generation(n, k, t)

# Generate a random message
message = np.random.randint(0, 2, k)
print("Original Message:", message)

# Encrypt the message
ciphertext = encrypt(public_key, message, t)
print("Ciphertext:", ciphertext)

# Decrypt the message
decrypted_message = decrypt(ciphertext, private_key)
print("Decrypted Message:", decrypted_message)

# Verify correctness
if np.array_equal(message, decrypted_message):
    print("Decryption successful!")
else:
    print("Decryption failed.")
