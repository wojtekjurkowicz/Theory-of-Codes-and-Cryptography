import tkinter as tk
from tkinter import simpledialog, messagebox
import random


# === Error-Correcting Code Functions ===
"""
Hamming (7,4) Code Parameters:
- Length (n): 7
- Dimension (k): 4
- Number of Codewords: 2^4 = 16
- Minimum Distance (d_min): 3
- Error Detection: Up to 2 errors
- Error Correction: 1 error
"""


def hamming_encode(bit_string):
    """Encodes a bit string using Hamming (7,4) code."""
    if len(bit_string) != 4:
        raise ValueError(f"Input must be 4-bit string.")

    # Calculate parity bits (for positions 1, 2, 4)
    p1 = int(bit_string[0]) ^ int(bit_string[1]) ^ int(bit_string[3])  # Parity bit 1
    p2 = int(bit_string[0]) ^ int(bit_string[2]) ^ int(bit_string[3])  # Parity bit 2
    p3 = int(bit_string[1]) ^ int(bit_string[2]) ^ int(bit_string[3])  # Parity bit 4

    # Form encoded word: p1, p2, d1, p3, d2, d3, d4
    encoded_word = f"{p1}{p2}{bit_string[0]}{p3}{bit_string[1:]}"

    return encoded_word


def hamming_decode(encoded_string):
    """Decodes a Hamming (7,4) codeword, correcting a single error if present."""
    if len(encoded_string) != 7:
        raise ValueError("Encoded string must be 7 bits long.")

    # Extract parity and data bits
    p1 = int(encoded_string[0])
    p2 = int(encoded_string[1])
    d1 = int(encoded_string[2])
    p3 = int(encoded_string[3])
    d2 = int(encoded_string[4])
    d3 = int(encoded_string[5])
    d4 = int(encoded_string[6])

    # Calculate syndrome bits
    s1 = p1 ^ d1 ^ d2 ^ d4
    s2 = p2 ^ d1 ^ d3 ^ d4
    s3 = p3 ^ d2 ^ d3 ^ d4

    # Calculate error position from syndrome (1-based index)
    error_position = s1 * 1 + s2 * 2 + s3 * 4

    # Correct the error if any
    corrected = list(encoded_string)
    if error_position:
        corrected[error_position - 1] = '1' if corrected[error_position - 1] == '0' else '0'

    # Extract the original data bits
    original_data = f"{corrected[2]}{corrected[4]}{corrected[5]}{corrected[6]}"

    return ''.join(corrected), original_data, error_position


def encode_arbitrary_length(bit_string):
    """Encodes a bit string of arbitrary length using Hamming (7,4) code."""
    if not all(c in "01" for c in bit_string):
        raise ValueError("Input must be a binary string.")

    # Pad the bit string to make its length a multiple of 4
    padding = (4 - len(bit_string) % 4) % 4
    bit_string = bit_string + "0" * padding

    # Encode in blocks of 4 bits
    blocks = [bit_string[i:i + 4] for i in range(0, len(bit_string), 4)]
    encoded_blocks = [hamming_encode(block) for block in blocks]

    return ''.join(encoded_blocks), padding


def decode_arbitrary_length(encoded_string, padding):
    """Decodes a Hamming (7,4) encoded string for arbitrary-length input and shows error positions."""
    if len(encoded_string) % 7 != 0:
        raise ValueError("Encoded string must be a multiple of 7 bits long.")

    # Decode in blocks of 7 bits
    blocks = [encoded_string[i:i + 7] for i in range(0, len(encoded_string), 7)]
    decoded_blocks = []
    error_positions = []

    for block_index, block in enumerate(blocks):
        corrected, decoded, error_pos = hamming_decode(block)
        decoded_blocks.append(decoded)
        if error_pos:
            # Convert error position to global index in the full encoded string
            global_error_pos = block_index * 7 + (error_pos - 1)  # 0-based index
            error_positions.append(global_error_pos)

    # Join blocks and remove padding
    decoded_string = ''.join(decoded_blocks)
    decoded_string = decoded_string[:-padding] if padding else decoded_string

    return decoded_string, error_positions


def introduce_errors(encoded_string, num_errors=None, error_positions=None):
    """
    Introduces errors into an encoded string.
    - If `error_positions` is provided, errors are introduced at those positions.
    - If `num_errors` is provided, random errors are introduced at `num_errors` positions.
    """
    encoded_list = list(encoded_string)

    if error_positions:
        # Validate user-specified error positions
        if any(pos < 0 or pos >= len(encoded_list) for pos in error_positions):
            raise ValueError("Error positions must be within the length of the string.")
        for pos in error_positions:
            encoded_list[pos] = '1' if encoded_list[pos] == '0' else '0'  # Flip the bit
        return ''.join(encoded_list), error_positions

    elif num_errors:
        if num_errors > len(encoded_list):
            raise ValueError("Too many errors for the length of the encoded string.")
        # Randomly select distinct positions for errors
        error_indices = random.sample(range(len(encoded_list)), num_errors)
        for idx in error_indices:
            encoded_list[idx] = '1' if encoded_list[idx] == '0' else '0'  # Flip the bit
        return ''.join(encoded_list), error_indices

    else:
        raise ValueError("Either `num_errors` or `error_positions` must be specified.")


"""
# === Example Test Flow ===
if __name__ == "__main__":
    # Test all 4-bit binary inputs
    for i in range(16):  # 4-bit binary strings range from 0 to 15
        original = f"{i:04b}"  # Convert number to 4-bit binary string
        encoded = hamming_encode(original)
        print(f"Original: {original}, Encoded: {encoded}")

        # Test all possible single-bit error positions in the encoded string
        for error_pos in range(len(encoded)):  # Encoded string has 7 bits
            # Introduce an error at a specific position
            erroneous = list(encoded)
            erroneous[error_pos] = '1' if erroneous[error_pos] == '0' else '0'  # Flip the bit
            erroneous = ''.join(erroneous)

            # Decode the erroneous string
            corrected, recovered, detected_error_pos = hamming_decode(erroneous)

            # Print results
            print(f"  Error Introduced at Position: {error_pos + 1}")
            print(f"    Erroneous: {erroneous}")
            print(f"    Corrected: {corrected}")
            print(f"    Recovered: {recovered}")
            print(f"    Detected Error Position: {detected_error_pos}")

            # Verify correctness
            if corrected != encoded or recovered != original or detected_error_pos != error_pos + 1:
                print("    ERROR: Decoding or correction failed!")
            else:
                print("    SUCCESS: Decoded correctly.")
"""
# Input: 1101011001
encoded, padding = encode_arbitrary_length("1101011001")
print(f"Encoded: {encoded}, Padding: {padding}")
# Introduce errors
erroneous, errors = introduce_errors(encoded, error_positions=[2, 9, 14])
print(f"Erroneous: {erroneous}, Errors: {errors}")
# Decode
decoded, error_positions = decode_arbitrary_length(erroneous, padding)
print(f"Decoded: {decoded}, Error Positions: {error_positions}")


# === GUI Functions ===

def encode_gui():
    """GUI to encode a bit string."""
    bit_string = simpledialog.askstring("Input", "Enter a binary string:")
    try:
        if not bit_string or not all(c in "01" for c in bit_string):
            raise ValueError("Input must be a binary string.")
        encoded, padding = encode_arbitrary_length(bit_string)
        messagebox.showinfo("Encoded", f"Encoded Bit String: {encoded}\nPadding: {padding}")
    except ValueError as e:
        messagebox.showerror("Error", str(e))


def introduce_errors_gui():
    """GUI to introduce errors into an encoded string."""
    encoded_string = simpledialog.askstring("Input", "Enter an encoded binary string:")
    try:
        if not encoded_string or not all(c in "01" for c in encoded_string):
            raise ValueError("Input must be a binary string.")

        def handle_manual():
            """Handle manual error input."""
            error_positions = simpledialog.askstring(
                "Manual Error Positions",
                "Enter error positions (comma-separated, 1-based):"
            )
            if not error_positions:
                raise ValueError("No error positions provided.")
            error_positions = [int(pos) - 1 for pos in error_positions.split(",") if pos.isdigit()]
            erroneous, positions = introduce_errors(encoded_string, error_positions=error_positions)
            messagebox.showinfo("Erroneous String", f"Erroneous Bit String: {erroneous}\nError Indices: {positions}")
            dialog.destroy()

        def handle_random():
            """Handle random error input."""
            num_errors = simpledialog.askinteger("Number of Errors", "Enter the number of random errors:")
            if num_errors is None or num_errors < 0:
                raise ValueError("Number of errors must be a non-negative integer.")
            erroneous, positions = introduce_errors(encoded_string, num_errors=num_errors)
            messagebox.showinfo("Erroneous String", f"Erroneous Bit String: {erroneous}\nError Indices: {positions}")
            dialog.destroy()

        # Create a pop-up dialog for choosing error injection method
        dialog = tk.Toplevel(root)
        dialog.title("Error Injection")
        dialog.geometry("300x150")

        tk.Label(dialog, text="Choose error injection method:", font=("Helvetica", 12)).pack(pady=10)

        tk.Button(dialog, text="Manual", command=handle_manual, width=20).pack(pady=5)
        tk.Button(dialog, text="Random", command=handle_random, width=20).pack(pady=5)

        dialog.mainloop()

    except ValueError as e:
        messagebox.showerror("Error", str(e))


def decode_gui():
    """GUI to decode and correct an erroneous bit string."""
    encoded_string = simpledialog.askstring("Input", "Enter an encoded binary string:")
    padding = simpledialog.askinteger("Padding", "Enter the padding used during encoding:")
    try:
        if not encoded_string or not all(c in "01" for c in encoded_string):
            raise ValueError("Input must be a binary string.")
        if padding is None or padding < 0:
            raise ValueError("Padding must be a non-negative integer.")

        # Decode the string and get error positions
        decoded, error_positions = decode_arbitrary_length(encoded_string, padding)

        # Format error positions for display
        error_positions_display = ", ".join(map(str, [pos + 1 for pos in error_positions]))  # Convert to 1-based indices
        if not error_positions_display:
            error_positions_display = "No errors detected."

        # Show decoded results and error positions
        messagebox.showinfo(
            "Decoded",
            f"Decoded Bit String: {decoded}\nError Positions: {error_positions_display}"
        )
    except ValueError as e:
        messagebox.showerror("Error", str(e))


# === GUI Setup ===
root = tk.Tk()
root.title("Bit String Encoding Tool")
root.geometry("400x300")

tk.Label(root, text="Bit String Encoding Tool", font=("Helvetica", 16)).pack(pady=20)
tk.Button(root, text="Encode Bit String", command=encode_gui, width=25).pack(pady=5)
tk.Button(root, text="Introduce Errors", command=introduce_errors_gui, width=25).pack(pady=5)
tk.Button(root, text="Decode and Correct", command=decode_gui, width=25).pack(pady=5)

root.mainloop()
