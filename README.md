# CryptoTool Suite

A modular cryptography toolkit offering:

* **Certificate-based encryption** with RSA + AES
* **Post-quantum McEliece encryption**
* **Hamming (7,4) error correction** with interactive GUI
* Full-featured **Tkinter GUI interfaces**
* Built with **PyCryptodome**, **NumPy**, and **Tkinter**

---

## Project Structure

```
project/
│
├── crypto_tool_v4.py    # Certificate-based encryption tool (GUI)
├── crypto_tool_v5.py    # Hamming code encoder/decoder GUI
├── crypto_tool_v6.py    # GUI for hybrid encryption (AES/3DES/DES/McEliece)
├── mceliece.py          # McEliece cryptosystem (simplified, academic)
```

---

## Features

### Certificate-Based Encryption (`crypto_tool_v4.py`)

* AES-encrypted file protection with RSA certificate layer
* RSA key pair derived from license number
* Encrypted private key storage
* GUI-driven:

  * App key generation
  * User certificate creation
  * File encryption for multiple users
  * File decryption with password-protected key

### McEliece Encryption (`crypto_tool_v6.py`)

* Hybrid scheme:

  * Symmetric AES encryption for data
  * McEliece public-key encryption of AES key
* Based on binary Goppa-like codes (academic approximation)
* Key generation and file operations via GUI

### Hamming Code GUI (`crypto_tool_v5.py`)

* Encode any binary string using Hamming (7,4)
* Supports random/manual bit-flip errors
* Decodes with correction and identifies error positions
* Interactive Tkinter interface

---

## Requirements

Install dependencies:

```bash
pip install pycryptodome numpy
```

GUI tools use `tkinter`, which is bundled with most Python distributions.

---

## How to Use

### Certificate Tool (v4)

```bash
python crypto_tool_v4.py
```

**Functions:**

* **Generate App Keys** – AES-encrypted RSA keys bound to license number
* **Generate Certificate** – RSA keypair + signed certificate for user
* **Encrypt File** – Choose file and recipient certificates
* **Decrypt File** – Enter identity + decrypt using password-protected key

Generated files:

* `app_public.pem`, `app_private_enc.pem`
* `public_keys/*.json`, `private_keys/*.enc`

---

### McEliece GUI (v6)

```bash
python crypto_tool_v6.py
```

**Modes:**

* AES / 3DES / DES
* McEliece + AES hybrid encryption

**GUI Actions:**

* Select file
* Generate symmetric/McEliece keys
* Encrypt & save `.mceliece` file
* Decrypt using stored private key

Files:

* `public_key.txt`, `private_key.txt` (stored as JSON)

---

### Hamming Tool (v5)

```bash
python crypto_tool_v5.py
```

GUI provides:

* Bit string encoder
* Error injection (random/manual)
* Decoder + error position indicator

All operations are performed on strings (no file I/O).

---

## Notes

* **McEliece implementation** is educational; not safe for production use.
* AES keys are padded and truncated for correct bit-length alignment.
* For the certificate system, correct password and identity must match header info.
* Hamming GUI allows up to 1 error correction per 7-bit block.

---

## License

This project is intended for **educational** and **research** purposes only. Do not use in production without thorough security review.

---
