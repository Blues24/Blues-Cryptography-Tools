# Blues-Cryptography-tools

# File Encryption/Decryption Tool

This is a Python-based tool for encrypting and decrypting files using various algorithms, including Fernet, AES, and RSA. It also supports key generation for these algorithms.

## Features

- **Encrypt and Decrypt Files**: Encrypt or decrypt any file using Fernet, AES, or RSA algorithms.
- **Key Generation**: Generate keys for Fernet and RSA encryption/decryption.
- **Password-Based Key Derivation**: Use a password to derive a key for AES encryption/decryption.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Blues24/Blues-Cryptography-tools.git
    cd Blues-Cryptography-tools

    ```
    Feel free to rename the directories

2. Install the required Python packages:
    ```sh
    pip install cryptography
    ```

## Usage
```sh
python bluescryptV2.py
```
Menu Options

    Encrypt a file:
        Select this option to encrypt a file.
        Choose the encryption algorithm (Fernet, AES, or RSA).
        Provide the path to the file you want to encrypt.

    Decrypt a file:
        Select this option to decrypt a file.
        Choose the decryption algorithm (Fernet, AES, or RSA).
        Provide the path to the file you want to decrypt.

    Generate a Fernet key:
        Select this option to generate a Fernet key.
        The key will be saved as fernet.key.

    Generate RSA keys:
        Select this option to generate RSA keys.
        The private key will be saved as rsa_private.key.
        The public key will be saved as rsa_public.key.

    Exit:
        Exit the program.

Detailed Explanation
1. Key Generation
Fernet Key

    The generate_fernet_key() function generates a Fernet key and saves it as fernet.key.
    The load_fernet_key() function loads the Fernet key from the fernet.key file.

RSA Keys

    The generate_rsa_keys() function generates a pair of RSA keys (private and public) and saves them as rsa_private.key and rsa_public.key.
    The load_rsa_keys() function loads the RSA private and public keys from the respective files.

2. Encryption
Fernet Encryption

    The encrypt_file_fernet(file_name, key) function encrypts the file using the Fernet key.
    The decrypt_file_fernet(file_name, key) function decrypts the file using the Fernet key.

AES Encryption

    The derive_key(password) function derives a key from the provided password using PBKDF2 with SHA256.
    The encrypt_file_aes(file_name, key) function encrypts the file using the derived AES key.
    The decrypt_file_aes(file_name, key) function decrypts the file using the derived AES key.

RSA Encryption

    The encrypt_file_rsa(file_name, public_key) function encrypts the file using the RSA public key.
    The decrypt_file_rsa(file_name, private_key) function decrypts the file using the RSA private key.

Notes

    Fernet: Suitable for symmetric encryption (same key for encryption and decryption). Ensure the key is kept secure.
    AES: Also a symmetric encryption method but uses a password to derive the encryption key.
    RSA: Asymmetric encryption (public key for encryption and private key for decryption). Suitable for secure key exchange and digital signatures.

Example

``` sh

# Encrypt a file using Fernet
python file_encryption_tool.py
# Choose option 1, then 1 (Fernet), and provide the file path.

# Decrypt a file using Fernet
python file_encryption_tool.py
# Choose option 2, then 1 (Fernet), and provide the file path.
```
Contributing

Feel free to fork this repository and submit pull requests. For major changes, please open an issue first to discuss what you would like to change.
