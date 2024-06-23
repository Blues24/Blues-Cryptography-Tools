#Dear Blues or Other maintainers remember to touch some grass
#dont waste time to something usseles but you can spend time here to make some program and learn something
#Its essentials to mark the time
#Time_wasted to build program: 1 Days

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Function to generate a Fernet key
def generate_fernet_key():
    key = Fernet.generate_key()
    with open ("Bluessecret.key", "wb") as key_file:
        key_file.write(key)

# Load Fernet key
def load_fernet_key():
    return open("Bluessecret.key", "rb").read()

# Function to encrypt a file using Fernet 
def encrypt_file_fernet(file_name, key):
    fernet = Fernet(key)
    with open(file_name, "rb") as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_name,"wb") as encrypted_file:
        encrypted_file.write(encrypted)

# Function to decrypt a file using Fernet
def decrypt_file_fernet(file_name, key):
    fernet = Fernet(key)
    with open(file_name, "rb") as encrypted_file:
        encrypted = encrypted_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(file_name, "wb") as decrypted_file:
        decrypted_file.write(decrypted)

# Function to derive a key from a password for AES
def derive_key(password):
    salt = b'\x00' * 16
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,
        backend=default_backend
    )
    key = kdf.derive(password.encode())
    return key

# Function to encrypt a fie using AES
def encrypt_file_aes(file_name, key):
    backend = default_backend()
    iv = os.urandom
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = Cipher.encryptor()

    with open(file_name, "rb") as file:
        original = file.read()

    decrypted = iv + encryptor.update(original) + encryptor.finalize()

    with open(file_name, "wb") as decrypted_file:
        decrypted_file.write(decrypted)

# Function to decrypt a file using AES
def decrypt_file_aes(file_name, key):
    backend = default_backend()
    
    with open(file_name, "rb") as encrypted_file:
        encrypted = encrypted_file.read()
    
    iv = encrypted[:16]
    encrypted_data = encrypted[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    
    with open(file_name, "wb") as decrypted_file:
        decrypted_file.write(decrypted)

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    with open("rsa_private.key", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    with open("rsa_public.key", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
# Function to load RSA keys
def load_rsa_keys():
    with open("rsa_private.key", "rb") as private_file:
        private_key = serialization.load_pem_public_key(
            private_file.read(),
            password=None,
            backend=default_backend()
        )
    with open("rsa_public.key", "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read(),
            backend=default_backend()
        )
    return private_key, public_key    
# Function to encrypt a file using RSA
def encrypt_file_rsa(file_name, public_key):
    with open(file_name, "rb") as file:
        original = file.read()

    encrypted = public_key.encrypt(
        original,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(file_name, "wb") as encrypted_file:
        encrypted_file.write(encrypted)
  
def decrypt_file_rsa(file_name, private_key):
    with open(file_name, "rb") as encrypted_file:
        encrypted = encrypted_file.read()

    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(file_name, "wb") as decrypted_file:
        decrypted_file.write(decrypted)    
# Main interactive menu
def main_menu():
    while True:
        print("Blues CryptoGraphy Tools")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Generate a key")
        print("4. Generate RSA keys")
        print("5. Exit")
        choice = input("Enter your Input: ")

        if choice == '1':
            file_path = input("Enter the path to the file you want to encrypt: ")
            if not os.path.exists(file_path):
                print("File not found.Please try again.")
                continue

            print("Choose encryption alghorithm:")
            print("1. Fernet")
            print("2. AES")
            print("3. RSA")
            algo_choice = input("Enter your alghorithm: ")

            if algo_choice == '1':
                if not os.path.exists("fernet.key"):
                    print("Fernet key not found. Generate a key first")
                    continue
                key = load_fernet_key()
                encrypt_file_fernet(file_path, key)
                print(f"File '{file_path}' has been encrypted using Fernet.")
            elif algo_choice == '2':
                password =getpass("Enter a password for AES encryption: ")
                key = derive_key(password)
                encrypt_file_aes(file_path, key)
                print(f"File '{file_path}' has been encrypted using AES.")

            elif algo_choice == '3':
                if not os.path.exists("rsa_public.key"):
                    print("RSA public key not found. Generate it first using option no 4.")
                    continue
            _, public_key = load_rsa_keys()
            encrypt_file_rsa(file_path, public_key)
            print(f"File '{file_path}' has been encrypted using RSA.")

        elif choice == '2':
            file_path = input("Enter the path to the file you want to decrypt: ")
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue
            
            print("Choose decryption algorithm:")
            print("1. Fernet")
            print("2. AES")
            print("3. RSA")
            algo_choice = input("Enter your choice: ")
            
            if algo_choice == '1':
                if not os.path.exists("fernet.key"):
                    print("Fernet key not found. Generate a key first using option 3.")
                    continue
                key = load_fernet_key()
                decrypt_file_fernet(file_path, key)
                print(f"File '{file_path}' decrypted successfully using Fernet.")
            
            elif algo_choice == '2':
                password = getpass("Enter the password for AES decryption: ")
                key = derive_key(password)
                decrypt_file_rsa(file_path, key)
                print(f"File '{file_path}' decrypted successfully using AES.")
            
            elif algo_choice == '3':
                if not os.path.exists("rsa_private.key"):
                    print("RSA private key not found. Generate RSA keys first using option 4.")
                    continue
                private_key, _ = load_rsa_keys()
                decrypt_file_rsa(file_path, private_key)
                print(f"File '{file_path}' decrypted successfully using RSA.")
            
            else:
                print("Invalid choice. Please try again.")
        
        elif choice == '3':
            generate_fernet_key()
            print("Fernet key generated and saved as 'fernet.key'.")
        
        elif choice == '4':
            generate_rsa_keys()
            print("RSA keys generated and saved as 'rsa_private.key' and 'rsa_public.key'.")
        
        elif choice == '5':
            print("Exiting the program. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()