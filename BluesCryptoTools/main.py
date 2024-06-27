#Dear Maintainers
#Always think positive and touch some grass
#Days wasted on this program:1 Days
#Time wasted on this program:00 H  
#this program use pyfiglet to generate banner to use it uncomment it
#from pyfiglet import Figlet
# this program use cryptography to generate hash and verify it
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
# this program use os to generate signature and verify it
import os
import sys

# main menu
def main_menu():
    print(
        """
        ==========================================
        ========= Blues Crypt V3 =================
        ==========================================
        ======== Made with 💙 by Blues24 =========
        """
    )
    print("1. Sign File")
    print("2. Verify File")
    print("3. Encrypt File Using AES.")
    print("4. Decrypt File Using AES.")
    print("5. Encrypt File Using RSA.")
    print("6. Decrypt File Using RSA.")
    print("7. Exit")
    choice = input("Enter your choice (1-7): ")
    if choice == '1':
        sign_file()
    elif choice == '2':
        verify_file()
    elif choice == '3':
        encrypt_file()
    elif choice == '4':
        decrypt_file()
    elif choice == '5':
        encrypt_RSA()
    elif choice == '6':
        decrypt_RSA()
    elif choice == '7':
        sys.exit()
    else:
        print("Invalid input")
        main_menu()

# generate signature
def sign_file():
    file_path = input("Enter the path of the file: ")
    with open(file_path, "rb") as file:
        data = file.read()
    private_key = serialization.load_pem_private_key(
        open("private_key.pem", "rb").read(),
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    with open("signature.txt", "wb") as file:
        file.write(signature)
    print("Signature generated successfully.")

# verify signature
def verify_file():
    file_path = input("Enter the path of the file: ")
    with open(file_path, "rb") as file:
        data = file.read()
    public_key = serialization.load_pem_public_key(
        open("public_key.pem", "rb").read(),
        backend=default_backend()
    )
    with open("signature.txt", "rb") as file:
        signature = file.read()
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature verified successfully.")
    except Exception as e:
        print("Signature verification failed.")
        print(e)

# encrypt file using AES
def encrypt_file():
    file_path = input("Enter the path of the file: ")
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(file_path, "rb") as file:
        data = file.read()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    with open("encrypted_file.enc", "wb") as file:
        file.write(iv + ciphertext)
    with open("key.txt", "wb") as file:
        file.write(key)
    print("File encrypted successfully.")

# decrypt file using AES
def decrypt_file():
    file_path = input("Enter the path of the file: ")
    with open("key.txt", "rb") as file:
        key = file.read()
    with open(file_path, "rb") as file:
        iv = file.read(16)
        ciphertext = file.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    with open("decrypted_file.txt", "wb") as file:
        file.write(plaintext)
    print("File decrypted successfully.")

def encrypt_RSA(public_key_path, message):
    with open(public_key_path, 'rb') as file:
        public_key = serialization.load_der_public_key(
            file.read(),
            backend=default_backend()
        )
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_RSA(private_key_path, ciphertext):
    with open(private_key_path, 'rb') as file:
        private_key = serialization.load_der_private_key(
            file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# run main menu
main_menu()
