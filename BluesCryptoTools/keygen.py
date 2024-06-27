from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os


def generate_RSA_key() -> None:
    """Generate RSA key pair."""
    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key: rsa.RSAPublicKey = private_key.public_key()

    private_key_pem: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem: bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as file:
        file.write(private_key_pem)
    with open("public_key.pem", "wb") as file:
        file.write(public_key_pem)
    print("RSA key pair generated successfully.")

def generate_AES_key():
    key = os.urandom(32)
    with open("key.pem", "wb") as file:
        file.write(key)
    print("AES key generated successfully.")

def main():
    print("Welcome to Key Generator Program")
    print("1. RSA Key Generator")
    print("2. AES Key Generator")
    choice = input("Enter your choice (1-2): ")
    if choice == '1':
        generate_RSA_key()
    elif choice == '2':
        generate_AES_key()
    else:
        print("Invalid input")

if __name__ == "__main__":
    main()
