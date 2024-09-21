# Q4. (4 marks) You realise that symmetric encryption implemented in task 1 is not secure.
# The issue is one secret key which can be hacked or lost to intruders.
# Write a program in Python (task4-hybrid.py) that uses hybrid encryption to secure the file exchange (task1.txt) with your friend.
# The program will use a hybrid technique- symmetric (AES) and asymmetric encryption (RSA) to make the communication more secure.
# Requirements: the program must display all the keys encrypted and decrypted outputs to the user.
# The RSA keys and decrypted files must be stored in separate files.
# RSA must be used with padding; in other words, textbook RSA is not allowed.

# L7 hybrid_crypto.py
# HARUSNYA UDAH BERES

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from os import urandom
import os

BASE = os.path.dirname(os.path.abspath(__file__))

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    # Generate a random symmetric key for AES
    symmetric_key = urandom(32)  # AES-256

    # Encrypt the data with AES
    iv = urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt the symmetric key with RSA
    encrypted_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_message, iv, encrypted_key

def decrypt_message(encrypted_message, iv, encrypted_key, private_key):
    # Decrypt the symmetric key
    symmetric_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the data
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(padded_message) + unpadder.finalize()

    return decrypted_message.decode()


plain_text_path = os.path.join(BASE, "input", "task1.txt")
encrypted_file_path = os.path.join(BASE, "output", "task4_enc")
decrypted_file_path = os.path.join(BASE, "output", "task4_dec")
private_key_path = os.path.join(BASE, "keys", "task4_private_key.pem")
public_key_path = os.path.join(BASE, "keys", "task4_public_key.pem")

# Generate RSA keys
private_key, public_key = generate_rsa_keys()
with open(private_key_path, "wb") as file:
    file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open(public_key_path, "wb") as file:
    file.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
with open(private_key_path, "rb") as file:
    private_key_disp = file.read()
with open(public_key_path, "rb") as file:
    public_key_disp = file.read()

print("Private Key path:", private_key_path)
print("Private Key:", private_key_disp)
print('─' * 20)
print("Public Key path:", public_key_path)
print("Public Key:", public_key_disp)
print('─' * 20)

# with open(file_path, "rb") as file:
with open(plain_text_path, "r") as file:
    message = ""
    message = file.read()
print("Plain text path:", plain_text_path)
print("Plain text:", message)
print('─' * 20)

# Encrypt the message
encrypted_message, iv, encrypted_key = encrypt_message(message, public_key)

with open(encrypted_file_path, "wb") as file:
    file.write(encrypted_message)
print("Encrypted Message path: ", encrypted_file_path)
print("Encrypted Message:", b64encode(encrypted_message).decode())
print('─' * 20)

with open(encrypted_file_path, "rb") as file:
    encrypted_message = file.read()

# Decrypt the message
decrypted_message = decrypt_message(encrypted_message, iv, encrypted_key, private_key)

with open(decrypted_file_path, "wb") as file:
    file.write(decrypted_message.encode())
print("Decrypted Message path: ", decrypted_file_path)

if decrypted_message == message:
# if decrypted_message == message.encode():
    print('Decrypted message matches the Plaintext Message')
    print("Decrypted Message: ", decrypted_message)
else:
    print('Decrypted message mismatch from the Plaintext Message')
    print("Plaintext Message: ", message)
    print("Decrypted Message: ", decrypted_message)

# print("Original:", message)
# print("Encrypted Message:", b64encode(encrypted_message).decode())
# print("IV (Initialization Vector):", b64encode(iv).decode())
# print("Encrypted Symmetric Key:", b64encode(encrypted_key).decode())
# print("Decrypted:", decrypted_message)
