"""
Q1. (13 marks) Read the following and answer the question that follows:
You want to share a file (task1.txt) with your friend securely over untrusted internet. You want to ensure only your friend can see it in the end and no one else.
Write a program in Python (task1-aes-cbc.py) that will use symmetric encryption using AES CBC mode to generate the secret key and perform encryption and decryption of this text file.
Requirements: The program must display the key, encrypted and decrypted output to the user. The decrypted output must be stored in a separate file. All the file paths must use the BASE variable to # make the code work on all operating systems.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os

BASE = os.path.dirname(os.path.abspath(__file__))
inputPath = os.path.join(BASE, 'input', 'task1.txt')
encryptedPath = os.path.join(BASE, 'output', 'task1_enc')
decryptedPath = os.path.join(BASE, 'output', 'task1_dec')

def encryptFile(inputFilePath, outputFilePath, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(inputFilePath, 'rb') as i:
        plaintext = i.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipherText = encryptor.update(padded) + encryptor.finalize()

    with open(outputFilePath, 'wb') as j:
        j.write(salt + iv + cipherText)

    return key, (salt + iv + cipherText)

def decryptFile(inputFilePath, outputFilePath, password):
    with open(inputFilePath, 'rb') as i:
        salt = i.read(16)
        iv = i.read(16)
        ciphertext = i.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpad = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpad.update(padded) + unpad.finalize()

    with open(outputFilePath, 'wb') as j:
        j.write(plaintext)

    return plaintext

# Example usage
key, encrypted_data = encryptFile(inputPath, encryptedPath, 'password')
decrypted_data = decryptFile(encryptedPath, decryptedPath, 'password')

# Print key, encrypted and decrypted data
print("Key : ")
print(key)

print("Encrypted : ")
print(encrypted_data)

print("Decrypted : ")
print(decrypted_data)
