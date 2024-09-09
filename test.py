import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

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

    with open(inputFilePath, 'rb') as f:
        plaintext = f.read()

    # Pad the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(outputFilePath, 'wb') as f:
        # Write salt + iv + ciphertext
        f.write(salt + iv + ciphertext)

def decryptFile(inputFilePath, outputFilePath, password):
    with open(inputFilePath, 'rb') as f:
        # Read salt (16 bytes) + iv (16 bytes) + ciphertext
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

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

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(outputFilePath, 'wb') as f:
        f.write(plaintext)

# Update your file paths
BASE = os.path.dirname(os.path.abspath(__file__))
inputPath = os.path.join(BASE, 'input', 'task1.txt')
encryptedPath = os.path.join(BASE, 'out', 'out1_encrypted.txt')
decryptedPath = os.path.join(BASE, 'out', 'out1_decrypted.txt')

# Encrypt the file
encryptFile(inputPath, encryptedPath, 'password')

# Decrypt the file
decryptFile(encryptedPath, decryptedPath, 'password')
