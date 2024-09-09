from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os

BASE = os.path.dirname(os.path.abspath(__file__))
inputPath = os.path.join(BASE, 'input', 'task1.txt')
encryptedPath = os.path.join(BASE, 'out', 'out1_enc')
decryptedPath = os.path.join(BASE, 'out', 'out1_dec')

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
    # print(key)
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

def decryptFile (inputFilePath, outputFilePath, password):
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
 

encryptFile(inputPath, encryptedPath, 'password')
decryptFile(encryptedPath, decryptedPath, 'password')