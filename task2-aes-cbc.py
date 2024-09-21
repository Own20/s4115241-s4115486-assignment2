# Q2. (10 marks) For this task, look at file task2.txt;
# you are given an AES key and a ciphertext (both are hex encoded),
# and your goal is to recover the plaintext.
# You can assume that the symmetric encryption scheme used is AES CBC mode with PKCS7 padding.
# Write a program in Python (task2-aes-cbc.py) that will be able to figure out the decrypted plaintext from the provided information.
# Requirements: The program must display the decrypted output to the user.
# The decrypted output must be stored in a separate file.
# All the file paths must use the BASE variable to make the code work on all operating systems.

# CBC key: 140b41b22a29beb4061bda66b6747e14

# CBC Ciphertext:
# 4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81






# P7 aes_cbc_file.py
# week 5

# make sure you have installed cryptography library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os
import os.path
import base64

#for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# function to decypt the encrypted file
# just the reverse steps
def decrypt_file(input_file_path, output_file_path, key_file_path):
    # Reading encrypted file
    with open(input_file_path, 'r') as f:
        # salt_hex = f.read(16)  # First 16 bytes for the salt
        # iv_hex = f.read(16)    # Next 16 bytes for the IV
        ciphertext_hex = f.read()  # The remaining is the ciphertext
    # print("Salt:", salt_hex)
    # print("IV:", iv_hex)
    print("Ciphertext hex:", ciphertext_hex)
    print("Ciphertext size hex:", len(ciphertext_hex))

    ciphertext = bytes.fromhex(ciphertext_hex)
    print("Ciphertext (bytes):", ciphertext)
    print("Ciphertext size (bytes):", len(ciphertext))

    salt_hex = ciphertext_hex[:32]
    salt = bytes.fromhex(salt_hex)
    print("Salt hex (bytes):", salt)
    print("Salt size hex (bytes):", len(salt))

    iv_hex = ciphertext_hex[32:64]
    iv = bytes.fromhex(iv_hex)
    print("IV hex (bytes):", iv)
    print("IV hex size (bytes):", len(iv))

    # Create key derivation function with the same parameters
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Using AES-128 (128 bits = 16 bytes)
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    print("Key derivation function:", kdf)
    
    # Read the key from the key file (assuming it's raw hex string)
    with open(key_file_path, 'r') as f:
        cbc_key_hex = f.read().strip()
    print("CBC key (hex):", cbc_key_hex)
    print("CBC key size (bytes):", len(cbc_key_hex))

    # Convert the hex key to bytes
    cbc_key = bytes.fromhex(cbc_key_hex)
    print("CBC key (bytes):", cbc_key)
    print("CBC key size (bytes):", len(cbc_key))

    # Derive the actual encryption key using PBKDF2
    key = kdf.derive(cbc_key)
    print("Derived key:", key)
    print("Derived key size (bytes):", len(key))

    # Set up the AES cipher in CBC mode with the IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    print("Cipher:", cipher)

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    print("Decryptor:", decryptor)

    decodedciphertext = base64.b64decode(ciphertext)
    print("Decoded ciphertext:", decodedciphertext)

    padded_plaintext = decryptor.update(decodedciphertext) + decryptor.finalize()
    print("Padded plaintext:", padded_plaintext)

    # Unpad the plaintext (AES uses PKCS7 padding)
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    print("Unpadder:", unpadder)

    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    print("Plaintext:", plaintext)

    # Write the decrypted (unpadded) plaintext to the output file
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)

# decrypt the file
decrypt_file(BASE + '/output/task2_enc', BASE  + '/output/task2_dec', BASE  + '/keys/task2_key.pem')

with open(BASE + '/output/task2_enc', 'rb') as f:
    print(f.read())
with open(BASE + '/output/task2_dec', 'rb') as f:
    print(f.read())
with open(BASE + '/keys/task2.key', 'rb') as f:
    print(f.read())





# with open(input_file_path, 'rb') as f:
#         salt = f.read(16)
#         iv = f.read(16)
#         ciphertext = f.read()
    
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=16,
#         # length=32,
#         salt=salt,
#         iterations=100000,
#     )
    
#     with open(key_file_path, 'r') as f:
#         cbc_key = f.read().strip()
    
#     key = kdf.derive(cbc_key.encode())
    
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    
#     decryptor = cipher.decryptor()
    
#     padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
#     unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

#     # plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
#     plaintext = unpadder.update(padded_plaintext)
    
#     with open(output_file_path, 'wb') as f:
#         f.write(plaintext)