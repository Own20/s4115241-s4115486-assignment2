"""
Please install the cryptography library using the following command:
pip install cryptography
To install all the required libraries for the program, please run the following command:
pip install -r "/path/to/requirements.txt"
Change "/path/to/requirements.txt" to the path of the requirements.txt file in the s4115241-s4115486-assignment2 folder.
"""

# Import required libraries necessary for the program
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import os

# Add BASE variable to make the code work on all operating systems
BASE = os.path.dirname(os.path.abspath(__file__))

# The function encryptFile is to encrypt the file using AES CBC mode and save the output to a file named task1_enc
def encryptFile(inputFilePath, outputFilePath, password):
    # Generate a random salt and derive a key using PBKDF2 with SHA256
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(password.encode())

    # Generate a random IV and set up the AES cipher in CBC mode with the IV and key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Read the plaintext from the input file
    with open(inputFilePath, 'rb') as i:
        plaintext = i.read()

    # Pad the plaintext with PKCS7 padding and encrypt it
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipherText = encryptor.update(padded) + encryptor.finalize()

    # Write the salt, IV, and ciphertext to the output file as binary
    with open(outputFilePath, 'wb') as j:
        j.write(salt + iv + cipherText)

    return key, (salt + iv + cipherText)

# The function decryptFile is to decrypt the file using the provided key and save the output to a file named task1_dec
def decryptFile(inputFilePath, outputFilePath, password):
    # Read the salt, IV, and ciphertext from the input file
    with open(inputFilePath, 'rb') as i:
        salt = i.read(16)
        iv = i.read(16)
        ciphertext = i.read()

    # Derive the key using PBKDF2 with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )

    # Decrypt the ciphertext using the key and IV
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext and remove PKCS7 padding
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpad = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpad.update(padded) + unpad.finalize()

    plaintextDecoded = plaintext.decode('utf-8')

    # Write the plaintext to the output file as binary
    with open(outputFilePath, 'w') as j:
        j.write(plaintextDecoded)

    return plaintextDecoded



# Run the program using the input file task1.txt and password 'password' to encrypt and decrypt the file and display the key, encrypted and decrypted output to the user.
# Define the paths for the input, encrypted, and decrypted files
inputPath = os.path.join(BASE, 'input', 'task1.txt')
encryptedPath = os.path.join(BASE, 'output', 'task1_enc')
decryptedPath = os.path.join(BASE, 'output', 'task1_dec')

# Encrypt and decrypt the file
key, encryptedData = encryptFile(inputPath, encryptedPath, 'password')
decryptedData = decryptFile(encryptedPath, decryptedPath, 'password')

# Print key, encrypted and decrypted data
print('─' * 20)
print("Input file path : ")
print(inputPath)

with open(inputPath, 'r') as r:
    input = r.read()
    print('─' * 20)
    print("Input data : ")
    print(input)

print('─' * 20)
print("Key : ")
print(key)

print('─' * 20)
print("Encrypted file path : ")
print(encryptedPath)

print('─' * 20)
print("Encrypted data: ")
print(encryptedData)

print('─' * 20)
print("Decrypted file path : ")
print(decryptedPath)

print('─' * 20)
print("Decrypted data: ")
print(decryptedData)

print('─' * 20)



"""
References:

Most of the code are used from 
Lectorial on Week 5, file named "aes_cbc_file.py", reexplained in 
Practical on Week 5, file named "aes_cbc_file.py", discussed in 
Lectorial on Week 7, file named "Example4_aes_cbc_string.py", and discussed in 
Practical on Week 7, file named "aes_cbc_file.py".

Throughout the code, we have understood the concepts of AES encryption and decryption using CBC mode with PKCS7 padding. This can be seen in the comments of the code.
So, the encryption starts with generating a random salt and deriving a key using PBKDF2 with SHA256. Then, a random IV is generated and the AES cipher is set up in CBC mode with the IV and key. The plaintext is read, encrypted with the key, and padded with PKCS7 padding. Finally, the salt, IV, and ciphertext are written to the output encrypted file as binary.
The decryption starts with reading the salt, IV, and ciphertext from the input encrypted file. Then, the key is derived using PBKDF2 with SHA256. The ciphertext is decrypted using the key and IV, and the PKCS7 padding is removed. Finally, the plaintext is written to the output decrypted file as binary.
"""