"""
Q4. (4 marks) You realise that symmetric encryption implemented in task 1 is not secure.
The issue is one secret key which can be hacked or lost to intruders.
Write a program in Python (task4-hybrid.py) that uses hybrid encryption to secure the file exchange (task1.txt) with your friend.
The program will use a hybrid technique-symmetric (AES) and asymmetric encryption (RSA) to make the communication more secure.
Requirements: the program must display all the keys encrypted and decrypted outputs to the user.
The RSA keys and decrypted files must be stored in separate files.
RSA must be used with padding; in other words, textbook RSA is not allowed.
"""

# Import required libraries necessary for the program
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from base64 import b64encode
from os import urandom
import os

# Add BASE variable to make the code work on all operating systems
BASE = os.path.dirname(os.path.abspath(__file__))

# The function generate_rsa_keys is to generate RSA private and public keys
def generate_rsa_keys():
    # Generate a new RSA private key with a public exponent of 65537 and a key size of 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Return the private and public keys
    return private_key, public_key

# The function encrypt_message is to encrypt the message using RSA and AES
def encrypt_message(message, public_key):
    # Generate a random symmetric key and IV for AES
    symmetric_key = urandom(32)
    iv = urandom(16)

    # Encrypt the message with AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    # Pad the message with PKCS7 padding
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded message
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

    # Return the encrypted message, IV, and encrypted key
    return encrypted_message, iv, encrypted_key

# The function decrypt_message is to decrypt the message using RSA and AES
def decrypt_message(encrypted_message, iv, encrypted_key, private_key):
    # Decrypt the symmetric key using RSA and the encrypted key is decrypted using the private key
    symmetric_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the message using AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    # Decrypt the encrypted message and remove the padding
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(padded_message) + unpadder.finalize()

    # Return the decrypted message
    return decrypted_message.decode()

# These are the paths to the files
plain_text_path = os.path.join(BASE, "input", "task1.txt")
encrypted_file_path = os.path.join(BASE, "output", "task4_enc")
decrypted_file_path = os.path.join(BASE, "output", "task4_dec")
private_key_path = os.path.join(BASE, "keys", "task4_private_key.pem")
public_key_path = os.path.join(BASE, "keys", "task4_public_key.pem")
encrypted_key_path = os.path.join(BASE, "keys", "task4_encrypted_key.pem")

# Generate RSA keys
private_key, public_key = generate_rsa_keys()

# Save the RSA keys to files in PEM format
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

# Open and display the RSA keys
with open(private_key_path, "r") as file:
    private_key_disp = file.read()
with open(public_key_path, "r") as file:
    public_key_disp = file.read()

print('─' * 20)
print("Private Key path:", private_key_path)
print("Private Key:", private_key_disp)
print('─' * 20)
print("Public Key path:", public_key_path)
print("Public Key:", public_key_disp)
print('─' * 20)

# Read the plaintext message from the file
with open(plain_text_path, "r") as file:
    message = ""
    message = file.read()

# Encrypt the message
encrypted_message, iv, encrypted_key = encrypt_message(message, public_key)

# Save the encrypted message and key to a file
with open(encrypted_file_path, "wb") as file:
    file.write(encrypted_message)
with open(encrypted_key_path, "wb") as file:
    file.write(encrypted_key)

# Display the encrypted message, IV, and encrypted key
print("Encrypted Message path:", encrypted_file_path)
print("Encrypted Message:", b64encode(encrypted_message).decode())
print('─' * 20)
print("IV (Initialization Vector):", b64encode(iv).decode())
print('─' * 20)
print("Encrypted Symmetric Key path:", encrypted_key_path)
print("Encrypted Symmetric Key:", b64encode(encrypted_key).decode())
print('─' * 20)

# Read the encrypted message from the file
with open(encrypted_file_path, "rb") as file:
    encrypted_message = file.read()

# Decrypt the message
decrypted_message = decrypt_message(encrypted_message, iv, encrypted_key, private_key)

# Save the decrypted message to a file
with open(decrypted_file_path, "wb") as file:
    file.write(decrypted_message.encode())

# Display the decrypted message path and check if the decrypted message matches the plaintext message
print("Decrypted Message path:", decrypted_file_path)
if decrypted_message == message:
    print('─' * 20)
    print("Decrypted message matches the Plaintext Message!!")
    print('─' * 20)
    print("Decrypted Message:", decrypted_message)
    print('─' * 20)
else:
    print('─' * 20)
    print("Decrypted message mismatch from the Plaintext Message")
    print('─' * 20)
    print("Plaintext Message:", message)
    print('─' * 20)
    print("Decrypted Message:", decrypted_message)
    print('─' * 20)



"""
References:
Some of the code is used from previous practicals.
The code from line 32 to 40 and 46 to 47 is used from Practical on Week 5, file named "aes_cbc_file.py" from line 64 to 70, and reexplained in Practical on Week 7, file named "aes_cbc_file.py" from line 62 to 68.
The code from line 30 to 96 is used from Lectorial on Week 7, file named "hybrid_crypto.py" from line 13 to 64, and reexplained in Practical on Week 8, file named "hybrid_crypto.py" from line 13 to 66.
The code from line 99 to 188 is adapted from Lectorial on Week 7, file named "hybrid_crypto.py" from line 67 to 82, and reexplained in Practical on Week 8, file named "hybrid_crypto_file.py" from line 77 to 121. This file is made during the practical session.
The rest of the code is explained in the comments.
"""