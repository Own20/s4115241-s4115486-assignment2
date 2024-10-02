"""
Q3. (9 marks) Write a program in Python (task3-rsa.py) that does the following:
i. Generates keys (1024-bit). Keys must be stored in separate files.
ii. Encrypt the provided plaintext file (task3.txt) using RSA with padding
iii. Add support for RSA digital signatures: implement a function to sign messages with the private key and verify signatures with the public key.
iv. Decrypt the ciphertext to arrive at the original plaintext. Save the decrypted output to a separate file.
v. Extend the program to add support for a bigger key size (2048-bit) and measure how the encryption and decryption time scales as compared to a 1024-bit key.
All the file paths must use the BASE variable to make the code work on all operating systems.
"""

# P7 rsa_with_signature.py
# week 6
# P7 rsa_padding_file.py
# week 6

import os
import timeit
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# A fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# File paths
original_file = os.path.join(BASE, "input", "task3.txt")
encrypted_file_1024 = os.path.join(BASE, "output", "task3_enc_1024")
decrypted_file_1024 = os.path.join(BASE, "output", "task3_dec_1024")
encrypted_file_2048 = os.path.join(BASE, "output", "task3_enc_2048")
decrypted_file_2048 = os.path.join(BASE, "output", "task3_dec_2048")

# Define file paths for keys
private_key_path_1024 = os.path.join(BASE, "keys", "task3_private_key_1024.pem")
public_key_path_1024 = os.path.join(BASE, "keys", "task3_public_key_1024.pem")

private_key_path_2048 = os.path.join(BASE, "keys", "task3_private_key_2048.pem")
public_key_path_2048 = os.path.join(BASE, "keys", "task3_public_key_2048.pem")

# Generate RSA keys
def generate_keys(key_size):
    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    # Derive the public key from the private key
    public_key = private_key.public_key()
    return private_key, public_key

# Save the private and public keys to files
def save_keys(private_key, public_key, private_key_path, public_key_path):
    # Save the private key
    # print ("save keys ", private_key, public_key)
    with open(private_key_path, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key
    with open(public_key_path, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Load the private and public keys from files
def load_keys(private_key_path, public_key_path):
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None
        )
    
    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read()
        )
    
    return private_key, public_key

# Encrypt the file
def encrypt_file(file_path, public_key, output_path):
    # Read the plaintext data from the file
    with open(file_path, "rb") as file:
        plaintext = file.read()

    # Encrypt the data using OAEP padding
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted data to the output file
    with open(output_path, "wb") as file:
        file.write(ciphertext)

# Decrypt the file
def decrypt_file(encrypted_file_path, private_key, output_path):
    # Read the encrypted data from the file
    with open(encrypted_file_path, "rb") as file:
        ciphertext = file.read()

    # Decrypt the data using OAEP padding
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the decrypted data to the output file
    with open(output_path, "wb") as file:
        file.write(plaintext)

# Sign the data
def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify the signature
def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Timing the encryption and decryption
def measure_time_encrypt_decrypt(file_path, private_key, public_key, encrypted_file, decrypted_file):
    # Time encryption
    encryption_time = timeit.timeit(lambda: encrypt_file(file_path, public_key, encrypted_file), number=1)
    
    # Time decryption
    decryption_time = timeit.timeit(lambda: decrypt_file(encrypted_file, private_key, decrypted_file), number=1)

    return encryption_time, decryption_time

# Generate keys for 1024 bits
private_key_1024, public_key_1024 = generate_keys(1024)

# Save 1024 bits keys
save_keys(private_key_1024, public_key_1024, private_key_path_1024, public_key_path_1024)

# Measure the time taken for encryption and decryption for 1024 bits
encryption_time_1024, decryption_time_1024 = measure_time_encrypt_decrypt(
    original_file, private_key_1024, public_key_1024, encrypted_file_1024, decrypted_file_1024
)

# Generate keys for 2048 bits
private_key_2048, public_key_2048 = generate_keys(2048)

# Save 2048 bits keys
save_keys(private_key_2048, public_key_2048, private_key_path_2048, public_key_path_2048)

# Measure the time taken for encryption and decryption for 2048 bits
encryption_time_2048, decryption_time_2048 = measure_time_encrypt_decrypt(
    original_file, private_key_2048, public_key_2048, encrypted_file_2048, decrypted_file_2048
)

# Display results for both key sizes
print('─' * 20)
print(f"Key Size: 1024 bits")
print(f"Time taken for encryption: {encryption_time_1024:.4f} seconds")
print(f"Time taken for decryption: {decryption_time_1024:.4f} seconds")
print('─' * 20)
print(f"Key Size: 2048 bits")
print(f"Time taken for encryption: {encryption_time_2048:.4f} seconds")
print(f"Time taken for decryption: {decryption_time_2048:.4f} seconds")
print('─' * 20)
