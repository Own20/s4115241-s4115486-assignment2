"""
Please install the cryptography library using the following command:
pip install cryptography
To install all the required libraries for the program, please run the following command:
pip install -r "/path/to/requirements.txt"
Change "/path/to/requirements.txt" to the path of the requirements.txt file in the s4115241-s4115486-assignment2 folder.
"""

# Import required libraries necessary for the program
import os
import timeit
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# Add BASE variable to make the code work on all operating systems
BASE = os.path.dirname(os.path.abspath(__file__))

# Generate RSA keys with the specified key size and return the private and public keys
def generateKeys(key_size):
    # Generate a private RSA key with the specified key size
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    # Derive the public key from the private key and return both keys
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt the file using the public key and save the output to a file
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

    # Write the encrypted data to the output file as binary
    with open(output_path, "wb") as file:
        file.write(ciphertext)

# Decrypt the file using the private key and save the output to a file
def decrypt_file(encrypted_file_path, private_key, output_path):
    # Read the encrypted data from the file
    with open(encrypted_file_path, "rb") as file:
        ciphertext = file.read()

    # Decrypt the data using OAEP padding and get the plaintext
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

# Sign the data using the private key and return the signature
def sign_data(data, private_key):
    # Sign the data using PSS padding and SHA256 hashing
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature

# Verify the signature using the public key and return True if the signature is valid
def verify_signature(data, signature, public_key):
    # Verify the signature using PSS padding and SHA256 hashing
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
    
    # Return False if the signature verification fails
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Save the private and public keys to files
def save_keys(private_key, public_key, private_key_path, public_key_path):
    # Save the private key to a file in PEM format
    with open(private_key_path, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key to a file in PEM format
    with open(public_key_path, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Load the private and public keys from files and return the keys
def load_keys(private_key_path, public_key_path):
    # Load the private key from the file
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None
        )
    
    # Load the public key from the file
    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read()
        )
    
    return private_key, public_key


# Timing the encryption and decryption process
def measure_time_encrypt_decrypt(file_path, private_key, public_key, encrypted_file, decrypted_file):
    # Time encryption process
    encryption_time = timeit.timeit(lambda: encrypt_file(file_path, public_key, encrypted_file), number=1)
    
    # Time decryption process
    decryption_time = timeit.timeit(lambda: decrypt_file(encrypted_file, private_key, decrypted_file), number=1)

    return encryption_time, decryption_time



# Define file paths for the program
original_file = os.path.join(BASE, "input", "task3.txt")
encrypted_file_1024 = os.path.join(BASE, "output", "task3_enc_1024")
decrypted_file_1024 = os.path.join(BASE, "output", "task3_dec_1024")
encrypted_file_2048 = os.path.join(BASE, "output", "task3_enc_2048")
decrypted_file_2048 = os.path.join(BASE, "output", "task3_dec_2048")
private_key_path_1024 = os.path.join(BASE, "keys", "task3_private_key_1024.pem")
public_key_path_1024 = os.path.join(BASE, "keys", "task3_public_key_1024.pem")
private_key_path_2048 = os.path.join(BASE, "keys", "task3_private_key_2048.pem")
public_key_path_2048 = os.path.join(BASE, "keys", "task3_public_key_2048.pem")

# Generate keys for 1024 bits
private_key_1024, public_key_1024 = generateKeys(1024)

# Save 1024 bits keys
save_keys(private_key_1024, public_key_1024, private_key_path_1024, public_key_path_1024)

# Measure the time taken for encryption and decryption for 1024 bits
encryption_time_1024, decryption_time_1024 = measure_time_encrypt_decrypt(
    original_file, private_key_1024, public_key_1024, encrypted_file_1024, decrypted_file_1024
)

# Generate keys for 2048 bits
private_key_2048, public_key_2048 = generateKeys(2048)

# Save 2048 bits keys
save_keys(private_key_2048, public_key_2048, private_key_path_2048, public_key_path_2048)

# Measure the time taken for encryption and decryption for 2048 bits
encryption_time_2048, decryption_time_2048 = measure_time_encrypt_decrypt(
    original_file, private_key_2048, public_key_2048, encrypted_file_2048, decrypted_file_2048
)

# Display results for both key sizes
print('─' * 20)
print("Plaintext file path:", original_file)

with open(original_file, "r") as o:
    plaintext = o.read()
    print('─' * 20)
    print("Plaintext data : ")
    print(plaintext)

print('─' * 20)
print("Encrypted file path (1024 bits):", encrypted_file_1024)

with open(encrypted_file_1024, "rb") as e10:
    encrypted_data = e10.read()
    print('─' * 20)
    print("Encrypted data (1024 bits):")
    print(encrypted_data)

print('─' * 20)
print("Decrypted file path (1024 bits):", decrypted_file_1024)

with open(decrypted_file_1024, "r") as d10:
    decrypted_data = d10.read()
    print('─' * 20)
    print("Decrypted data (1024 bits):")
    print(decrypted_data)

print('─' * 20)
print("Encrypted file path (2048 bits):", encrypted_file_2048)

with open(encrypted_file_2048, "rb") as e20:
    encrypted_data = e20.read()
    print('─' * 20)
    print("Encrypted data (2048 bits):")
    print(encrypted_data)

print('─' * 20)
print("Decrypted file path (2048 bits):", decrypted_file_2048)

with open(decrypted_file_2048, "r") as d20:
    decrypted_data = d20.read()
    print('─' * 20)
    print("Decrypted data (2048 bits):")
    print(decrypted_data)
    print('─' * 20)

print(f"Key Size: 1024 bits")
print(f"Time taken for encryption: {encryption_time_1024:.4f} seconds")
print(f"Time taken for decryption: {decryption_time_1024:.4f} seconds")
print('─' * 20)
print(f"Key Size: 2048 bits")
print(f"Time taken for encryption: {encryption_time_2048:.4f} seconds")
print(f"Time taken for decryption: {decryption_time_2048:.4f} seconds")
print('─' * 20)



"""
References:

For the signature part in this code, it is derived from 
Practical week 7 rsa_with_signature.py

For the padding code snippet, it is derived and inspired from 
week 7 I5 rsa_padding_file.py

For calculating time consumed, we use this website to grab some ideas
https://docs.python.org/3/library/timeit.html 

"""