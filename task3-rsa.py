# P7 rsa_with_signature.py
# week 6

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# a fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# Generate RSA keys
def generate_keys():
    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Derive the public key from the private key
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt the file
def encrypt_file(file_path, public_key, output_path):
    # Read the plaintext data from tahe file
    with open(file_path, "rb") as file:
        plaintext = file.read()

    # Encrypt the data using OAEP padding
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'), # added encode to convert bytes to string
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

    return plaintext.decode('utf-8') # added decode to convert bytes to string
    # Write the decrypted data to the output file
    with open(output_path, "wb") as file:
        file.write(plaintext)

# Sign the data
def sign_data(data, private_key):
    signature = private_key.sign(
        data.encode('utf-8'), # added encode to convert bytes to string
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
            data.encode('utf-8'), # added encode to convert bytes to string
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

# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_keys()

    # Print private and public keys
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print("Private Key:\n", private_key_pem.decode('utf-8'))
    print("Public Key:\n", public_key_pem.decode('utf-8'))

    # File paths
    original_file = os.path.join(BASE, "in", "sensitive.txt")
    encrypted_file = os.path.join(BASE, "out", "sensitive_enc")
    decrypted_file = os.path.join(BASE, "out", "sensitive_dec")

    # Encrypt the file
    encrypt_file(original_file, public_key, encrypted_file)

    # Decrypt the file
    decrypt_file(encrypted_file, private_key, decrypted_file)

    # Sign the original data
    with open(original_file, "rb") as file:
        original_data = file.read()
    signature = sign_data(original_data, private_key)

    print('─' * 10) 

    # Print the signature
    print("Signature:\n", signature.hex())

    print('─' * 10) 
    

    # Verify the signature
    is_valid = verify_signature(original_data, signature, public_key)
    print(f"Signature valid: {is_valid}")







import timeit
start = timeit.timeit()
end = timeit.timeit()



# P7 rsa_padding_file.py
# week 6

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# a fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# Create keys
def generate_keys():
    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Derive the public key from the private key
    public_key = private_key.public_key()
    return private_key, public_key

# encrypt plaintext file
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

    # Write the encrypted data to the specified output file
    with open(output_path, "wb") as file:
        file.write(ciphertext)

# decrypt ciphertext file
def decrypt_file(encrypted_file_path, private_key, output_path):
    # Read the encrypted data
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

    # Write the decrypted data back to the specified output file
    with open(output_path, "wb") as file:
        file.write(plaintext)

def main():
    # Generate RSA keys
    private_key, public_key = generate_keys()

    # Define file paths using BASE for relative paths
    file_path = os.path.join(BASE, "in", "sensitive.txt")
    encrypted_file_path = os.path.join(BASE, "out", "sensitive_enc")
    decrypted_file_path = os.path.join(BASE,  "out", "sensitive_dec")

    # Encrypt and decrypt the file
    encrypt_file(file_path, public_key, encrypted_file_path)
    decrypt_file(encrypted_file_path, private_key, decrypted_file_path)
    print("CHECK INSIDE out FOLDER")

if __name__ == "__main__":
    main()


'''

RATIONALE:

Textbook RSA

- takes a plaintext message m, a public key (e,n) 
- (that's usually not kept secret) and 
- creates a ciphertext c = m^e mod n and 
- can be decrypted with the secret key (d) via m = c^d mod n 

This may leak information. 

For example, if you were using textbook RSA to send a simple 
message that's one of a few options  (e.g., it's a yes/no message 
or an order to buy X shares of a stock), an attacker could just encrypt
all the likely messages with public key and see which 
one exactly matches the true ciphertext.


'''
