"""
Please install the cryptography library using the following command:
pip install cryptography
To install all the required libraries for the program, please run the following command:
pip install -r "/path/to/requirements.txt"
Change "/path/to/requirements.txt" to the path of the requirements.txt file in the s4115241-s4115486-assignment2 folder.
"""

# Import required libraries necessary for the program
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# Add BASE variable to make the code work on all operating systems
BASE = os.path.dirname(os.path.abspath(__file__))

# The function decrypt_file is to decrypt the ciphertext using the provided key and save the output to a file
def decryptFile(ciphertext_hex, key_hex, output_file_path):
    # Convert hexadecimal inputs to bytes
    key = bytes.fromhex(key_hex)
    ciphertextBytes = bytes.fromhex(ciphertext_hex)

    # Extract IV from the first 16 bytes of the ciphertext and the rest of the ciphertext is the actual ciphertext
    iv = ciphertextBytes[:16]
    ciphertext = ciphertextBytes[16:]

    # Set up the AES cipher in CBC mode with the IV and key, and create a decryptor object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext using the decryptor
    plaintextPadded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding and get the unpadded plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(plaintextPadded) + unpadder.finalize()

    # Decode the plaintext from bytes to string using UTF-8 encoding
    plaintextDecoded = plaintext.decode('utf-8')

    # Write the decoded plaintext to the output file as a string, not in binary
    with open(output_file_path, 'w') as f:
        f.write(plaintextDecoded)



# Run the decryption process for the given key and ciphertext to recover the plaintext from the file task2.txt.
# Given key and ciphertext in hexadecimal format, and the expected plaintext
keyHex = "140b41b22a29beb4061bda66b6747e14"
ciphertextHex = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
plaintext = "Basic CBC mode encryption needs padding."

# Decrypt the file using the provided key and ciphertext, and save the output to a file named task2_dec
decryptedPath = BASE + '/output/task2_dec'
decryptFile(ciphertextHex, keyHex, decryptedPath)

print('─' * 20)
print("Decrypted file path : ")
print(decryptedPath)

# check if decryption was successful by comparing the decrypted output with the expected plaintext and print the result
with open(decryptedPath, 'r') as d:
    decryptext = d.read()
    print('─' * 20)
    print("Decrypted data :", decryptext)

if decryptext == plaintext:
    print('─' * 20)
    print("Decryption successful.")
    print('─' * 20)
else:
    print('─' * 20)
    print("Decryption failed.")
    print('─' * 20)



"""
References:

Some of the code is used from previous practicals.
The code from line 32 to 40 and 46 to 47 is used from 
Practical on Week 5, file named "aes_cbc_file.py" from line 64 to 70, and reexplained in 
Practical on Week 7, file named "aes_cbc_file.py" from line 62 to 68.

It is mentioned that the AES decryption is set using CBC mode with PKCS7 padding.
So, the AES cipher is set up in CBC mode with the IV and key, and a decryptor object is created.
The ciphertext is decrypted using the decryptor and unpadding using PKCS7 padding.

The rest of the code is explained in the comments.
"""