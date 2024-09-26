"""
Q2. (10 marks) For this task, look at file task2.txt;
you are given an AES key and a ciphertext (both are hex encoded),
and your goal is to recover the plaintext.
You can assume that the symmetric encryption scheme used is AES CBC mode with PKCS7 padding.
Write a program in Python (task2-aes-cbc.py) that will be able to figure out the decrypted plaintext from the provided information.
Requirements: The program must display the decrypted output to the user.
The decrypted output must be stored in a separate file.
All the file paths must use the BASE variable to make the code work on all operating systems.
"""



# Import required libraries necessary for the program
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# Add BASE variable to make the code work on all operating systems
BASE = os.path.dirname(os.path.abspath(__file__))

# The function decrypt_file is to decrypt the ciphertext using the provided key and save the output to a file
def decrypt_file(ciphertext_hex, key_hex, output_file_path):
    # Convert hexadecimal inputs to bytes
    key = bytes.fromhex(key_hex)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    # Extract IV from the first 16 bytes of the ciphertext and the rest of the ciphertext is the actual ciphertext
    iv = ciphertext_bytes[:16]
    ciphertext = ciphertext_bytes[16:]

    # Set up the AES cipher in CBC mode with the IV and key, and create a decryptor object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext using the decryptor
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding and get the unpadded plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

    # Decode the plaintext from bytes to string using UTF-8 encoding
    plaintext_decoded = plaintext.decode('utf-8')

    # Write the decoded plaintext to the output file as a string, not in binary
    with open(output_file_path, 'w') as f:
        f.write(plaintext_decoded)

# Given key and ciphertext in hexadecimal format, and the expected plaintext
key_hex = "140b41b22a29beb4061bda66b6747e14"
ciphertext_hex = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
plaintext = "Basic CBC mode encryption needs padding."

# Decrypt the file using the provided key and ciphertext, and save the output to a file named task2_dec
output_file_path = BASE + '/output/task2_dec'
decrypt_file(ciphertext_hex, key_hex, output_file_path)

# check if decryption was successful by comparing the decrypted output with the expected plaintext and print the result
with open(BASE + '/output/task2_dec', 'r') as f:
    decryptext = f.read()
    if decryptext == plaintext:
        print("Decryption successful.")
        print("Decrypted output:", decryptext)
    else:
        print("Decryption failed.")



"""
References:
Some of the code is used from previous practicals.
The code from line 32 to 40 and 46 to 47 is used from Practical on Week 5, file named "aes_cbc_file.py" from line 64 to 70, and reexplained in Practical on Week 7, file named "aes_cbc_file.py" from line 62 to 68.
It is mentioned that the AES decryption is set using CBC mode with PKCS7 padding.
So, the AES cipher is set up in CBC mode with the IV and key, and a decryptor object is created.
The ciphertext is decrypted using the decryptor and unpadding using PKCS7 padding.
The rest of the code is explained in the comments.
"""
