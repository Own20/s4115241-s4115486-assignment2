"""
Please install the cryptography library using the following command:
pip install cryptography numpy pillow opencv-python
To install all the required libraries for the program, please run the following command:
pip install -r "/path/to/requirements.txt"
Change "/path/to/requirements.txt" to the path of the requirements.txt file in the s4115241-s4115486-assignment2 folder.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
from os import urandom
from PIL import Image
import numpy as np
import cv2
import os

# Add BASE variable to make the code work on all operating systems
BASE = os.path.dirname(os.path.abspath(__file__))

# Encrypt the message using AES encryption
def encryptMessage(plaintext, key):
    # Generate a random IV (Initialization Vector) for AES
    iv = urandom(16)

    # Create an AES cipher object with the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Create an encryptor object using the cipher
    encryptor = cipher.encryptor()

    # Pad the message with PKCS7 padding to make it a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    paddedPlaintext = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded message
    ciphertext = encryptor.update(paddedPlaintext) + encryptor.finalize()

    # Return the IV and ciphertext as bytes
    return iv + ciphertext

# Decrypt the message using AES decryption
def decryptMessage(ciphertext, key):
    # Extract IV from the first 16 bytes of the ciphertext and the rest of the ciphertext is the actual ciphertext
    iv = ciphertext[:16]
    cipherText = ciphertext[16:]

    # Set up the AES cipher in CBC mode with the IV and key, and create a decryptor object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext using the decryptor
    paddedMessage = decryptor.update(cipherText) + decryptor.finalize()

    # Remove PKCS7 padding and get the unpadded plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(paddedMessage) + unpadder.finalize()

    # Decode the plaintext from bytes to string using UTF-8 encoding
    return message.decode('utf-8')

# Extract DCT coefficients from an image's color channels (B, G, R)
def extract_dct_color(image_path):
    
    # Extract Discrete Cosine Transform (DCT) coefficients from an image's color channels (B, G, R).
    # DCT (Discrete Cosine Transform) is a mathematical process that changes data (like image pixels)
    # from the regular image format (spatial domain) into frequency values (frequency domain).
    # In JPEG compression, DCT is used to break down 8x8 pixel blocks into frequency values called coefficients.
    # Most of the key visual details are found in the lower frequencies, while higher frequencies are less noticeable 
    # to the human eye. This helps JPEG compress images by removing higher frequency details that don't affect the overall quality as much.
    # We use DCT here because JPEG already uses this method for compression, and it is a good spot to hide data in 
    # the low-frequency coefficients without changing the way the image looks too much.
    
    # Read the image using OpenCV
    image = cv2.imread(image_path)

    # Split the image into its color channels (Blue, Green, Red)
    channels = cv2.split(image)
    
    # List to store the DCT values for each color channel and the shapes of each channel
    dct_coefficients = []
    shapes = []

    # Go through each color channel (B, G, R) and extract DCT coefficients for each 8x8 block of pixels
    for channel in channels:
        height, width = channel.shape
        shapes.append(channel.shape)
        dct_channel = []

        for i in range(0, height, 8):
            for j in range(0, width, 8):
                block = channel[i:i+8, j:j+8]
                dct_block = cv2.dct(np.float32(block))
                dct_channel.append(dct_block)
        dct_coefficients.append(np.array(dct_channel))

    # Return the DCT coefficients and shapes of the color channels
    return dct_coefficients, shapes

# Embed the message in the DCT coefficients
def embed_data_in_dct(dct_coefficients, message):
    # Hide a message into the DCT coefficients of an image by altering the least significant bits (LSB) 
    # of the low-frequency DCT values.

    # Since the low-frequency DCT coefficients capture most of the important visual details of the image,
    # making slight changes to their least significant bits allows data to be embedded without creating any
    # noticeable changes in the image's appearance.

    # By hiding the message in the low-frequency DCT coefficients, it's less likely to be impacted by JPEG's 
    # lossy compression. JPEG typically removes high-frequency DCT values while retaining low-frequency ones 
    # to preserve image quality. Since we are modifying the low-frequency coefficients, the hidden data stays 
    # intact even after the image undergoes JPEG compression.

    # This approach is commonly used in JPEG steganography because it ensures that the embedded message 
    # survives compression with minimal visual changes or data loss.

    # Convert the message to binary format
    binary_message = ''.join(format(ord(char), '08b') for char in message)

    # Track the index of the current bit in the message
    message_idx = 0

    # Go through each DCT block and modify the least significant bits of the low-frequency DCT values
    for block in dct_coefficients:
        for coeff_idx in range(1, min(6, len(block.flatten()))):
            coeff = np.int32(block.flat[coeff_idx])
            
            # Embed the message bits into the least significant bits of the DCT coefficients
            if message_idx < len(binary_message):
                if binary_message[message_idx] == '1':
                    coeff = coeff | 1  # set LSB to 1
                else:
                    coeff = coeff & ~1  # set LSB to 0

                # Update the DCT coefficient with the embedded bit
                block.flat[coeff_idx] = np.float32(coeff)
                message_idx += 1

            # Break if we've embedded the entire message
            if message_idx >= len(binary_message):
                break

        # Break if we've embedded the entire message
        if message_idx >= len(binary_message):
            break

    # Return the modified DCT coefficients
    return dct_coefficients

# Extract the hidden message from the DCT coefficients
def extract_data_from_dct(dct_coefficients, message_length):
    # Extract the hidden message by reading the least significant bits (LSBs) of the low-frequency DCT coefficients.

    # Since the message is embedded in the least significant bits of the low-frequency DCT values, we can extract it
    # by reading these bits and converting them back to characters.

    # By extracting the message from the low-frequency DCT coefficients, we can recover the hidden data without
    # affecting the image's visual quality. This method is effective because the low-frequency DCT values contain
    # important visual information that is less likely to be altered during compression or editing.
    
    # List to store the extracted bits and the index of the current bit in the message
    bits = []
    message_idx = 0
    
    # Go through each DCT block and extract the least significant bits of the low-frequency DCT values
    for block in dct_coefficients:
        # Extract the LSBs from the low-frequency DCT values
        for coeff_idx in range(1, min(6, len(block.flatten()))):
            coeff = np.int32(block.flat[coeff_idx])
            
            # Extract the LSB of the DCT coefficient
            if message_idx < message_length * 8:
                bits.append(coeff & 1)
                message_idx += 1

            # Break if we've extracted the entire message
            if message_idx >= message_length * 8:
                break

        # Break if we've extracted the entire message
        if message_idx >= message_length * 8:
            break

    # Convert the extracted bits to characters (8 bits to a character)
    binary_message = ''.join(str(bit) for bit in bits)
    message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))

    # Return the extracted message
    return message


# Rebuild an image from the modified DCT coefficients after embedding a message
def rebuild_image_from_dct_color(dct_coefficients, shapes, output_image_path):
    # Rebuild an image from the modified DCT coefficients after embedding a message. This function
    # applies the inverse DCT to turn the frequency data back into pixel values and saves the image.
    
    # The process involves going through the DCT coefficients of each color channel (B, G, R), applying the inverse DCT
    # to convert the frequency data back to pixel values, and merging the color channels to reconstruct the image.

    # The rebuilt image is saved to the specified output path using the Pillow library, which supports saving images
    # in various formats like JPEG, PNG, and BMP.

    # List to store the rebuilt color channels (B, G, R)
    rebuilt_channels = []

    # Go through each color channel (B, G, R) and rebuild the channel from the DCT coefficients
    for k in range(3):
        height, width = shapes[k]
        rebuilt_channel = np.zeros((height, width), dtype=np.float32)
        dct_channel = dct_coefficients[k]
        block_idx = 0

        # Rebuild the channel by applying the inverse DCT to each 8x8 block of DCT coefficients
        for i in range(0, height, 8):
            for j in range(0, width, 8):
                block = dct_channel[block_idx].astype(np.float32)
                idct_block = cv2.idct(block)
                rebuilt_channel[i:i+8, j:j+8] = idct_block
                block_idx += 1

        # Clip the pixel values to the valid range [0, 255] and convert them to unsigned 8-bit integers
        rebuilt_channels.append(np.clip(rebuilt_channel, 0, 255).astype(np.uint8))

    # Merge the rebuilt color channels (B, G, R) to form the final image
    rebuilt_image = cv2.merge(rebuilt_channels)

    # Save the rebuilt image using the Pillow library to handle image formats like JPEG
    output_image = Image.fromarray(cv2.cvtColor(rebuilt_image, cv2.COLOR_BGR2RGB))
    output_image.save(output_image_path)
    print(f"Stego image saved to {output_image_path}")


# Define the paths for the input and output images
input_image_path = os.path.join(BASE, 'input', 'task6_input_image.jpeg')
output_image_path = os.path.join(BASE, 'output', 'task6_stego_image.jpeg')

# Read the secret message from the user
original_message = input("Enter secret message (up to 1,036,800 characters): \n")

# Generate a random key for AES encryption
key = urandom(32)

# Encrypt the message using AES encryption and decode it to a string
encrypted_message = encryptMessage(original_message, key)
encrypted_message_str = b64encode(encrypted_message).decode('utf-8')

# Print the encrypted message (Base64)
print('─' * 20)
print("Encrypted Message : ")
print(encrypted_message_str)
print('─' * 20)
print("Generating Stego Image...")
print('─' * 20)

# Extract DCT coefficients from the input image
dct_coefficients, image_shapes = extract_dct_color(input_image_path)

# Embed the encrypted message in the DCT coefficients of the blue channel
modified_dct = embed_data_in_dct(dct_coefficients[0], encrypted_message_str)
dct_coefficients[0] = modified_dct

# Rebuild the image from the modified DCT coefficients
rebuild_image_from_dct_color(dct_coefficients, image_shapes, output_image_path)

# Extract the encrypted message from the modified DCT coefficients
extracted_encrypted_message_str = extract_data_from_dct(modified_dct, len(encrypted_message_str))

# Print the extracted encrypted message
print('─' * 20)
print("Extracted Encrypted Message : ")
print(extracted_encrypted_message_str)

# Decode the extracted encrypted message from Base64
extracted_encrypted_message = b64decode(extracted_encrypted_message_str)

# Decrypt the extracted encrypted message using the AES key
decrypted_message = decryptMessage(extracted_encrypted_message, key)

# Print the decrypted message
print('─' * 20)
print("Decrypted Message : ")
print(decrypted_message)
print('─' * 20)



"""
References:

SOME FUNCTIONALITY OF THIS CODE IS DERIVED FROM EXAMPLE CODE OF LECTORIAL 7 
- Functions Referenced: encrypt_message(), decrypt_message()
- File Referenced: /L7-code/hybrid_crypto.py 
- Written and Published by Shekhar Kalra on Canvas

"""