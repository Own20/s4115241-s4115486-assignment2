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

# Extract DCT coefficients from an image's color channels (Blue, Green, Red)
def extract_dct_color(image_path):
    # Read the image using OpenCV
    image = cv2.imread(image_path)

    # Split the image into its color channels (Blue, Green, Red)
    color_channels = cv2.split(image)
    
    # List to store the DCT values for each color channel and the shapes of each channel
    dct_coefficients = []
    channel_shapes  = []

    # Go through each color channel (B, G, R) and extract DCT coefficients for each 8x8 block of pixels
    for channel in color_channels:
        height, width = channel.shape
        channel_shapes .append(channel.shape)
        dct_channel = []

        # Extract DCT coefficients for each 8x8 block of pixels in the channel
        for i in range(0, height, 8):
            for j in range(0, width, 8):
                pixel_block = channel[i:i+8, j:j+8]
                dct_block = cv2.dct(np.float32(pixel_block ))
                dct_channel.append(dct_block)
        dct_coefficients.append(np.array(dct_channel))

    # Return the DCT coefficients and shapes of the color channels
    return dct_coefficients, channel_shapes

# Embed the message in the DCT coefficients
def embed_message_in_dct(dct_coefficients, secret_message):
    # Convert the message to binary format
    binary_secret_message = ''.join(format(ord(char), '08b') for char in secret_message)

    # Track the index of the current bit in the message
    bit_index  = 0

    # Go through each DCT block and modify the least significant bits of the low-frequency DCT values
    for block in dct_coefficients:
        for coeff_index in range(1, min(6, len(block.flatten()))):
            coeff = np.int32(block.flat[coeff_index])
            
            # Embed the message bits into the least significant bits of the DCT coefficients
            if bit_index < len(binary_secret_message):
                if binary_secret_message[bit_index] == '1':
                    coeff = coeff | 1  # set LSB to 1
                else:
                    coeff = coeff & ~1  # set LSB to 0

                # Update the DCT coefficient with the embedded bit
                block.flat[coeff_index] = np.float32(coeff)
                bit_index += 1

            # Break if we've embedded the entire message
            if bit_index >= len(binary_secret_message):
                break

        # Break if we've embedded the entire message
        if bit_index >= len(binary_secret_message):
            break

    # Return the modified DCT coefficients
    return dct_coefficients

# Extract the hidden message from the DCT coefficients
def extract_hidden_message_from_dct(dct_coefficients, secret_message_length):
    # List to store the extracted bits and the index of the current bit in the message
    extracted_bits  = []
    bit_index  = 0
    
    # Go through each DCT block and extract the least significant bits of the low-frequency DCT values
    for block in dct_coefficients:
        # Extract the LSBs from the low-frequency DCT values
        for coeff_index  in range(1, min(6, len(block.flatten()))):
            coeff = np.int32(block.flat[coeff_index])
            
            # Extract the LSB of the DCT coefficient
            if bit_index < secret_message_length  * 8:
                extracted_bits.append(coeff & 1)
                bit_index  += 1

            # Break if we've extracted the entire message
            if bit_index  >= secret_message_length  * 8:
                break

        # Break if we've extracted the entire message
        if bit_index  >= secret_message_length  * 8:
            break

    # Convert the extracted bits to characters (8 bits to a character)
    binary_message = ''.join(str(bit) for bit in extracted_bits)
    hidden_message  = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))

    # Return the extracted message
    return hidden_message


# Rebuild an image from the modified DCT coefficients after embedding a message
def rebuild_image_from_dct_coefficients(dct_coefficients, channel_shapes, output_image_path):
    # List to store the rebuilt color channels (B, G, R)
    rebuilt_color_channels  = []

    # Go through each color channel (B, G, R) and rebuild the channel from the DCT coefficients
    for k in range(3):
        height, width = channel_shapes[k]
        rebuilt_channel = np.zeros((height, width), dtype=np.float32)
        dct_channel = dct_coefficients[k]
        block_index = 0

        # Rebuild the channel by applying the inverse DCT to each 8x8 block of DCT coefficients
        for i in range(0, height, 8):
            for j in range(0, width, 8):
                dct_block  = dct_channel[block_index].astype(np.float32)
                idct_block = cv2.idct(dct_block)
                rebuilt_channel[i:i+8, j:j+8] = idct_block
                block_index  += 1

        # Clip the pixel values to the valid range [0, 255] and convert them to unsigned 8-bit integers
        rebuilt_color_channels.append(np.clip(rebuilt_channel, 0, 255).astype(np.uint8))

    # Merge the rebuilt color channels (B, G, R) to form the final image
    rebuilt_image = cv2.merge(rebuilt_color_channels)

    # Save the rebuilt image using the Pillow library to handle image formats like JPEG
    output_image = Image.fromarray(cv2.cvtColor(rebuilt_image, cv2.COLOR_BGR2RGB)) # convert image from BGT to RGB to ensure image are displayed correctly
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
modified_dct = embed_message_in_dct(dct_coefficients[0], encrypted_message_str)
dct_coefficients[0] = modified_dct

# Rebuild the image from the modified DCT coefficients
rebuild_image_from_dct_coefficients(dct_coefficients, image_shapes, output_image_path)

# Extract the encrypted message from the modified DCT coefficients
extracted_encrypted_message_str = extract_hidden_message_from_dct(modified_dct, len(encrypted_message_str))

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

Hybrid crypto is utilised in this code and derived from 
Lectorial on Week 7, file named "hybrid_crypto.py" from line 13 to 64, and reexplained in Practical on Week 8, file named "hybrid_crypto.py" from line 13 to 66.

The Discrete Cosine Transform (DCT) steganography mathematical process allows for hiding a secret message within an image by manipulating the Discrete Cosine Transform (DCT) coefficients of the image. This technique uses the way JPEG images are compressed and how the human eye perceives changes in image data. The process can be done using these steps:
- Extract the DCT coefficients from the image's color channels from the spatial domain (the normal pixel values of the image) into the frequency domain (the DCT coefficients). It categorises the image data into different frequencies, with the low-frequency coefficients are ideal for data embedding since small alterations have minimal visual impact.
- Embed the secret message into the low-frequency DCT coefficients by modifying the least significant bits (LSBs) of the coefficients. This process involves changing the LSBs of the DCT values to encode the message bits without significantly altering the image's appearance. This technique ensures that the hidden message can survive JPEG compression, which tends to remove high-frequency details while retaining low-frequency components.
- Extract the hidden message from the DCT coefficients by reading the LSBs of the low-frequency DCT values. This process involves decoding the LSBs to recover the embedded message without affecting the image's quality. The effectiveness of this method relies on the ability to recover hidden data from the low-frequency components, which are less likely to change during image processing.
- Rebuild the image from the modified DCT coefficients by applying the inverse DCT to convert the frequency data back into pixel values. This step merges the color channels to reconstruct the image with the embedded message.

Splitting multi-channel image
https://www.geeksforgeeks.org/splitting-and-merging-channels-with-python-opencv/ 

Some other splitting and merging method are inspired from this
https://pyimagesearch.com/2021/01/23/splitting-and-merging-channels-with-opencv/

Getting DCT 
https://stackoverflow.com/questions/15488700/how-to-get-dct-of-an-image-in-python-using-opencv 

Convert image from one BGR to RGB 
https://www.geeksforgeeks.org/python-opencv-cv2-cvtcolor-method/ 

"""