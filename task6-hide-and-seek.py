import numpy as np
from PIL import Image
import cv2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# AES Encryption with Padding
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)  # AES with CBC mode
    iv = cipher.iv  # Initialization vector
    padded_message = pad(message.encode('utf-8'), AES.block_size)  # Pad message
    encrypted_message = cipher.encrypt(padded_message)
    return iv + encrypted_message  # IV is needed for decryption

# AES Decryption with Padding
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]  # Extract the IV
    encrypted_message = encrypted_message[AES.block_size:]  # Get the actual encrypted message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(encrypted_message)  # Decrypt
    plaintext = unpad(padded_plaintext, AES.block_size)  # Unpad the decrypted plaintext
    return plaintext.decode('utf-8')

# Convert message to binary
def message_to_binary(message):
    binary_message = ''.join(format(byte, '08b') for byte in message)
    return binary_message

# Convert binary data to message
def binary_to_message(binary_data):
    byte_chunks = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    message = bytearray([int(byte, 2) for byte in byte_chunks])
    return message

# Embed the binary message into the image using LSB
def embed_message_dct(input_image_path, binary_message, output_image_path):
    # Load image with OpenCV (cv2)
    img = cv2.imread(input_image_path, cv2.IMREAD_COLOR)
    height, width, channels = img.shape
    
    # Convert image to YCrCb (for DCT)
    img_ycc = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    y_channel, cr_channel, cb_channel = cv2.split(img_ycc)

    # Apply DCT on 8x8 blocks of the Y channel
    block_size = 8
    binary_index = 0
    for i in range(0, height, block_size):
        for j in range(0, width, block_size):
            if binary_index >= len(binary_message):
                break
            block = y_channel[i:i+block_size, j:j+block_size]
            dct_block = cv2.dct(np.float32(block))
            
            # Modify the DCT coefficients (least significant bit embedding)
            for m in range(block_size):
                for n in range(block_size):
                    if binary_index < len(binary_message):
                        coeff = dct_block[m, n]
                        coeff_binary = format(int(coeff), '016b')
                        # Replace the LSB of the coefficient with the message bit
                        new_coeff_binary = coeff_binary[:-1] + binary_message[binary_index]
                        dct_block[m, n] = int(new_coeff_binary, 2)
                        binary_index += 1
            
            # Apply inverse DCT and put the block back
            y_channel[i:i+block_size, j:j+block_size] = cv2.idct(dct_block)

    # Merge channels and save the output image
    img_ycc = cv2.merge([y_channel, cr_channel, cb_channel])
    stego_img = cv2.cvtColor(img_ycc, cv2.COLOR_YCrCb2BGR)
    cv2.imwrite(output_image_path, stego_img)

# Extract the binary message from the image
def extract_message_dct(stego_image_path, message_length):
    # Load the stego image
    stego_img = cv2.imread(stego_image_path, cv2.IMREAD_COLOR)
    height, width, channels = stego_img.shape
    
    # Convert to YCrCb
    img_ycc = cv2.cvtColor(stego_img, cv2.COLOR_BGR2YCrCb)
    y_channel, _, _ = cv2.split(img_ycc)
    
    # Extract the message bits from the DCT coefficients
    binary_message = ''
    block_size = 8
    for i in range(0, height, block_size):
        for j in range(0, width, block_size):
            if len(binary_message) >= message_length:
                break
            block = y_channel[i:i+block_size, j:j+block_size]
            dct_block = cv2.dct(np.float32(block))
            
            for m in range(block_size):
                for n in range(block_size):
                    coeff = dct_block[m, n]
                    coeff_binary = format(int(coeff), '016b')
                    binary_message += coeff_binary[-1]  # Extract the LSB
                    
                    if len(binary_message) >= message_length:
                        break

    return binary_message


# Define base path
BASE = os.path.dirname(os.path.abspath(__file__))
input_image_path = os.path.join(BASE, "input", "task6_input_image_jpeg.jpeg")
output_image_path = os.path.join(BASE, "output", "task6_stego_image.jpeg")
    
# Define message and encryption key
secret_message = "s4115241"
key = get_random_bytes(16)  # AES 128-bit key
    
# Step 1: Encrypt the message
encrypted_message = encrypt_message(key, secret_message)
print(f"Encrypted message: {encrypted_message}")
    
# Step 2: Convert the encrypted message to binary
binary_message = message_to_binary(encrypted_message)
print(f"Encrypted message (in binary): {binary_message}")
    
# Step 3: Embed the encrypted binary message into the image
embed_message_dct(input_image_path, binary_message, output_image_path)
print(f"Message embedded in {output_image_path}")
    
# Step 4: Extract the binary message from the stego image
# Extract the exact number of bits corresponding to the encrypted message
binary_message_extracted = extract_message_dct(output_image_path, len(binary_message))
encrypted_message_extracted = binary_to_message(binary_message_extracted)

# After extraction, print the encrypted message to verify
print(f"Encrypted message extracted (in binary): {binary_message_extracted}")
print(f"Encrypted message extracted (in bytes): {encrypted_message_extracted}")
    
# Step 5: Convert the extracted binary data back to encrypted message
encrypted_message_extracted = binary_to_message(binary_message_extracted)
print(f"Encrypted message extracted: {encrypted_message_extracted}")
    
# Step 6: Decrypt the extracted message
decrypted_message = decrypt_message(key, encrypted_message_extracted)
print(f"Decrypted message: {decrypted_message}")
