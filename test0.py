import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np

# Define base path
BASE = os.path.dirname(os.path.abspath(__file__)) # Update this with the actual base directory

# AES Encryption/Decryption Functions
def generate_aes_key():
    return get_random_bytes(16)  # AES-128 key

def encrypt_message_aes(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return nonce, ciphertext

def decrypt_message_aes(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

# Convert text to binary
def text_to_binary(data):
    binary_data = ''.join(format(byte, '08b') for byte in data)
    return binary_data

# Convert binary to text
def binary_to_text(binary_data):
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_data = ''.join([chr(int(byte, 2)) for byte in all_bytes])
    return decoded_data

# # Embedding binary data into image using LSB
# def embed_message_lsb(image_path, binary_message, output_image_path):
#     img = Image.open(image_path)
#     pixels = np.array(img)

#     flat_pixels = pixels.flatten()
    
#     binary_index = 0
#     message_length = len(binary_message)

#     for i in range(len(flat_pixels)):
#         if binary_index < message_length:
#             flat_pixels[i] = (flat_pixels[i] & ~1) | int(binary_message[binary_index])
#             binary_index += 1
    
#     img_with_message = flat_pixels.reshape(pixels.shape)
#     img_with_message = Image.fromarray(img_with_message.astype(np.uint8))
#     img_with_message.save(output_image_path)

# Embedding binary data into image using LSB
def embed_message_lsb(image_path, binary_message, output_image_path):
    img = Image.open(image_path)
    pixels = np.array(img)

    flat_pixels = pixels.flatten()

    binary_index = 0
    message_length = len(binary_message)
    
    # To track changes, create a list to hold pixel changes
    pixel_changes = []
    
    for i in range(len(flat_pixels)):
        if binary_index < message_length:
            # Before changing the pixel
            original_pixel = flat_pixels[i]
            
            # Change LSB of the pixel
            flat_pixels[i] = (flat_pixels[i] & ~1) | int(binary_message[binary_index])
            binary_index += 1
            
            # If the pixel was changed, record the change
            if original_pixel != flat_pixels[i]:
                pixel_changes.append((i, original_pixel, flat_pixels[i]))

    # Print pixel changes
    print("Pixel changes (Index, Original, Modified):")
    for change in pixel_changes:  # Limiting to first 10 changes for brevity
        print(f"Index {change[0]}: {change[1]} -> {change[2]}")

    img_with_message = flat_pixels.reshape(pixels.shape)
    img_with_message = Image.fromarray(img_with_message.astype(np.uint8))
    img_with_message.save(output_image_path)

# # Extracting binary data from image
# def extract_message_lsb(image_path, message_length):
#     img = Image.open(image_path)
#     pixels = np.array(img)
    
#     flat_pixels = pixels.flatten()
#     binary_message = ''
    
#     for i in range(message_length * 8):  # Each character is 8 bits
#         binary_message += str(flat_pixels[i] & 1)
    
#     return binary_message

# Extracting binary data from image
def extract_message_lsb(image_path, message_length):
    img = Image.open(image_path)
    pixels = np.array(img)
    flat_pixels = pixels.flatten()

    binary_message = ''
    bit_changes = []

    # Each character is 8 bits, so we iterate over the necessary number of bits
    for i in range(message_length * 8):
        # Extract the LSB from the current pixel
        lsb = flat_pixels[i] & 1
        binary_message += str(lsb)

        # Track bit changes for display
        bit_changes.append((i, flat_pixels[i], lsb))

    # Print the changes for each bit (index, pixel value, extracted bit)
    print("Bit changes (Index, Pixel Value, Extracted Bit):")
    for change in bit_changes:
        print(f"Pixel {change[0]}: {change[1]} -> Extracted Bit: {change[2]}")

    return binary_message


def main():
    # Paths
    encrypted_file_path = os.path.join(BASE, "output", "task7_enc")
    decrypted_file_path = os.path.join(BASE, "output", "task7_dec")
    aes_key_path = os.path.join(BASE, "keys", "task7_aes_key.pem")
    image_path = os.path.join(BASE, "input", "task6_input_image.png")
    output_image_path = os.path.join(BASE, "output", "task7_stego_image.png")
    
    # Message
    secret_message = "Hello, World!"  # Professional, simple text
    print(f"Original Message: {secret_message}")

    # Generate AES key
    aes_key = generate_aes_key()
    print(f"AES Key: {base64.b64encode(aes_key).decode()}")
    with open(aes_key_path, "w") as f:
        f.write(base64.b64encode(aes_key).decode())

    # Encrypt the message
    nonce, encrypted_message = encrypt_message_aes(aes_key, secret_message)
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_message)
    print(f"Encrypted Message: {base64.b64encode(encrypted_message).decode()}")

    # Convert encrypted message to binary
    binary_message = text_to_binary(encrypted_message)
    print(f"Binary Message: {binary_message}")
    
    # Embed binary message in image using LSB
    embed_message_lsb(image_path, binary_message, output_image_path)
    print(f"Message embedded into {output_image_path}")

    # Extract binary message from the image
    extracted_binary_message = extract_message_lsb(output_image_path, len(encrypted_message))
    print(f"Extracted Binary Message: {extracted_binary_message}")

    # Convert extracted binary message back to ciphertext
    extracted_encrypted_message = bytes([int(extracted_binary_message[i:i+8], 2) for i in range(0, len(extracted_binary_message), 8)])
    print(f"Extracted Encrypted Message: {extracted_encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt_message_aes(aes_key, nonce, extracted_encrypted_message)
    with open(decrypted_file_path, "w") as f:
        f.write(decrypted_message)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()