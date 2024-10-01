import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from PIL import Image
import numpy as np

# AES Encryption Function with IV and Padding
def encrypt_message_aes(aes_key, message):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    
    # Print lengths
    print(f"Original Message Length: {len(message)}")
    print(f"Padded Message Length: {len(padded_message)}")
    print(f"IV Length: {len(iv)}")
    print(f"Ciphertext Length: {len(ciphertext)}")
    
    return iv, ciphertext

# AES Decryption Function with IV and Unpadding
def decrypt_message_aes(aes_key, iv, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(ciphertext)
    try:
        return unpad(decrypted_message, AES.block_size).decode('utf-8')
    except (ValueError, UnicodeDecodeError) as e:
        print(f"Decryption error: {e}")
        return None

# Embed binary message in image using LSB (JPEG)
def embed_message_lsb(image_path, binary_message, output_image_path):
    img = Image.open(image_path)
    pixels = np.array(img)

    if img.mode not in ["RGB", "L"]:
        raise ValueError("Image must be in RGB or grayscale format.")

    flat_pixels = pixels.flatten()

    if len(binary_message) > len(flat_pixels):
        raise ValueError("Binary message is too long to be embedded in the image.")

    for i in range(len(binary_message)):
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(binary_message[i])

    new_pixels = flat_pixels.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels)
    new_img.save(output_image_path, 'JPEG')

# Extract binary message from image
def extract_message_lsb(image_path, message_length):
    img = Image.open(image_path)
    pixels = np.array(img)
    flat_pixels = pixels.flatten()
    binary_message = ''.join(str(flat_pixels[i] & 1) for i in range(message_length))
    return binary_message

# Convert bytes to binary string
def bytes_to_binary(byte_array):
    return ''.join(format(byte, '08b') for byte in byte_array)

# Convert binary string to bytes
def binary_to_bytes(binary_string):
    return bytes(int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8))

# Generate AES Key
def generate_aes_key():
    return get_random_bytes(16)  # 16 bytes for AES-128

# Main Function
def main():
    # Define the base path for all file operations
    BASE = os.path.dirname(os.path.abspath(__file__))

    # Paths
    encrypted_file_path = os.path.join(BASE, "output", "task8_enc")
    decrypted_file_path = os.path.join(BASE, "output", "task8_dec")
    aes_key_path = os.path.join(BASE, "keys", "task8_aes_key.pem")
    image_path = os.path.join(BASE, "input", "task6_input_image_jpg.jpg")
    output_image_path = os.path.join(BASE, "output", "task8_stego_image.jpg")

    # Secret message
    secret_message = "Hello, this is a test!"
    print(f"Original Message: {secret_message}")

    # Generate AES key
    aes_key = generate_aes_key()
    print(f"AES Key (Base64): {base64.b64encode(aes_key).decode()}")
    os.makedirs(os.path.dirname(aes_key_path), exist_ok=True)  # Ensure directory exists
    with open(aes_key_path, "wb") as f:
        f.write(aes_key)

    # Encrypt the message using AES with IV and padding
    iv, encrypted_message = encrypt_message_aes(aes_key, secret_message)

    # Convert the IV and encrypted message to binary
    binary_message = bytes_to_binary(iv + encrypted_message)
    
    # Print lengths of binary message and related data
    print(f"IV + Ciphertext Length: {len(iv + encrypted_message)}")
    print(f"Binary Encrypted Message Length: {len(binary_message)}")

    # Embed the binary message into the JPEG image
    embed_message_lsb(image_path, binary_message, output_image_path)
    print(f"Message embedded into image: {output_image_path}")

    # Extract the binary message from the JPEG image
    extracted_binary_message = extract_message_lsb(output_image_path, len(binary_message))

    # Convert binary to ciphertext (IV + encrypted message)
    extracted_iv_and_encrypted_message = binary_to_bytes(extracted_binary_message)

    # Split the IV and ciphertext from the extracted data
    extracted_iv = extracted_iv_and_encrypted_message[:AES.block_size]
    extracted_encrypted_message = extracted_iv_and_encrypted_message[AES.block_size:]

    # Print lengths after extraction
    print(f"Extracted IV Length: {len(extracted_iv)}")
    print(f"Extracted Ciphertext Length: {len(extracted_encrypted_message)}")

    # Decrypt the message
    decrypted_message = decrypt_message_aes(aes_key, extracted_iv, extracted_encrypted_message)
    
    if decrypted_message is not None:
        print(f"Decrypted Message: {decrypted_message}")
        os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)  # Ensure directory exists
        with open(decrypted_file_path, 'w') as f:
            f.write(decrypted_message)
    else:
        print("Decryption failed.")

if __name__ == "__main__":
    main()
