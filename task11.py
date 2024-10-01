import gzip
import base64
import os
from Crypto.Cipher import AES
from stegano import lsb

def pad_message(message):
    return message + (16 - len(message) % 16) * chr(16 - len(message) % 16)

def encrypt_message(message, key):
    compressed_message = gzip.compress(message.encode('utf-8'))
    key = key.ljust(32)[:32]  # Ensure key is 32 bytes
    iv = os.urandom(16)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    padded_message = pad_message(compressed_message.decode('latin1')).encode('latin1')
    encrypted_message = cipher.encrypt(padded_message)
    return base64.b64encode(iv + encrypted_message).decode('utf-8')

def embed_message_in_image(image_path, message, output_path):
    secret_image = lsb.hide(image_path, message)
    secret_image.save(output_path)
    print(f"Encrypted message successfully hidden in {output_path}")

def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    key = key.ljust(32)[:32]  # Ensure key is 32 bytes
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message).decode('latin1')
    
    padding_len = ord(decrypted_message[-1])
    decrypted_message = decrypted_message[:-padding_len].encode('latin1')
    return gzip.decompress(decrypted_message).decode('utf-8')

def extract_message_from_image(image_path):
    extracted_message = lsb.reveal(image_path)
    if extracted_message is None:
        return "No hidden message found!"
    return extracted_message

# Define the base path for all file operations
BASE = os.path.dirname(os.path.abspath(__file__))

# The image where you want to hide the message (should be 1280x720 pixels)
# image_path = "input_image.jpg"  # Path to your input image
# output_path = "output_image_with_secret.jpg"  # Path to save the image with the hidden message
image_path = os.path.join(BASE, "input", "task6_input_image_jpg.jpg")
output_path = os.path.join(BASE, "output", "task11_stego_image.jpg")
key = "my_secret_key_123"  # Make sure this is a valid key

# Short test message
message = "Hello, this is a test message."

# Step 1: Encrypt the message
encrypted_message = encrypt_message(message, key)
print(f"Encrypted message length: {len(encrypted_message)} bytes")

# Step 2: Embed the encrypted message in the image
embed_message_in_image(image_path, encrypted_message, output_path)

# Step 3: Extract the message from the image
extracted_message = extract_message_from_image(output_path)
print(f"Extracted message: {extracted_message}")

# Step 4: Decrypt the extracted message
if extracted_message != "No hidden message found!":
    decrypted_message = decrypt_message(extracted_message, key)
    print(f"Decrypted message: {decrypted_message}")
