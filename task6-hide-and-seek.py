# Q6. (5 marks) Encrypted messages can indeed be hidden inside an image using a technique called steganography.
# Steganography allows cybersecurity professionals to conceal information within other seemingly innocuous data, such as images, audio files, or even text. 
# When applied to images, this process involves embedding encrypted or hidden data into the image in such a way that the image itself appears unchanged to the human eye.
# Write a program in Python (task6-hide-and-seek.py) that encrypts a message using AES and embeds the message in a jpeg file using LBS or metadata steganography techniques. The program can then decrypt and reveal this secret message as well.

import os
import base64
from cryptography.fernet import Fernet
from PIL import Image, ImageDraw, ImageFont

# Path base (modify to your base directory)
BASE = os.path.dirname(os.path.abspath(__file__))

# Generate a key for AES encryption
def generate_key():
    return Fernet.generate_key()

# Save encryption key to a file
def save_key_to_file(key, file_path):
    with open(file_path, "wb") as file:
        file.write(key)

# Load encryption key from a file
def load_key_from_file(file_path):
    with open(file_path, "rb") as file:
        return file.read()

# Encrypt the message from a file
def encrypt_message(file_path, key):
    with open(file_path, "r") as file:
        message = file.read()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

# Decrypt the message
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

# Embed the encrypted message in the image (for simplicity, saving it as metadata)
from PIL import Image, PngImagePlugin
import base64

# Embed the encrypted message in the image (using metadata)
def embed_message_in_image(image_path, encrypted_message, output_image_path):
    img = Image.open(image_path)
    
    # Convert the encrypted message to a base64 string
    hidden_message = base64.urlsafe_b64encode(encrypted_message).decode()
    
    # Create PngInfo object to store metadata
    png_info = PngImagePlugin.PngInfo()
    png_info.add_text("Comment", hidden_message)
    
    # Save the image with the embedded message
    img.save(output_image_path, "png", pnginfo=png_info)


# Extract the hidden message from the image
def extract_message_from_image(image_path):
    img = Image.open(image_path)
    try:
        return img.info['Comment']
    except KeyError:
        print("No hidden message found in the image.")
        return None

def main():
    # Paths
    plain_text_path = os.path.join(BASE, "input", "task1.txt")
    encrypted_file_path = os.path.join(BASE, "output", "task6_enc")
    decrypted_file_path = os.path.join(BASE, "output", "task6_dec")
    private_key_path = os.path.join(BASE, "keys", "task6_private_key.pem")
    public_key_path = os.path.join(BASE, "keys", "task6_public_key.pem")
    
    # Image paths
    image_path = os.path.join(BASE, "input", "input_image.png")
    output_image_path = os.path.join(BASE, "output", "task6_output_image.png")

    # Generate a key and save it to a file
    key = generate_key()
    save_key_to_file(key, private_key_path)
    print(f"Encryption Key saved to {private_key_path}")

    # Encrypt the message from the text file
    encrypted_message = encrypt_message(plain_text_path, key)
    print(f"Encrypted Message: {base64.urlsafe_b64encode(encrypted_message).decode()}")

    # Embed the encrypted message into the image
    embed_message_in_image(image_path, encrypted_message, output_image_path)
    print(f"Encrypted message embedded into {output_image_path}")

    # Extract the encrypted message from the image
    extracted_encrypted_message = extract_message_from_image(output_image_path)
    if extracted_encrypted_message:
        encrypted_message_bytes = base64.urlsafe_b64decode(extracted_encrypted_message)
        
        # Decrypt the extracted message
        decrypted_message = decrypt_message(encrypted_message_bytes, key)
        print(f"Decrypted Message: {decrypted_message}")

        # Save decrypted message to a file
        with open(decrypted_file_path, "w") as file:
            file.write(decrypted_message)
        print(f"Decrypted message saved to {decrypted_file_path}")

if __name__ == "__main__":
    main()
