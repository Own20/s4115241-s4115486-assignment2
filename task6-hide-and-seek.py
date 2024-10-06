import os
import base64
from cryptography.fernet import Fernet
from PIL import Image
import piexif

# Path base (modify to your base directory)
BASE = os.path.dirname(os.path.abspath(__file__))

# Generate a key for AES encryption
def generate_key():
    return Fernet.generate_key()

# Save encryption key to a file
def save_key_to_file(key, file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
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

# Embed the encrypted message in the JPEG image using EXIF metadata
def embed_message_in_jpeg(image_path, encrypted_message, output_image_path):
    img = Image.open(image_path)
    
    # Convert the encrypted message to a base64 string
    hidden_message = base64.urlsafe_b64encode(encrypted_message).decode()

    # Load existing EXIF data (if any)
    exif_dict = piexif.load(img.info.get('exif', b''))

    # Embed the hidden message in the "UserComment" tag of EXIF data
    exif_dict['Exif'][piexif.ExifIFD.UserComment] = hidden_message.encode('utf-8')

    # Convert the EXIF dictionary back to bytes and save the image
    exif_bytes = piexif.dump(exif_dict)
    img.save(output_image_path, "jpeg", exif=exif_bytes)

# Extract the hidden message from the JPEG image's EXIF metadata
def extract_message_from_jpeg(image_path):
    img = Image.open(image_path)
    exif_dict = piexif.load(img.info.get('exif', b''))
    
    # Extract the hidden message from the "UserComment" field, if available
    hidden_message = exif_dict['Exif'].get(piexif.ExifIFD.UserComment)
    if hidden_message:
        return hidden_message.decode('utf-8')
    else:
        print("No hidden message found in the image.")
        return None

# Paths
plain_text_path = os.path.join(BASE, "input", "task1.txt")
decrypted_file_path = os.path.join(BASE, "output", "task6_dec")
key_path = os.path.join(BASE, "keys", "task6_key.pem")
    
# Image paths
image_path = os.path.join(BASE, "input", "task6_input_image_jpeg.jpeg")
output_image_path = os.path.join(BASE, "output", "task6_output_image.jpeg")

# Generate a key and save it to a file
key = generate_key()
save_key_to_file(key, key_path)
print('─' * 20)
print(f"Encryption Key saved to {key_path}")
print('─' * 20)
print(f"Encryption Key: {key}")
print('─' * 20)

# Encrypt the message from the text file
encrypted_message = encrypt_message(plain_text_path, key)
print(f"Encrypted Message: {base64.urlsafe_b64encode(encrypted_message).decode()}")
print('─' * 20)

# Embed the encrypted message into the JPEG image
embed_message_in_jpeg(image_path, encrypted_message, output_image_path)
print(f"Encrypted message embedded into {output_image_path}")
print('─' * 20)

# Extract the encrypted message from the JPEG image
extracted_encrypted_message = extract_message_from_jpeg(output_image_path)

if extracted_encrypted_message:
    encrypted_message_bytes = base64.urlsafe_b64decode(extracted_encrypted_message)
    
    # Decrypt the extracted message
    decrypted_message = decrypt_message(encrypted_message_bytes, key)
    print(f"Decrypted Message: {decrypted_message}")
    print('─' * 20)
    
    # Save decrypted message to a file
    with open(decrypted_file_path, "w") as file:
        file.write(decrypted_message)
    print(f"Decrypted message saved to {decrypted_file_path}")
    print('─' * 20)

# choose message to hide
# encrypt_message
# hide embed_message
# read stego
# find encrypt message
# decrypt 
# print message 