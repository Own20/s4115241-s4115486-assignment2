import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from PIL import Image, PngImagePlugin
import base64

# Define base path
BASE = os.path.dirname(os.path.abspath(__file__)) # Update this with the actual base directory

# Generate RSA public and private keys
def generate_rsa_keys(private_key_path, public_key_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save the private key to a file
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key to a file
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Encrypt message using RSA public key
def encrypt_with_rsa(message, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Decrypt message using RSA private key
def decrypt_with_rsa(encrypted_message, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# Save the encrypted message to a file
def save_encrypted_message_to_file(encrypted_message, file_path):
    with open(file_path, "wb") as file:
        file.write(encrypted_message)

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

# Main function
def main():
    plain_text_path = os.path.join(BASE, "input", "task1.txt")
    encrypted_file_path = os.path.join(BASE, "output", "task7_enc")
    decrypted_file_path = os.path.join(BASE, "output", "task7_dec")
    private_key_path = os.path.join(BASE, "keys", "task7_private_key.pem")
    public_key_path = os.path.join(BASE, "keys", "task7_public_key.pem")
    
    # Generate RSA keys and save them
    generate_rsa_keys(private_key_path, public_key_path)
    print(f"RSA keys saved to {private_key_path} and {public_key_path}")
    
    # Read and encrypt the message using the public key
    with open(plain_text_path, "r") as file:
        message = file.read()
    
    encrypted_message = encrypt_with_rsa(message, public_key_path)
    
    # Save encrypted message to a file
    save_encrypted_message_to_file(encrypted_message, encrypted_file_path)
    print(f"Encrypted message saved to {encrypted_file_path}")

    # Embed the encrypted message into the image
    image_path = os.path.join(BASE, "input", "input_image.png")
    output_image_path = os.path.join(BASE, "output", "task7_output_image.png")
    embed_message_in_image(image_path, encrypted_message, output_image_path)
    print(f"Message embedded in image at {output_image_path}")
    
    # Decrypt the message using the private key
    decrypted_message = decrypt_with_rsa(encrypted_message, private_key_path)
    print(f"Decrypted Message: {decrypted_message}")

    # Save decrypted message to a file
    with open(decrypted_file_path, "w") as file:
        file.write(decrypted_message)
    print(f"Decrypted message saved to {decrypted_file_path}")

if __name__ == "__main__":
    main()
