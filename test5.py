import random
from math import gcd
import os.path
import os

#for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))
encryptedPath = os.path.join(BASE, 'output', 'task5_enc')
decryptedPath = os.path.join(BASE, 'output', 'task5_dec')
# Square and Multiply algorithm for fast modular exponentiation
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

# Function to check if a number is prime
def is_prime(num):
    if num <= 1:
        return False
    if num == 2 or num == 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

# Generate a large random prime number
def generate_large_prime(bits=16):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

# Function to compute modular inverse using extended Euclidean algorithm
def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % phi

# RSA key generation
def rsa_keygen(bits=16):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    print(f"Generated primes: p={p}, q={q}")
    print(f"n={n}, phi(n)={phi_n}")

    # Choose a random e such that 1 < e < phi(n) and gcd(e, phi(n)) == 1
    e = random.randrange(2, phi_n)
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)

    # Compute the private key d
    d = mod_inverse(e, phi_n)

    return (e, n), (d, n)  # (public_key, private_key)

# RSA encryption
def rsa_encrypt(message, public_key):
    e, n = public_key
    # Convert the message to an integer
    message_int = int.from_bytes(message.encode('utf-8'), 'big')
    # Ensure message is smaller than n
    if message_int >= n:
        raise ValueError("Message is too large for the modulus")
    cipher = mod_exp(message_int, e, n)
    return cipher

# RSA decryption
def rsa_decrypt(cipher, private_key):
    d, n = private_key
    decrypted_int = mod_exp(cipher, d, n)
    # Convert the decrypted integer back to bytes, then to string
    try:
        decrypted_message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode('utf-8')
    except UnicodeDecodeError:
        # If there's an error in decoding, handle it here (e.g., improper padding)
        raise ValueError("Decryption failed: message was not properly encoded or padded")
    return decrypted_message

# Input message (student number without 's')
message = "4115241"
    
# Generate RSA keys
public_key, private_key = rsa_keygen(bits=32)
print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}")
    
# Encrypt the message
cipher = rsa_encrypt(message, public_key)
print(f"Encrypted message: {cipher}")
    
# Decrypt the message
decrypted_message = rsa_decrypt(cipher, private_key)
print(f"Decrypted message: {decrypted_message}")

# Save the encrypted and decrypted messages to files
with open(encryptedPath, 'w') as f:
    f.write(str(cipher))
with open(decryptedPath, 'w') as f:
    f.write(decrypted_message)
