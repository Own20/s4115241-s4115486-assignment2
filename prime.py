import random
from math import gcd
import os.path
import os

# For making paths work on all OS
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

    print('─' * 20)
    print(f"Generated primes: p={p}, q={q}")
    print(f"n={n}, phi(n)={phi_n}")
    print('─' * 20)

    # Choose a random e such that 1 < e < phi(n) and gcd(e, phi(n)) == 1
    e = random.randrange(2, phi_n)
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)

    # Compute the private key d
    d = mod_inverse(e, phi_n)

    return (e, n), (d, n)  # (public_key, private_key)

# Simple padding function similar to PKCS#1 v1.5 padding
def simple_padding(message, n):
    max_msg_len = (n.bit_length() + 7) // 8 - 11
    message_bytes = message.encode('utf-8')

    if len(message_bytes) > max_msg_len:
        raise ValueError("Message too long for RSA encryption")

    # Add padding: \x00\x02 + random non-zero padding bytes + \x00 + message
    padding_length = max_msg_len - len(message_bytes)
    padding = bytes([random.randint(1, 255) for _ in range(padding_length)])
    padded_message = b'\x00\x02' + padding + b'\x00' + message_bytes
    return int.from_bytes(padded_message, 'big')

# RSA encryption with padding
def rsa_encrypt(message, public_key):
    e, n = public_key
    padded_message_int = simple_padding(message, n)
    
    if padded_message_int >= n:
        raise ValueError("Message too large for the modulus")
    
    cipher = mod_exp(padded_message_int, e, n)
    return cipher

# RSA decryption
def rsa_decrypt(cipher, private_key):
    d, n = private_key
    decrypted_int = mod_exp(cipher, d, n)
    
    decrypted_message_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
    
    # Strip padding (\x00\x02 at the start and the padding bytes)
    if decrypted_message_bytes[:2] != b'\x00\x02':
        raise ValueError("Decryption error: Invalid padding")
    
    decrypted_message = decrypted_message_bytes.split(b'\x00', 2)[-1].decode('utf-8')
    
    return decrypted_message

# Input message (student number without 's')
message = "4115241"

# Generate RSA keys with larger prime numbers (e.g., 64 bits instead of 32)
public_key, private_key = rsa_keygen(bits=64)

print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}")
print('─' * 20)

# Encrypt the message
cipher = rsa_encrypt(message, public_key)
print(f"Encrypted message: {cipher}")
print('─' * 20)

# Decrypt the message
decrypted_message = rsa_decrypt(cipher, private_key)
print(f"Decrypted message: {decrypted_message}")
print('─' * 20)

# Save the encrypted message to a file
with open(encryptedPath, 'w') as f:
    f.write(str(cipher))
# Save the decrypted message to a file
with open(decryptedPath, 'w') as f:
    f.write(decrypted_message)
