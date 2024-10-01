# Q5. (4 marks) Write a program in python (task5-rsa-manual.py) to manually implement the encryption and decryption of a string message (your student number without the s).
# You are NOT allowed to use any Python cryptographic libraries.
# In other words, the task involves generating large prime numbers, computing public and private keys, and using those keys to encrypt and decrypt messages. 
# Python must do all mathematical calculations without the use of cryptographic libraries.
# Add the support for padding and improve performance by using fast, modular exponentiation (e.g., square-and-multiply algorithm).

# string message: 4115241
# generate large prime numbers
# compute public and private keys
# encrypt and decrypt messages

import random
from math import gcd
import os.path
import os

#for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

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

# Generate RSA keys with larger prime numbers (e.g., 32 bits instead of 16)
public_key, private_key = rsa_keygen(bits=32)

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
with open(BASE + '/output/task5_enc', 'w') as f:
    f.write(str(cipher))
# Save the decrypted message to a file
with open(BASE + '/output/task5_dec', 'w') as f:
    f.write(decrypted_message)
