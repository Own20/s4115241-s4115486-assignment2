import random
from math import gcd
import os

BASE = os.path.dirname(os.path.abspath(__file__))
encryptedPath = os.path.join(BASE, 'output', 'task5_enc')
decryptedPath = os.path.join(BASE, 'output', 'task5_dec')

# Fast modular exponentiation
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

# Miller-Rabin primality test for faster prime generation
# We used Miller_Rabin primality test because the conventional method cost too much time to do calculation
def miller_rabin_test(n, k=5):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = mod_exp(a, d, n) 
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Generate a large random prime number using Miller-Rabin
def generate_large_prime(bits=16):
    while True:
        num = random.getrandbits(bits) # Using getrandbits to control exactly 16 bits (in this case) of prime number
        if miller_rabin_test(num): # Pass the number to check if it's prime
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

# RSA key generation with faster prime generation
def rsa_keygen(bits=64):  # Reduced key size because the larger key size requires longer computation time
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    print('─' * 20)
    print(f"Generated primes: p={p}, q={q}")
    print(f"n={n}, phi(n)={phi_n}")
    print('─' * 20)

    e = random.randrange(2, phi_n)
    while gcd(e, phi_n) != 1: # To ensure e is coprime with phi_n, gcd between them must be 1
        e = random.randrange(2, phi_n)

    d = mod_inverse(e, phi_n)
    return (e, n), (d, n)

# Function to pad the message with fixed padding
def add_padding(message, n_len):
    message_bytes = message.encode('utf-8')
    max_message_len = n_len - 11  # Allow some room for padding
    if len(message_bytes) > max_message_len:
        raise ValueError("Message too long for the given modulus")

    padded_message = b'\x00' * (max_message_len - len(message_bytes)) + message_bytes # Padded message
    return padded_message

# Function to remove padding from the decrypted message
def remove_padding(padded_message):
    return padded_message.lstrip(b'\x00').decode('utf-8')

# RSA encryption with padding
def rsa_encrypt(message, public_key):
    e, n = public_key
    n_len = (n.bit_length() + 7) // 8  # Length of n in bytes

    print(f"Modulus size (in bytes): {n_len}")
    print(f"Message size (in bytes): {len(message.encode('utf-8'))}")

    padded_message = add_padding(message, n_len)
    message_int = int.from_bytes(padded_message, 'big') # Converts the byte representation of the padded message into an integer

    cipher = mod_exp(message_int, e, n)
    return cipher

# RSA decryption with unpadding
def rsa_decrypt(cipher, private_key):
    d, n = private_key
    n_len = (n.bit_length() + 7) // 8 # Rounding up for the full byte example : (1023 + 7) // 8 = 128 bytes

    decrypted_int = mod_exp(cipher, d, n)
    decrypted_bytes = decrypted_int.to_bytes(n_len, 'big')

    return remove_padding(decrypted_bytes)

# Input message (student number without 's')
message = "4115241"

# Generate RSA keys with larger prime numbers (e.g., 128 or 256 bits)
public_key, private_key = rsa_keygen(bits=128)  


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

"""
References:

Miller-Rabin calculation 
https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/ 
For the inverse modulo we took some ideas from this 
https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/ 
To specify bits of generated number
https://www.w3schools.com/python/ref_random_getrandbits.asp 
For the general RSA encryption, the steps ideas from the week 2 lectorial slide
For the add_padding part, chatgpt was utilise to help debug the problem

"""
