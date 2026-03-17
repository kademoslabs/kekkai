"""
Weak Cryptography Vulnerabilities (CWE-327, CWE-330)
WARNING: This code is intentionally vulnerable for testing purposes.
DO NOT USE IN PRODUCTION.
"""

import hashlib
import random
from Crypto.Cipher import DES


def hash_password_md5(password):
    """Vulnerable: Using MD5 for password hashing."""
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    """Vulnerable: Using SHA1 for password hashing."""
    # VULNERABLE: SHA1 is deprecated and insecure
    return hashlib.sha1(password.encode()).hexdigest()


def generate_session_token():
    """Vulnerable: Using weak random number generator."""
    # VULNERABLE: random module is not cryptographically secure
    token = ''.join([str(random.randint(0, 9)) for _ in range(32)])
    return token


def generate_api_key():
    """Vulnerable: Predictable random generation."""
    # VULNERABLE: random.random() is not suitable for security
    key = str(random.random()).replace(".", "")
    return key[:32]


def encrypt_data_des(data, key):
    """Vulnerable: Using DES encryption."""
    # VULNERABLE: DES has 56-bit key, easily brute-forced
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = data + (8 - len(data) % 8) * " "
    encrypted = cipher.encrypt(padded_data.encode())
    return encrypted


def simple_xor_encrypt(plaintext, key):
    """Vulnerable: Using XOR as encryption."""
    # VULNERABLE: XOR is not a secure encryption method
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(plaintext))
    return encrypted


def insecure_random_password():
    """Vulnerable: Using insecure random for password generation."""
    # VULNERABLE: random.choice is not cryptographically secure
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    password = ''.join(random.choice(chars) for _ in range(12))
    return password


class CryptoManager:
    """Cryptography manager with multiple vulnerabilities."""
    
    def hash_user_password(self, password):
        """VULNERABLE: Using deprecated hashing."""
        return hashlib.md5(password.encode()).hexdigest()
    
    def generate_reset_token(self):
        """VULNERABLE: Weak token generation."""
        return str(random.randint(100000, 999999))
    
    def encrypt_sensitive_data(self, data):
        """VULNERABLE: No encryption, just base64."""
        import base64
        # VULNERABLE: Base64 is encoding, not encryption
        return base64.b64encode(data.encode()).decode()
