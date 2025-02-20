# utils/key_derivation.py
import hashlib

def derive_key(password, salt=b'salt', iterations=100000):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)