import os

IV_SIZE = 16
RSA_KEY_SIZE = 2048

def generate_random_bytes(n: int) -> bytes:
    return os.urandom(n)