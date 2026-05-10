from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from utilites import generate_random_bytes

def generate_sym_key(n: int) -> bytes:
    return generate_random_bytes(n)

def apply_padding(data: bytes) -> bytes:
    padder = padding.ANSIX923(128).padder()
    return padder.update(data) + padder.finalize()

def remove_padding(padded_data: bytes) -> bytes:
    unpadder = padding.ANSIX923(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt(key: bytes, data: bytes) -> bytes:
    iv = generate_random_bytes(16)
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext, iv

def decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(data) + decryptor.finalize()
    return remove_padding(decrypted_padded)

