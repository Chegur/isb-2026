from cryptography.hazmat.primitives.asymmetric import rsa, padding as aspad
from cryptography.hazmat.primitives import hashes
from utilites import RSA_KEY_SIZE

def generate_asym_keys()->tuple:
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = RSA_KEY_SIZE
    )
    return private_key, private_key.public_key()

def encrypt_sym_key_rsa(sym_key_rsa: bytes, public_key) -> bytes:
    try:
        return public_key.encrypt(
            sym_key_rsa,
            aspad.OAEP(
                mgf=aspad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except BaseException.Exception as e:
        raise ValueError(f"Ошибка шифрования ключа: {e}")

def decrypt_sym_key_rsa(encrypted_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    try:
        return private_key.decrypt(
            encrypted_key,
            aspad.OAEP(
                mgf=aspad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except BaseException.Exception as e:
        raise ValueError(f"Ошибка расшифровки ключа: {e}")