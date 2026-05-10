import struct
import os
from cryptography.hazmat.primitives import serialization

def serialize_public_key_pem(path:str, public_key):
    """Сохраняет публичный ключ в .pem"""
    with open(path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def serialize_private_key_pem(path:str, private_key):
    """Сохраняет приватный ключ в формате .pem"""
    with open(path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            ))
        
def load_private_key_pem(path:str):
    """Загружает приватный ключ из файла"""
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)
    
def save_encrypted_sym_key(path:str, key:bytes):
    """Сохраняет зашифрованный симметричный ключ в бинарный файл"""
    with open(path, 'wb') as f:
        f.write(key)

def load_encrypted_sym_key(path: str) ->bytes:
    """Загружает зашифрованный симметричный ключ из файла"""
    with open(path,'rb') as f:
        return f.read()
    
def save_cipher_with_iv(path:str, iv:bytes, ciphertext: bytes):
    """Сохраняет зашифрованный текст с IV в начале файла"""
    with open(path, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)

def load_cipher_with_iv(path) -> tuple:
    """Читает IV и шифротекст из файла"""
    with open(path,'rb') as f:
        iv = f.read(16)
        if len(iv) != 16:
            raise ValueError("Неверный формат файла: не ужалось прочитать IV :(")
        ciphertext = f.read()
    return iv, ciphertext

def read_raw_file(path: str) -> bytes:
    """
    Читает любой файл в бинарном режиме и возвращает его содержимое как байты.
    
    Args:
        path (str): Путь к файлу.
        
    Returns:
        bytes: Содержимое файла.
        
    Raises:
        FileNotFoundError: Если файл не найден.
        PermissionError: Если нет прав на чтение.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Файл не найден: {path}")
    
    with open(path, 'rb') as f:
        return f.read()

def write_raw_file(path: str, data: bytes):
    """
    Записывает байты в файл в бинарном режиме.
    Если файл существует, он будет перезаписан.
    Если папка назначения не существует, она будет создана.
    
    Args:
        path (str): Путь к файлу для записи.
        data (bytes): Данные для записи.
        
    Raises:
        PermissionError: Если нет прав на запись.
        OSError: Если невозможно создать директорию.
    """
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)

    with open(path, 'wb') as f:
        f.write(data)