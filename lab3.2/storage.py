import struct
import os
from cryptography.hazmat.primitives import serialization

def serialize_public_key_pem(path:str, public_key):
    """Сериализует и сохраняет публичный RSA-ключ в файл в формате PEM.
    
    Args:
        path (str): Путь к файлу, куда будет сохранен ключ (например, 'public.pem').
        public_key: Объект публичного ключа типа RSAPublicKey.
        
    Raises:
        PermissionError: Если нет прав на запись в указанную директорию.
        OSError: Если путь некорректен."""
    with open(path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def serialize_private_key_pem(path:str, private_key):
    """Сериализует и сохраняет приватный RSA-ключ в файл в формате PEM без шифрования паролем.
    
    Args:
        path (str): Путь к файлу, куда будет сохранен ключ (например, 'private.pem').
        private_key: Объект приватного ключа типа RSAPrivateKey.
        
    Raises:
        PermissionError: Если нет прав на запись в указанную директорию.
        OSError: Если путь некорректен."""
    with open(path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            ))
        
def load_private_key_pem(path:str):
    """
    Загружает приватный RSA-ключ из PEM-файла.
    
    Args:
        path (str): Путь к файлу с приватным ключом (.pem).
        
    Returns:
        RSAPrivateKey: Объект приватного ключа.
        
    Raises:
        FileNotFoundError: Если файл не найден.
        ValueError: Если файл не содержит корректного PEM-ключа или зашифрован паролем.
        PermissionError: Если нет прав на чтение файла.
    """
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)
    
def save_encrypted_sym_key(path:str, key:bytes):
    """
    Сохраняет зашифрованный симметричный ключ (байты) в бинарный файл.
    
    Args:
        path (str): Путь к файлу для сохранения (например, 'key.enc').
        key (bytes): Зашифрованные данные симметричного ключа.
        
    Raises:
        PermissionError: Если нет прав на запись.
        OSError: Если путь некорректен.
    """
    with open(path, 'wb') as f:
        f.write(key)

def load_encrypted_sym_key(path: str) ->bytes:
    """
    Загружает зашифрованный симметричный ключ из бинарного файла.
    
    Args:
        path (str): Путь к файлу с зашифрованным ключом.
        
    Returns:
        bytes: Сырые байты зашифрованного ключа.
        
    Raises:
        FileNotFoundError: Если файл не найден.
        PermissionError: Если нет прав на чтение.
    """
    with open(path,'rb') as f:
        return f.read()
    
def save_cipher_with_iv(path:str, iv:bytes, ciphertext: bytes):
    """
    Сохраняет зашифрованные данные в бинарный файл, записывая вектор инициализации (IV)
    в начало файла, за ним следует шифротекст.
    
    Структура файла: [IV (16 байт)][Ciphertext]
    
    Args:
        path (str): Путь к файлу для сохранения зашифрованных данных.
        iv (bytes): Вектор инициализации (должен быть длиной 16 байт для Camellia/AES).
        ciphertext (bytes): Зашифрованные данные.
        
    Raises:
        PermissionError: Если нет прав на запись.
        OSError: Если путь некорректен.
    """
    with open(path, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)

def load_cipher_with_iv(path) -> tuple:
    """
    Читает зашифрованный файл, разделяя вектор инициализации (IV) и шифротекст.
    Ожидает, что первые 16 байт файла содержат IV.
    
    Args:
        path (str): Путь к зашифрованному файлу.
        
    Returns:
        tuple[bytes, bytes]: Кортеж (iv, ciphertext).
        
    Raises:
        FileNotFoundError: Если файл не найден.
        ValueError: Если файл слишком короткий и не содержит полноценный IV (менее 16 байт).
        PermissionError: Если нет прав на чтение.
    """
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
