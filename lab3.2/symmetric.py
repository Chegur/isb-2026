from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from utilites import generate_random_bytes

def generate_sym_key(n: int) -> bytes:
    """
    Генерирует криптографически стойкий случайный ключ для симметричного шифрования.
    
    Использует генератор случайных чисел операционной системы (os.urandom) через 
    функцию-обертку из модуля utilites.
    
    Args:
        n (int): Длина ключа в байтах. 
                 Рекомендуется: 32 (для Camellia-256), 16 (для Camellia-128).
        
    Returns:
        bytes: Случайная последовательность байтов заданной длины, пригодная для использования в качестве ключа.
    """
    return generate_random_bytes(n)

def apply_padding(data: bytes) -> bytes:
    """
    Применяет схему дополнения ANSIX923 к исходным данным для выравнивания их по размеру блока.
    
    Необходима для режимов блочного шифрования (например, CBC), где длина входных данных 
    должна быть кратна размеру блока алгоритма (128 бит / 16 байт для Camellia/AES).
    
    Args:
        data (bytes): Исходные данные произвольной длины.
        
    Returns:
        bytes: Данные с добавленным паддингом, длина которых кратна 16 байтам.
    """
    padder = padding.ANSIX923(128).padder()
    return padder.update(data) + padder.finalize()

def remove_padding(padded_data: bytes) -> bytes:
    """
    Удаляет схему дополнения ANSIX923 из расшифрованных данных.
    
    Восстанавливает исходную длину данных, отрезая добавленные при шифровании байты.
    Выполняет проверку корректности структуры паддинга.
    
    Args:
        padded_data (bytes): Данные, полученные после дешифрования, содержащие паддинг.
        
    Returns:
        bytes: Исходные данные без паддинга.
        
    Raises:
        ValueError: Если структура паддинга неверна (что может указывать на повреждение данных 
                    или использование неверного ключа/алгоритма).
    """
    unpadder = padding.ANSIX923(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt(key: bytes, data: bytes) -> bytes:
    """
    Шифрует данные алгоритмом Camellia в режиме CBC с использованием предоставленного ключа.
    
    Автоматически генерирует случайный вектор инициализации (IV) для обеспечения уникальности 
    шифротекста даже при повторном шифровании одинаковых данных одним ключом.
    Примечание: Данные должны быть предварительно дополнены (padded) перед вызовом этой функции,
    либо эта функция должна быть модифицирована для внутреннего вызова apply_padding.
    (В текущей реализации ожидается, что data уже подготовлены, либо пользователь сам добавит паддинг).
    
    Args:
        key (bytes): Симметричный ключ шифрования (должен быть длиной 16, 24 или 32 байта).
        data (bytes): Данные для шифрования (желательно уже с примененным паддингом).
        
    Returns:
        tuple[bytes, bytes]: Кортеж, содержащий:
            - ciphertext (bytes): Зашифрованные данные.
            - iv (bytes): Сгенерированный вектор инициализации (16 байт), необходимый для дешифрования.
            
    Raises:
        ValueError: Если длина ключа недопустима для алгоритма Camellia.
    """
    iv = generate_random_bytes(16)
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext, iv

def decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    """
    Расшифровывает данные алгоритмом Camellia в режиме CBC и удаляет паддинг.
    
    Выполняет обратную операцию шифрованию: использует предоставленный ключ и вектор инициализации (IV)
    для восстановления зашифрованных данных, после чего автоматически удаляет дополнение ANSIX923.
    
    Args:
        key (bytes): Симметричный ключ шифрования (тот же, что использовался при шифровании).
        data (bytes): Зашифрованные данные (шифротекст).
        iv (bytes): Вектор инициализации (16 байт), полученный при шифровании.
        
    Returns:
        bytes: Расшифрованные исходные данные без паддинга.
        
    Raises:
        ValueError: Если ключ неверен, IV не совпадает с использованным при шифровании, 
                    или данные были повреждены (ошибка при удалении паддинга).
    """
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(data) + decryptor.finalize()
    return remove_padding(decrypted_padded)
