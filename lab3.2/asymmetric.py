from cryptography.hazmat.primitives.asymmetric import rsa, padding as aspad
from cryptography.hazmat.primitives import hashes
from utilites import RSA_KEY_SIZE

def generate_asym_keys()->tuple:
    """
    Генерирует новую пару асимметричных ключей RSA (приватный и публичный).
    
    Использует стандартную публичную экспоненту 65537 (0x10001), которая обеспечивает 
    хороший баланс между производительностью шифрования и безопасностью.
    Размер ключа определяется константой RSA_KEY_SIZE из модуля utils (по умолчанию 2048 бит).
    
    Returns:
        tuple[RSAPrivateKey, RSAPublicKey]: Кортеж, содержащий:
            - private_key: Объект приватного ключа (хранится в секрете).
            - public_key: Объект публичного ключа (может быть передан кому угодно).
            
    Note:
        Генерация ключей такого размера может занять от нескольких миллисекунд до секунд 
        в зависимости от производительности процессора и доступной энтропии системы.
    """
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = RSA_KEY_SIZE
    )
    return private_key, private_key.public_key()

def encrypt_sym_key_rsa(sym_key_rsa: bytes, public_key) -> bytes:
    """
    Шифрует симметричный ключ с использованием публичного ключа RSA и схемы дополнения OAEP.
    
    Эта функция используется в гибридной криптосистеме для безопасной передачи 
    сеансового симметричного ключа. Схема OAEP (Optimal Asymmetric Encryption Padding) 
    обеспечивает защиту от различных криптографических атак, свойственных "голому" RSA.
    
    Args:
        sym_key (bytes): Симметричный ключ (байты), который необходимо зашифровать.
                         Длина ключа должна быть меньше размера модуля RSA минус размер паддинга.
        public_key (RSAPublicKey): Публичный ключ получателя.
        
    Returns:
        bytes: Зашифрованный симметричный ключ (шифротекст).
        
    Raises:
        ValueError: Если длина симметричного ключа слишком велика для выбранного размера RSA-ключа
                    или если произошла ошибка в процессе шифрования.
    """
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
    """
    Расшифровывает симметричный ключ с использованием приватного ключа RSA и схемы OAEP.
    
    Обратная операция к encrypt_sym_key_rsa. Позволяет получателю восстановить исходный 
    симметричный ключ, используя свой секретный приватный ключ.
    
    Args:
        encrypted_key (bytes): Зашифрованный симметричный ключ (полученный от отправителя).
        private_key (RSAPrivateKey): Приватный ключ получателя.
        
    Returns:
        bytes: Расшифрованный симметричный ключ (готов к использованию в Camellia/AES).
        
    Raises:
        ValueError: Если расшифровка не удалась. Это может произойти, если:
                    - Использован неверный приватный ключ (не пара к публичному).
                    - Данные были повреждены при передаче.
                    - Произошла атака подмены данных (OAEP обнаружил несоответствие).
    """
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
