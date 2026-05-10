import asymmetric
import storage
import symmetric
import sys
import os

def run_generation():
    print(f"Генерация ключей\n")
    path_enc_sym = input("Путь для зашифрованного симм. ключа [key.enc]: ").strip() or "key.enc"
    path_pub = input("Путь для публичного ключа [public.pem]: ").strip() or "public.pem"
    path_priv = input("Путь для приватного ключа [private.pem]: ").strip() or "private.pem"
    n = int(input("Введите длину ключа: ").strip() or "128")
    try:
        print("Генерация Симметричного ключа...")
        sym_key = symmetric.generate_sym_key(n)

        print("Генерация пары ключей RSA...")
        priv_key,pub_key = asymmetric.generate_asym_keys()

        print("Шифрование симметричного ключа...")
        enc_sym_key = asymmetric.encrypt_sym_key_rsa(sym_key, pub_key)

        print("Сохранение файлов...")
        storage.serialize_private_key_pem(path_priv, priv_key)
        storage.serialize_public_key_pem(path_pub, pub_key)
        storage.save_encrypted_sym_key(path_enc_sym, enc_sym_key)

        print(f"Успешно!\n -Приватный ключ: {path_priv}\n -Публичный ключ: {path_pub}\n -Зашифрованный симметричный ключ: {path_enc_sym}")

    except Exception as e:
        print(f"Ошибка при генерации: {e}")

def run_encryption():
    print(f"Шифрование даных")
    path_src = input("Путь к исходному файлу: ").strip()
    path_priv = input("Путь к приватному ключу: ").strip()
    path_enc_sym = input("Путь к зашифрованному симм. ключу: ").strip()
    path_dst = input("Путь для зашифрованного файла: ").strip()
    if not all([path_src, path_priv, path_enc_sym, path_dst]):
        print("Все пути должны быть заполнены.")
        return

    if not os.path.exists(path_src):
        print(f"Файл '{path_src}' не найден.")
        return

    try:
        print("Загрузка ключей...")
        priv_key = storage.load_private_key_pem(path_priv)
        enc_sym_key_bytes = storage.load_encrypted_sym_key(path_enc_sym)

        print("Расшифровка симметричного ключа...")
        sym_key = asymmetric.decrypt_sym_key_rsa(enc_sym_key_bytes, priv_key)

        print("Чтение исходного файла...")
        data = storage.read_raw_file(path_src)

        print("Шифрование данных (Camellia)...")
        data = symmetric.apply_padding(data)
        ciphertext, iv = symmetric.encrypt(sym_key, data)

        print("Сохранение зашифрованного файла...")
        storage.save_cipher_with_iv(path_dst, iv, ciphertext)

        print(f"Успешно! Файл зашифрован: {path_dst}")

    except FileNotFoundError as e:
        print(f"Файл не найден: {e}")
    except ValueError as e:
        print(f"Ошибка данных (неверный ключ или формат): {e}")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")
    return

def run_decryption():
    print("ДЕШИФРОВАНИЕ ДАННЫХ")

    path_src = input("Путь к зашифрованному файлу: ").strip()
    path_priv = input("Путь к приватному ключу: ").strip()
    path_enc_sym = input("Путь к зашифрованному симм. ключу: ").strip()
    path_dst = input("Путь для расшифрованного файла: ").strip()

    if not all([path_src, path_priv, path_enc_sym, path_dst]):
        print("Все пути должны быть заполнены.")
        return

    if not os.path.exists(path_src):
        print(f"Файл '{path_src}' не найден.")
        return

    try:
        print("Загрузка ключей...")
        priv_key = storage.load_private_key(path_priv)
        enc_sym_key_bytes = storage.load_encrypted_key(path_enc_sym)

        print("Расшифровка симметричного ключа...")
        sym_key = asymmetric.decrypt_key(enc_sym_key_bytes, priv_key)

        print("Чтение зашифрованного файла (IV + Data)...")
        iv, ciphertext = storage.load_encrypted_data(path_src)

        print("Дешифрование данных (Camellia)...")
        decrypted_data = symmetric.decrypt(sym_key, ciphertext, iv)
        unpadded = symmetric.remove_padding(decrypted_data)
        print("Сохранение расшифрованного файла...")
        storage.write_raw_file(path_dst, unpadded)

        print(f"Успешно! Файл расшифрован: {path_dst}")

    except FileNotFoundError as e:
        print(f"Файл не найден: {e}")
    except ValueError as e:
        print(f"Ошибка данных (неверный ключ, поврежден файл или паддинг): {e}")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")

def main():
    commands = {
        '1': 'gen', 'g': 'gen', 'ген': 'gen', 'gen': 'gen', 'generation': 'gen',
        '2': 'enc', 'e': 'enc', 'шиф': 'enc', 'enc': 'enc', 'encryption': 'enc',
        '3': 'dec', 'd': 'dec', 'дешиф': 'dec', 'dec': 'dec', 'decryption': 'dec',
        '0': 'exit', 'q': 'exit', 'выход': 'exit', 'exit': 'exit', 'quit': 'exit'
    }

    while True:
        print("\n=== ГИБРИДНАЯ КРИПТОСИСТЕМА (RSA + Camellia) ===")
        print("  [1/Г] Генерация ключей")
        print("  [2/Ш] Шифрование файла")
        print("  [3/Д] Дешифрование файла")
        print("  [0/Q] Выход")
        
        user_input = input("\nВыберите действие: ").strip().lower()

        action = commands.get(user_input)

        if not action:
            for key, val in commands.items():
                if len(key) > 1 and user_input.startswith(key):
                    action = val
                    break
        
        match action:
            case 'gen':
                run_generation()
            case 'enc':
                run_encryption()
            case 'dec':
                run_decryption()
            case 'exit':
                print("Выход из программы.")
                break
            case None:
                print("Неверный выбор. Попробуйте снова (цифры, буквы или слова).")
            case _:
                print(f"Неизвестная команда: '{action}'. Попробуйте снова.")

if __name__ == "__main__":
    try:
        import utilites, symmetric, asymmetric, storage
        main()
    except ImportError as e:
        print(f"Ошибка импорта модулей: {e}")
        print("Убедитесь, что папка 'modules' существует и содержит все необходимые файлы.")
        sys.exit(1)