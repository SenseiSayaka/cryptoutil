#!/usr/bin/env python3
"""
Простой скрипт для проверки работоспособности
"""
import os
import tempfile
from src import AESCipher, calculate_file_hash, SignatureManager

def test_basic_encryption():
    """Базовый тест шифрования"""
    print("🔐 Тест 1: Базовое шифрование")
    
    # Шифрование
    plaintext = b"Hello, World! This is a secret message."
    cipher = AESCipher()
    
    print(f"   Исходный текст: {plaintext.decode()}")
    
    ciphertext = cipher.encrypt(plaintext)
    print(f"   Зашифровано: {len(ciphertext)} байт")
    
    decrypted = cipher.decrypt(ciphertext)
    print(f"   Расшифровано: {decrypted.decode()}")
    
    assert plaintext == decrypted
    print("   ✅ УСПЕХ!\n")


def test_file_encryption():
    """Тест шифрования файла"""
    print("📁 Тест 2: Шифрование файла")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Создаём файл
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("Секретное содержимое файла")
        
        print(f"   Создан файл: {test_file}")
        
        # Шифруем
        cipher = AESCipher()
        with open(test_file, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = cipher.encrypt(plaintext)
        
        encrypted_file = os.path.join(tmpdir, "encrypted.bin")
        with open(encrypted_file, 'wb') as f:
            f.write(ciphertext)
        
        print(f"   Зашифрован: {encrypted_file}")
        
        # Расшифровываем
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted = cipher.decrypt(encrypted_data)
        
        decrypted_file = os.path.join(tmpdir, "decrypted.txt")
        with open(decrypted_file, 'wb') as f:
            f.write(decrypted)
        
        print(f"   Расшифрован: {decrypted_file}")
        
        # Проверяем
        with open(decrypted_file, 'r') as f:
            content = f.read()
        
        print(f"   Содержимое: {content}")
        assert content == "Секретное содержимое файла"
        print("   ✅ УСПЕХ!\n")


def test_hashing():
    """Тест хеширования"""
    print("#️⃣  Тест 3: Хеширование")
    
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        tmp.write("Test file content")
        tmp_path = tmp.name
    
    try:
        file_hash = calculate_file_hash(tmp_path, 'sha256')
        print(f"   SHA-256: {file_hash}")
        print(f"   Длина: {len(file_hash)} символов")
        assert len(file_hash) == 64  # 32 байта = 64 hex символа
        print("   ✅ УСПЕХ!\n")
    finally:
        os.unlink(tmp_path)


def test_signature():
    """Тест подписи"""
    print("✍️  Тест 4: Цифровая подпись")
    
    message = b"Important document"
    
    manager = SignatureManager('Ed25519')
    print(f"   Сообщение: {message.decode()}")
    
    signed_msg = manager.sign_message(message)
    print(f"   Подпись создана: {len(signed_msg.signature)} байт")
    
    is_valid = manager.verify_signed_message(signed_msg)
    print(f"   Подпись валидна: {is_valid}")
    
    assert is_valid
    print("   ✅ УСПЕХ!\n")


def test_password_encryption():
    """Тест шифрования с паролем"""
    print("🔑 Тест 5: Шифрование с паролем")
    
    plaintext = b"Secret data with password"
    password = "my_secure_password_123"
    
    print(f"   Пароль: {password}")
    
    # Шифрование
    cipher1, salt = AESCipher.from_password(password)
    ciphertext = cipher1.encrypt(plaintext)
    print(f"   Зашифровано с солью: {salt.hex()[:32]}...")
    
    # Расшифровка
    cipher2, _ = AESCipher.from_password(password, salt)
    decrypted = cipher2.decrypt(ciphertext)
    
    assert plaintext == decrypted
    print(f"   Расшифровано: {decrypted.decode()}")
    print("   ✅ УСПЕХ!\n")


if __name__ == '__main__':
    print("=" * 60)
    print("🧪 ЗАПУСК ТЕСТОВ КРИПТОГРАФИЧЕСКОЙ УТИЛИТЫ")
    print("=" * 60 + "\n")
    
    try:
        test_basic_encryption()
        test_file_encryption()
        test_hashing()
        test_signature()
        test_password_encryption()
        
        print("=" * 60)
        print("✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        print("=" * 60)
    except Exception as e:
        print(f"\n❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()