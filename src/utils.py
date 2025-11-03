"""
Вспомогательные функции
"""
import os
import secrets
import json
from typing import Dict, Any
from pathlib import Path


class CryptoUtils:
    """Основные утилиты"""
    
    @staticmethod
    def generate_random_bytes(length: int = 32) -> bytes:
        """Генерация криптостойких случайных байт"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        """Генерация соли"""
        return os.urandom(length)
    
    @staticmethod
    def generate_iv(length: int = 16) -> bytes:
        """Генерация IV для AES"""
        return os.urandom(length)
    
    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        """Генерация nonce для GCM/ChaCha20"""
        return os.urandom(length)
    
    @staticmethod
    def save_to_file(filepath: str, data: bytes) -> None:
        """Безопасное сохранение данных в файл"""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(data)
    
    @staticmethod
    def load_from_file(filepath: str) -> bytes:
        """Загрузка данных из файла"""
        with open(filepath, 'rb') as f:
            return f.read()
    
    @staticmethod
    def create_header(version: int, algorithm: str, params: Dict[str, Any]) -> bytes:
        """Создание заголовка для зашифрованных данных"""
        header = {
            'version': version,
            'algorithm': algorithm,
            'params': params
        }
        header_json = json.dumps(header).encode('utf-8')
        header_length = len(header_json).to_bytes(4, 'big')
        return header_length + header_json
    
    @staticmethod
    def parse_header(data: bytes) -> tuple[Dict[str, Any], bytes]:
        """Парсинг заголовка"""
        header_length = int.from_bytes(data[:4], 'big')
        header_json = data[4:4+header_length]
        header = json.loads(header_json.decode('utf-8'))
        remaining_data = data[4+header_length:]
        return header, remaining_data
    
    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        """Конвертация байт в hex строку"""
        return data.hex()
    
    @staticmethod
    def hex_to_bytes(hex_string: str) -> bytes:
        """Конвертация hex строки в байты"""
        return bytes.fromhex(hex_string)


def derive_key_from_password(password: str, salt: bytes = None, 
                             key_length: int = 32) -> tuple[bytes, bytes]:
    """
    Получение ключа из пароля используя Argon2
    
    Args:
        password: Пароль
        salt: Соль (если None - генерируется новая)
        key_length: Длина ключа в байтах
    
    Returns:
        (ключ, соль)
    """
    from argon2 import low_level
    from argon2 import Type
    
    if salt is None:
        salt = CryptoUtils.generate_salt(16)
    
    key = low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,          # Количество итераций
        memory_cost=65536,    # 64 MB
        parallelism=4,        # 4 потока
        hash_len=key_length,
        type=Type.ID          # Argon2id (гибрид Argon2i и Argon2d)
    )
    
    return key, salt


class FileProcessor:
    """Обработка файлов с поддержкой потоковой обработки"""
    
    CHUNK_SIZE = 64 * 1024  # 64 KB
    
    @classmethod
    def process_file_in_chunks(cls, input_path: str, output_path: str, 
                               processor_func, **kwargs):
        """
        Обработка файла по частям
        
        Args:
            input_path: Путь к входному файлу
            output_path: Путь к выходному файлу
            processor_func: Функция обработки чанка
            **kwargs: Дополнительные параметры для processor_func
        """
        with open(input_path, 'rb') as infile:
            with open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(cls.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    processed_chunk = processor_func(chunk, **kwargs)
                    outfile.write(processed_chunk)
    
    @classmethod
    def get_file_size(cls, filepath: str) -> int:
        """Получение размера файла"""
        return Path(filepath).stat().st_size
    
    @classmethod
    def is_large_file(cls, filepath: str, threshold_mb: int = 10) -> bool:
        """Проверка является ли файл большим"""
        size_mb = cls.get_file_size(filepath) / (1024 * 1024)
        return size_mb > threshold_mb