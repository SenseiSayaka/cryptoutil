"""
Хеширование и проверка целостности: SHA-256, SHA-512, BLAKE2
"""
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Union, BinaryIO
import os


class HashAlgorithm:
    """Базовый класс для хеширования"""
    
    def __init__(self, algorithm_name: str):
        self.algorithm_name = algorithm_name
    
    def hash_data(self, data: bytes) -> bytes:
        """Хеширование данных"""
        raise NotImplementedError
    
    def hash_file(self, filepath: str, chunk_size: int = 8192) -> bytes:
        """Хеширование файла с потоковой обработкой"""
        raise NotImplementedError
    
    def verify_data(self, data: bytes, expected_hash: bytes) -> bool:
        """Проверка хеша данных"""
        actual_hash = self.hash_data(data)
        return actual_hash == expected_hash
    
    def verify_file(self, filepath: str, expected_hash: bytes) -> bool:
        """Проверка хеша файла"""
        actual_hash = self.hash_file(filepath)
        return actual_hash == expected_hash


class SHA256Hash(HashAlgorithm):
    """SHA-256 хеширование"""
    
    def __init__(self):
        super().__init__("SHA-256")
    
    def hash_data(self, data: bytes) -> bytes:
        """Хеширование данных (256 бит = 32 байта)"""
        return hashlib.sha256(data).digest()
    
    def hash_file(self, filepath: str, chunk_size: int = 8192) -> bytes:
        """Хеширование файла"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.digest()
    
    def hash_to_hex(self, data: bytes) -> str:
        """Хеширование с выводом в hex формате"""
        return hashlib.sha256(data).hexdigest()


class SHA512Hash(HashAlgorithm):
    """SHA-512 хеширование"""
    
    def __init__(self):
        super().__init__("SHA-512")
    
    def hash_data(self, data: bytes) -> bytes:
        """Хеширование данных (512 бит = 64 байта)"""
        return hashlib.sha512(data).digest()
    
    def hash_file(self, filepath: str, chunk_size: int = 8192) -> bytes:
        """Хеширование файла"""
        sha512 = hashlib.sha512()
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha512.update(chunk)
        return sha512.digest()
    
    def hash_to_hex(self, data: bytes) -> str:
        """Хеширование с выводом в hex формате"""
        return hashlib.sha512(data).hexdigest()


class BLAKE2Hash(HashAlgorithm):
    """BLAKE2b хеширование (быстрее SHA-2)"""
    
    def __init__(self, digest_size: int = 32, key: bytes = None):
        """
        Args:
            digest_size: Размер хеша в байтах (1-64)
            key: Ключ для HMAC-режима (опционально)
        """
        super().__init__(f"BLAKE2b-{digest_size*8}")
        self.digest_size = digest_size
        self.key = key
    
    def hash_data(self, data: bytes) -> bytes:
        """Хеширование данных"""
        return hashlib.blake2b(data, digest_size=self.digest_size, key=self.key).digest()
    
    def hash_file(self, filepath: str, chunk_size: int = 8192) -> bytes:
        """Хеширование файла"""
        blake2 = hashlib.blake2b(digest_size=self.digest_size, key=self.key)
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                blake2.update(chunk)
        return blake2.digest()
    
    def hash_to_hex(self, data: bytes) -> str:
        """Хеширование с выводом в hex формате"""
        return hashlib.blake2b(data, digest_size=self.digest_size, key=self.key).hexdigest()


class SHA3Hash(HashAlgorithm):
    """SHA-3 (Keccak) хеширование"""
    
    def __init__(self, digest_size: int = 256):
        """
        Args:
            digest_size: 224, 256, 384, или 512 бит
        """
        super().__init__(f"SHA3-{digest_size}")
        self.digest_size = digest_size
        
        # Выбор функции хеширования
        self.hash_func = {
            224: hashlib.sha3_224,
            256: hashlib.sha3_256,
            384: hashlib.sha3_384,
            512: hashlib.sha3_512
        }[digest_size]
    
    def hash_data(self, data: bytes) -> bytes:
        """Хеширование данных"""
        return self.hash_func(data).digest()
    
    def hash_file(self, filepath: str, chunk_size: int = 8192) -> bytes:
        """Хеширование файла"""
        hasher = self.hash_func()
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.digest()
    
    def hash_to_hex(self, data: bytes) -> str:
        """Хеширование с выводом в hex формате"""
        return self.hash_func(data).hexdigest()


class HashManager:
    """Менеджер для работы с разными алгоритмами хеширования"""
    
    ALGORITHMS = {
        'sha256': SHA256Hash,
        'sha512': SHA512Hash,
        'blake2': BLAKE2Hash,
        'sha3-256': lambda: SHA3Hash(256),
        'sha3-512': lambda: SHA3Hash(512),
    }
    
    @classmethod
    def get_hasher(cls, algorithm: str = 'sha256', **kwargs) -> HashAlgorithm:
        """
        Получение хешера по имени алгоритма
        
        Args:
            algorithm: Название алгоритма
            **kwargs: Дополнительные параметры для алгоритма
        """
        if algorithm not in cls.ALGORITHMS:
            raise ValueError(f"Unknown algorithm: {algorithm}. Available: {list(cls.ALGORITHMS.keys())}")
        
        hasher_class = cls.ALGORITHMS[algorithm]
        
        if callable(hasher_class) and not isinstance(hasher_class, type):
            return hasher_class()
        else:
            return hasher_class(**kwargs)
    
    @classmethod
    def hash_data(cls, data: bytes, algorithm: str = 'sha256') -> bytes:
        """Быстрое хеширование данных"""
        hasher = cls.get_hasher(algorithm)
        return hasher.hash_data(data)
    
    @classmethod
    def hash_file(cls, filepath: str, algorithm: str = 'sha256') -> bytes:
        """Быстрое хеширование файла"""
        hasher = cls.get_hasher(algorithm)
        return hasher.hash_file(filepath)
    
    @classmethod
    def create_checksum_file(cls, filepath: str, algorithm: str = 'sha256') -> str:
        """
        Создание файла с контрольной суммой
        
        Returns:
            Путь к созданному файлу
        """
        hasher = cls.get_hasher(algorithm)
        file_hash = hasher.hash_file(filepath)
        hash_hex = file_hash.hex()
        
        checksum_file = f"{filepath}.{algorithm}"
        with open(checksum_file, 'w') as f:
            f.write(f"{hash_hex}  {os.path.basename(filepath)}\n")
        
        return checksum_file
    
    @classmethod
    def verify_checksum_file(cls, filepath: str, checksum_file: str, 
                            algorithm: str = 'sha256') -> bool:
        """
        Проверка файла по файлу контрольной суммы
        
        Returns:
            True если хеш совпадает
        """
        # Читаем ожидаемый хеш
        with open(checksum_file, 'r') as f:
            line = f.readline().strip()
            expected_hash = bytes.fromhex(line.split()[0])
        
        # Вычисляем актуальный хеш
        hasher = cls.get_hasher(algorithm)
        actual_hash = hasher.hash_file(filepath)
        
        return actual_hash == expected_hash


# Утилиты для HMAC (Hash-based Message Authentication Code)
class HMAC:
    """HMAC для аутентификации сообщений"""
    
    @staticmethod
    def generate(key: bytes, message: bytes, algorithm: str = 'sha256') -> bytes:
        """
        Генерация HMAC
        
        Args:
            key: Секретный ключ
            message: Сообщение
            algorithm: Алгоритм хеширования
        """
        import hmac as hmac_module
        
        hash_algorithms = {
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'blake2': lambda: hashlib.blake2b(key=key)
        }
        
        if algorithm == 'blake2':
            return hashlib.blake2b(message, key=key).digest()
        else:
            return hmac_module.new(key, message, hash_algorithms[algorithm]).digest()
    
    @staticmethod
    def verify(key: bytes, message: bytes, expected_hmac: bytes, 
               algorithm: str = 'sha256') -> bool:
        """
        Проверка HMAC
        
        Returns:
            True если HMAC валиден
        """
        import hmac as hmac_module
        actual_hmac = HMAC.generate(key, message, algorithm)
        return hmac_module.compare_digest(actual_hmac, expected_hmac)


# Удобные функции
def calculate_file_hash(filepath: str, algorithm: str = 'sha256') -> str:
    """
    Вычисление хеша файла в hex формате
    
    Args:
        filepath: Путь к файлу
        algorithm: Алгоритм (sha256, sha512, blake2, sha3-256, sha3-512)
    
    Returns:
        Hex строка хеша
    """
    file_hash = HashManager.hash_file(filepath, algorithm)
    return file_hash.hex()


def verify_file_integrity(filepath: str, expected_hash: str, 
                         algorithm: str = 'sha256') -> bool:
    """
    Проверка целостности файла
    
    Args:
        filepath: Путь к файлу
        expected_hash: Ожидаемый хеш (hex строка)
        algorithm: Алгоритм
    
    Returns:
        True если хеш совпадает
    """
    actual_hash = calculate_file_hash(filepath, algorithm)
    return actual_hash.lower() == expected_hash.lower()