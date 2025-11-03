"""
Симметричное шифрование: AES-GCM, ChaCha20-Poly1305
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from typing import Tuple, Optional
from .utils import CryptoUtils, derive_key_from_password
import struct


class SymmetricCrypto:
    """Базовый класс для симметричного шифрования"""
    
    def __init__(self, key: bytes = None):
        """
        Инициализация
        
        Args:
            key: Ключ шифрования (если None - генерируется новый)
        """
        if key is None:
            key = CryptoUtils.generate_random_bytes(32)  # 256 бит
        self.key = key
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """Шифрование данных"""
        raise NotImplementedError
    
    def decrypt(self, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        """Расшифровка данных"""
        raise NotImplementedError


class AESCipher(SymmetricCrypto):
    """AES-GCM шифрование"""
    
    ALGORITHM = "AES-256-GCM"
    NONCE_LENGTH = 12  # 96 бит (рекомендуется для GCM)
    TAG_LENGTH = 16    # 128 бит
    
    def __init__(self, key: bytes = None):
        super().__init__(key)
        self.cipher = AESGCM(self.key)
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """
        Шифрование с аутентификацией
        
        Args:
            plaintext: Исходные данные
            associated_data: Дополнительные аутентифицированные данные (AAD)
        
        Returns:
            nonce + ciphertext + tag
        """
        nonce = CryptoUtils.generate_nonce(self.NONCE_LENGTH)
        ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
        
        # Формат: [nonce][ciphertext+tag]
        return nonce + ciphertext
    
    def decrypt(self, data: bytes, associated_data: bytes = None) -> bytes:
        """
        Расшифровка с проверкой аутентичности
        
        Args:
            data: nonce + ciphertext + tag
            associated_data: Дополнительные аутентифицированные данные (AAD)
        
        Returns:
            Расшифрованные данные
        """
        nonce = data[:self.NONCE_LENGTH]
        ciphertext = data[self.NONCE_LENGTH:]
        
        plaintext = self.cipher.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    
    @classmethod
    def from_password(cls, password: str, salt: bytes = None) -> Tuple['AESCipher', bytes]:
        """
        Создание шифра из пароля
        
        Returns:
            (cipher, salt)
        """
        key, salt = derive_key_from_password(password, salt, key_length=32)
        return cls(key), salt


class ChaCha20Cipher(SymmetricCrypto):
    """ChaCha20-Poly1305 шифрование"""
    
    ALGORITHM = "ChaCha20-Poly1305"
    NONCE_LENGTH = 12
    TAG_LENGTH = 16
    
    def __init__(self, key: bytes = None):
        super().__init__(key)
        self.cipher = ChaCha20Poly1305(self.key)
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """Шифрование с аутентификацией"""
        nonce = CryptoUtils.generate_nonce(self.NONCE_LENGTH)
        ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext
    
    def decrypt(self, data: bytes, associated_data: bytes = None) -> bytes:
        """Расшифровка с проверкой аутентичности"""
        nonce = data[:self.NONCE_LENGTH]
        ciphertext = data[self.NONCE_LENGTH:]
        plaintext = self.cipher.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    
    @classmethod
    def from_password(cls, password: str, salt: bytes = None) -> Tuple['ChaCha20Cipher', bytes]:
        """Создание шифра из пароля"""
        key, salt = derive_key_from_password(password, salt, key_length=32)
        return cls(key), salt


class StreamCipher:
    """Потоковое шифрование для больших файлов"""
    
    def __init__(self, cipher_class, key: bytes):
        """
        Args:
            cipher_class: Класс шифра (AESCipher или ChaCha20Cipher)
            key: Ключ шифрования
        """
        self.cipher = cipher_class(key)
        self.chunk_size = 64 * 1024  # 64 KB
    
    def encrypt_file(self, input_path: str, output_path: str, 
                     associated_data: bytes = None) -> None:
        """
        Шифрование файла с потоковой обработкой
        
        Формат выходного файла:
        [header_length(4)][header][salt(16)][encrypted_chunks]
        """
        # Создаем заголовок
        header = CryptoUtils.create_header(
            version=1,
            algorithm=self.cipher.ALGORITHM,
            params={'chunk_size': self.chunk_size}
        )
        
        with open(input_path, 'rb') as infile:
            with open(output_path, 'wb') as outfile:
                # Записываем заголовок
                outfile.write(header)
                
                # Читаем и шифруем по частям
                chunk_index = 0
                while True:
                    chunk = infile.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    # Добавляем индекс чанка в AAD для защиты от переупорядочивания
                    aad = struct.pack('<Q', chunk_index)  # 8 байт
                    if associated_data:
                        aad += associated_data
                    
                    encrypted_chunk = self.cipher.encrypt(chunk, aad)
                    
                    # Записываем длину чанка + сам чанк
                    chunk_length = len(encrypted_chunk)
                    outfile.write(struct.pack('<I', chunk_length))  # 4 байта
                    outfile.write(encrypted_chunk)
                    
                    chunk_index += 1
    
    def decrypt_file(self, input_path: str, output_path: str,
                     associated_data: bytes = None) -> None:
        """Расшифровка файла с потоковой обработкой"""
        with open(input_path, 'rb') as infile:
            # Читаем заголовок
            header, remaining = CryptoUtils.parse_header(infile.read())
            
            # Возвращаем непрочитанные данные обратно
            infile.seek(len(infile.read()) - len(remaining), 0)
            infile.seek(4 + len(CryptoUtils.create_header(
                header['version'], 
                header['algorithm'], 
                header['params']
            )) - 4)
            
            with open(output_path, 'wb') as outfile:
                chunk_index = 0
                while True:
                    # Читаем длину чанка
                    length_bytes = infile.read(4)
                    if not length_bytes:
                        break
                    
                    chunk_length = struct.unpack('<I', length_bytes)[0]
                    encrypted_chunk = infile.read(chunk_length)
                    
                    # Восстанавливаем AAD
                    aad = struct.pack('<Q', chunk_index)
                    if associated_data:
                        aad += associated_data
                    
                    decrypted_chunk = self.cipher.decrypt(encrypted_chunk, aad)
                    outfile.write(decrypted_chunk)
                    
                    chunk_index += 1


# Удобные функции для быстрого использования
def encrypt_data(data: bytes, password: str = None, key: bytes = None,
                 algorithm: str = 'AES') -> Tuple[bytes, Optional[bytes]]:
    """
    Шифрование данных
    
    Args:
        data: Данные для шифрования
        password: Пароль (если используется)
        key: Ключ (если используется вместо пароля)
        algorithm: 'AES' или 'ChaCha20'
    
    Returns:
        (encrypted_data, salt) или (encrypted_data, None)
    """
    cipher_class = AESCipher if algorithm == 'AES' else ChaCha20Cipher
    
    if password:
        cipher, salt = cipher_class.from_password(password)
        encrypted = cipher.encrypt(data)
        return salt + encrypted, salt
    else:
        cipher = cipher_class(key)
        encrypted = cipher.encrypt(data)
        return encrypted, None


def decrypt_data(data: bytes, password: str = None, key: bytes = None,
                 algorithm: str = 'AES', salt: bytes = None) -> bytes:
    """
    Расшифровка данных
    
    Args:
        data: Данные для расшифровки
        password: Пароль (если используется)
        key: Ключ (если используется)
        algorithm: 'AES' или 'ChaCha20'
        salt: Соль (если используется пароль)
    
    Returns:
        Расшифрованные данные
    """
    cipher_class = AESCipher if algorithm == 'AES' else ChaCha20Cipher
    
    if password:
        if salt is None:
            # Соль в начале данных
            salt = data[:16]
            data = data[16:]
        cipher, _ = cipher_class.from_password(password, salt)
    else:
        cipher = cipher_class(key)
    
    return cipher.decrypt(data)