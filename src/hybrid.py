"""
Гибридное шифрование: комбинация RSA + AES для эффективного шифрования больших данных
"""
from typing import Tuple, Optional
import struct
from .symmetric import AESCipher, ChaCha20Cipher
from .asymmetric import RSACrypto
from .utils import CryptoUtils


class HybridCrypto:
    """
    Гибридное шифрование
    
    Принцип работы:
    1. Генерируем случайный симметричный ключ (AES/ChaCha20)
    2. Шифруем данные симметричным ключом (быстро)
    3. Шифруем симметричный ключ асимметричным ключом (RSA)
    4. Сохраняем: encrypted_key + encrypted_data
    """
    
    def __init__(self, symmetric_algorithm: str = 'AES', rsa_key_size: int = 2048):
        """
        Args:
            symmetric_algorithm: 'AES' или 'ChaCha20'
            rsa_key_size: Размер RSA ключа (2048, 3072, 4096)
        """
        self.symmetric_algorithm = symmetric_algorithm
        self.rsa_crypto = RSACrypto(rsa_key_size)
    
    def encrypt(self, plaintext: bytes, public_key = None) -> bytes:
        """
        Гибридное шифрование данных
        
        Args:
            plaintext: Данные для шифрования
            public_key: RSA публичный ключ (если None - используется свой)
        
        Returns:
            Зашифрованные данные в формате:
            [version(1)][algo(1)][encrypted_key_len(2)][encrypted_key][encrypted_data]
        """
        if public_key is None:
            if self.rsa_crypto.public_key is None:
                raise ValueError("Public key not set. Generate or load a keypair first.")
            public_key = self.rsa_crypto.public_key
        
        # 1. Генерируем случайный симметричный ключ
        symmetric_key = CryptoUtils.generate_random_bytes(32)  # 256 бит
        
        # 2. Шифруем данные симметричным ключом
        if self.symmetric_algorithm == 'AES':
            cipher = AESCipher(symmetric_key)
        else:
            cipher = ChaCha20Cipher(symmetric_key)
        
        encrypted_data = cipher.encrypt(plaintext)
        
        # 3. Шифруем симметричный ключ RSA
        encrypted_key = self.rsa_crypto.encrypt(symmetric_key, public_key)
        
        # 4. Формируем результат
        version = 1
        algo = 1 if self.symmetric_algorithm == 'AES' else 2
        
        result = bytearray()
        result.append(version)
        result.append(algo)
        result.extend(struct.pack('<H', len(encrypted_key)))  # 2 байта длины
        result.extend(encrypted_key)
        result.extend(encrypted_data)
        
        return bytes(result)
    
    def decrypt(self, ciphertext: bytes, private_key = None) -> bytes:
        """
        Расшифровка гибридно зашифрованных данных
        
        Args:
            ciphertext: Зашифрованные данные
            private_key: RSA приватный ключ (если None - используется свой)
        
        Returns:
            Расшифрованные данные
        """
        if private_key is None:
            if self.rsa_crypto.private_key is None:
                raise ValueError("Private key not set. Generate or load a keypair first.")
            private_key = self.rsa_crypto.private_key
        
        # Парсим формат
        offset = 0
        version = ciphertext[offset]
        offset += 1
        
        algo = ciphertext[offset]
        offset += 1
        
        encrypted_key_len = struct.unpack('<H', ciphertext[offset:offset+2])[0]
        offset += 2
        
        encrypted_key = ciphertext[offset:offset+encrypted_key_len]
        offset += encrypted_key_len
        
        encrypted_data = ciphertext[offset:]
        
        # 1. Расшифровываем симметричный ключ
        symmetric_key = self.rsa_crypto.decrypt(encrypted_key, private_key)
        
        # 2. Расшифровываем данные
        if algo == 1:
            cipher = AESCipher(symmetric_key)
        else:
            cipher = ChaCha20Cipher(symmetric_key)
        
        plaintext = cipher.decrypt(encrypted_data)
        
        return plaintext
    
    def encrypt_file(self, input_path: str, output_path: str, 
                     public_key = None) -> None:
        """
        Шифрование файла гибридным методом
        
        Args:
            input_path: Путь к исходному файлу
            output_path: Путь к зашифрованному файлу
            public_key: RSA публичный ключ
        """
        # Читаем файл
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        # Шифруем
        ciphertext = self.encrypt(plaintext, public_key)
        
        # Сохраняем
        with open(output_path, 'wb') as f:
            f.write(ciphertext)
    
    def decrypt_file(self, input_path: str, output_path: str,
                     private_key = None) -> None:
        """
        Расшифровка файла
        
        Args:
            input_path: Путь к зашифрованному файлу
            output_path: Путь к расшифрованному файлу
            private_key: RSA приватный ключ
        """
        # Читаем зашифрованный файл
        with open(input_path, 'rb') as f:
            ciphertext = f.read()
        
        # Расшифровываем
        plaintext = self.decrypt(ciphertext, private_key)
        
        # Сохраняем
        with open(output_path, 'wb') as f:
            f.write(plaintext)
    
    def generate_keypair(self) -> Tuple:
        """Генерация пары RSA ключей"""
        return self.rsa_crypto.generate_keypair()
    
    def save_keypair(self, private_key_path: str, public_key_path: str,
                     password: str = None) -> None:
        """
        Сохранение пары ключей
        
        Args:
            private_key_path: Путь для приватного ключа
            public_key_path: Путь для публичного ключа
            password: Пароль для шифрования приватного ключа (опционально)
        """
        self.rsa_crypto.save_private_key(private_key_path, password)
        self.rsa_crypto.save_public_key(public_key_path)
    
    def load_keypair(self, private_key_path: str = None, 
                     public_key_path: str = None,
                     password: str = None) -> None:
        """
        Загрузка ключей
        
        Args:
            private_key_path: Путь к приватному ключу (опционально)
            public_key_path: Путь к публичному ключу (опционально)
            password: Пароль для расшифровки приватного ключа
        """
        if private_key_path:
            self.rsa_crypto.load_private_key(private_key_path, password)
        if public_key_path:
            self.rsa_crypto.load_public_key(public_key_path)


class StreamHybridCrypto:
    """Гибридное шифрование с поддержкой потоковой обработки больших файлов"""
    
    def __init__(self, symmetric_algorithm: str = 'AES', rsa_key_size: int = 2048):
        self.symmetric_algorithm = symmetric_algorithm
        self.rsa_crypto = RSACrypto(rsa_key_size)
        self.chunk_size = 64 * 1024  # 64 KB
    
    def encrypt_large_file(self, input_path: str, output_path: str,
                           public_key = None) -> None:
        """
        Шифрование большого файла с потоковой обработкой
        
        Формат файла:
        [header][encrypted_symmetric_key][chunk1][chunk2]...
        где каждый chunk: [length(4)][encrypted_data]
        """
        if public_key is None:
            public_key = self.rsa_crypto.public_key
        
        # Генерируем симметричный ключ
        symmetric_key = CryptoUtils.generate_random_bytes(32)
        
        # Создаем шифр
        if self.symmetric_algorithm == 'AES':
            cipher = AESCipher(symmetric_key)
        else:
            cipher = ChaCha20Cipher(symmetric_key)
        
        # Шифруем симметричный ключ
        encrypted_key = self.rsa_crypto.encrypt(symmetric_key, public_key)
        
        with open(input_path, 'rb') as infile:
            with open(output_path, 'wb') as outfile:
                # Записываем заголовок
                header = CryptoUtils.create_header(
                    version=1,
                    algorithm=self.symmetric_algorithm,
                    params={'chunk_size': self.chunk_size}
                )
                outfile.write(header)
                
                # Записываем зашифрованный ключ
                outfile.write(struct.pack('<H', len(encrypted_key)))
                outfile.write(encrypted_key)
                
                # Шифруем файл по частям
                chunk_index = 0
                while True:
                    chunk = infile.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    # Добавляем индекс чанка в AAD
                    aad = struct.pack('<Q', chunk_index)
                    encrypted_chunk = cipher.encrypt(chunk, aad)
                    
                    # Записываем длину и данные
                    outfile.write(struct.pack('<I', len(encrypted_chunk)))
                    outfile.write(encrypted_chunk)
                    
                    chunk_index += 1
    
    def decrypt_large_file(self, input_path: str, output_path: str,
                           private_key = None) -> None:
        """Расшифровка большого файла"""
        if private_key is None:
            private_key = self.rsa_crypto.private_key
        
        with open(input_path, 'rb') as infile:
            # Читаем заголовок
            header, _ = CryptoUtils.parse_header(infile.read())
            
            # Возвращаемся к началу и пропускаем заголовок правильно
            infile.seek(0)
            header_length = struct.unpack('<I', infile.read(4))[0]
            infile.read(header_length)
            
            # Читаем зашифрованный ключ
            key_length = struct.unpack('<H', infile.read(2))[0]
            encrypted_key = infile.read(key_length)
            
            # Расшифровываем симметричный ключ
            symmetric_key = self.rsa_crypto.decrypt(encrypted_key, private_key)
            
            # Создаем шифр
            if header['algorithm'] == 'AES':
                cipher = AESCipher(symmetric_key)
            else:
                cipher = ChaCha20Cipher(symmetric_key)
            
            with open(output_path, 'wb') as outfile:
                chunk_index = 0
                while True:
                    # Читаем длину чанка
                    length_bytes = infile.read(4)
                    if not length_bytes:
                        break
                    
                    chunk_length = struct.unpack('<I', length_bytes)[0]
                    encrypted_chunk = infile.read(chunk_length)
                    
                    # Расшифровываем
                    aad = struct.pack('<Q', chunk_index)
                    decrypted_chunk = cipher.decrypt(encrypted_chunk, aad)
                    
                    outfile.write(decrypted_chunk)
                    chunk_index += 1
    
    def generate_keypair(self):
        """Генерация пары ключей"""
        return self.rsa_crypto.generate_keypair()
    
    def save_keypair(self, private_key_path: str, public_key_path: str,
                     password: str = None):
        """Сохранение пары ключей"""
        self.rsa_crypto.save_private_key(private_key_path, password)
        self.rsa_crypto.save_public_key(public_key_path)
    
    def load_keypair(self, private_key_path: str = None,
                     public_key_path: str = None, password: str = None):
        """Загрузка ключей"""
        if private_key_path:
            self.rsa_crypto.load_private_key(private_key_path, password)
        if public_key_path:
            self.rsa_crypto.load_public_key(public_key_path)