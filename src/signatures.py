"""
подписи: RSA-PSS, Ed25519
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional
import json
from datetime import datetime
from .hashing import SHA256Hash, SHA512Hash
from .asymmetric import RSACrypto, Ed25519Crypto
from .utils import CryptoUtils


class SignatureBase:
    """Базовый класс для цифровых подписей"""
    
    def sign(self, message: bytes) -> bytes:
        """Создание подписи"""
        raise NotImplementedError
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Проверка подписи"""
        raise NotImplementedError


class RSASignature(SignatureBase):
    """RSA-PSS цифровые подписи"""
    
    def __init__(self, rsa_crypto: RSACrypto = None, key_size: int = 2048):
        """
        Args:
            rsa_crypto: Объект RSACrypto с ключами
            key_size: Размер ключа если генерируем новый
        """
        if rsa_crypto is None:
            rsa_crypto = RSACrypto(key_size)
            rsa_crypto.generate_keypair()
        
        self.rsa_crypto = rsa_crypto
    
    def sign(self, message: bytes, private_key: rsa.RSAPrivateKey = None) -> bytes:
        """
        Подпись сообщения приватным ключом (RSA-PSS)
        
        Args:
            message: Данные для подписи
            private_key: Приватный ключ (если None - используется из rsa_crypto)
        
        Returns:
            Подпись
        """
        if private_key is None:
            private_key = self.rsa_crypto.private_key
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify(self, message: bytes, signature: bytes, 
               public_key: rsa.RSAPublicKey = None) -> bool:
        """
        Проверка подписи публичным ключом
        
        Args:
            message: Исходные данные
            signature: Подпись
            public_key: Публичный ключ (если None - используется из rsa_crypto)
        
        Returns:
            True если подпись валидна
        """
        if public_key is None:
            public_key = self.rsa_crypto.public_key
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def sign_file(self, filepath: str) -> bytes:
        """Подпись файла"""
        # Сначала хешируем файл
        hasher = SHA256Hash()
        file_hash = hasher.hash_file(filepath)
        # Подписываем хеш
        return self.sign(file_hash)
    
    def verify_file(self, filepath: str, signature: bytes) -> bool:
        """Проверка подписи файла"""
        hasher = SHA256Hash()
        file_hash = hasher.hash_file(filepath)
        return self.verify(file_hash, signature)


class Ed25519Signature(SignatureBase):
    """Ed25519 цифровые подписи (быстрее и безопаснее RSA)"""
    
    def __init__(self, ed_crypto: Ed25519Crypto = None):
        """
        Args:
            ed_crypto: Объект Ed25519Crypto с ключами
        """
        if ed_crypto is None:
            ed_crypto = Ed25519Crypto()
            ed_crypto.generate_keypair()
        
        self.ed_crypto = ed_crypto
    
    def sign(self, message: bytes, private_key: ed25519.Ed25519PrivateKey = None) -> bytes:
        """
        Подпись сообщения
        
        Args:
            message: Данные для подписи
            private_key: Приватный ключ
        
        Returns:
            Подпись (64 байта)
        """
        if private_key is None:
            private_key = self.ed_crypto.private_key
        
        return private_key.sign(message)
    
    def verify(self, message: bytes, signature: bytes,
               public_key: ed25519.Ed25519PublicKey = None) -> bool:
        """
        Проверка подписи
        
        Args:
            message: Исходные данные
            signature: Подпись
            public_key: Публичный ключ
        
        Returns:
            True если подпись валидна
        """
        if public_key is None:
            public_key = self.ed_crypto.public_key
        
        try:
            public_key.verify(signature, message)
            return True
        except Exception:
            return False
    
    def sign_file(self, filepath: str) -> bytes:
        """Подпись файла"""
        hasher = SHA512Hash()  # Ed25519 обычно используется с SHA-512
        file_hash = hasher.hash_file(filepath)
        return self.sign(file_hash)
    
    def verify_file(self, filepath: str, signature: bytes) -> bool:
        """Проверка подписи файла"""
        hasher = SHA512Hash()
        file_hash = hasher.hash_file(filepath)
        return self.verify(file_hash, signature)


class SignedMessage:
    """Структура для подписанного сообщения с метаданными"""
    
    def __init__(self, message: bytes, signature: bytes, 
                 algorithm: str, metadata: dict = None):
        """
        Args:
            message: Исходное сообщение
            signature: Подпись
            algorithm: Алгоритм подписи (RSA-PSS или Ed25519)
            metadata: Дополнительные метаданные
        """
        self.message = message
        self.signature = signature
        self.algorithm = algorithm
        self.metadata = metadata or {}
        self.metadata['timestamp'] = datetime.utcnow().isoformat()
    
    def to_dict(self) -> dict:
        """Конвертация в словарь"""
        return {
            'message': self.message.hex(),
            'signature': self.signature.hex(),
            'algorithm': self.algorithm,
            'metadata': self.metadata
        }
    
    def to_json(self) -> str:
        """Конвертация в JSON"""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_bytes(self) -> bytes:
        """
        Сериализация в бинарный формат
        
        Формат: [version(1)][algo_len(1)][algo][metadata_len(4)][metadata_json]
                [signature_len(2)][signature][message]
        """
        import struct
        
        version = 1
        algo_bytes = self.algorithm.encode('utf-8')
        metadata_bytes = json.dumps(self.metadata).encode('utf-8')
        
        result = bytearray()
        result.append(version)
        result.append(len(algo_bytes))
        result.extend(algo_bytes)
        result.extend(struct.pack('<I', len(metadata_bytes)))
        result.extend(metadata_bytes)
        result.extend(struct.pack('<H', len(self.signature)))
        result.extend(self.signature)
        result.extend(self.message)
        
        return bytes(result)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SignedMessage':
        """Десериализация из бинарного формата"""
        import struct
        
        offset = 0
        version = data[offset]
        offset += 1
        
        algo_len = data[offset]
        offset += 1
        
        algorithm = data[offset:offset+algo_len].decode('utf-8')
        offset += algo_len
        
        metadata_len = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        metadata = json.loads(data[offset:offset+metadata_len].decode('utf-8'))
        offset += metadata_len
        
        signature_len = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2
        
        signature = data[offset:offset+signature_len]
        offset += signature_len
        
        message = data[offset:]
        
        return cls(message, signature, algorithm, metadata)
    
    def save_to_file(self, filepath: str) -> None:
        """Сохранение подписанного сообщения в файл"""
        CryptoUtils.save_to_file(filepath, self.to_bytes())
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'SignedMessage':
        """Загрузка подписанного сообщения из файла"""
        data = CryptoUtils.load_from_file(filepath)
        return cls.from_bytes(data)


class SignatureManager:
    """Менеджер для работы с разными алгоритмами подписи"""
    
    def __init__(self, algorithm: str = 'Ed25519'):
        """
        Args:
            algorithm: 'RSA' или 'Ed25519'
        """
        self.algorithm = algorithm
        
        if algorithm == 'RSA':
            self.signer = RSASignature()
        elif algorithm == 'Ed25519':
            self.signer = Ed25519Signature()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
    
    def sign_message(self, message: bytes, metadata: dict = None) -> SignedMessage:
        """
        Подпись сообщения с созданием структуры SignedMessage
        
        Args:
            message: Данные для подписи
            metadata: Дополнительные метаданные
        
        Returns:
            SignedMessage объект
        """
        signature = self.signer.sign(message)
        return SignedMessage(message, signature, self.algorithm, metadata)
    
    def verify_signed_message(self, signed_msg: SignedMessage) -> bool:
        """
        Проверка подписанного сообщения
        
        Args:
            signed_msg: SignedMessage объект
        
        Returns:
            True если подпись валидна
        """
        if signed_msg.algorithm != self.algorithm:
            raise ValueError(f"Algorithm mismatch: expected {self.algorithm}, got {signed_msg.algorithm}")
        
        return self.signer.verify(signed_msg.message, signed_msg.signature)
    
    def sign_file(self, filepath: str, output_path: str = None, 
                  metadata: dict = None) -> str:
        """
        Подпись файла
        
        Args:
            filepath: Путь к файлу для подписи
            output_path: Путь для сохранения подписи (если None - добавляется .sig)
            metadata: Дополнительные метаданные
        
        Returns:
            Путь к файлу с подписью
        """
        signature = self.signer.sign_file(filepath)
        
        if metadata is None:
            metadata = {}
        metadata['original_file'] = filepath
        
        # Создаем SignedMessage только с хешем файла
        hasher = SHA256Hash()
        file_hash = hasher.hash_file(filepath)
        
        signed_msg = SignedMessage(file_hash, signature, self.algorithm, metadata)
        
        if output_path is None:
            output_path = f"{filepath}.sig"
        
        signed_msg.save_to_file(output_path)
        return output_path
    
    def verify_file_signature(self, filepath: str, signature_path: str) -> bool:
        """
        Проверка подписи файла
        
        Args:
            filepath: Путь к файлу
            signature_path: Путь к файлу с подписью
        
        Returns:
            True если подпись валидна
        """
        signed_msg = SignedMessage.load_from_file(signature_path)
        
        # Вычисляем хеш файла
        hasher = SHA256Hash()
        file_hash = hasher.hash_file(filepath)
        
        # Проверяем что хеш совпадает с подписанным
        if file_hash != signed_msg.message:
            return False
        
        # Проверяем подпись
        return self.verify_signed_message(signed_msg)
    
    def save_public_key(self, filepath: str) -> None:
        """Сохранение публичного ключа"""
        if isinstance(self.signer, RSASignature):
            self.signer.rsa_crypto.save_public_key(filepath)
        else:
            self.signer.ed_crypto.save_public_key(filepath)
    
    def save_private_key(self, filepath: str, password: str = None) -> None:
        """Сохранение приватного ключа"""
        if isinstance(self.signer, RSASignature):
            self.signer.rsa_crypto.save_private_key(filepath, password)
        else:
            self.signer.ed_crypto.save_private_key(filepath, password)
    
    def load_public_key(self, filepath: str) -> None:
        """Загрузка публичного ключа"""
        if isinstance(self.signer, RSASignature):
            self.signer.rsa_crypto.load_public_key(filepath)
        else:
            self.signer.ed_crypto.load_public_key(filepath)
    
    def load_private_key(self, filepath: str, password: str = None) -> None:
        """Загрузка приватного ключа"""
        if isinstance(self.signer, RSASignature):
            self.signer.rsa_crypto.load_private_key(filepath, password)
        else:
            self.signer.ed_crypto.load_private_key(filepath, password)