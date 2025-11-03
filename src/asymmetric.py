"""
Асимметричное шифрование: RSA, Ed25519
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple
from .utils import CryptoUtils


class RSACrypto:
    """RSA шифрование и управление ключами"""
    
    def __init__(self, key_size: int = 2048):
        """
        Args:
            key_size: Размер ключа в битах (2048, 3072, 4096)
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Генерация пары ключей"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def encrypt(self, plaintext: bytes, public_key: rsa.RSAPublicKey = None) -> bytes:
        """
        Шифрование данных публичным ключом
        
        Максимальный размер данных: key_size/8 - 66 байт
        Для RSA-2048: 256 - 66 = 190 байт
        """
        if public_key is None:
            public_key = self.public_key
        
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt(self, ciphertext: bytes, private_key: rsa.RSAPrivateKey = None) -> bytes:
        """Расшифровка данных приватным ключом"""
        if private_key is None:
            private_key = self.private_key
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def save_private_key(self, filepath: str, password: str = None) -> None:
        """
        Сохранение приватного ключа в файл
        
        Args:
            filepath: Путь к файлу
            password: Пароль для шифрования ключа (опционально)
        """
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        CryptoUtils.save_to_file(filepath, pem)
    
    def save_public_key(self, filepath: str) -> None:
        """Сохранение публичного ключа в файл"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        CryptoUtils.save_to_file(filepath, pem)
    
    def load_private_key(self, filepath: str, password: str = None) -> rsa.RSAPrivateKey:
        """Загрузка приватного ключа из файла"""
        pem = CryptoUtils.load_from_file(filepath)
        
        pwd = password.encode() if password else None
        self.private_key = serialization.load_pem_private_key(
            pem, password=pwd, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return self.private_key
    
    def load_public_key(self, filepath: str) -> rsa.RSAPublicKey:
        """Загрузка публичного ключа из файла"""
        pem = CryptoUtils.load_from_file(filepath)
        self.public_key = serialization.load_pem_public_key(
            pem, backend=default_backend()
        )
        return self.public_key
    
    def get_max_message_size(self) -> int:
        """Максимальный размер сообщения для шифрования"""
        # OAEP padding добавляет 2*hash_length + 2 байта
        # Для SHA-256: 2*32 + 2 = 66 байт
        return (self.key_size // 8) - 66


class Ed25519Crypto:
    """Ed25519 для цифровых подписей (быстрее и безопаснее RSA)"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Генерация пары ключей"""
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def sign(self, message: bytes, private_key: ed25519.Ed25519PrivateKey = None) -> bytes:
        """Подпись сообщения"""
        if private_key is None:
            private_key = self.private_key
        
        signature = private_key.sign(message)
        return signature
    
    def verify(self, message: bytes, signature: bytes, 
               public_key: ed25519.Ed25519PublicKey = None) -> bool:
        """
        Проверка подписи
        
        Returns:
            True если подпись валидна, False иначе
        """
        if public_key is None:
            public_key = self.public_key
        
        try:
            public_key.verify(signature, message)
            return True
        except Exception:
            return False
    
    def save_private_key(self, filepath: str, password: str = None) -> None:
        """Сохранение приватного ключа"""
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        CryptoUtils.save_to_file(filepath, pem)
    
    def save_public_key(self, filepath: str) -> None:
        """Сохранение публичного ключа"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        CryptoUtils.save_to_file(filepath, pem)
    
    def load_private_key(self, filepath: str, password: str = None) -> ed25519.Ed25519PrivateKey:
        """Загрузка приватного ключа"""
        pem = CryptoUtils.load_from_file(filepath)
        pwd = password.encode() if password else None
        self.private_key = serialization.load_pem_private_key(
            pem, password=pwd, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return self.private_key
    
    def load_public_key(self, filepath: str) -> ed25519.Ed25519PublicKey:
        """Загрузка публичного ключа"""
        pem = CryptoUtils.load_from_file(filepath)
        self.public_key = serialization.load_pem_public_key(
            pem, backend=default_backend()
        )
        return self.public_key