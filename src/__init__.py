"""
Криптографическая утилита
Полный набор криптографических алгоритмов для шифрования, подписи и хеширования
"""

__version__ = "1.0.0"
__author__ = "Jan Pachimari"

# Симметричное шифрование
from .symmetric import (
    AESCipher,
    ChaCha20Cipher,
    StreamCipher,
    encrypt_data,
    decrypt_data
)

# Асимметричное шифрование
from .asymmetric import (
    RSACrypto,
    Ed25519Crypto
)

# Хеширование
from .hashing import (
    SHA256Hash,
    SHA512Hash,
    BLAKE2Hash,
    SHA3Hash,
    HashManager,
    HMAC,
    calculate_file_hash,
    verify_file_integrity
)

# Цифровые подписи
from .signatures import (
    RSASignature,
    Ed25519Signature,
    SignedMessage,
    SignatureManager
)

# Гибридное шифрование
from .hybrid import (
    HybridCrypto,
    StreamHybridCrypto
)

# Утилиты
from .utils import (
    CryptoUtils,
    derive_key_from_password,
    FileProcessor
)

__all__ = [
    # Symmetric
    'AESCipher',
    'ChaCha20Cipher',
    'StreamCipher',
    'encrypt_data',
    'decrypt_data',
    
    # Asymmetric
    'RSACrypto',
    'Ed25519Crypto',
    
    # Hashing
    'SHA256Hash',
    'SHA512Hash',
    'BLAKE2Hash',
    'SHA3Hash',
    'HashManager',
    'HMAC',
    'calculate_file_hash',
    'verify_file_integrity',
    
    # Signatures
    'RSASignature',
    'Ed25519Signature',
    'SignedMessage',
    'SignatureManager',
    
    # Hybrid
    'HybridCrypto',
    'StreamHybridCrypto',
    
    # Utils
    'CryptoUtils',
    'derive_key_from_password',
    'FileProcessor',
]


def get_version():
    """Получение версии библиотеки"""
    return __version__


def list_algorithms():
    """Список доступных алгоритмов"""
    return {
        'symmetric': ['AES-256-GCM', 'ChaCha20-Poly1305'],
        'asymmetric': ['RSA-2048', 'RSA-3072', 'RSA-4096', 'Ed25519'],
        'hashing': ['SHA-256', 'SHA-512', 'SHA3-256', 'SHA3-512', 'BLAKE2b'],
        'signatures': ['RSA-PSS', 'Ed25519']
    }