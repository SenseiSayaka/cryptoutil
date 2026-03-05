"""
Цифровые подписи: RSA-PSS, Ed25519
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import Optional
import json
from datetime import datetime
from .hashing import SHA256Hash
from .asymmetric import RSACrypto, Ed25519Crypto
from .utils import CryptoUtils


class SignatureBase:
    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, message: bytes, signature: bytes) -> bool:
        raise NotImplementedError


class RSASignature(SignatureBase):
    """RSA-PSS подпись. Всегда генерирует keypair при создании."""

    def __init__(self, rsa_crypto: RSACrypto = None, key_size: int = 2048):
        if rsa_crypto is None:
            rsa_crypto = RSACrypto(key_size)
            rsa_crypto.generate_keypair()   # ← всегда генерируем, никогда не None
        self.rsa_crypto = rsa_crypto

    def sign(self, message: bytes) -> bytes:
        return self.rsa_crypto.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.rsa_crypto.public_key.verify(
                signature, message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


class Ed25519Signature(SignatureBase):
    """Ed25519 подпись. Всегда генерирует keypair при создании."""

    def __init__(self, ed_crypto: Ed25519Crypto = None):
        if ed_crypto is None:
            ed_crypto = Ed25519Crypto()
            ed_crypto.generate_keypair()   # ← всегда генерируем, никогда не None
        self.ed_crypto = ed_crypto

    def sign(self, message: bytes) -> bytes:
        return self.ed_crypto.private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.ed_crypto.public_key.verify(signature, message)
            return True
        except Exception:
            return False


class SignedMessage:
    """Контейнер подписанного сообщения с метаданными"""

    def __init__(self, message: bytes, signature: bytes,
                 algorithm: str, metadata: dict = None):
        self.message   = message
        self.signature = signature
        self.algorithm = algorithm
        self.metadata  = metadata or {}
        if 'timestamp' not in self.metadata:
            self.metadata['timestamp'] = datetime.utcnow().isoformat()

    def to_bytes(self) -> bytes:
        import struct
        algo_b = self.algorithm.encode('utf-8')
        meta_b = json.dumps(self.metadata).encode('utf-8')
        r = bytearray()
        r.append(1)                                    # version
        r.append(len(algo_b))
        r.extend(algo_b)
        r.extend(struct.pack('<I', len(meta_b)))
        r.extend(meta_b)
        r.extend(struct.pack('<H', len(self.signature)))
        r.extend(self.signature)
        r.extend(self.message)
        return bytes(r)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SignedMessage':
        import struct
        off = 0
        _v = data[off]; off += 1
        al = data[off]; off += 1
        algorithm = data[off:off + al].decode('utf-8'); off += al
        ml = struct.unpack('<I', data[off:off + 4])[0]; off += 4
        metadata = json.loads(data[off:off + ml].decode('utf-8')); off += ml
        sl = struct.unpack('<H', data[off:off + 2])[0]; off += 2
        signature = data[off:off + sl]; off += sl
        message = data[off:]
        return cls(message, signature, algorithm, metadata)

    def save_to_file(self, filepath: str) -> None:
        CryptoUtils.save_to_file(filepath, self.to_bytes())

    @classmethod
    def load_from_file(cls, filepath: str) -> 'SignedMessage':
        return cls.from_bytes(CryptoUtils.load_from_file(filepath))


class SignatureManager:
    """
    Менеджер подписей.

    Использование:
        # Вариант 1 — передать готовый crypto-объект с ключами:
        rsa = RSACrypto(); rsa.load_private_key(path)
        mgr = SignatureManager.from_crypto(rsa)

        # Вариант 2 — загрузить ключи после создания:
        mgr = SignatureManager('RSA')
        mgr.load_private_key(path)
        mgr.sign_file(filepath)
    """

    def __init__(self, algorithm: str = 'Ed25519'):
        self.algorithm = algorithm
        if algorithm == 'RSA':
            self.signer = RSASignature()
        elif algorithm == 'Ed25519':
            self.signer = Ed25519Signature()
        else:
            raise ValueError(f"Неизвестный алгоритм подписи: {algorithm}")

    @classmethod
    def from_crypto(cls, crypto) -> 'SignatureManager':
        """
        Создать менеджер из готового RSACrypto или Ed25519Crypto с ключами.
        Ключи уже загружены — не нужно вызывать load_private_key отдельно.
        """
        if isinstance(crypto, RSACrypto):
            mgr = cls.__new__(cls)
            mgr.algorithm = 'RSA'
            mgr.signer = RSASignature(rsa_crypto=crypto)
            return mgr
        elif isinstance(crypto, Ed25519Crypto):
            mgr = cls.__new__(cls)
            mgr.algorithm = 'Ed25519'
            mgr.signer = Ed25519Signature(ed_crypto=crypto)
            return mgr
        else:
            raise TypeError(f"Ожидался RSACrypto или Ed25519Crypto, получен {type(crypto)}")

    # ── Подпись файла ────────────────────────────────────────────────────────

    def sign_file(self, filepath: str, output_path: str = None,
                  metadata: dict = None) -> str:
        """
        Подписать файл. Схема:
          SHA-256(file) → signer.sign() → .sig

        Returns: путь к .sig файлу
        """
        file_hash = SHA256Hash().hash_file(filepath)
        signature = self.signer.sign(file_hash)

        meta = dict(metadata or {})
        meta['original_file']  = filepath
        meta['hash_algorithm'] = 'sha256'

        signed_msg = SignedMessage(file_hash, signature, self.algorithm, meta)

        if output_path is None:
            output_path = f"{filepath}.sig"

        signed_msg.save_to_file(output_path)
        return output_path

    # ── Проверка подписи файла ───────────────────────────────────────────────

    def verify_file_signature(self, filepath: str, signature_path: str) -> bool:
        """
        Проверить подпись. Схема:
          SHA-256(file) == hash_in_sig  AND  verify(hash, signature, public_key)
        """
        signed_msg   = SignedMessage.load_from_file(signature_path)
        current_hash = SHA256Hash().hash_file(filepath)

        # Хеш в .sig должен совпасть с реальным хешем файла
        if current_hash != signed_msg.message:
            return False

        return self.signer.verify(signed_msg.message, signed_msg.signature)

    # ── Управление ключами ───────────────────────────────────────────────────

    def load_private_key(self, filepath: str, password: str = None) -> None:
        """Загрузить приватный ключ нужного типа."""
        if isinstance(self.signer, RSASignature):
            self.signer.rsa_crypto.load_private_key(filepath, password)
        else:
            self.signer.ed_crypto.load_private_key(filepath, password)

    def load_public_key(self, filepath: str) -> None:
        """Загрузить публичный ключ нужного типа."""
        if isinstance(self.signer, RSASignature):
            self.signer.rsa_crypto.load_public_key(filepath)
        else:
            self.signer.ed_crypto.load_public_key(filepath)

    def save_private_key(self, filepath: str, password: str = None) -> None:
        if isinstance(self.signer, RSASignature):
            self.signer.rsa_crypto.save_private_key(filepath, password)
        else:
            self.signer.ed_crypto.save_private_key(filepath, password)

    def save_public_key(self, filepath: str) -> None:
        if isinstance(self.signer, RSASignature):
            self.signer.rsa_crypto.save_public_key(filepath)
        else:
            self.signer.ed_crypto.save_public_key(filepath)
