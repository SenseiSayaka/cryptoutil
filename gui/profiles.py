"""Управление профилями шифрования"""
import json
import os
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional


@dataclass
class EncryptionProfile:
    """Профиль шифрования"""
    name: str
    description: str = ""
    # Тип операции
    mode: str = "hybrid"  # hybrid, symmetric, asymmetric
    # Симметричный алгоритм
    symmetric_algorithm: str = "AES"  # AES, ChaCha20
    # Размер ключа RSA
    rsa_key_size: int = 2048  # 2048, 3072, 4096
    # Алгоритм подписи
    signature_algorithm: str = "Ed25519"  # RSA, Ed25519
    # Алгоритм хеширования
    hash_algorithm: str = "sha256"
    # Пути к ключам шифрования (RSA hybrid/asymmetric)
    private_key_path: str = ""
    public_key_path: str = ""
    # Пути к ключам подписи (отдельно от шифрования!)
    # Если пусты — sign_file использует private_key_path как fallback
    signing_private_key_path: str = ""
    signing_public_key_path: str = ""
    # Использовать пароль
    use_password: bool = False
    # Автоподпись
    auto_sign: bool = False
    # Создано
    created_at: str = ""
    # Цвет иконки
    color: str = "#3b82f6"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict):
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


# Предустановленные профили
DEFAULT_PROFILES = [
    EncryptionProfile(
        name="🛡️ Максимальная защита",
        description="RSA-4096 + AES-256 + Ed25519 подпись",
        mode="hybrid",
        symmetric_algorithm="AES",
        rsa_key_size=4096,
        signature_algorithm="Ed25519",
        hash_algorithm="sha512",
        auto_sign=True,
        color="#ef4444",
    ),
    EncryptionProfile(
        name="⚡ Быстрое шифрование",
        description="ChaCha20 с паролем, без RSA",
        mode="symmetric",
        symmetric_algorithm="ChaCha20",
        use_password=True,
        hash_algorithm="blake2",
        color="#f59e0b",
    ),
    EncryptionProfile(
        name="📧 Для переписки",
        description="RSA-2048 + AES-256, стандартная защита",
        mode="hybrid",
        symmetric_algorithm="AES",
        rsa_key_size=2048,
        hash_algorithm="sha256",
        color="#3b82f6",
    ),
    EncryptionProfile(
        name="📁 Архивное хранение",
        description="AES-256 с паролем + SHA-512 контрольная сумма",
        mode="symmetric",
        symmetric_algorithm="AES",
        use_password=True,
        hash_algorithm="sha512",
        auto_sign=False,
        color="#8b5cf6",
    ),
]


class ProfileManager:
    """Менеджер профилей"""

    def __init__(self, config_dir: str = None):
        if config_dir is None:
            config_dir = os.path.join(Path.home(), ".crypto_util")
        self.config_dir = config_dir
        self.profiles_file = os.path.join(config_dir, "profiles.json")
        os.makedirs(config_dir, exist_ok=True)
        self.profiles: list[EncryptionProfile] = []
        self.load()

    def load(self):
        if os.path.exists(self.profiles_file):
            try:
                with open(self.profiles_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.profiles = [EncryptionProfile.from_dict(p) for p in data]
            except Exception:
                self.profiles = list(DEFAULT_PROFILES)
                self.save()
        else:
            self.profiles = list(DEFAULT_PROFILES)
            self.save()

    def save(self):
        data = [p.to_dict() for p in self.profiles]
        with open(self.profiles_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def add_profile(self, profile: EncryptionProfile):
        self.profiles.append(profile)
        self.save()

    def remove_profile(self, index: int):
        if 0 <= index < len(self.profiles):
            self.profiles.pop(index)
            self.save()

    def update_profile(self, index: int, profile: EncryptionProfile):
        if 0 <= index < len(self.profiles):
            self.profiles[index] = profile
            self.save()

    def get_profile(self, index: int) -> Optional[EncryptionProfile]:
        if 0 <= index < len(self.profiles):
            return self.profiles[index]
        return None