"""Управление ключами, включая хранение на USB"""
import os
import platform
import string
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class KeyLocation:
    """Информация о расположении ключей"""
    path: str
    is_removable: bool
    drive_label: str
    free_space_mb: float


class KeyManager:
    """Менеджер ключей с поддержкой USB-накопителей"""

    KEY_DIR_NAME = ".crypto_keys"

    @staticmethod
    def detect_removable_drives() -> list[KeyLocation]:
        """Обнаружение съёмных накопителей"""
        drives = []
        system = platform.system()

        if system == "Windows":
            try:
                import ctypes
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drive_path = f"{letter}:\\"
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                        # 2 = DRIVE_REMOVABLE
                        if drive_type == 2:
                            try:
                                import shutil
                                usage = shutil.disk_usage(drive_path)
                                drives.append(KeyLocation(
                                    path=drive_path,
                                    is_removable=True,
                                    drive_label=f"USB ({letter}:)",
                                    free_space_mb=usage.free / (1024 * 1024)
                                ))
                            except (OSError, PermissionError):
                                pass
                    bitmask >>= 1
            except Exception:
                pass

        elif system == "Linux":
            media_dirs = [
                f"/media/{os.getenv('USER', 'user')}",
                "/mnt",
                "/run/media/" + os.getenv('USER', 'user'),
            ]
            for media_dir in media_dirs:
                if os.path.exists(media_dir):
                    try:
                        for item in os.listdir(media_dir):
                            mount_path = os.path.join(media_dir, item)
                            if os.path.ismount(mount_path):
                                import shutil
                                try:
                                    usage = shutil.disk_usage(mount_path)
                                    drives.append(KeyLocation(
                                        path=mount_path,
                                        is_removable=True,
                                        drive_label=f"USB ({item})",
                                        free_space_mb=usage.free / (1024 * 1024)
                                    ))
                                except (OSError, PermissionError):
                                    pass
                    except PermissionError:
                        pass

        elif system == "Darwin":
            volumes_dir = "/Volumes"
            if os.path.exists(volumes_dir):
                for item in os.listdir(volumes_dir):
                    vol_path = os.path.join(volumes_dir, item)
                    if item != "Macintosh HD" and os.path.ismount(vol_path):
                        import shutil
                        try:
                            usage = shutil.disk_usage(vol_path)
                            drives.append(KeyLocation(
                                path=vol_path,
                                is_removable=True,
                                drive_label=f"USB ({item})",
                                free_space_mb=usage.free / (1024 * 1024)
                            ))
                        except (OSError, PermissionError):
                            pass

        return drives

    @classmethod
    def get_key_storage_path(cls, drive_path: str, profile_name: str = "default") -> str:
        """Путь к хранилищу ключей на накопителе"""
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in profile_name)
        key_dir = os.path.join(drive_path, cls.KEY_DIR_NAME, safe_name)
        os.makedirs(key_dir, exist_ok=True)
        return key_dir

    @classmethod
    def save_keys_to_drive(cls, drive_path: str, profile_name: str,
                           private_key_data: bytes, public_key_data: bytes,
                           password: str = None) -> dict:
        """Сохранение ключей на накопитель"""
        key_dir = cls.get_key_storage_path(drive_path, profile_name)

        priv_path = os.path.join(key_dir, "private_key.pem")
        pub_path = os.path.join(key_dir, "public_key.pem")

        with open(priv_path, "wb") as f:
            f.write(private_key_data)
        with open(pub_path, "wb") as f:
            f.write(public_key_data)

        # Сохраняем метаинформацию
        import json
        from datetime import datetime
        meta = {
            "profile_name": profile_name,
            "created_at": datetime.now().isoformat(),
            "has_password": password is not None,
        }
        meta_path = os.path.join(key_dir, "meta.json")
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        return {
            "private_key_path": priv_path,
            "public_key_path": pub_path,
            "meta_path": meta_path,
        }

    @classmethod
    def find_keys_on_drive(cls, drive_path: str) -> list[dict]:
        """Поиск ключей на накопителе"""
        keys_found = []
        key_base = os.path.join(drive_path, cls.KEY_DIR_NAME)

        if not os.path.exists(key_base):
            return keys_found

        for profile_dir in os.listdir(key_base):
            full_path = os.path.join(key_base, profile_dir)
            if os.path.isdir(full_path):
                priv_path = os.path.join(full_path, "private_key.pem")
                pub_path = os.path.join(full_path, "public_key.pem")
                meta_path = os.path.join(full_path, "meta.json")

                meta = {}
                if os.path.exists(meta_path):
                    try:
                        import json
                        with open(meta_path, "r") as f:
                            meta = json.load(f)
                    except Exception:
                        pass

                keys_found.append({
                    "profile_name": profile_dir,
                    "private_key_exists": os.path.exists(priv_path),
                    "public_key_exists": os.path.exists(pub_path),
                    "private_key_path": priv_path if os.path.exists(priv_path) else None,
                    "public_key_path": pub_path if os.path.exists(pub_path) else None,
                    "meta": meta,
                    "drive_path": drive_path,
                })

        return keys_found

    @classmethod
    def get_local_key_dir(cls) -> str:
        """Локальная директория для ключей"""
        key_dir = os.path.join(Path.home(), ".crypto_util", "keys")
        os.makedirs(key_dir, exist_ok=True)
        return key_dir