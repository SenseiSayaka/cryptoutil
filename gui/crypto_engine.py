"""Движок для выполнения криптографических операций через GUI"""
import os
import traceback
from typing import Optional
from dataclasses import dataclass

from src.symmetric import AESCipher, ChaCha20Cipher, encrypt_data, decrypt_data
from src.asymmetric import RSACrypto, Ed25519Crypto
from src.hybrid import HybridCrypto
from src.hashing import HashManager, calculate_file_hash
from src.signatures import SignatureManager
from src.utils import CryptoUtils

from .profiles import EncryptionProfile


@dataclass
class OperationResult:
    success: bool
    message: str
    output_path: Optional[str] = None
    details: Optional[dict] = None
    error: Optional[str] = None


class CryptoEngine:
    """Выполнение криптоопераций по профилю"""

    @staticmethod
    def encrypt_file(filepath: str, profile: EncryptionProfile,
                     password: str = None, output_dir: str = None) -> OperationResult:
        """
        Шифрование файла
        
        Логика:
        - symmetric + пароль: шифруем паролем, salt в начале файла
        - symmetric без пароля: генерируем ключ, сохраняем .key файл
        - hybrid: нужен ТОЛЬКО публичный ключ (приватный НЕ нужен для шифрования)
        - asymmetric: нужен ТОЛЬКО публичный ключ
        """
        try:
            filename = os.path.basename(filepath)
            if output_dir is None:
                output_dir = os.path.dirname(filepath)
            output_path = os.path.join(output_dir, filename + ".encrypted")

            details = {}

            # ── SYMMETRIC ───────────────────────────────────────────
            if profile.mode == "symmetric":
                if not password and profile.use_password:
                    return OperationResult(
                        False,
                        "Требуется пароль для шифрования. "
                        "Введите пароль в поле выше."
                    )

                with open(filepath, "rb") as f:
                    data = f.read()

                cipher_class = AESCipher if profile.symmetric_algorithm == "AES" else ChaCha20Cipher

                if password:
                    # Шифруем паролем: salt(16) + encrypted_data
                    cipher, salt = cipher_class.from_password(password)
                    encrypted = cipher.encrypt(data)
                    result_data = salt + encrypted
                    details["key_source"] = "пароль"
                else:
                    # Генерируем случайный ключ и сохраняем его
                    key = CryptoUtils.generate_random_bytes(32)
                    cipher = cipher_class(key)
                    encrypted = cipher.encrypt(data)
                    result_data = encrypted

                    # Сохраняем ключ рядом с зашифрованным файлом
                    key_path = output_path + ".key"
                    with open(key_path, "wb") as f:
                        f.write(key)
                    details["key_source"] = "файл ключа"
                    details["key_file"] = key_path

                with open(output_path, "wb") as f:
                    f.write(result_data)

            # ── HYBRID ──────────────────────────────────────────────
            elif profile.mode == "hybrid":
                hybrid = HybridCrypto(profile.symmetric_algorithm, profile.rsa_key_size)
                keys_generated = False

                # Для шифрования нужен ТОЛЬКО публичный ключ
                if profile.public_key_path and os.path.exists(profile.public_key_path):
                    # Загружаем только публичный ключ (пароль НЕ нужен)
                    hybrid.rsa_crypto.load_public_key(profile.public_key_path)
                    details["key_source"] = "публичный ключ из файла"
                elif profile.private_key_path and os.path.exists(profile.private_key_path):
                    # Если есть только приватный ключ — извлекаем из него публичный
                    try:
                        hybrid.rsa_crypto.load_private_key(
                            profile.private_key_path,
                            password if password else None
                        )
                        details["key_source"] = "публичный ключ извлечён из приватного"
                    except Exception as key_err:
                        if "encrypted" in str(key_err).lower() or "password" in str(key_err).lower():
                            return OperationResult(
                                False,
                                "Приватный ключ зашифрован паролем. "
                                "Введите пароль или укажите публичный ключ отдельно.\n"
                                "Для шифрования достаточно только публичного ключа."
                            )
                        raise
                else:
                    # Нет ключей — генерируем новую пару
                    hybrid.generate_keypair()
                    keys_generated = True

                    keys_dir = os.path.join(output_dir, "keys")
                    os.makedirs(keys_dir, exist_ok=True)

                    priv_path = os.path.join(keys_dir, "private_key.pem")
                    pub_path = os.path.join(keys_dir, "public_key.pem")

                    hybrid.save_keypair(priv_path, pub_path, password)

                    details["key_source"] = "новые ключи сгенерированы"
                    details["private_key_path"] = priv_path
                    details["public_key_path"] = pub_path
                    details["warning"] = (
                        "ВАЖНО: Сохраните приватный ключ! "
                        "Без него расшифровка невозможна."
                    )

                hybrid.encrypt_file(filepath, output_path)

            # ── ASYMMETRIC ──────────────────────────────────────────
            elif profile.mode == "asymmetric":
                rsa_crypto = RSACrypto(profile.rsa_key_size)
                keys_generated = False

                if profile.public_key_path and os.path.exists(profile.public_key_path):
                    rsa_crypto.load_public_key(profile.public_key_path)
                    details["key_source"] = "публичный ключ из файла"
                elif profile.private_key_path and os.path.exists(profile.private_key_path):
                    try:
                        rsa_crypto.load_private_key(
                            profile.private_key_path,
                            password if password else None
                        )
                        details["key_source"] = "публичный ключ извлечён из приватного"
                    except Exception as key_err:
                        if "encrypted" in str(key_err).lower() or "password" in str(key_err).lower():
                            return OperationResult(
                                False,
                                "Приватный ключ зашифрован паролем. "
                                "Введите пароль или укажите публичный ключ."
                            )
                        raise
                else:
                    rsa_crypto.generate_keypair()
                    keys_generated = True

                    keys_dir = os.path.join(output_dir, "keys")
                    os.makedirs(keys_dir, exist_ok=True)

                    priv_path = os.path.join(keys_dir, "private_key.pem")
                    pub_path = os.path.join(keys_dir, "public_key.pem")

                    rsa_crypto.save_private_key(priv_path, password)
                    rsa_crypto.save_public_key(pub_path)

                    details["private_key_path"] = priv_path
                    details["public_key_path"] = pub_path
                    details["warning"] = "ВАЖНО: Сохраните приватный ключ!"

                with open(filepath, "rb") as f:
                    data = f.read()

                max_size = rsa_crypto.get_max_message_size()
                if len(data) > max_size:
                    return OperationResult(
                        False,
                        f"Файл слишком большой для прямого RSA "
                        f"({len(data)} байт > {max_size} байт макс). "
                        f"Используйте гибридный режим (hybrid)."
                    )

                encrypted = rsa_crypto.encrypt(data)
                with open(output_path, "wb") as f:
                    f.write(encrypted)

            # ── Автоподпись ─────────────────────────────────────────
            sig_path = None
            if profile.auto_sign:
                sig_result = CryptoEngine.sign_file(filepath, profile, password)
                if sig_result.success:
                    sig_path = sig_result.output_path
                    details["signature_file"] = sig_path
                else:
                    details["signature_error"] = sig_result.message

            # ── Хеш исходного файла ────────────────────────────────
            try:
                file_hash = calculate_file_hash(filepath, profile.hash_algorithm)
                details["hash"] = file_hash
                details["hash_algorithm"] = profile.hash_algorithm
            except Exception:
                pass

            details["algorithm"] = f"{profile.mode}: {profile.symmetric_algorithm}"
            details["output_size"] = os.path.getsize(output_path)

            msg = "Файл успешно зашифрован"
            if details.get("warning"):
                msg += f"\n⚠️ {details['warning']}"

            return OperationResult(True, msg, output_path, details)

        except Exception as e:
            return OperationResult(
                False,
                f"Ошибка шифрования: {str(e)}",
                error=traceback.format_exc()
            )

    @staticmethod
    def decrypt_file(filepath: str, profile: EncryptionProfile,
                     password: str = None, output_dir: str = None) -> OperationResult:
        """
        Расшифровка файла
        
        Логика:
        - symmetric + пароль: salt в первых 16 байтах
        - symmetric без пароля: ищем .key файл рядом
        - hybrid/asymmetric: нужен ПРИВАТНЫЙ ключ (+ пароль если ключ зашифрован)
        """
        try:
            filename = os.path.basename(filepath)
            if filename.endswith(".encrypted"):
                original_name = filename[:-10]
            else:
                original_name = "decrypted_" + filename

            if output_dir is None:
                output_dir = os.path.dirname(filepath)
            output_path = os.path.join(output_dir, original_name)

            # ── SYMMETRIC ───────────────────────────────────────────
            if profile.mode == "symmetric":
                with open(filepath, "rb") as f:
                    data = f.read()

                cipher_class = AESCipher if profile.symmetric_algorithm == "AES" else ChaCha20Cipher

                if password:
                    # Первые 16 байт — salt
                    salt = data[:16]
                    encrypted = data[16:]
                    cipher, _ = cipher_class.from_password(password, salt)
                    decrypted = cipher.decrypt(encrypted)
                else:
                    # Ищем файл ключа
                    key_path = filepath + ".key"
                    if not os.path.exists(key_path):
                        # Попробуем найти ключ без .encrypted
                        alt_key_path = filepath.replace(".encrypted", "") + ".encrypted.key"
                        if os.path.exists(alt_key_path):
                            key_path = alt_key_path
                        else:
                            return OperationResult(
                                False,
                                f"Не найден файл ключа.\n"
                                f"Искали: {key_path}\n"
                                f"Введите пароль если файл был зашифрован паролем."
                            )
                    with open(key_path, "rb") as f:
                        key = f.read()
                    cipher = cipher_class(key)
                    decrypted = cipher.decrypt(data)

                with open(output_path, "wb") as f:
                    f.write(decrypted)

            # ── HYBRID ──────────────────────────────────────────────
            elif profile.mode == "hybrid":
                # Для расшифровки НУЖЕН приватный ключ
                if not profile.private_key_path or not os.path.exists(profile.private_key_path):
                    return OperationResult(
                        False,
                        "Для расшифровки нужен приватный ключ.\n"
                        "Укажите путь к приватному ключу в настройках профиля\n"
                        "или загрузите ключи с USB (вкладка 'Ключи')."
                    )

                hybrid = HybridCrypto(profile.symmetric_algorithm, profile.rsa_key_size)

                try:
                    hybrid.rsa_crypto.load_private_key(
                        profile.private_key_path,
                        password if password else None
                    )
                except Exception as key_err:
                    err_str = str(key_err).lower()
                    if "encrypted" in err_str or "password" in err_str:
                        return OperationResult(
                            False,
                            "Приватный ключ зашифрован паролем.\n"
                            "Введите пароль в поле выше."
                        )
                    elif "bad decrypt" in err_str or "wrong" in err_str:
                        return OperationResult(
                            False,
                            "Неверный пароль для приватного ключа."
                        )
                    raise

                hybrid.decrypt_file(filepath, output_path)

            # ── ASYMMETRIC ──────────────────────────────────────────
            elif profile.mode == "asymmetric":
                if not profile.private_key_path or not os.path.exists(profile.private_key_path):
                    return OperationResult(
                        False,
                        "Для расшифровки нужен приватный ключ.\n"
                        "Укажите путь в настройках профиля."
                    )

                rsa_crypto = RSACrypto(profile.rsa_key_size)

                try:
                    rsa_crypto.load_private_key(
                        profile.private_key_path,
                        password if password else None
                    )
                except Exception as key_err:
                    err_str = str(key_err).lower()
                    if "encrypted" in err_str or "password" in err_str:
                        return OperationResult(
                            False,
                            "Приватный ключ зашифрован паролем.\n"
                            "Введите пароль в поле выше."
                        )
                    raise

                with open(filepath, "rb") as f:
                    encrypted = f.read()

                decrypted = rsa_crypto.decrypt(encrypted)
                with open(output_path, "wb") as f:
                    f.write(decrypted)

            return OperationResult(True, "Файл успешно расшифрован", output_path)

        except Exception as e:
            err_msg = str(e)
            # Дружелюбные сообщения об ошибках
            if "tag" in err_msg.lower() or "authentication" in err_msg.lower():
                return OperationResult(
                    False,
                    "Ошибка расшифровки: данные повреждены или неверный пароль/ключ.\n"
                    "Проверьте что используете тот же профиль и пароль.",
                    error=traceback.format_exc()
                )
            return OperationResult(
                False,
                f"Ошибка расшифровки: {err_msg}",
                error=traceback.format_exc()
            )

    @staticmethod
    def sign_file(filepath: str, profile: EncryptionProfile,
                  password: str = None) -> OperationResult:
        """Подпись файла"""
        try:
            sig_manager = SignatureManager(profile.signature_algorithm)

            if profile.private_key_path and os.path.exists(profile.private_key_path):
                try:
                    sig_manager.load_private_key(
                        profile.private_key_path,
                        password if password else None
                    )
                except Exception as key_err:
                    err_str = str(key_err).lower()
                    if "encrypted" in err_str or "password" in err_str:
                        return OperationResult(
                            False,
                            "Приватный ключ для подписи зашифрован паролем.\n"
                            "Введите пароль."
                        )
                    raise
            # Если ключ не указан — SignatureManager генерирует свой при создании

            sig_path = sig_manager.sign_file(filepath)
            return OperationResult(
                True,
                f"Файл подписан: {os.path.basename(sig_path)}",
                sig_path
            )

        except Exception as e:
            return OperationResult(
                False,
                f"Ошибка подписи: {str(e)}",
                error=traceback.format_exc()
            )

    @staticmethod
    def verify_signature(filepath: str, signature_path: str,
                         profile: EncryptionProfile) -> OperationResult:
        """Проверка подписи"""
        try:
            if not os.path.exists(signature_path):
                return OperationResult(
                    False,
                    f"Файл подписи не найден: {signature_path}\n"
                    f"Укажите путь к .sig файлу."
                )

            sig_manager = SignatureManager(profile.signature_algorithm)

            if profile.public_key_path and os.path.exists(profile.public_key_path):
                sig_manager.load_public_key(profile.public_key_path)

            is_valid = sig_manager.verify_file_signature(filepath, signature_path)

            if is_valid:
                return OperationResult(True, "Подпись ВАЛИДНА — файл не изменён")
            else:
                return OperationResult(False, "Подпись НЕДЕЙСТВИТЕЛЬНА — файл изменён или ключ не совпадает")

        except Exception as e:
            return OperationResult(
                False,
                f"Ошибка проверки подписи: {str(e)}",
                error=traceback.format_exc()
            )

    @staticmethod
    def hash_file(filepath: str, algorithm: str = "sha256") -> OperationResult:
        """Хеширование файла"""
        try:
            file_hash = calculate_file_hash(filepath, algorithm)
            return OperationResult(
                True,
                f"Хеш ({algorithm}): {file_hash}",
                details={"hash": file_hash, "algorithm": algorithm}
            )
        except Exception as e:
            return OperationResult(
                False,
                f"Ошибка хеширования: {str(e)}",
                error=traceback.format_exc()
            )

    @staticmethod
    def generate_keys(profile: EncryptionProfile, output_dir: str,
                      password: str = None) -> OperationResult:
        """Генерация ключей по профилю"""
        try:
            os.makedirs(output_dir, exist_ok=True)

            priv_path = os.path.join(output_dir, "private_key.pem")
            pub_path = os.path.join(output_dir, "public_key.pem")

            key_type = None

            if profile.mode in ("hybrid", "asymmetric"):
                rsa_crypto = RSACrypto(profile.rsa_key_size)
                rsa_crypto.generate_keypair()
                rsa_crypto.save_private_key(priv_path, password)
                rsa_crypto.save_public_key(pub_path)
                key_type = f"RSA-{profile.rsa_key_size}"

            elif profile.signature_algorithm == "Ed25519":
                ed_crypto = Ed25519Crypto()
                ed_crypto.generate_keypair()
                ed_crypto.save_private_key(priv_path, password)
                ed_crypto.save_public_key(pub_path)
                key_type = "Ed25519"

            else:
                # Для symmetric — генерируем Ed25519 для подписей
                ed_crypto = Ed25519Crypto()
                ed_crypto.generate_keypair()
                ed_crypto.save_private_key(priv_path, password)
                ed_crypto.save_public_key(pub_path)
                key_type = "Ed25519 (для подписей)"

            if key_type is None:
                return OperationResult(False, "Не удалось определить тип ключей")

            password_note = " (зашифрован паролем)" if password else " (без пароля)"

            return OperationResult(
                True,
                f"{key_type} ключи сгенерированы{password_note}",
                output_dir,
                {
                    "private_key_path": priv_path,
                    "public_key_path": pub_path,
                    "key_type": key_type,
                    "encrypted": bool(password),
                }
            )

        except Exception as e:
            return OperationResult(
                False,
                f"Ошибка генерации ключей: {str(e)}",
                error=traceback.format_exc()
            )