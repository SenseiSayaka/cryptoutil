"""Движок для выполнения криптографических операций через GUI"""
import os
import traceback
from typing import Optional
from dataclasses import dataclass

from src.symmetric import AESCipher, ChaCha20Cipher
from src.asymmetric import RSACrypto, Ed25519Crypto
from src.hybrid import HybridCrypto
from src.hashing import calculate_file_hash
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

    # ── Шифрование ───────────────────────────────────────────────────────────

    @staticmethod
    def encrypt_file(filepath: str, profile: EncryptionProfile,
                     password: str = None, output_dir: str = None) -> OperationResult:
        try:
            filename = os.path.basename(filepath)
            if output_dir is None:
                output_dir = os.path.dirname(filepath)
            output_path = os.path.join(output_dir, filename + ".encrypted")
            details = {}

            if profile.mode == "symmetric":
                if not password and profile.use_password:
                    return OperationResult(False, "Требуется пароль для шифрования.")

                with open(filepath, "rb") as f:
                    data = f.read()

                cipher_class = AESCipher if profile.symmetric_algorithm == "AES" else ChaCha20Cipher

                if password:
                    cipher, salt = cipher_class.from_password(password)
                    encrypted    = cipher.encrypt(data)
                    result_data  = salt + encrypted
                    details["key_source"] = "пароль"
                else:
                    key = CryptoUtils.generate_random_bytes(32)
                    cipher      = cipher_class(key)
                    encrypted   = cipher.encrypt(data)
                    result_data = encrypted
                    key_path    = output_path + ".key"
                    with open(key_path, "wb") as f:
                        f.write(key)
                    details["key_source"] = "файл ключа"
                    details["key_file"]   = key_path

                with open(output_path, "wb") as f:
                    f.write(result_data)

            elif profile.mode == "hybrid":
                hybrid = HybridCrypto(profile.symmetric_algorithm, profile.rsa_key_size)
                rsa    = _load_or_generate_rsa(profile, output_dir, password, details,
                                               need_private=False)
                hybrid.rsa_crypto = rsa
                hybrid.encrypt_file(filepath, output_path)

            elif profile.mode == "asymmetric":
                rsa = _load_or_generate_rsa(profile, output_dir, password, details,
                                            need_private=False)
                with open(filepath, "rb") as f:
                    data = f.read()
                max_size = rsa.get_max_message_size()
                if len(data) > max_size:
                    return OperationResult(
                        False,
                        f"Файл слишком большой для RSA ({len(data)} > {max_size} байт). "
                        f"Используйте гибридный режим."
                    )
                encrypted = rsa.encrypt(data)
                with open(output_path, "wb") as f:
                    f.write(encrypted)

            # Автоподпись
            if profile.auto_sign:
                sig_result = CryptoEngine.sign_file(filepath, profile, password)
                if sig_result.success:
                    details["signature_file"] = sig_result.output_path
                else:
                    details["signature_error"] = sig_result.message

            try:
                details["hash"]           = calculate_file_hash(filepath, profile.hash_algorithm)
                details["hash_algorithm"] = profile.hash_algorithm
            except Exception:
                pass

            details["algorithm"]   = f"{profile.mode}: {profile.symmetric_algorithm}"
            details["output_size"] = os.path.getsize(output_path)

            msg = "Файл успешно зашифрован"
            if details.get("warning"):
                msg += f"\n⚠️ {details['warning']}"
            return OperationResult(True, msg, output_path, details)

        except Exception as e:
            return OperationResult(False, f"Ошибка шифрования: {e}",
                                   error=traceback.format_exc())

    # ── Расшифровка ──────────────────────────────────────────────────────────

    @staticmethod
    def decrypt_file(filepath: str, profile: EncryptionProfile,
                     password: str = None, output_dir: str = None) -> OperationResult:
        try:
            filename = os.path.basename(filepath)
            original_name = (filename[:-10] if filename.endswith(".encrypted")
                             else "decrypted_" + filename)
            if output_dir is None:
                output_dir = os.path.dirname(filepath)
            output_path = os.path.join(output_dir, original_name)

            if profile.mode == "symmetric":
                with open(filepath, "rb") as f:
                    data = f.read()
                cipher_class = AESCipher if profile.symmetric_algorithm == "AES" else ChaCha20Cipher

                if password:
                    salt      = data[:16]
                    encrypted = data[16:]
                    cipher, _ = cipher_class.from_password(password, salt)
                    decrypted = cipher.decrypt(encrypted)
                else:
                    key_path = filepath + ".key"
                    if not os.path.exists(key_path):
                        alt = filepath.replace(".encrypted", "") + ".encrypted.key"
                        if os.path.exists(alt):
                            key_path = alt
                        else:
                            return OperationResult(
                                False,
                                f"Не найден файл ключа: {key_path}\n"
                                f"Если файл зашифрован паролем — введите пароль."
                            )
                    with open(key_path, "rb") as f:
                        key = f.read()
                    cipher    = cipher_class(key)
                    decrypted = cipher.decrypt(data)

                with open(output_path, "wb") as f:
                    f.write(decrypted)

            elif profile.mode == "hybrid":
                if not profile.private_key_path or not os.path.exists(profile.private_key_path):
                    return OperationResult(False, "Для расшифровки нужен приватный ключ.")
                hybrid = HybridCrypto(profile.symmetric_algorithm, profile.rsa_key_size)
                try:
                    hybrid.rsa_crypto.load_private_key(
                        profile.private_key_path, password if password else None
                    )
                except Exception as e:
                    return _key_error(e, "Приватный ключ зашифрован паролем.")
                hybrid.decrypt_file(filepath, output_path)

            elif profile.mode == "asymmetric":
                if not profile.private_key_path or not os.path.exists(profile.private_key_path):
                    return OperationResult(False, "Для расшифровки нужен приватный ключ.")
                rsa = RSACrypto(profile.rsa_key_size)
                try:
                    rsa.load_private_key(profile.private_key_path, password if password else None)
                except Exception as e:
                    return _key_error(e, "Приватный ключ зашифрован паролем.")
                with open(filepath, "rb") as f:
                    encrypted = f.read()
                decrypted = rsa.decrypt(encrypted)
                with open(output_path, "wb") as f:
                    f.write(decrypted)

            return OperationResult(True, "Файл успешно расшифрован", output_path)

        except Exception as e:
            msg = str(e)
            if "tag" in msg.lower() or "authentication" in msg.lower():
                return OperationResult(
                    False,
                    "Ошибка расшифровки: повреждённые данные или неверный пароль/ключ.",
                    error=traceback.format_exc()
                )
            return OperationResult(False, f"Ошибка расшифровки: {msg}",
                                   error=traceback.format_exc())

    # ── Подпись файла ────────────────────────────────────────────────────────

    @staticmethod
    def sign_file(filepath: str, profile: EncryptionProfile,
                  password: str = None) -> OperationResult:
        """
        Подпись файла.

        Приоритет ключей:
          1. profile.signing_private_key_path  — выделенный ключ подписи
          2. profile.private_key_path          — ключ шифрования (fallback для RSA)
          3. Генерация новой пары в ~/.crypto_util/keys/<profile_name>/

        Сгенерированные ключи сохраняются в стабильное место привязанное
        к профилю, а НЕ рядом с шифруемым файлом.
        Пути возвращаются в details["signing_private_key_path"] и
        details["signing_public_key_path"] — main.py должен сохранить их
        в profile.signing_private_key_path / signing_public_key_path.
        """
        try:
            algo    = profile.signature_algorithm
            details = {}

            # 1. Выделенный ключ подписи (единственный надёжный источник)
            priv_path = getattr(profile, 'signing_private_key_path', '') or ''
            # 2. Fallback на ключ шифрования ТОЛЬКО если алгоритм совпадает.
            #    Например: профиль hybrid/RSA + signature_algorithm=RSA → OK.
            #    Но:       профиль hybrid/RSA + signature_algorithm=Ed25519 → НЕЛЬЗЯ,
            #    иначе RSA ключ попадёт в Ed25519Signature и упадёт с ошибкой.
            if not priv_path or not os.path.exists(priv_path):
                enc_priv = profile.private_key_path or ''
                if enc_priv and os.path.exists(enc_priv) and algo == 'RSA':
                    priv_path = enc_priv

            if priv_path and os.path.exists(priv_path):
                crypto = _load_signing_private_key(algo, priv_path, password,
                                                   profile.rsa_key_size)
                if isinstance(crypto, OperationResult):
                    return crypto
                mgr = SignatureManager.from_crypto(crypto)
                details["key_source"] = os.path.basename(priv_path)

            else:
                # 3. Генерируем в стабильное место — папка профиля
                crypto, priv_path, pub_path = _generate_profile_signing_keys(
                    algo, profile.name, password, profile.rsa_key_size
                )
                mgr = SignatureManager.from_crypto(crypto)
                # Возвращаем пути через отдельные ключи — main.py сохранит их
                # в signing_private/public_key_path, не трогая ключи шифрования
                details["signing_private_key_path"] = priv_path
                details["signing_public_key_path"]  = pub_path
                details["warning"] = (
                    f"Сгенерированы ключи подписи для профиля «{profile.name}». "
                    f"Они сохранены в: {os.path.dirname(priv_path)}"
                )

            sig_path = mgr.sign_file(filepath)
            return OperationResult(
                True,
                f"Файл подписан ({algo}): {os.path.basename(sig_path)}",
                sig_path,
                details
            )

        except Exception as e:
            return OperationResult(False, f"Ошибка подписи: {e}",
                                   error=traceback.format_exc())

    # ── Проверка подписи ─────────────────────────────────────────────────────

    @staticmethod
    def verify_signature(filepath: str, signature_path: str,
                         profile: EncryptionProfile) -> OperationResult:
        """
        Проверить подпись файла.
        Публичный ключ берётся из profile.signing_public_key_path
        или profile.public_key_path.
        """
        try:
            if not os.path.exists(signature_path):
                return OperationResult(
                    False, f"Файл подписи не найден: {signature_path}"
                )

            algo = profile.signature_algorithm

            # Определяем публичный ключ:
            # 1. Выделенный ключ подписи
            pub_path = getattr(profile, 'signing_public_key_path', '') or ''
            # 2. Fallback на ключ шифрования только для RSA подписи
            if not pub_path or not os.path.exists(pub_path):
                enc_pub = profile.public_key_path or ''
                if enc_pub and os.path.exists(enc_pub) and algo == 'RSA':
                    pub_path = enc_pub

            if not pub_path or not os.path.exists(pub_path):
                return OperationResult(
                    False,
                    "Для проверки подписи нужен публичный ключ.\n"
                    "Укажите public_key.pem в настройках профиля\n"
                    "или нажмите «Сгенерировать ключи» во вкладке «Ключи»."
                )

            crypto = _load_signing_public_key(algo, pub_path)
            if isinstance(crypto, OperationResult):
                return crypto   # ошибка загрузки

            mgr      = SignatureManager.from_crypto(crypto)
            is_valid = mgr.verify_file_signature(filepath, signature_path)

            if is_valid:
                return OperationResult(True, "✅ Подпись ВАЛИДНА — файл не изменён")
            else:
                return OperationResult(
                    False,
                    "❌ Подпись НЕДЕЙСТВИТЕЛЬНА — файл изменён или использован другой ключ"
                )

        except Exception as e:
            return OperationResult(False, f"Ошибка проверки подписи: {e}",
                                   error=traceback.format_exc())

    # ── Хеш файла ────────────────────────────────────────────────────────────

    @staticmethod
    def verify_gost_signature(data_path: str, sig_path: str) -> OperationResult:
        """
        Проверить российскую ЭЦП (ГОСТ Р 34.10-2012) из .sig/.p7s файла.
        Не требует КриптоПро — использует pygost + pyasn1.
        """
        try:
            from .gost_verifier import GostVerifier, format_result
        except ImportError:
            try:
                import sys, os
                sys.path.insert(0, os.path.dirname(__file__))
                from gost_verifier import GostVerifier, format_result
            except ImportError:
                return OperationResult(
                    False,
                    "Модуль gost_verifier.py не найден в папке gui/."
                )

        try:
            verifier = GostVerifier()
            if data_path and os.path.exists(data_path):
                result = verifier.verify(data_path, sig_path)
            else:
                result = verifier.parse_sig_only(sig_path)

            text = format_result(result)

            if not result.success:
                return OperationResult(False, text,
                                       details={"raw": result})

            return OperationResult(
                success=True,
                message=text,
                details={
                    "raw":           result,
                    "certificates":  result.certificates,
                    "sign_time":     result.sign_time,
                    "algo":          result.signature_algo,
                    "math_valid":    result.signature_valid,
                    "warnings":      result.warnings,
                }
            )
        except Exception as e:
            return OperationResult(False, f"Ошибка ЭЦП верификации: {e}",
                                   error=traceback.format_exc())

    @staticmethod
    def hash_file(filepath: str, algorithm: str = "sha256") -> OperationResult:
        try:
            file_hash = calculate_file_hash(filepath, algorithm)
            return OperationResult(
                True,
                f"Хеш ({algorithm}): {file_hash}",
                details={"hash": file_hash, "algorithm": algorithm}
            )
        except Exception as e:
            return OperationResult(False, f"Ошибка хеширования: {e}",
                                   error=traceback.format_exc())

    # ── Генерация ключей ─────────────────────────────────────────────────────

    @staticmethod
    def generate_keys(profile: EncryptionProfile, output_dir: str,
                      password: str = None) -> OperationResult:
        """
        Генерирует ключи для профиля.

        Логика:
          hybrid/asymmetric + Ed25519 подпись → RSA ключи (шифрование) +
                                                 Ed25519 ключи (подпись) — РАЗДЕЛЬНО
          hybrid/asymmetric + RSA подпись     → RSA ключи (шифрование и подпись)
          symmetric + Ed25519 подпись         → только Ed25519 ключи (для подписи)
          symmetric + RSA подпись             → только RSA ключи (для подписи)

        В details возвращаются:
          private_key_path / public_key_path       — ключи шифрования
          signing_private_key_path / signing_public_key_path — ключи подписи
          (могут совпадать если алгоритм один)
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            details  = {}
            key_type = ""

            needs_rsa_encryption = profile.mode in ("hybrid", "asymmetric")
            sig_algo = profile.signature_algorithm  # 'Ed25519' или 'RSA'

            # ── Ключи шифрования ────────────────────────────────────────────
            if needs_rsa_encryption:
                rsa_priv = os.path.join(output_dir, "private_key.pem")
                rsa_pub  = os.path.join(output_dir, "public_key.pem")
                rsa = RSACrypto(profile.rsa_key_size)
                rsa.generate_keypair()
                rsa.save_private_key(rsa_priv, password)
                rsa.save_public_key(rsa_pub)
                details["private_key_path"] = rsa_priv
                details["public_key_path"]  = rsa_pub
                key_type = f"RSA-{profile.rsa_key_size}"

            # ── Ключи подписи ────────────────────────────────────────────────
            if sig_algo == "Ed25519":
                # Ed25519 ключи всегда отдельный файл — нельзя путать с RSA
                ed_priv = os.path.join(output_dir, "signing_private.pem")
                ed_pub  = os.path.join(output_dir, "signing_public.pem")
                ed = Ed25519Crypto()
                ed.generate_keypair()
                ed.save_private_key(ed_priv, password)
                ed.save_public_key(ed_pub)
                details["signing_private_key_path"] = ed_priv
                details["signing_public_key_path"]  = ed_pub
                key_type = (key_type + " + Ed25519").lstrip(" + ")

                # Если нет ключей шифрования — основные пути тоже Ed25519
                if not needs_rsa_encryption:
                    details["private_key_path"] = ed_priv
                    details["public_key_path"]  = ed_pub

            else:
                # RSA подпись — используем те же RSA ключи что и для шифрования
                rsa_priv = details.get("private_key_path",
                                       os.path.join(output_dir, "private_key.pem"))
                rsa_pub  = details.get("public_key_path",
                                       os.path.join(output_dir, "public_key.pem"))
                if not needs_rsa_encryption:
                    # Только подпись, шифрования нет — генерируем RSA
                    rsa = RSACrypto(profile.rsa_key_size)
                    rsa.generate_keypair()
                    rsa.save_private_key(rsa_priv, password)
                    rsa.save_public_key(rsa_pub)
                    details["private_key_path"] = rsa_priv
                    details["public_key_path"]  = rsa_pub
                    key_type = f"RSA-{profile.rsa_key_size}"
                details["signing_private_key_path"] = rsa_priv
                details["signing_public_key_path"]  = rsa_pub

            pw_note = " (зашифрован паролем)" if password else " (без пароля)"
            details["key_type"]   = key_type
            details["encrypted"]  = bool(password)

            return OperationResult(
                True,
                f"{key_type} ключи сгенерированы{pw_note}",
                output_dir,
                details
            )

        except Exception as e:
            return OperationResult(False, f"Ошибка генерации ключей: {e}",
                                   error=traceback.format_exc())


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _load_or_generate_rsa(profile: EncryptionProfile, output_dir: str,
                           password, details: dict,
                           need_private: bool) -> RSACrypto:
    """Загружает RSA ключи из профиля или генерирует новые."""
    rsa = RSACrypto(profile.rsa_key_size)

    if need_private:
        if profile.private_key_path and os.path.exists(profile.private_key_path):
            try:
                rsa.load_private_key(profile.private_key_path,
                                     password if password else None)
                details["key_source"] = "приватный ключ из файла"
                return rsa
            except Exception as e:
                raise RuntimeError(f"Не удалось загрузить приватный ключ: {e}")
    else:
        if profile.public_key_path and os.path.exists(profile.public_key_path):
            rsa.load_public_key(profile.public_key_path)
            details["key_source"] = "публичный ключ из файла"
            return rsa
        if profile.private_key_path and os.path.exists(profile.private_key_path):
            try:
                rsa.load_private_key(profile.private_key_path,
                                     password if password else None)
                details["key_source"] = "публичный ключ извлечён из приватного"
                return rsa
            except Exception as e:
                raise RuntimeError(f"Не удалось загрузить ключ: {e}")

    # Нет ключей — генерируем
    rsa.generate_keypair()
    keys_dir  = os.path.join(output_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path  = os.path.join(keys_dir, "public_key.pem")
    rsa.save_private_key(priv_path, password)
    rsa.save_public_key(pub_path)
    details["key_source"]        = "новые ключи сгенерированы"
    details["private_key_path"]  = priv_path
    details["public_key_path"]   = pub_path
    details["warning"]           = "ВАЖНО: Сохраните приватный ключ!"
    return rsa


def _load_signing_private_key(algo: str, path: str, password,
                               rsa_key_size: int):
    """
    Загружает приватный ключ — тип определяется из содержимого PEM файла,
    а НЕ из параметра algo. Это защищает от случая когда в профиле
    signature_algorithm=Ed25519, но private_key_path указывает на RSA ключ.
    """
    from cryptography.hazmat.primitives.asymmetric import (
        rsa as _rsa, ed25519 as _ed25519
    )
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.backends import default_backend as _backend
    from src.utils import CryptoUtils

    try:
        pem     = CryptoUtils.load_from_file(path)
        pwd     = password.encode() if password else None
        raw_key = _ser.load_pem_private_key(pem, password=pwd, backend=_backend())
    except Exception as e:
        err = str(e).lower()
        if "encrypted" in err or "password" in err or "bad decrypt" in err:
            return OperationResult(False, "Приватный ключ зашифрован паролем. Введите пароль.")
        return OperationResult(False, f"Не удалось загрузить ключ подписи: {e}")

    # Определяем тип по объекту — не по строке algo
    if isinstance(raw_key, _rsa.RSAPrivateKey):
        crypto             = RSACrypto(rsa_key_size)
        crypto.private_key = raw_key
        crypto.public_key  = raw_key.public_key()
        return crypto
    elif isinstance(raw_key, _ed25519.Ed25519PrivateKey):
        crypto             = Ed25519Crypto()
        crypto.private_key = raw_key
        crypto.public_key  = raw_key.public_key()
        return crypto
    else:
        return OperationResult(
            False,
            f"Неподдерживаемый тип ключа: {type(raw_key).__name__}. "
            f"Ожидался RSA или Ed25519."
        )


def _load_signing_public_key(algo: str, path: str):
    """
    Загружает публичный ключ — тип определяется из содержимого PEM файла.
    """
    from cryptography.hazmat.primitives.asymmetric import (
        rsa as _rsa, ed25519 as _ed25519
    )
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.backends import default_backend as _backend
    from src.utils import CryptoUtils

    try:
        pem     = CryptoUtils.load_from_file(path)
        raw_key = _ser.load_pem_public_key(pem, backend=_backend())
    except Exception as e:
        return OperationResult(False, f"Не удалось загрузить публичный ключ: {e}")

    if isinstance(raw_key, _rsa.RSAPublicKey):
        crypto            = RSACrypto()
        crypto.public_key = raw_key
        return crypto
    elif isinstance(raw_key, _ed25519.Ed25519PublicKey):
        crypto            = Ed25519Crypto()
        crypto.public_key = raw_key
        return crypto
    else:
        return OperationResult(
            False,
            f"Неподдерживаемый тип ключа: {type(raw_key).__name__}."
        )


def _generate_signing_keys(algo: str, filepath: str, password,
                            rsa_key_size: int):
    """Генерирует ключи рядом с файлом (устаревший метод, не используется)."""
    return _generate_profile_signing_keys(algo, "default", password, rsa_key_size)


def _generate_profile_signing_keys(algo: str, profile_name: str, password,
                                    rsa_key_size: int):
    """
    Генерирует пару ключей подписи в стабильное место привязанное к профилю:
      ~/.crypto_util/keys/<safe_profile_name>/

    Это гарантирует что при автоподписи разных файлов всегда используется
    одна и та же пара ключей — верификация будет работать всегда.
    """
    from pathlib import Path

    # Безопасное имя папки из имени профиля
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_"
                        for c in profile_name).strip("_") or "default"
    keys_dir = os.path.join(Path.home(), ".crypto_util", "keys", safe_name)
    os.makedirs(keys_dir, exist_ok=True)

    if algo == "RSA":
        crypto    = RSACrypto(rsa_key_size)
        crypto.generate_keypair()
        priv_path = os.path.join(keys_dir, "signing_private.pem")
        pub_path  = os.path.join(keys_dir, "signing_public.pem")
        crypto.save_private_key(priv_path, password if password else None)
        crypto.save_public_key(pub_path)
    else:
        crypto    = Ed25519Crypto()
        crypto.generate_keypair()
        priv_path = os.path.join(keys_dir, "signing_private.pem")
        pub_path  = os.path.join(keys_dir, "signing_public.pem")
        crypto.save_private_key(priv_path, password if password else None)
        crypto.save_public_key(pub_path)

    print(f"[CryptoEngine] Ключи подписи ({algo}) сохранены: {keys_dir}")
    return crypto, priv_path, pub_path


def _key_error(exc: Exception, password_msg: str) -> OperationResult:
    err = str(exc).lower()
    if "encrypted" in err or "password" in err or "bad decrypt" in err:
        return OperationResult(False, password_msg)
    raise exc
