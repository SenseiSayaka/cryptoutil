"""
Верификация российской ЭЦП (ГОСТ Р 34.10-2012) и просмотр сертификатов.

Поддерживаемые форматы:
  .sig  — отсоединённая подпись (detached), CMS/PKCS#7
  .p7s  — присоединённая или отсоединённая подпись, CMS/PKCS#7
  .p7   — то же что p7s

Зависимости:
  pip install gostcrypto pyasn1 pyasn1-modules

Алгоритмы:
  ГОСТ Р 34.10-2012 (256 и 512 бит)
  ГОСТ Р 34.11-2012 «Стрибог» (256 и 512 бит)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
import os


# ── OID справочник ───────────────────────────────────────────────────────────

OID_NAMES = {
    # ГОСТ алгоритмы
    "1.2.643.7.1.1.1.1":  "ГОСТ Р 34.10-2012 (256 бит)",
    "1.2.643.7.1.1.1.2":  "ГОСТ Р 34.10-2012 (512 бит)",
    "1.2.643.7.1.1.2.2":  "ГОСТ Р 34.11-2012 Стрибог-256",
    "1.2.643.7.1.1.2.3":  "ГОСТ Р 34.11-2012 Стрибог-512",
    "1.2.643.7.1.1.3.2":  "ГОСТ Р 34.10-2012 + Стрибог-256",
    "1.2.643.7.1.1.3.3":  "ГОСТ Р 34.10-2012 + Стрибог-512",
    # Старые ГОСТ
    "1.2.643.2.2.3":      "ГОСТ Р 34.10-2001",
    "1.2.643.2.2.9":      "ГОСТ Р 34.11-94",
    "1.2.643.2.2.19":     "ГОСТ Р 34.10-2001 (параметры)",
    # X.509 атрибуты
    "2.5.4.3":   "CN",
    "2.5.4.4":   "SN",
    "2.5.4.6":   "C",
    "2.5.4.7":   "L",
    "2.5.4.8":   "ST",
    "2.5.4.10":  "O",
    "2.5.4.11":  "OU",
    "2.5.4.12":  "T",
    "1.2.840.113549.1.9.1": "emailAddress",
    # Российские расширения
    "1.2.643.100.1":  "ОГРН",
    "1.2.643.100.5":  "ОГРНИП",
    "1.2.643.3.131.1.1": "ИНН",
    "1.2.643.100.3":  "СНИЛС",
    # RSA/EC для справки
    "1.2.840.113549.1.1.1":  "RSA",
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.10045.4.3.2":   "SHA256withECDSA",
}

# OID подписи ГОСТ (для верификации)
GOST_SIGN_OIDS = {
    "1.2.643.7.1.1.3.2",   # ГОСТ 2012-256
    "1.2.643.7.1.1.3.3",   # ГОСТ 2012-512
    "1.2.643.2.2.3",        # ГОСТ 2001
}
GOST_HASH_OID_TO_ALGO = {
    "1.2.643.7.1.1.2.2": "streebog256",
    "1.2.643.7.1.1.2.3": "streebog512",
    "1.2.643.2.2.9":      "md_gost94",
}


# ── Результирующие структуры ──────────────────────────────────────────────────

@dataclass
class CertificateInfo:
    """Информация о сертификате из подписи"""
    subject:      dict = field(default_factory=dict)   # CN, O, OU и т.д.
    issuer:       dict = field(default_factory=dict)
    serial:       str  = ""
    valid_from:   Optional[datetime] = None
    valid_to:     Optional[datetime] = None
    algorithm:    str  = ""
    thumbprint:   str  = ""   # SHA-256 отпечаток сертификата
    is_expired:   bool = False
    raw_subject:  str  = ""   # полная строка субъекта

    @property
    def owner_name(self) -> str:
        return (self.subject.get("CN")
                or self.subject.get("O")
                or self.raw_subject
                or "Неизвестно")

    @property
    def org(self) -> str:
        return self.subject.get("O", "")

    @property
    def inn(self) -> str:
        return self.subject.get("ИНН", "")

    @property
    def ogrn(self) -> str:
        return self.subject.get("ОГРН", "")

    @property
    def validity_str(self) -> str:
        if not self.valid_from or not self.valid_to:
            return "Неизвестно"
        fmt = "%d.%m.%Y"
        return f"{self.valid_from.strftime(fmt)} — {self.valid_to.strftime(fmt)}"

    @property
    def days_left(self) -> Optional[int]:
        if not self.valid_to:
            return None
        delta = self.valid_to - datetime.utcnow()
        return delta.days


@dataclass
class VerificationResult:
    """Результат верификации подписи"""
    success:          bool = False
    signature_valid:  Optional[bool] = None   # None = не проверялась математически
    certificates:     List[CertificateInfo] = field(default_factory=list)
    signature_algo:   str = ""
    sign_time:        Optional[datetime] = None
    error:            str = ""
    warnings:         List[str] = field(default_factory=list)

    @property
    def primary_cert(self) -> Optional[CertificateInfo]:
        return self.certificates[0] if self.certificates else None


# ── Парсер CMS/PKCS#7 ─────────────────────────────────────────────────────────

class GostVerifier:
    """
    Верификатор ГОСТ подписей.
    Работает без КриптоПро — использует gostcrypto и pyasn1.
    """

    def verify(self, data_path: str, sig_path: str) -> VerificationResult:
        """
        Проверить подпись файла.

        Args:
            data_path: путь к подписанному файлу
            sig_path:  путь к файлу подписи (.sig / .p7s)
        """
        result = VerificationResult()
        try:
            self._check_imports(result)
            if result.error:
                return result

            sig_bytes = self._read_sig(sig_path, result)
            if not sig_bytes:
                return result

            cms = self._parse_cms(sig_bytes, result)
            if cms is None:
                return result

            self._extract_certificates(cms, result)
            self._extract_sign_time(cms, result)
            self._extract_algo(cms, result)

            # Математическая верификация
            if os.path.exists(data_path):
                self._verify_math(data_path, sig_bytes, cms, result)
            else:
                result.warnings.append("Файл данных не найден — математическая верификация пропущена")

            result.success = True

        except Exception as exc:
            import traceback
            result.error = f"Ошибка разбора подписи: {exc}"
            result.success = False

        return result

    def parse_sig_only(self, sig_path: str) -> VerificationResult:
        """Разобрать .sig/.p7s без файла данных — только сертификаты и метаданные."""
        return self.verify("", sig_path)

    # ── Внутренние методы ─────────────────────────────────────────────────────

    def _check_imports(self, result: VerificationResult):
        missing = []
        try:
            import pyasn1  # noqa
        except ImportError:
            missing.append("pyasn1")
        try:
            import pyasn1_modules  # noqa
        except ImportError:
            missing.append("pyasn1-modules")

        if missing:
            result.error = (
                f"Не установлены зависимости: {', '.join(missing)}.\n"
                f"Установите: pip install {' '.join(missing)}"
            )

    def _read_sig(self, sig_path: str, result: VerificationResult) -> Optional[bytes]:
        if not os.path.exists(sig_path):
            result.error = f"Файл подписи не найден: {sig_path}"
            return None
        with open(sig_path, "rb") as f:
            data = f.read()

        # PEM → DER
        if data.startswith(b"-----"):
            import base64
            lines = [l for l in data.splitlines()
                     if l and not l.startswith(b"-----")]
            data = base64.b64decode(b"".join(lines))
        return data

    def _parse_cms(self, sig_bytes: bytes, result: VerificationResult):
        """
        Разобрать CMS ContentInfo → SignedData.
        Пробует rfc5652 (современный CMS) и rfc2315 (PKCS#7 старый формат).
        Все обращения к полям через getComponentByName() — pyasn1 не поддерживает .get().
        """
        from pyasn1.codec.der import decoder as der_decoder
        from pyasn1_modules import rfc2315

        SIGNED_DATA_OID = "1.2.840.113549.1.7.2"

        # ── Попытка 1: rfc5652 (современный CMS, ГОСТ 2012) ─────────────────
        try:
            from pyasn1_modules import rfc5652
            ci, _ = der_decoder.decode(sig_bytes, asn1Spec=rfc5652.ContentInfo())
            content_type = str(ci.getComponentByName("contentType"))

            if SIGNED_DATA_OID not in content_type:
                result.error = f"Неподдерживаемый тип CMS: {content_type}"
                return None

            # Извлекаем Any → декодируем как SignedData
            content_any = ci.getComponentByName("content")
            sd, _ = der_decoder.decode(
                bytes(content_any),
                asn1Spec=rfc5652.SignedData()
            )
            # Быстрая проверка что структура разобралась
            _ = sd.getComponentByName("signerInfos")
            return sd

        except Exception as e1:
            pass  # пробуем fallback

        # ── Попытка 2: rfc2315 (PKCS#7, старые КЭП до 2019) ─────────────────
        try:
            ci2, _ = der_decoder.decode(sig_bytes,
                                        asn1Spec=rfc2315.ContentInfo())
            content_type2 = str(ci2.getComponentByName("contentType"))

            if SIGNED_DATA_OID not in content_type2:
                result.error = f"Неподдерживаемый тип PKCS#7: {content_type2}"
                return None

            content_any2 = ci2.getComponentByName("content")
            sd2, _ = der_decoder.decode(
                bytes(content_any2),
                asn1Spec=rfc2315.SignedData()
            )
            return sd2

        except Exception as e2:
            result.error = f"Не удалось разобрать CMS/PKCS#7 структуру: {e2}"
            return None

    def _extract_certificates(self, cms, result: VerificationResult):
        """Извлечь сертификаты из SignedData.certificates."""
        try:
            # pyasn1 объекты используют getComponentByName, не .get()
            certs_field = None
            for field_name in ("certificates", "extendedCertificatesAndCertificates"):
                try:
                    cf = cms.getComponentByName(field_name)
                    if cf is not None and cf.hasValue():
                        certs_field = cf
                        break
                except Exception:
                    continue

            if certs_field is None:
                result.warnings.append("Сертификаты не встроены в подпись")
                return

            for cert_choice in certs_field:
                try:
                    cert_der = self._get_cert_der(cert_choice)
                    if cert_der:
                        info = self._parse_certificate(cert_der)
                        if info:
                            result.certificates.append(info)
                except Exception:
                    continue

        except Exception as e:
            result.warnings.append(f"Ошибка чтения сертификатов: {e}")

    def _get_cert_der(self, cert_choice) -> Optional[bytes]:
        from pyasn1.codec.der import encoder as der_encoder
        try:
            # CertificateChoices (rfc5652): содержит choice certificate/...
            if hasattr(cert_choice, "getComponentByPosition"):
                # Пробуем как CertificateChoices — берём компонент [0]
                try:
                    inner = cert_choice.getComponentByPosition(0)
                    if inner is not None:
                        return der_encoder.encode(inner)
                except Exception:
                    pass
            # Прямой Certificate объект
            return der_encoder.encode(cert_choice)
        except Exception:
            return None

    def _parse_certificate(self, cert_der: bytes) -> Optional[CertificateInfo]:
        """Разобрать X.509 сертификат."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import hashlib

            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            info = CertificateInfo()

            # Субъект
            info.subject    = self._parse_name(cert.subject)
            info.issuer     = self._parse_name(cert.issuer)
            info.raw_subject = cert.subject.rfc4514_string()

            # Серийный номер
            info.serial = hex(cert.serial_number).upper().lstrip("0X") or "0"

            # Срок действия
            try:
                info.valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
                info.valid_to   = cert.not_valid_after_utc.replace(tzinfo=None)
            except AttributeError:
                # Старые версии cryptography
                info.valid_from = cert.not_valid_before
                info.valid_to   = cert.not_valid_after

            info.is_expired = datetime.utcnow() > info.valid_to if info.valid_to else False

            # Алгоритм подписи сертификата
            algo_oid = cert.signature_algorithm_oid.dotted_string
            info.algorithm = OID_NAMES.get(algo_oid, algo_oid)

            # SHA-256 отпечаток
            info.thumbprint = hashlib.sha256(cert_der).hexdigest().upper()

            return info

        except Exception as e:
            # Fallback: разбор через pyasn1 если cryptography не справилась
            return self._parse_certificate_pyasn1(cert_der)

    def _parse_certificate_pyasn1(self, cert_der: bytes) -> Optional[CertificateInfo]:
        """Fallback парсер сертификата через pyasn1."""
        try:
            from pyasn1.codec.der import decoder as der_decoder
            from pyasn1_modules import rfc2459
            import hashlib

            cert, _ = der_decoder.decode(cert_der, asn1Spec=rfc2459.Certificate())
            tbs = cert["tbsCertificate"]
            info = CertificateInfo()

            info.subject = self._parse_name_pyasn1(tbs["subject"])
            info.issuer  = self._parse_name_pyasn1(tbs["issuer"])
            info.serial  = str(int(tbs["serialNumber"])).upper()
            info.thumbprint = hashlib.sha256(cert_der).hexdigest().upper()

            # Срок действия
            validity = tbs["validity"]
            try:
                nb = str(validity["notBefore"].getComponent())
                na = str(validity["notAfter"].getComponent())
                info.valid_from = self._parse_asn1_time(nb)
                info.valid_to   = self._parse_asn1_time(na)
                info.is_expired = (datetime.utcnow() > info.valid_to
                                   if info.valid_to else False)
            except Exception:
                pass

            algo_oid = str(tbs["signature"]["algorithm"])
            info.algorithm = OID_NAMES.get(algo_oid, algo_oid)

            return info
        except Exception:
            return None

    def _parse_name(self, name) -> dict:
        """Разобрать X.509 Name из cryptography объекта."""
        from cryptography.x509.oid import NameOID
        result = {}
        oid_map = {
            NameOID.COMMON_NAME:            "CN",
            NameOID.ORGANIZATION_NAME:      "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME:           "C",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.LOCALITY_NAME:          "L",
            NameOID.EMAIL_ADDRESS:          "emailAddress",
        }
        for attr in name:
            label = oid_map.get(attr.oid)
            if label is None:
                # Российские OID
                label = OID_NAMES.get(attr.oid.dotted_string,
                                      attr.oid.dotted_string)
            result[label] = attr.value
        return result

    def _parse_name_pyasn1(self, name) -> dict:
        """Разобрать X.509 Name из pyasn1 объекта."""
        result = {}
        try:
            for rdn in name:
                for atv in rdn:
                    try:
                        oid   = str(atv.getComponentByName("type"))
                        value = str(atv.getComponentByName("value").getComponent())
                        label = OID_NAMES.get(oid, oid)
                        result[label] = value
                    except Exception:
                        continue
        except Exception:
            pass
        return result

    def _parse_asn1_time(self, s: str) -> Optional[datetime]:
        """Разобрать ASN.1 время (UTCTime или GeneralizedTime)."""
        for fmt in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ",
                    "%y%m%d%H%M%S+0000", "%Y%m%d%H%M%S+0000"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None

    def _extract_sign_time(self, cms, result: VerificationResult):
        """Извлечь время подписания из SignerInfo.signedAttrs."""
        SIGNING_TIME_OID = "1.2.840.113549.1.9.5"
        try:
            signer_infos = cms.getComponentByName("signerInfos")
            if signer_infos is None:
                return
            for si in signer_infos:
                # Пробуем оба имени (rfc5652 и rfc2315)
                signed_attrs = None
                for attr_name in ("signedAttrs", "authenticatedAttributes"):
                    try:
                        sa = si.getComponentByName(attr_name)
                        if sa is not None and sa.hasValue():
                            signed_attrs = sa
                            break
                    except Exception:
                        continue
                if signed_attrs is None:
                    continue
                for attr in signed_attrs:
                    try:
                        attr_type = str(attr.getComponentByName("attrType"))
                        if SIGNING_TIME_OID in attr_type:
                            vals = attr.getComponentByName("attrValues")
                            time_str = str(vals[0].getComponent())
                            result.sign_time = self._parse_asn1_time(time_str)
                            return
                    except Exception:
                        continue
        except Exception:
            pass

    def _extract_algo(self, cms, result: VerificationResult):
        """Извлечь алгоритм подписи."""
        try:
            signer_infos = cms.getComponentByName("signerInfos")
            if signer_infos is None:
                return
            for si in signer_infos:
                for algo_name in ("signatureAlgorithm", "digestEncryptionAlgorithm"):
                    try:
                        algo_field = si.getComponentByName(algo_name)
                        if algo_field is not None:
                            oid = str(algo_field.getComponentByName("algorithm"))
                            result.signature_algo = OID_NAMES.get(oid, oid)
                            return
                    except Exception:
                        continue
        except Exception:
            pass

    def _verify_math(self, data_path: str, sig_bytes: bytes,
                     cms, result: VerificationResult):
        """
        Математическая верификация ГОСТ подписи через gostcrypto.
        Если gostcrypto не установлен — пропускаем, только предупреждаем.
        """
        try:
            import gostcrypto
        except ImportError:
            result.warnings.append(
                "gostcrypto не установлен — математическая верификация недоступна.\n"
                "Установите: pip install gostcrypto pyasn1 pyasn1-modules"
            )
            return

        try:
            signer_infos = cms.getComponentByName("signerInfos")
            if signer_infos is None or len(signer_infos) == 0:
                result.warnings.append("SignerInfo не найден")
                return

            si = signer_infos[0]

            # Алгоритм хеша из SignerInfo
            digest_algo_obj = si.getComponentByName("digestAlgorithm")
            digest_algo = str(digest_algo_obj.getComponentByName("algorithm"))
            if digest_algo == "1.2.643.7.1.1.2.2":
                hash_algo = "streebog256"
                mode      = gostcrypto.gostsignature.MODE_256
                hash_len  = 32
            elif digest_algo == "1.2.643.7.1.1.2.3":
                hash_algo = "streebog512"
                mode      = gostcrypto.gostsignature.MODE_512
                hash_len  = 64
            else:
                result.warnings.append(
                    f"Неподдерживаемый алгоритм хеша: "
                    f"{OID_NAMES.get(digest_algo, digest_algo)}"
                )
                return

            # Хешируем файл данных через gostcrypto (Стрибог)
            with open(data_path, "rb") as f:
                data = f.read()

            hash_obj    = gostcrypto.gosthash.new(hash_algo, data=bytearray(data))
            digest      = bytearray(hash_obj.digest())

            # Подпись из SignerInfo
            sig_raw = bytearray(bytes(si.getComponentByName("signature")))

            # Сертификат с публичным ключом
            certs_field = None
            try:
                cf = cms.getComponentByName("certificates")
                if cf is not None and cf.hasValue():
                    certs_field = cf
            except Exception:
                pass
            if not certs_field:
                result.warnings.append("Сертификат не встроен в подпись")
                return

            cert_der = self._get_cert_der(list(certs_field)[0])
            if not cert_der:
                return

            pub_key_bytes = self._extract_public_key_bytes(cert_der)
            if not pub_key_bytes:
                result.warnings.append("Не удалось извлечь публичный ключ")
                return

            # pub_key_bytes: 0x04 || X || Y (каждый hash_len байт, little-endian)
            # Убираем 0x04 prefix если есть
            if pub_key_bytes[0] == 0x04:
                pub_key_bytes = pub_key_bytes[1:]
            pub_key = bytearray(pub_key_bytes)

            # Параметры кривой — пробуем стандартные наборы ГОСТ 2012
            algo_oid = str(si["signatureAlgorithm"]["algorithm"])
            curves   = gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019

            # Выбираем кривую по размеру ключа
            if mode == gostcrypto.gostsignature.MODE_512:
                curve_candidates = [
                    "id-tc26-gost-3410-2012-512-paramSetA",
                    "id-tc26-gost-3410-2012-512-paramSetB",
                    "id-tc26-gost-3410-2012-512-paramSetC",
                ]
            else:
                curve_candidates = [
                    "id-tc26-gost-3410-2012-256-paramSetA",
                    "id-tc26-gost-3410-2012-256-paramSetB",
                    "id-GostR3410-2001-CryptoPro-A-ParamSet",
                    "id-GostR3410-2001-CryptoPro-B-ParamSet",
                    "id-GostR3410-2001-CryptoPro-C-ParamSet",
                ]

            # Пробуем каждую кривую — при неверной будет исключение
            verified   = False
            last_error = ""
            for curve_name in curve_candidates:
                if curve_name not in curves:
                    continue
                try:
                    sign_obj = gostcrypto.gostsignature.new(mode, curves[curve_name])
                    verified = sign_obj.verify(pub_key, digest, sig_raw)
                    if verified:
                        break
                except Exception as ce:
                    last_error = str(ce)
                    continue

            result.signature_valid = verified
            if not verified and last_error:
                result.warnings.append(f"Детали верификации: {last_error}")

        except Exception as e:
            result.warnings.append(f"Математическая верификация: {e}")
            result.signature_valid = None

    def _extract_public_key_bytes(self, cert_der: bytes) -> Optional[bytes]:
        """Извлечь сырые байты публичного ключа из DER сертификата."""
        try:
            from pyasn1.codec.der import decoder as der_decoder
            from pyasn1_modules import rfc2459
            cert, _ = der_decoder.decode(cert_der, asn1Spec=rfc2459.Certificate())
            pub_key_info = cert["tbsCertificate"]["subjectPublicKeyInfo"]
            bit_string = pub_key_info["subjectPublicKey"]
            return bytes(bit_string)[1:]  # убираем leading 0x04
        except Exception:
            return None


# ── Удобная точка входа ───────────────────────────────────────────────────────

def verify_gost_file(data_path: str, sig_path: str) -> VerificationResult:
    """Проверить ГОСТ подпись файла."""
    return GostVerifier().verify(data_path, sig_path)


def inspect_sig_file(sig_path: str) -> VerificationResult:
    """Разобрать .sig/.p7s файл и вернуть информацию без верификации."""
    return GostVerifier().parse_sig_only(sig_path)


def format_result(result: VerificationResult) -> str:
    """Форматировать результат для вывода в журнал."""
    lines = []

    if not result.success:
        lines.append(f"❌ Ошибка: {result.error}")
        return "\n".join(lines)

    # Статус подписи
    if result.signature_valid is True:
        lines.append("✅ Подпись ВАЛИДНА — математически подтверждена")
    elif result.signature_valid is False:
        lines.append("❌ Подпись НЕДЕЙСТВИТЕЛЬНА — данные изменены")
    else:
        lines.append("⚠️ Структура подписи разобрана (математическая верификация недоступна)")

    # Алгоритм
    if result.signature_algo:
        lines.append(f"  Алгоритм: {result.signature_algo}")

    # Время подписания
    if result.sign_time:
        lines.append(f"  Подписано: {result.sign_time.strftime('%d.%m.%Y %H:%M:%S')} UTC")

    # Сертификаты
    for i, cert in enumerate(result.certificates):
        lines.append(f"  {'─'*40}")
        lines.append(f"  Подписант #{i+1}: {cert.owner_name}")
        if cert.org:
            lines.append(f"  Организация: {cert.org}")
        if cert.inn:
            lines.append(f"  ИНН: {cert.inn}")
        if cert.ogrn:
            lines.append(f"  ОГРН: {cert.ogrn}")
        lines.append(f"  Срок действия: {cert.validity_str}")
        if cert.is_expired:
            lines.append("  ⚠️ СЕРТИФИКАТ ПРОСРОЧЕН")
        elif cert.days_left is not None and cert.days_left < 30:
            lines.append(f"  ⚠️ До истечения: {cert.days_left} дн.")
        lines.append(f"  Выдан: {cert.issuer.get('O') or cert.issuer.get('CN', '?')}")
        lines.append(f"  Алгоритм: {cert.algorithm}")
        lines.append(f"  Серийный №: {cert.serial}")
        lines.append(f"  Отпечаток: {cert.thumbprint[:32]}...")

    # Предупреждения
    for w in result.warnings:
        lines.append(f"  ⚠️ {w}")

    return "\n".join(lines)
