import base64
import json
import re
from typing import Any, Dict, List, Optional, Union, cast

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .models import RawUserInfo, UserInfo

# One DNS label: letters, digits, and inner hyphens, up to 63 characters. A-Z and a-z are listed instead of using
# re.IGNORECASE, which would let some non-ASCII letters (e.g. the Kelvin sign) match.
_DNS_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TENANT_NAME_PATTERN = re.compile(_DNS_LABEL)
_DOMAIN_NAME_PATTERN = re.compile(rf"(?:{_DNS_LABEL}\.)+{_DNS_LABEL}")


def to_safe_tenant_name(value: Optional[str]) -> str:
    """
    Returns the tenant name if it is a valid DNS label, otherwise an empty string. Tenant names become part of
    Wristband URL hosts, so anything else (e.g. "evil.com#") could redirect users off Wristband.

    fullmatch() is used instead of "$", which also matches before a trailing newline.
    """
    return value if value and _TENANT_NAME_PATTERN.fullmatch(value) else ""


def to_safe_domain_name(value: Optional[str]) -> str:
    """
    Returns the domain if it is a valid DNS hostname (two or more labels, no port, path, or credentials),
    otherwise an empty string.
    """
    return value if value and _DOMAIN_NAME_PATTERN.fullmatch(value) else ""


def map_userinfo_claims(raw: RawUserInfo) -> UserInfo:
    """
    Maps a RawUserInfo (OIDC claim names) to UserInfo (User entity field names).

    Args:
        raw: RawUserInfo object with OIDC claim names

    Returns:
        UserInfo object with User entity field names
    """
    return UserInfo(
        user_id=raw.sub,
        tenant_id=raw.tnt_id,
        application_id=raw.app_id,
        identity_provider_name=raw.idp_name,
        full_name=raw.name,
        given_name=raw.given_name,
        family_name=raw.family_name,
        middle_name=raw.middle_name,
        nickname=raw.nickname,
        display_name=raw.preferred_username,
        picture_url=raw.picture,
        email=raw.email,
        email_verified=raw.email_verified,
        gender=raw.gender,
        birthdate=raw.birthdate,
        time_zone=raw.zoneinfo,
        locale=raw.locale,
        phone_number=raw.phone_number,
        phone_number_verified=raw.phone_number_verified,
        updated_at=raw.updated_at,
        roles=raw.roles,
        custom_claims=raw.custom_claims,
    )


class DataEncryptor:
    """
    Provides encryption and decryption of data using Fernet symmetric encryption.

    This class is designed to securely encrypt data dictionaries into strings suitable
    for storage in cookies and to decrypt those strings back into dictionaries.

    Supports key rotation by accepting multiple keys. The first key is used for
    encryption, while all keys are tried for decryption (allowing old sessions
    to remain valid during key rotation).

    The secret key(s) must be at least 32 characters to ensure sufficient entropy.
    Each Fernet key is derived from the whole secret with HKDF-SHA256.
    """

    _hkdf_salt = b"wristband-fastapi-auth-v1"
    _hkdf_info = b"fernet-key"

    cipher: Union[Fernet, MultiFernet]

    def __init__(self, secret_key: Union[str, List[str]]) -> None:
        """
        Initialize the DataEncryptor with secret key(s).

        Args:
            secret_key: A secret string or list of strings, each at least 32 characters.
                       If a list, the first key encrypts, all keys can decrypt (key rotation).

        Raises:
            ValueError: If no secret_key is provided, if any key is less than 32 characters,
                       or if the list is empty.
        """
        # Handle single key or list of keys
        keys = [secret_key] if isinstance(secret_key, str) else secret_key

        if not keys:
            raise ValueError("Data Encryptor: secret_key is required")

        # Validate and convert all keys to Fernet format
        fernet_keys: List[Fernet] = []
        for i, key in enumerate(keys):
            if not key:
                raise ValueError(f"Data Encryptor: secret_key at index {i} cannot be empty")
            if len(key) < 32:
                raise ValueError(f"Data Encryptor: secret_key at index {i} must be at least 32 characters long")

            fernet_keys.append(Fernet(self._derive_fernet_key(key)))

        # Use MultiFernet if multiple keys, otherwise single Fernet
        if len(fernet_keys) > 1:
            self.cipher = MultiFernet(fernet_keys)
        else:
            self.cipher = fernet_keys[0]

    def _derive_fernet_key(self, secret: str) -> bytes:
        """
        Derives a Fernet key (base64 urlsafe-encoded 32 bytes) from the whole secret using HKDF-SHA256.
        """
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=self._hkdf_salt, info=self._hkdf_info)
        return base64.urlsafe_b64encode(hkdf.derive(secret.encode("utf-8")))

    def encrypt(self, data: Dict[str, Any]) -> str:
        """
        Encrypt a dictionary of data into a base64-encoded string.

        Uses the first key for encryption.

        Args:
            data (dict): The data dictionary to encrypt.

        Returns:
            str: The encrypted string representation suitable for use in cookies.

        Raises:
            TypeError: If the input data is not a dictionary.
        """
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary")

        json_data: bytes = json.dumps(data).encode()
        encrypted: bytes = self.cipher.encrypt(json_data)
        return encrypted.decode()

    def decrypt(self, encrypted_str: str, max_age: Optional[int] = None) -> Dict[str, Any]:
        """
        Decrypt an encrypted string back into a dictionary.

        Tries all configured keys for decryption (supports key rotation).

        Args:
            encrypted_str (str): The encrypted string to decrypt.
            max_age (Optional[int]): The maximum age in seconds of the encrypted data, checked against the
                timestamp that Fernet encrypts into every token. A copied cookie is rejected once it's older
                than this, even if the browser would still send it. No age check when None.

        Returns:
            dict: The decrypted data dictionary.

        Raises:
            ValueError: If the input string is empty.
            cryptography.fernet.InvalidToken: If decryption fails with all keys, or the data is older than max_age.
            json.JSONDecodeError: If decrypted data is not valid JSON.
        """
        if not encrypted_str:
            raise ValueError("Empty encrypted string cannot be decrypted")

        decrypted_bytes: bytes = self.cipher.decrypt(encrypted_str.encode(), ttl=max_age)
        return cast(Dict[str, Any], json.loads(decrypted_bytes.decode()))
