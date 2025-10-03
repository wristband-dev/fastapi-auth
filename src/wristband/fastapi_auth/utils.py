import base64
import json
from typing import Any, Dict, Optional, cast

from cryptography.fernet import Fernet

from .models import RawUserInfo, UserInfo


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

    The encryption key is derived from a secret key string supplied at initialization.
    The secret key must be at least 32 characters to ensure sufficient entropy.
    """

    def __init__(self, secret_key: Optional[str] = None) -> None:
        """
        Initialize the DataEncryptor with a secret key.

        Args:
            secret_key (str): A secret string of at least 32 characters used to derive the encryption key.

        Raises:
            ValueError: If no secret_key is provided or if its length is less than 32 characters.
        """
        if not secret_key:
            raise ValueError("Data Encryptor: secret_key is required")
        if len(secret_key) < 32:
            raise ValueError("Data Encryptor: secret_key must be at least 32 characters long")

        # Convert string to proper Fernet key format (base64 urlsafe-encoded 32 bytes)
        key_bytes: bytes = secret_key.encode("utf-8")[:32].ljust(32, b"\0")  # truncate to 32 bytes if longer
        self.secret_key: bytes = base64.urlsafe_b64encode(key_bytes)
        self.cipher: Fernet = Fernet(self.secret_key)

    def encrypt(self, data: Dict[str, Any]) -> str:
        """
        Encrypt a dictionary of data into a base64-encoded string.

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

    def decrypt(self, encrypted_str: str) -> Dict[str, Any]:
        """
        Decrypt an encrypted string back into a dictionary.

        Args:
            encrypted_str (str): The encrypted string to decrypt.

        Returns:
            dict: The decrypted data dictionary.

        Raises:
            ValueError: If the input string is empty.
            cryptography.fernet.InvalidToken: If decryption fails due to an invalid token.
            json.JSONDecodeError: If decrypted data is not valid JSON.
        """
        if not encrypted_str:
            raise ValueError("Empty encrypted string cannot be decrypted")

        decrypted_bytes: bytes = self.cipher.decrypt(encrypted_str.encode())
        return cast(Dict[str, Any], json.loads(decrypted_bytes.decode()))
