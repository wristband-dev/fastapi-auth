from cryptography.fernet import Fernet
import json
import base64


class SessionEncryptor:
    """
    Provides encryption and decryption of session data using Fernet symmetric encryption.

    This class is designed to securely encrypt session data dictionaries into strings suitable
    for storage in cookies and to decrypt those strings back into dictionaries.

    The encryption key is derived from a secret key string supplied at initialization.
    The secret key must be at least 32 characters to ensure sufficient entropy.
    """

    def __init__(self, secret_key=None):
        """
        Initialize the SessionEncryptor with a secret key.

        Args:
            secret_key (str): A secret string of at least 32 characters used to derive the encryption key.

        Raises:
            ValueError: If no secret_key is provided or if its length is less than 32 characters.
        """
        if not secret_key:
            raise ValueError("Session Encryptor: secret_key is required")
        if len(secret_key) < 32:
            raise ValueError("Session Encryptor: secret_key must be at least 32 characters long")

        # Convert string to proper Fernet key format (base64 urlsafe-encoded 32 bytes)
        key_bytes: bytes = secret_key.encode("utf-8")[:32].ljust(32, b"\0")  # truncate to 32 bytes if longer
        self.secret_key: bytes = base64.urlsafe_b64encode(key_bytes)
        self.cipher: Fernet = Fernet(self.secret_key)

    def encrypt(self, data) -> str:
        """
        Encrypt a dictionary of session data into a base64-encoded string.

        Args:
            data (dict): The session data dictionary to encrypt.

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

    def decrypt(self, encrypted_str: str) -> dict:
        """
        Decrypt an encrypted session string back into a dictionary.

        Args:
            encrypted_str (str): The encrypted string to decrypt.

        Returns:
            dict: The decrypted session data dictionary.

        Raises:
            ValueError: If the input string is empty.
            cryptography.fernet.InvalidToken: If decryption fails due to an invalid token.
            json.JSONDecodeError: If decrypted data is not valid JSON.
        """
        if not encrypted_str:
            raise ValueError("Empty encrypted string cannot be decrypted")

        decrypted_bytes = self.cipher.decrypt(encrypted_str.encode())
        return json.loads(decrypted_bytes.decode())
