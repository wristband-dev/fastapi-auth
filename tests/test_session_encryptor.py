import pytest
from cryptography.fernet import InvalidToken

from wristband.fastapi_auth.utils import SessionEncryptor

SECRET = "a" * 32  # valid 32-char secret
LONG_SECRET = "a" * 64  # longer than 32 chars


def test_encrypt_and_decrypt_roundtrip():
    enc = SessionEncryptor(SECRET)
    data = {"user_id": "123", "email": "user@example.com"}
    encrypted = enc.encrypt(data)
    assert isinstance(encrypted, str)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encrypt_rejects_non_dict():
    enc = SessionEncryptor(SECRET)
    with pytest.raises(TypeError, match="Data must be a dictionary"):
        enc.encrypt(["not", "a", "dict"])  # type: ignore


def test_decrypt_rejects_empty_string():
    enc = SessionEncryptor(SECRET)
    with pytest.raises(ValueError, match="Empty encrypted string cannot be decrypted"):
        enc.decrypt("")


def test_decrypt_rejects_invalid_token():
    enc = SessionEncryptor(SECRET)
    with pytest.raises(InvalidToken):
        enc.decrypt("invalid.encrypted.string")


def test_short_secret_raises():
    with pytest.raises(ValueError, match="secret_key must be at least 32 characters long"):
        SessionEncryptor("short")


def test_missing_secret_raises():
    with pytest.raises(ValueError, match="secret_key is required"):
        SessionEncryptor(None)


def test_empty_string_secret_raises():
    with pytest.raises(ValueError, match="secret_key is required"):
        SessionEncryptor("")


def test_exactly_32_char_secret():
    """Test that exactly 32 characters works correctly."""
    enc = SessionEncryptor(SECRET)
    data = {"test": "value"}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_long_secret_truncated():
    """Test that secrets longer than 32 chars are properly truncated."""
    enc = SessionEncryptor(LONG_SECRET)
    data = {"test": "value"}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_different_keys_cannot_decrypt():
    """Test that data encrypted with one key cannot be decrypted with another."""
    enc1 = SessionEncryptor("a" * 32)
    enc2 = SessionEncryptor("b" * 32)

    data = {"user_id": "123"}
    encrypted = enc1.encrypt(data)

    with pytest.raises(InvalidToken):
        enc2.decrypt(encrypted)


def test_encrypt_various_data_types():
    """Test encryption/decryption with various data types in the dictionary."""
    enc = SessionEncryptor(SECRET)
    data = {
        "string": "test",
        "number": 42,
        "float": 3.14,
        "boolean": True,
        "null": None,
        "list": [1, 2, 3],
        "nested_dict": {"key": "value"},
    }
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encrypt_empty_dict():
    """Test that empty dictionaries can be encrypted and decrypted."""
    enc = SessionEncryptor(SECRET)
    data = {}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encrypted_strings_are_different():
    """Test that encrypting the same data twice produces different encrypted strings."""
    enc = SessionEncryptor(SECRET)
    data = {"user_id": "123"}
    encrypted1 = enc.encrypt(data)
    encrypted2 = enc.encrypt(data)
    # Fernet includes timestamp and random IV, so encryptions should be different
    assert encrypted1 != encrypted2
    # But both should decrypt to the same data
    assert enc.decrypt(encrypted1) == data
    assert enc.decrypt(encrypted2) == data


def test_unicode_data():
    """Test encryption/decryption with unicode characters."""
    enc = SessionEncryptor(SECRET)
    data = {"name": "José", "emoji": "🔐", "chinese": "你好"}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data
