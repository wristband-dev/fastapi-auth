import pytest
from cryptography.fernet import InvalidToken

from wristband.fastapi_auth.utils import SessionEncryptor

SECRET = "a" * 32  # valid 32-char secret


def test_encrypt_and_decrypt_roundtrip():
    enc = SessionEncryptor(SECRET)
    data = {"user_id": "123", "email": "user@example.com"}
    encrypted = enc.encrypt(data)
    assert isinstance(encrypted, str)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encrypt_rejects_non_dict():
    enc = SessionEncryptor(SECRET)
    with pytest.raises(TypeError):
        enc.encrypt(["not", "a", "dict"])


def test_decrypt_rejects_empty_string():
    enc = SessionEncryptor(SECRET)
    with pytest.raises(ValueError):
        enc.decrypt("")


def test_decrypt_rejects_invalid_token():
    enc = SessionEncryptor(SECRET)
    with pytest.raises(InvalidToken):
        enc.decrypt("invalid.encrypted.string")


def test_short_secret_raises():
    with pytest.raises(ValueError):
        SessionEncryptor("short")


def test_missing_secret_raises():
    with pytest.raises(ValueError):
        SessionEncryptor(None)
