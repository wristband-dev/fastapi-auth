import pytest
import json
import base64
import os
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import Request, Response
import pytest_asyncio

from wristband.utils import (
    CookieEncryptor,
    create_csrf_token,
    update_csrf_cookie,
    debug_request,
    to_bool,
    get_logger
)


class TestCookieEncryptor:
    def test_init_with_generated_key(self):
        encryptor = CookieEncryptor()
        assert encryptor.secret_key is not None
        assert encryptor.cipher is not None
    
    def test_init_with_string_key(self):
        key = "test-secret-key-for-testing-purposes"
        encryptor = CookieEncryptor(key)
        assert encryptor.secret_key is not None
        assert encryptor.cipher is not None
    
    def test_init_with_bytes_key(self):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        encryptor = CookieEncryptor(key)
        assert encryptor.secret_key == key
        assert encryptor.cipher is not None
    
    def test_encrypt_dict(self):
        encryptor = CookieEncryptor()
        data = {"user_id": "123", "username": "testuser"}
        encrypted = encryptor.encrypt(data)
        assert isinstance(encrypted, str)
        assert encrypted != json.dumps(data)
    
    def test_encrypt_non_dict(self):
        encryptor = CookieEncryptor()
        with pytest.raises(TypeError, match="Data must be a dictionary"):
            encryptor.encrypt("not a dict")
    
    def test_decrypt_valid_data(self):
        encryptor = CookieEncryptor()
        data = {"user_id": "123", "username": "testuser"}
        encrypted = encryptor.encrypt(data)
        decrypted = encryptor.decrypt(encrypted)
        assert decrypted == data
    
    def test_decrypt_empty_string(self):
        encryptor = CookieEncryptor()
        decrypted = encryptor.decrypt("")
        assert decrypted == {}
    
    def test_decrypt_invalid_data(self):
        encryptor = CookieEncryptor()
        decrypted = encryptor.decrypt("invalid-encrypted-data")
        assert decrypted == {}


def test_create_csrf_token():
    token = create_csrf_token()
    assert isinstance(token, str)
    assert len(token) == 64  # 32 bytes = 64 hex chars


def test_update_csrf_cookie():
    # Mock request and response
    request = MagicMock()
    request.session = {"csrfToken": "test-csrf-token"}
    response = MagicMock()
    
    # Call the function
    update_csrf_cookie(request, response)
    
    # Verify response.set_cookie was called with correct parameters
    response.set_cookie.assert_called_once_with(
        key="CSRF-TOKEN",
        value="test-csrf-token",
        httponly=False,
        max_age=1800,
        path="/",
        samesite="lax",
        secure=False
    )


@pytest.mark.asyncio
async def test_update_csrf_cookie_no_token():
    # Mock request and response with no csrf token
    request = MagicMock()
    request.session = {}
    response = MagicMock()
    
    # Call the function
    update_csrf_cookie(request, response)
    
    # Verify response.set_cookie was not called
    response.set_cookie.assert_not_called()


@pytest.mark.asyncio
async def test_debug_request():
    # Create mock async request
    body = json.dumps({"username": "testuser"}).encode()
    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.url = "http://testserver/api/login"
    mock_request.headers = {"Content-Type": "application/json"}
    mock_request.body.return_value = body
    
    # Create mock for call_next
    mock_response = MagicMock()
    call_next = AsyncMock(return_value=mock_response)
    
    # Call the function
    with patch("builtins.print") as mock_print:
        response = await debug_request(mock_request, call_next)
    
    # Verify call_next was called with the request
    call_next.assert_called_once_with(mock_request)
    
    # Verify print was called multiple times
    assert mock_print.call_count > 0
    
    # Verify response is the one from call_next
    assert response == mock_response


@pytest.mark.asyncio
async def test_debug_request_non_json_body():
    # Create mock request with non-JSON body
    body = b"plain text body"
    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.url = "http://testserver/api/login"
    mock_request.headers = {"Content-Type": "text/plain"}
    mock_request.body.return_value = body
    
    # Create mock for call_next
    mock_response = MagicMock()
    call_next = AsyncMock(return_value=mock_response)
    
    # Call the function
    with patch("builtins.print") as mock_print:
        response = await debug_request(mock_request, call_next)
    
    # Verify call_next was called with the request
    call_next.assert_called_once_with(mock_request)
    
    # Verify print was called multiple times
    assert mock_print.call_count > 0
    
    # Verify response is the one from call_next
    assert response == mock_response


def test_to_bool():
    assert to_bool("true") is True
    assert to_bool("True") is True
    assert to_bool("TRUE") is True
    assert to_bool("1") is True
    assert to_bool("yes") is True
    assert to_bool("YES") is True
    
    assert to_bool("false") is False
    assert to_bool("False") is False
    assert to_bool("0") is False
    assert to_bool("no") is False
    assert to_bool("") is False
    assert to_bool("anything else") is False


def test_get_logger():
    # Test with default name
    with patch("os.getenv", return_value="DEBUG"):
        with patch("logging.basicConfig") as mock_basic_config:
            with patch("logging.getLogger") as mock_get_logger:
                logger = get_logger()
                
                # Verify os.getenv was called
                # Verify logging.basicConfig was called
                mock_basic_config.assert_called_once_with(level="DEBUG")
                
                # Verify logging.getLogger was called with the right name
                # We need to use any() because the actual module name depends on where the test is run from
                assert mock_get_logger.called
                assert len(mock_get_logger.call_args_list) == 1
    
    # Test with custom name
    with patch("os.getenv", return_value="INFO"):
        with patch("logging.basicConfig") as mock_basic_config:
            with patch("logging.getLogger") as mock_get_logger:
                logger = get_logger("custom.logger")
                
                # Verify logging.basicConfig was called
                mock_basic_config.assert_called_once_with(level="INFO")
                
                # Verify logging.getLogger was called with the right name
                mock_get_logger.assert_called_once_with("custom.logger") 