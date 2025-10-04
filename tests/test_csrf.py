from unittest.mock import patch

import pytest
from fastapi import Request, Response

from wristband.fastapi_auth.csrf import (
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_CSRF_HEADER_NAME,
    DEFAULT_SAME_SITE,
    create_csrf_token,
    delete_csrf_cookie,
    is_csrf_token_valid,
    update_csrf_cookie,
)


class DummySession:
    def __init__(self, csrf_token=None, raise_error=False):
        self._data = {"csrf_token": csrf_token} if csrf_token else {}
        self._raise_error = raise_error

    def __getattr__(self, key: str):
        """Mimic the real Session's __getattr__ behavior"""
        if self._raise_error:
            raise RuntimeError("session failure")
        return self._data.get(key)

    def get(self, key: str = None, default=None):  # type: ignore
        """Mimic the real Session's get method"""
        if self._raise_error:
            raise RuntimeError("session failure")
        return self._data.get(key, default)


def make_request(headers=None, csrf_token=None, raise_error=False):
    scope = {"type": "http", "headers": []}
    if headers:
        scope["headers"] = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    request = Request(scope)
    request.state.session = DummySession(csrf_token=csrf_token, raise_error=raise_error)
    return request


def test_create_csrf_token_generates_hex():
    token = create_csrf_token()
    assert isinstance(token, str)
    assert len(token) == 32
    int(token, 16)  # Valid hex


def test_create_csrf_token_uniqueness():
    """Test that multiple tokens are unique"""
    tokens = [create_csrf_token() for _ in range(100)]
    assert len(set(tokens)) == 100  # All unique


def test_update_csrf_cookie_sets_cookie_and_fields():
    response = Response()
    token = "testtoken"
    update_csrf_cookie(
        response=response,
        csrf_token=token,
        cookie_name="MYCSRF",
        domain="example.com",
        max_age=120,
        path="/test",
        same_site="strict",
        secure=False,
    )
    cookies = response.headers.get("set-cookie")
    assert cookies is not None
    cookies_l = cookies.lower()
    assert "mycsrf" in cookies_l
    assert "testtoken" in cookies_l
    assert "domain=example.com" in cookies_l
    assert "max-age=120" in cookies_l
    assert "path=/test" in cookies_l
    assert "samesite=strict" in cookies_l
    assert "secure" not in cookies_l  # secure=False


def test_update_csrf_cookie_raises_for_empty_token():
    response = Response()
    with pytest.raises(ValueError, match="csrf_token cannot be None or empty"):
        update_csrf_cookie(response=response, csrf_token="")


def test_update_csrf_cookie_raises_for_none_token():
    response = Response()
    with pytest.raises(ValueError, match="csrf_token cannot be None or empty"):
        update_csrf_cookie(response=response, csrf_token=None)  # type: ignore


@pytest.mark.parametrize("same_site", ["lax", "strict", "none"])
def test_update_csrf_cookie_same_site_variants(same_site):
    response = Response()
    token = "token123"
    update_csrf_cookie(response, token, same_site=same_site)
    cookies = response.headers.get("set-cookie")
    assert cookies is not None
    assert f"samesite={same_site}" in cookies.lower()


def test_update_csrf_cookie_uses_default_same_site():
    response = Response()
    token = "def-token"
    update_csrf_cookie(response=response, csrf_token=token)  # use default same_site
    cookies = response.headers.get("set-cookie")
    assert cookies is not None
    assert f"samesite={DEFAULT_SAME_SITE}" in cookies.lower()


def test_is_csrf_token_valid_success():
    token = "validtoken"
    headers = {DEFAULT_CSRF_HEADER_NAME: token}
    request = make_request(headers=headers, csrf_token=token)

    with patch("wristband.fastapi_auth.csrf._logger") as mock_logger:
        assert is_csrf_token_valid(request, DEFAULT_CSRF_HEADER_NAME) is True
        mock_logger.debug.assert_not_called()


def test_is_csrf_token_valid_custom_header_name():
    """Test validation with a custom header name"""
    token = "validtoken"
    custom_header = "X-Custom-CSRF"
    headers = {custom_header: token}
    request = make_request(headers=headers, csrf_token=token)
    assert is_csrf_token_valid(request, custom_header) is True


def test_is_csrf_token_valid_wrong_header_name():
    """Test that validation fails when using wrong header name"""
    token = "validtoken"
    headers = {"X-Wrong-Header": token}
    request = make_request(headers=headers, csrf_token=token)
    assert is_csrf_token_valid(request, DEFAULT_CSRF_HEADER_NAME) is False


def test_is_csrf_token_valid_mismatch():
    headers = {DEFAULT_CSRF_HEADER_NAME: "wrong"}
    request = make_request(headers=headers, csrf_token="expected")

    with patch("wristband.fastapi_auth.csrf._logger") as mock_logger:
        assert is_csrf_token_valid(request, DEFAULT_CSRF_HEADER_NAME) is False

        mock_logger.debug.assert_called_once()
        log_message = mock_logger.debug.call_args[0][0]
        assert "CSRF validation failed - tokens do not match" in log_message


def test_is_csrf_token_valid_missing_header():
    request = make_request(csrf_token="sometoken")

    with patch("wristband.fastapi_auth.csrf._logger") as mock_logger:
        assert is_csrf_token_valid(request, DEFAULT_CSRF_HEADER_NAME) is False

        mock_logger.debug.assert_called_once()
        log_message = mock_logger.debug.call_args[0][0]
        assert "CSRF validation failed - missing token" in log_message
        assert f"{DEFAULT_CSRF_HEADER_NAME} Header token present: False" in log_message


def test_is_csrf_token_valid_missing_session_token():
    headers = {DEFAULT_CSRF_HEADER_NAME: "header_token"}
    request = make_request(headers=headers, csrf_token=None)

    with patch("wristband.fastapi_auth.csrf._logger") as mock_logger:
        assert is_csrf_token_valid(request, DEFAULT_CSRF_HEADER_NAME) is False

        mock_logger.debug.assert_called_once()
        log_message = mock_logger.debug.call_args[0][0]
        assert "CSRF validation failed - missing token" in log_message
        assert "Session token present: False" in log_message
        assert f"{DEFAULT_CSRF_HEADER_NAME} Header token present: True" in log_message


def test_is_csrf_token_valid_exception_handling():
    headers = {DEFAULT_CSRF_HEADER_NAME: "header_token"}
    request = make_request(headers=headers, raise_error=True)

    with patch("wristband.fastapi_auth.csrf._logger") as mock_logger:
        assert is_csrf_token_valid(request, DEFAULT_CSRF_HEADER_NAME) is False
        mock_logger.debug.assert_not_called()


def test_is_csrf_token_valid_case_sensitive_header():
    """Test that header names are case-insensitive (FastAPI normalizes)"""
    token = "validtoken"
    headers = {"x-csrf-token": token}  # lowercase
    request = make_request(headers=headers, csrf_token=token)
    # FastAPI normalizes headers, so this should work
    assert is_csrf_token_valid(request, "X-CSRF-TOKEN") is True


def test_delete_csrf_cookie_sets_empty_cookie_and_fields():
    response = Response()
    delete_csrf_cookie(response, domain="example.com", path="/del", same_site="none", secure=True)
    cookies = response.headers.get("set-cookie")
    assert cookies is not None
    cookies_l = cookies.lower()
    assert DEFAULT_CSRF_COOKIE_NAME.lower() in cookies_l
    assert "max-age=0" in cookies_l
    assert "domain=example.com" in cookies_l
    assert "path=/del" in cookies_l
    assert "samesite=none" in cookies_l
    assert "secure" in cookies_l
    assert "httponly" not in cookies_l  # httponly False


@pytest.mark.parametrize("same_site", ["lax", "strict", "none"])
def test_delete_csrf_cookie_same_site_variants(same_site):
    response = Response()
    delete_csrf_cookie(response, same_site=same_site)
    cookies = response.headers.get("set-cookie")
    assert cookies is not None
    assert "max-age=0" in cookies.lower()
    assert f"samesite={same_site}" in cookies.lower()


def test_update_csrf_cookie_raises_when_response_none():
    with pytest.raises(ValueError, match="response cannot be None"):
        update_csrf_cookie(response=None, csrf_token="token")  # type: ignore


def test_is_csrf_token_valid_raises_when_request_none():
    with pytest.raises(ValueError, match="request cannot be None"):
        is_csrf_token_valid(request=None, csrf_header_name=DEFAULT_CSRF_HEADER_NAME)  # type: ignore


def test_is_csrf_token_valid_raises_when_header_name_none():
    """Test that validation raises when csrf_header_name is None"""
    request = make_request(csrf_token="token")
    with pytest.raises(ValueError, match="csrf_header_name cannot be None"):
        is_csrf_token_valid(request, csrf_header_name=None)  # type: ignore


def test_is_csrf_token_valid_raises_when_header_name_empty():
    """Test that validation raises when csrf_header_name is empty string"""
    request = make_request(csrf_token="token")
    with pytest.raises(ValueError, match="csrf_header_name cannot be None"):
        is_csrf_token_valid(request, csrf_header_name="")


def test_delete_csrf_cookie_raises_when_response_none():
    with pytest.raises(ValueError, match="response cannot be None"):
        delete_csrf_cookie(response=None)  # type: ignore
