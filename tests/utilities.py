"""
Test utilities for FastAPI Auth SDK tests.
Provides helper functions for common test scenarios and assertions.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from unittest.mock import Mock
from urllib.parse import ParseResult, parse_qs, urlparse

from fastapi import Request, Response
from fastapi.responses import RedirectResponse

from wristband.fastapi_auth.models import LoginState
from wristband.fastapi_auth.utils import SessionEncryptor

# Shared test secret
TEST_LOGIN_STATE_SECRET = "this_is_a_very_long_secret_key_for_testing_purposes_123456789"

# Singleton encryptor instance
_login_state_encryptor = SessionEncryptor(TEST_LOGIN_STATE_SECRET)


def create_mock_request(
    url: str = "https://example.com/callback",
    query_params: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    host: Optional[str] = None,
) -> Request:
    """
    Create a mock FastAPI Request object for testing.

    Args:
        url: The request URL
        query_params: Query parameters as key-value pairs
        cookies: Request cookies as key-value pairs
        host: Override host for subdomain testing

    Returns:
        Mock Request object configured with the provided data
    """
    mock_request = Mock(spec=Request)

    # Parse URL
    parsed_url = urlparse(url)
    netloc = host if host else parsed_url.netloc

    # Mock URL object properly
    mock_url = Mock()
    mock_url.netloc = netloc
    mock_url.__str__ = Mock(return_value=url)
    mock_request.url = mock_url

    # Mock query params
    if query_params:
        # Create a mock that supports both get() and getlist()
        mock_query_params = Mock()
        mock_query_params.get = lambda key, default=None: query_params.get(key, default)
        mock_query_params.getlist = lambda key: [query_params[key]] if key in query_params else []
        mock_request.query_params = mock_query_params
    else:
        mock_query_params = Mock()
        mock_query_params.get = Mock(return_value=None)
        mock_query_params.getlist = Mock(return_value=[])
        mock_request.query_params = mock_query_params

    # Mock cookies
    mock_request.cookies = cookies or {}

    return mock_request


def assert_redirect_no_cache(response: Response, expected_url: str) -> Tuple[ParseResult, Dict[str, List[str]]]:
    """
    Assert that a response is a proper redirect with no-cache headers.

    Args:
        response: The FastAPI Response object to check
        expected_url: The expected redirect URL

    Returns:
        Tuple of (parsed_url, query_params) for further assertions

    Raises:
        AssertionError: If response doesn't match expectations
    """
    assert isinstance(response, RedirectResponse), f"Expected RedirectResponse but got {type(response)}"
    assert response.status_code == 302, f"Expected status 302 but got {response.status_code}"

    # Check headers
    headers = response.headers
    assert (
        headers.get("cache-control") == "no-store"
    ), f"Expected Cache-Control no-store but got {headers.get('cache-control')}"
    assert headers.get("pragma") == "no-cache", f"Expected Pragma no-cache but got {headers.get('pragma')}"

    # For RedirectResponse, the URL is in the Location header
    actual_url = headers.get("location")
    assert actual_url is not None, "No Location header found in redirect response"

    parsed_url = urlparse(actual_url)
    expected = urlparse(expected_url)

    assert parsed_url.scheme == expected.scheme, f"Expected scheme {expected.scheme}, got {parsed_url.scheme}"
    assert parsed_url.netloc == expected.netloc, f"Expected netloc {expected.netloc}, got {parsed_url.netloc}"
    assert parsed_url.path == expected.path, f"Expected path {expected.path}, got {parsed_url.path}"

    # Query params
    query_params = parse_qs(parsed_url.query)

    return parsed_url, query_params


def assert_single_login_cookie_valid(response: Response) -> Tuple[str, str]:
    """
    Assert that response contains exactly one valid login cookie.

    Args:
        response: The FastAPI Response object to check

    Returns:
        Tuple of (cookie_name, cookie_value)

    Raises:
        AssertionError: If cookie validation fails
    """
    # Get all Set-Cookie headers
    set_cookie_headers = []

    # Handle both single string and list of strings for set-cookie
    set_cookie_raw = response.headers.get("set-cookie")
    if isinstance(set_cookie_raw, str):
        set_cookie_headers = [set_cookie_raw]
    elif isinstance(set_cookie_raw, list):
        set_cookie_headers = set_cookie_raw
    else:
        assert False, "No Set-Cookie header found"

    # Find login cookies
    login_cookies = []
    for header in set_cookie_headers:
        if "login#" in header:
            login_cookies.append(header)

    assert len(login_cookies) == 1, f"Expected 1 login cookie, found {len(login_cookies)}"

    set_cookie_header = login_cookies[0]

    # Parse the cookie to extract name and value
    # Format: "login#state#timestamp=value; attributes..."
    cookie_parts = set_cookie_header.split("=", 1)
    assert len(cookie_parts) == 2, "Invalid cookie format"

    cookie_name = cookie_parts[0]
    cookie_value_and_attrs = cookie_parts[1]
    cookie_value = cookie_value_and_attrs.split(";")[0]  # Remove attributes

    # Validate cookie name structure
    parts = cookie_name.split("#")
    assert len(parts) == 3, f"Cookie name structure invalid: {cookie_name}"
    login, state, timestamp_str = parts
    assert login == "login", "Login prefix is missing or empty"
    assert state, "State is missing or empty"

    # Validate timestamp
    timestamp = int(timestamp_str)
    assert timestamp > 0, "Cookie timestamp must be positive"

    # Assert cookie has a value
    assert cookie_value, "Cookie value is missing or empty"

    # Validate cookie attributes in the header
    header_lower = set_cookie_header.lower()
    assert "httponly" in header_lower, "Cookie should be httponly"
    assert "samesite=lax" in header_lower, "Cookie should have samesite=lax"
    assert "path=/" in header_lower, "Cookie should have path=/"
    assert "max-age=3600" in header_lower, "Cookie should have max-age=3600"
    assert "secure" in header_lower, "Secure should be present"

    # Check for expires attribute and validate it's in the future
    if "expires=" in header_lower:
        # Extract expires value
        expires_start = header_lower.find("expires=") + 8
        expires_end = header_lower.find(";", expires_start)
        if expires_end == -1:
            expires_end = len(header_lower)
        expires_str = set_cookie_header[expires_start:expires_end]

        # Parse expires datetime
        expires_dt = datetime.strptime(expires_str, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        assert expires_dt > now, f"Cookie expiration {expires_dt} is not in the future"

    return cookie_name, cookie_value


def assert_authorize_query_params(
    query_params: Dict[str, List[str]], client_id: str, redirect_uri: str, scopes: str = "openid offline_access email"
) -> None:
    """
    Assert that OAuth authorize URL query parameters are correct.

    Args:
        query_params: Parsed query parameters from URL
        client_id: Expected client ID
        redirect_uri: Expected redirect URI
        scopes: Expected scopes string

    Raises:
        AssertionError: If parameters don't match expectations
    """
    assert query_params["client_id"] == [
        client_id
    ], f"Expected client_id [{client_id}], got {query_params.get('client_id')}"
    assert query_params["redirect_uri"] == [
        redirect_uri
    ], f"Expected redirect_uri [{redirect_uri}], got {query_params.get('redirect_uri')}"
    assert query_params["scope"] == [scopes], f"Expected scope [{scopes}], got {query_params.get('scope')}"

    assert query_params["response_type"] == ["code"]
    assert query_params["code_challenge_method"] == ["S256"]

    assert "state" in query_params and len(query_params["state"][0]) > 0, "Missing or empty 'state'"
    assert "nonce" in query_params and len(query_params["nonce"][0]) > 0, "Missing or empty 'nonce'"
    assert (
        "code_challenge" in query_params and len(query_params["code_challenge"][0]) > 0
    ), "Missing or empty 'code_challenge'"


def encrypt_login_state(login_state: LoginState) -> str:
    """
    Encrypt a LoginState object for testing.

    Args:
        login_state: The LoginState to encrypt

    Returns:
        Encrypted login state string
    """
    return _login_state_encryptor.encrypt(login_state.to_dict())


def decrypt_login_state(login_state_cookie: str) -> LoginState:
    """
    Decrypt a login state cookie for testing.

    Args:
        login_state_cookie: Encrypted login state string

    Returns:
        Decrypted LoginState object
    """
    login_state_dict = _login_state_encryptor.decrypt(login_state_cookie)
    return LoginState(**login_state_dict)


def assert_no_login_cookies(response: Response) -> None:
    """
    Assert that response contains no login cookies.

    Args:
        response: The FastAPI Response object to check

    Raises:
        AssertionError: If any login cookies are found
    """
    set_cookie_headers = response.headers.get("set-cookie")
    if set_cookie_headers:
        login_cookies = [
            h
            for h in (set_cookie_headers if isinstance(set_cookie_headers, list) else [set_cookie_headers])
            if "login#" in h
        ]
        assert len(login_cookies) == 0, f"Expected 0 login cookies, found {len(login_cookies)}"


def create_test_login_state(
    state: str = "test_state_123",
    code_verifier: str = "test_code_verifier_123",
    redirect_uri: str = "https://example.com/callback",
    return_url: Optional[str] = None,
    custom_state: Optional[Dict[str, str]] = None,
) -> LoginState:
    """
    Create a LoginState object for testing.

    Args:
        state: OAuth state parameter
        code_verifier: PKCE code verifier
        redirect_uri: OAuth redirect URI
        return_url: Optional return URL after auth
        custom_state: Optional custom state data

    Returns:
        LoginState object with test data
    """
    return LoginState(
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        return_url=return_url,
        custom_state=custom_state,
    )
