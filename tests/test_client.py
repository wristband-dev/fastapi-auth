import base64
from unittest.mock import Mock, patch

import httpx
import pytest

from wristband.fastapi_auth.client import WristbandApiClient
from wristband.fastapi_auth.exceptions import InvalidGrantError, WristbandError
from wristband.fastapi_auth.models import SdkConfiguration, TokenResponse

########################################
# INITIALIZATION TESTS
########################################


def test_client_initialization_success():
    """Test successful WristbandApiClient initialization."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    assert client._base_url == "https://app.wristband.dev/api/v1"
    assert client.client_id == "client123"
    assert "Authorization" in client._basic_auth_headers
    assert "Content-Type" in client._basic_auth_headers
    assert client._basic_auth_headers["Content-Type"] == "application/x-www-form-urlencoded"

    # Verify the Authorization header is properly base64 encoded
    expected_credentials = base64.b64encode(b"client123:secret456").decode("utf-8")
    expected_auth = f"Basic {expected_credentials}"
    assert client._basic_auth_headers["Authorization"] == expected_auth

    assert "Content-Type" in client._json_headers
    assert client._json_headers["Content-Type"] == "application/json"
    assert client._json_headers["Accept"] == "application/json"
    assert isinstance(client.client, httpx.AsyncClient)


def test_client_initialization_empty_domain():
    """Test initialization fails with empty domain."""
    with pytest.raises(ValueError, match="Wristband application vanity domain is required"):
        WristbandApiClient("", "client123", "secret456")


def test_client_initialization_whitespace_domain():
    """Test initialization fails with whitespace-only domain."""
    with pytest.raises(ValueError, match="Wristband application vanity domain is required"):
        WristbandApiClient("   ", "client123", "secret456")


def test_client_initialization_none_domain():
    """Test initialization fails with None domain."""
    with pytest.raises(ValueError, match="Wristband application vanity domain is required"):
        WristbandApiClient(None, "client123", "secret456")  # type: ignore


def test_client_initialization_empty_client_id():
    """Test initialization fails with empty client ID."""
    with pytest.raises(ValueError, match="Client ID is required"):
        WristbandApiClient("app.wristband.dev", "", "secret456")


def test_client_initialization_whitespace_client_id():
    """Test initialization fails with whitespace-only client ID."""
    with pytest.raises(ValueError, match="Client ID is required"):
        WristbandApiClient("app.wristband.dev", "   ", "secret456")


def test_client_initialization_none_client_id():
    """Test initialization fails with None client ID."""
    with pytest.raises(ValueError, match="Client ID is required"):
        WristbandApiClient("app.wristband.dev", None, "secret456")  # type: ignore


def test_client_initialization_empty_client_secret():
    """Test initialization fails with empty client secret."""
    with pytest.raises(ValueError, match="Client secret is required"):
        WristbandApiClient("app.wristband.dev", "client123", "")


def test_client_initialization_whitespace_client_secret():
    """Test initialization fails with whitespace-only client secret."""
    with pytest.raises(ValueError, match="Client secret is required"):
        WristbandApiClient("app.wristband.dev", "client123", "   ")


def test_client_initialization_none_client_secret():
    """Test initialization fails with None client secret."""
    with pytest.raises(ValueError, match="Client secret is required"):
        WristbandApiClient("app.wristband.dev", "client123", None)  # type: ignore


########################################
# GET_SDK_CONFIGURATION TESTS
########################################


@pytest.mark.asyncio
async def test_get_sdk_configuration_success():
    """Test successful SDK configuration retrieval."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock successful response
    mock_response = Mock()
    mock_response.json.return_value = {
        "loginUrl": "https://auth.example.com/login",
        "redirectUri": "https://app.example.com/callback",
        "customApplicationLoginPageUrl": "https://custom.example.com/login",
        "isApplicationCustomDomainActive": True,
        "loginUrlTenantDomainSuffix": "example.com",
    }

    with patch.object(client.client, "get", return_value=mock_response) as mock_get:
        # Mock raise_for_status to do nothing (success case)
        mock_response.raise_for_status = Mock()

        result = await client.get_sdk_configuration()

        # Verify the request was made correctly
        mock_get.assert_called_once_with(
            "https://app.wristband.dev/api/v1/clients/client123/sdk-configuration",
            headers=client._json_headers,
        )

        # Verify the result
        assert isinstance(result, SdkConfiguration)
        assert result.login_url == "https://auth.example.com/login"
        assert result.redirect_uri == "https://app.example.com/callback"
        assert result.custom_application_login_page_url == "https://custom.example.com/login"
        assert result.is_application_custom_domain_active is True
        assert result.login_url_tenant_domain_suffix == "example.com"


@pytest.mark.asyncio
async def test_get_sdk_configuration_error():
    """Test SDK configuration retrieval with error."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock HTTP error
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "404 Not Found", request=Mock(), response=mock_response
    )

    with patch.object(client.client, "get", return_value=mock_response):
        with pytest.raises(WristbandError) as exc_info:
            await client.get_sdk_configuration()

        assert exc_info.value.error == "unexpected_error"
        assert "404 Not Found" in exc_info.value.error_description


########################################
# GET_TOKENS TESTS
########################################


@pytest.mark.asyncio
async def test_get_tokens_success():
    """Test successful token exchange."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock successful response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "access123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh123",
        "id_token": "id123",
        "scope": "openid email",
    }

    with patch.object(client.client, "post", return_value=mock_response) as mock_post:
        result = await client.get_tokens("code123", "https://app.com/callback", "verifier123")

        # Verify the request was made correctly
        mock_post.assert_called_once_with(
            "https://app.wristband.dev/api/v1/oauth2/token",
            headers=client._basic_auth_headers,
            data={
                "grant_type": "authorization_code",
                "code": "code123",
                "redirect_uri": "https://app.com/callback",
                "code_verifier": "verifier123",
            },
        )

        # Verify the result
        assert isinstance(result, TokenResponse)
        assert result.access_token == "access123"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600


@pytest.mark.asyncio
async def test_get_tokens_invalid_grant_error():
    """Test get_tokens raises InvalidGrantError for invalid_grant."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock error response
    mock_response = Mock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": "invalid_grant", "error_description": "Authorization code has expired"}

    with patch.object(client.client, "post", return_value=mock_response):
        with pytest.raises(InvalidGrantError) as exc_info:
            await client.get_tokens("expired_code", "https://app.com/callback", "verifier123")

        assert exc_info.value.error == "invalid_grant"
        assert exc_info.value.error_description == "Authorization code has expired"


@pytest.mark.asyncio
async def test_get_tokens_invalid_grant_no_description():
    """Test get_tokens raises InvalidGrantError with default description."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock error response without description
    mock_response = Mock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": "invalid_grant"}

    with patch.object(client.client, "post", return_value=mock_response):
        with pytest.raises(InvalidGrantError) as exc_info:
            await client.get_tokens("expired_code", "https://app.com/callback", "verifier123")

        assert exc_info.value.error == "invalid_grant"
        assert exc_info.value.error_description == "Invalid grant"


@pytest.mark.asyncio
async def test_get_tokens_other_error():
    """Test get_tokens raises WristbandError for other errors."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock other error response
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"error": "unauthorized", "error_description": "Invalid client credentials"}

    with patch.object(client.client, "post", return_value=mock_response):
        with pytest.raises(WristbandError) as exc_info:
            await client.get_tokens("code123", "https://app.com/callback", "verifier123")

        assert exc_info.value.error == "unauthorized"
        assert exc_info.value.error_description == "Invalid client credentials"


@pytest.mark.asyncio
async def test_get_tokens_unknown_error():
    """Test get_tokens raises WristbandError with defaults for unknown errors."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock response with missing error fields
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.json.return_value = {}

    with patch.object(client.client, "post", return_value=mock_response):
        with pytest.raises(WristbandError) as exc_info:
            await client.get_tokens("code123", "https://app.com/callback", "verifier123")

        assert exc_info.value.error == "unknown_error"
        assert exc_info.value.error_description == "Unknown error"


@pytest.mark.asyncio
async def test_get_tokens_empty_code():
    """Test get_tokens fails with empty code."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    with pytest.raises(ValueError, match="Authorization code is required"):
        await client.get_tokens("", "https://app.com/callback", "verifier123")


@pytest.mark.asyncio
async def test_get_tokens_whitespace_code():
    """Test get_tokens fails with whitespace-only code."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    with pytest.raises(ValueError, match="Authorization code is required"):
        await client.get_tokens("   ", "https://app.com/callback", "verifier123")


@pytest.mark.asyncio
async def test_get_tokens_empty_redirect_uri():
    """Test get_tokens fails with empty redirect URI."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    with pytest.raises(ValueError, match="Redirect URI is required"):
        await client.get_tokens("code123", "", "verifier123")


@pytest.mark.asyncio
async def test_get_tokens_empty_code_verifier():
    """Test get_tokens fails with empty code verifier."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    with pytest.raises(ValueError, match="Code verifier is required"):
        await client.get_tokens("code123", "https://app.com/callback", "")


########################################
# GET_USERINFO TESTS
########################################


@pytest.mark.asyncio
async def test_get_userinfo_success():
    """Test successful userinfo retrieval."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock successful response
    mock_response = Mock()
    mock_response.json.return_value = {"sub": "user123", "email": "user@example.com", "name": "Test User"}

    with patch.object(client.client, "get", return_value=mock_response) as mock_get:
        mock_response.raise_for_status = Mock()
        result = await client.get_userinfo("access_token_123")
        mock_get.assert_called_once_with(
            "https://app.wristband.dev/api/v1/oauth2/userinfo", headers={"Authorization": "Bearer access_token_123"}
        )
        assert result == {"sub": "user123", "email": "user@example.com", "name": "Test User"}


@pytest.mark.asyncio
async def test_get_userinfo_empty_response():
    """Test get_userinfo with empty response."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock empty response
    mock_response = Mock()
    mock_response.json.return_value = {}

    with patch.object(client.client, "get", return_value=mock_response):
        mock_response.raise_for_status = Mock()
        result = await client.get_userinfo("access_token_123")
        assert result == {}


@pytest.mark.asyncio
async def test_get_userinfo_error():
    """Test get_userinfo with HTTP error."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock HTTP error
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "401 Unauthorized", request=Mock(), response=mock_response
    )

    with patch.object(client.client, "get", return_value=mock_response):
        with pytest.raises(WristbandError) as exc_info:
            await client.get_userinfo("invalid_token")

        assert exc_info.value.error == "unexpected_error"
        assert "401 Unauthorized" in exc_info.value.error_description


########################################
# REFRESH_TOKEN TESTS
########################################


@pytest.mark.asyncio
async def test_refresh_token_success():
    """Test successful token refresh."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock successful response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "new_access123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "new_refresh123",
        "id_token": "new_id123",
        "scope": "openid email",
    }

    with patch.object(client.client, "post", return_value=mock_response) as mock_post:
        result = await client.refresh_token("refresh123")

        # Verify the request was made correctly
        mock_post.assert_called_once_with(
            "https://app.wristband.dev/api/v1/oauth2/token",
            headers=client._basic_auth_headers,
            data={"grant_type": "refresh_token", "refresh_token": "refresh123"},
        )

        # Verify the result
        assert isinstance(result, TokenResponse)
        assert result.access_token == "new_access123"


@pytest.mark.asyncio
async def test_refresh_token_invalid_grant():
    """Test refresh_token raises InvalidGrantError for invalid_grant."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock error response
    mock_response = Mock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": "invalid_grant", "error_description": "Refresh token has expired"}

    with patch.object(client.client, "post", return_value=mock_response):
        with pytest.raises(InvalidGrantError) as exc_info:
            await client.refresh_token("expired_refresh")

        assert exc_info.value.error == "invalid_grant"
        assert exc_info.value.error_description == "Refresh token has expired"


@pytest.mark.asyncio
async def test_refresh_token_other_error():
    """Test refresh_token raises WristbandError for other HTTP errors."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock other error response
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"error": "unauthorized", "error_description": "Invalid client"}

    with patch.object(client.client, "post", return_value=mock_response):
        with pytest.raises(WristbandError) as exc_info:
            await client.refresh_token("refresh123")

        assert exc_info.value.error == "unauthorized"
        assert exc_info.value.error_description == "Invalid client"


########################################
# REVOKE_REFRESH_TOKEN TESTS
########################################


@pytest.mark.asyncio
async def test_revoke_refresh_token_success():
    """Test successful refresh token revocation."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock successful response
    mock_response = Mock()
    mock_response.status_code = 200

    with patch.object(client.client, "post", return_value=mock_response) as mock_post:
        result = await client.revoke_refresh_token("refresh123")

        # Verify the request was made correctly
        mock_post.assert_called_once_with(
            "https://app.wristband.dev/api/v1/oauth2/revoke",
            headers=client._basic_auth_headers,
            data={"token": "refresh123"},
        )

        # Verify no return value
        assert result is None


@pytest.mark.asyncio
async def test_revoke_refresh_token_with_error():
    """Test revoke_refresh_token doesn't raise errors (fire and forget)."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock error response
    mock_response = Mock()
    mock_response.status_code = 400

    with patch.object(client.client, "post", return_value=mock_response):
        # Should not raise an exception
        result = await client.revoke_refresh_token("invalid_refresh")
        assert result is None


########################################
# INTEGRATION TESTS
########################################


def test_base_url_construction():
    """Test that base URL is constructed correctly."""
    test_cases = [
        ("app.wristband.dev", "https://app.wristband.dev/api/v1"),
        ("custom.domain.com", "https://custom.domain.com/api/v1"),
        ("localhost:8080", "https://localhost:8080/api/v1"),
    ]

    for domain, expected_url in test_cases:
        client = WristbandApiClient(domain, "client123", "secret456")
        assert client._base_url == expected_url


def test_authorization_header_encoding():
    """Test various client ID and secret combinations."""
    test_cases = [
        ("client123", "secret456"),
        ("special@client", "secret!@#$%"),
        ("client_with_underscore", "secret-with-dash"),
        ("123456", "abcdef"),
    ]

    for client_id, client_secret in test_cases:
        client = WristbandApiClient("app.wristband.dev", client_id, client_secret)

        # Decode and verify the authorization header
        auth_header = client._basic_auth_headers["Authorization"]
        assert auth_header.startswith("Basic ")

        encoded_part = auth_header[6:]  # Remove "Basic "
        decoded = base64.b64decode(encoded_part).decode("utf-8")
        assert decoded == f"{client_id}:{client_secret}"


@pytest.mark.asyncio
async def test_concurrent_requests():
    """Test that multiple concurrent requests work correctly."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock responses for different endpoints
    mock_token_response = Mock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {
        "access_token": "access123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh123",
        "id_token": "id123",
        "scope": "openid",
    }

    mock_userinfo_response = Mock()
    mock_userinfo_response.json.return_value = {"sub": "user123", "email": "user@example.com"}

    with (
        patch.object(client.client, "post", return_value=mock_token_response),
        patch.object(client.client, "get", return_value=mock_userinfo_response),
    ):

        # Make concurrent requests
        import asyncio

        tasks = [
            client.get_tokens("code1", "https://app.com/callback", "verifier1"),
            client.get_userinfo("access_token_123"),
            client.refresh_token("refresh123"),
        ]

        results = await asyncio.gather(*tasks)

        # Verify all requests completed
        assert len(results) == 3
        assert isinstance(results[0], TokenResponse)  # get_tokens result
        assert isinstance(results[1], dict)  # get_userinfo result
        assert isinstance(results[2], TokenResponse)  # refresh_token result


@pytest.mark.asyncio
async def test_error_response_parsing():
    """Test various error response formats are handled correctly."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    error_cases = [
        # Standard OAuth error
        (
            {"error": "invalid_request", "error_description": "Missing parameter"},
            "invalid_request",
            "Missing parameter",
        ),
        # Error without description
        ({"error": "access_denied"}, "access_denied", "Unknown error"),
        # Completely empty response
        ({}, "unknown_error", "Unknown error"),
        # Response with extra fields
        (
            {"error": "server_error", "error_description": "Internal error", "extra": "ignored"},
            "server_error",
            "Internal error",
        ),
    ]

    for response_data, expected_error, expected_description in error_cases:
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = response_data

        with patch.object(client.client, "post", return_value=mock_response):
            with pytest.raises(WristbandError) as exc_info:
                await client.get_tokens("code123", "https://app.com/callback", "verifier123")

            assert exc_info.value.error == expected_error
            assert exc_info.value.error_description == expected_description
