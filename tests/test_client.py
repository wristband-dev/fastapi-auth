import base64
from unittest.mock import Mock, patch

import httpx
import pytest

from wristband.fastapi_auth.client import WristbandApiClient
from wristband.fastapi_auth.exceptions import InvalidGrantError, WristbandError
from wristband.fastapi_auth.models import SdkConfiguration, UserInfo, WristbandTokenResponse
from wristband.fastapi_auth.retry import MAX_API_RETRY_ATTEMPTS

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
    mock_response.status_code = 404
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
        assert isinstance(result, WristbandTokenResponse)
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
    mock_json = {
        "sub": "user123",
        "tnt_id": "tenant123",
        "app_id": "app123",
        "idp_name": "Wristband",
        "email": "user@example.com",
        "name": "Test User",
    }
    mock_response.json.return_value = mock_json

    with patch.object(client.client, "get", return_value=mock_response) as mock_get:
        mock_response.raise_for_status = Mock()
        result = await client.get_userinfo("access_token_123")
        mock_get.assert_called_once_with(
            "https://app.wristband.dev/api/v1/oauth2/userinfo", headers={"Authorization": "Bearer access_token_123"}
        )
        assert isinstance(result, UserInfo)
        assert result.user_id == "user123"
        assert result.tenant_id == "tenant123"
        assert result.application_id == "app123"
        assert result.identity_provider_name == "Wristband"
        assert result.email == "user@example.com"
        assert result.full_name == "Test User"


@pytest.mark.asyncio
async def test_get_userinfo_empty_response():
    """Test get_userinfo with empty response."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock empty response
    mock_response = Mock()
    mock_response.json.return_value = {}

    with patch.object(client.client, "get", return_value=mock_response):
        mock_response.raise_for_status = Mock()

        with pytest.raises(WristbandError) as exc_info:
            await client.get_userinfo("access_token_123")

        assert exc_info.value.error == "unexpected_error"
        assert "Field required" in exc_info.value.error_description


@pytest.mark.asyncio
async def test_get_userinfo_error():
    """Test get_userinfo with HTTP error."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    # Mock HTTP error
    mock_response = Mock()
    mock_response.status_code = 401
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
        assert isinstance(result, WristbandTokenResponse)
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
    mock_userinfo_response.json.return_value = {
        "sub": "user123",
        "tnt_id": "tenant123",
        "app_id": "app123",
        "idp_name": "Wristband",
        "email": "user@example.com",
    }

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
        assert isinstance(results[0], WristbandTokenResponse)  # get_tokens result
        assert isinstance(results[1], UserInfo)  # get_userinfo result
        assert isinstance(results[2], WristbandTokenResponse)  # refresh_token result


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


########################################
# RETRY BEHAVIOR TESTS
########################################


def _mock_response(status_code: int, json_data: dict = None, text: str = "") -> Mock:
    mock_response = Mock()
    mock_response.status_code = status_code
    if json_data is not None:
        mock_response.json.return_value = json_data
    mock_response.text = text
    if status_code >= 400:
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"{status_code} error", request=Mock(), response=mock_response
        )
    else:
        mock_response.raise_for_status = Mock()
    return mock_response


@pytest.mark.asyncio
async def test_get_sdk_configuration_retries_on_5xx_and_eventually_succeeds():
    """Test get_sdk_configuration retries transient failures and succeeds."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_500 = _mock_response(500)
    mock_200 = _mock_response(
        200,
        {
            "loginUrl": "https://auth.example.com/login",
            "redirectUri": "https://app.example.com/callback",
            "customApplicationLoginPageUrl": None,
            "isApplicationCustomDomainActive": False,
            "loginUrlTenantDomainSuffix": None,
        },
    )

    with patch.object(client.client, "get", side_effect=[mock_500, mock_500, mock_200]) as mock_get:
        result = await client.get_sdk_configuration()

    assert isinstance(result, SdkConfiguration)
    assert mock_get.call_count == 3


@pytest.mark.asyncio
async def test_get_sdk_configuration_does_not_retry_on_4xx():
    """Test get_sdk_configuration does not retry a 4xx error."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_404 = _mock_response(404)

    with patch.object(client.client, "get", return_value=mock_404) as mock_get:
        with pytest.raises(WristbandError):
            await client.get_sdk_configuration()

    assert mock_get.call_count == 1


@pytest.mark.asyncio
async def test_get_tokens_retries_on_5xx_and_eventually_succeeds():
    """Test get_tokens retries transient failures and succeeds."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_500 = _mock_response(500)
    mock_200 = _mock_response(
        200,
        {
            "access_token": "access123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh123",
            "id_token": "id123",
            "scope": "openid",
        },
    )

    with patch.object(client.client, "post", side_effect=[mock_500, mock_500, mock_200]) as mock_post:
        result = await client.get_tokens("code123", "https://app.com/callback", "verifier123")

    assert isinstance(result, WristbandTokenResponse)
    assert mock_post.call_count == 3


@pytest.mark.asyncio
async def test_get_tokens_exhausts_retries_on_persistent_5xx():
    """Test get_tokens retries up to the max attempts on a persistent 5xx, then maps the error."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_500 = _mock_response(500, {"error": "server_error", "error_description": "Down for maintenance"})

    with patch.object(client.client, "post", return_value=mock_500) as mock_post:
        with pytest.raises(WristbandError) as exc_info:
            await client.get_tokens("code123", "https://app.com/callback", "verifier123")

    assert mock_post.call_count == MAX_API_RETRY_ATTEMPTS
    assert exc_info.value.error == "server_error"
    assert exc_info.value.error_description == "Down for maintenance"


@pytest.mark.asyncio
async def test_refresh_token_exhausts_retries_on_persistent_5xx():
    """Test refresh_token retries up to the max attempts on a persistent 5xx, then maps the error."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_500 = _mock_response(500, {"error": "server_error", "error_description": "Down for maintenance"})

    with patch.object(client.client, "post", return_value=mock_500) as mock_post:
        with pytest.raises(WristbandError) as exc_info:
            await client.refresh_token("refresh123")

    assert mock_post.call_count == MAX_API_RETRY_ATTEMPTS
    assert exc_info.value.error == "server_error"
    assert exc_info.value.error_description == "Down for maintenance"


@pytest.mark.asyncio
async def test_refresh_token_retries_on_5xx_and_eventually_succeeds():
    """Test refresh_token retries transient failures and succeeds."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_500 = _mock_response(500)
    mock_200 = _mock_response(
        200,
        {
            "access_token": "new_access123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh123",
            "id_token": "new_id123",
            "scope": "openid",
        },
    )

    with patch.object(client.client, "post", side_effect=[mock_500, mock_500, mock_200]) as mock_post:
        result = await client.refresh_token("refresh123")

    assert isinstance(result, WristbandTokenResponse)
    assert mock_post.call_count == 3


########################################
# NON-JSON ERROR BODY TESTS
########################################
#
# Regression: an error response whose body isn't JSON (e.g. a plain-text or HTML error
# page from a proxy/CDN) must not crash with a JSON decoding error, and a 4xx with such
# a body must still be treated as non-retryable.


@pytest.mark.asyncio
async def test_get_tokens_non_json_4xx_body_does_not_crash_and_is_not_retried():
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_response = _mock_response(401, json_data=None, text="Unauthorized")
    mock_response.json.side_effect = ValueError("not valid json")

    with patch.object(client.client, "post", return_value=mock_response) as mock_post:
        with pytest.raises(WristbandError) as exc_info:
            await client.get_tokens("code123", "https://app.com/callback", "verifier123")

    assert mock_post.call_count == 1
    assert exc_info.value.error == "unknown_error"
    assert exc_info.value.error_description == "Unknown error"


@pytest.mark.asyncio
async def test_refresh_token_non_json_4xx_body_does_not_crash_and_is_not_retried():
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_response = _mock_response(400, json_data=None, text="<html>Bad Request</html>")
    mock_response.json.side_effect = ValueError("not valid json")

    with patch.object(client.client, "post", return_value=mock_response) as mock_post:
        with pytest.raises(WristbandError):
            await client.refresh_token("refresh123")

    assert mock_post.call_count == 1


@pytest.mark.asyncio
async def test_get_tokens_non_json_5xx_body_is_still_retried():
    """A non-JSON body on a 5xx should still be retried -- only the final mapping is affected."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_500 = _mock_response(500, json_data=None, text="Internal Server Error")
    mock_500.json.side_effect = ValueError("not valid json")

    with patch.object(client.client, "post", return_value=mock_500) as mock_post:
        with pytest.raises(WristbandError) as exc_info:
            await client.get_tokens("code123", "https://app.com/callback", "verifier123")

    assert mock_post.call_count == MAX_API_RETRY_ATTEMPTS
    assert exc_info.value.error == "unknown_error"


########################################
# VALIDATE_TENANT_CUSTOM_DOMAIN TESTS
########################################


@pytest.mark.asyncio
async def test_validate_tenant_custom_domain_valid():
    """Test validate_tenant_custom_domain returns True for a valid domain."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_response = _mock_response(200, {"valid": True})

    with patch.object(client.client, "post", return_value=mock_response) as mock_post:
        result = await client.validate_tenant_custom_domain("tenant.custom.com")

    assert result is True
    mock_post.assert_called_once_with(
        "https://app.wristband.dev/api/v1/custom-domains/validate",
        headers=client._json_headers,
        json={"tenantCustomDomain": "tenant.custom.com"},
    )


@pytest.mark.asyncio
async def test_validate_tenant_custom_domain_invalid():
    """Test validate_tenant_custom_domain returns False for an invalid/unverified domain."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_response = _mock_response(200, {"valid": False})

    with patch.object(client.client, "post", return_value=mock_response):
        result = await client.validate_tenant_custom_domain("unverified.custom.com")

    assert result is False


@pytest.mark.asyncio
async def test_validate_tenant_custom_domain_empty_domain():
    """Test validate_tenant_custom_domain fails with an empty domain."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    with pytest.raises(ValueError, match="Tenant custom domain is required"):
        await client.validate_tenant_custom_domain("")


@pytest.mark.asyncio
async def test_validate_tenant_custom_domain_whitespace_domain():
    """Test validate_tenant_custom_domain fails with a whitespace-only domain."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    with pytest.raises(ValueError, match="Tenant custom domain is required"):
        await client.validate_tenant_custom_domain("   ")


@pytest.mark.asyncio
async def test_validate_tenant_custom_domain_retries_on_5xx_and_eventually_succeeds():
    """Test validate_tenant_custom_domain retries transient failures and succeeds."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_500 = _mock_response(500)
    mock_200 = _mock_response(200, {"valid": True})

    with patch.object(client.client, "post", side_effect=[mock_500, mock_500, mock_200]) as mock_post:
        result = await client.validate_tenant_custom_domain("tenant.custom.com")

    assert result is True
    assert mock_post.call_count == 3


@pytest.mark.asyncio
async def test_validate_tenant_custom_domain_does_not_retry_on_4xx():
    """Test validate_tenant_custom_domain does not retry a 4xx error."""
    client = WristbandApiClient("app.wristband.dev", "client123", "secret456")

    mock_400 = _mock_response(400, {"message": "invalid_domain_name"})

    with patch.object(client.client, "post", return_value=mock_400) as mock_post:
        with pytest.raises(httpx.HTTPStatusError):
            await client.validate_tenant_custom_domain("not a real domain")

    assert mock_post.call_count == 1
