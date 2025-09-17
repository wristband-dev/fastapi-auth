from datetime import datetime
from unittest.mock import Mock, patch

import httpx
import pytest

from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.exceptions import InvalidGrantError, WristbandError
from wristband.fastapi_auth.models import AuthConfig, TokenData, TokenResponse


@pytest.fixture
def auth_config():
    """Create a valid AuthConfig for testing."""
    return AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        login_state_secret="a" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
        wristband_application_vanity_domain="app.wristband.dev",
        token_expiration_buffer=60,
    )


@pytest.fixture
def wristband_auth(auth_config):
    """Create a WristbandAuth instance for testing."""
    return WristbandAuth(auth_config)


@pytest.fixture
def mock_token_response():
    """Create a mock token response."""
    return TokenResponse(
        access_token="new_access_token",
        id_token="new_id_token",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="new_refresh_token",
        scope="openid email",
    )


########################################
# PARAMETER VALIDATION TESTS
########################################


@pytest.mark.asyncio
async def test_refresh_token_if_expired_empty_refresh_token(wristband_auth):
    """Test that empty refresh token raises TypeError."""
    with pytest.raises(TypeError, match="Refresh token must be a valid string"):
        await wristband_auth.refresh_token_if_expired("", 1234567890000)


@pytest.mark.asyncio
async def test_refresh_token_if_expired_none_refresh_token(wristband_auth):
    """Test that None refresh token raises TypeError."""
    with pytest.raises(TypeError, match="Refresh token must be a valid string"):
        await wristband_auth.refresh_token_if_expired(None, 1234567890000)


@pytest.mark.asyncio
async def test_refresh_token_if_expired_whitespace_refresh_token(wristband_auth):
    """Test that whitespace-only refresh token raises TypeError."""
    with pytest.raises(TypeError, match="Refresh token must be a valid string"):
        await wristband_auth.refresh_token_if_expired("   ", 1234567890000)


@pytest.mark.asyncio
async def test_refresh_token_if_expired_none_expires_at(wristband_auth):
    """Test that None expires_at raises TypeError."""
    with pytest.raises(TypeError, match="The expiresAt field must be an integer greater than 0"):
        await wristband_auth.refresh_token_if_expired("refresh_token", None)


@pytest.mark.asyncio
async def test_refresh_token_if_expired_negative_expires_at(wristband_auth):
    """Test that negative expires_at raises TypeError."""
    with pytest.raises(TypeError, match="The expiresAt field must be an integer greater than 0"):
        await wristband_auth.refresh_token_if_expired("refresh_token", -1)


@pytest.mark.asyncio
async def test_refresh_token_if_expired_zero_expires_at(wristband_auth):
    """Test that zero expires_at raises TypeError."""
    with pytest.raises(TypeError, match="The expiresAt field must be an integer greater than 0"):
        await wristband_auth.refresh_token_if_expired("refresh_token", 0)


########################################
# TOKEN NOT EXPIRED TESTS
########################################


@pytest.mark.asyncio
async def test_refresh_token_if_expired_token_not_expired(wristband_auth):
    """Test that valid token returns None (no refresh needed)."""
    # Set expires_at to far future (1 hour from now)
    future_timestamp = int((datetime.now().timestamp() + 3600) * 1000)

    result = await wristband_auth.refresh_token_if_expired("refresh_token", future_timestamp)

    assert result is None


@pytest.mark.asyncio
async def test_refresh_token_if_expired_token_expires_soon_but_not_expired(wristband_auth):
    """Test that token expiring soon but not yet expired returns None."""
    # Set expires_at to 30 seconds from now (should not trigger refresh)
    near_future_timestamp = int((datetime.now().timestamp() + 30) * 1000)

    result = await wristband_auth.refresh_token_if_expired("refresh_token", near_future_timestamp)

    assert result is None


########################################
# SUCCESSFUL REFRESH TESTS
########################################


@pytest.mark.asyncio
async def test_refresh_token_if_expired_success(wristband_auth, mock_token_response):
    """Test successful token refresh."""
    # Set expires_at to past (token expired)
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    # Mock the API call
    with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response) as mock_refresh:
        # Mock time.time() to return a consistent value for calculation
        with patch("time.time", return_value=1000000):
            result = await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Verify API was called
    mock_refresh.assert_called_once_with("refresh_token")

    # Verify result
    assert result is not None
    assert isinstance(result, TokenData)
    assert result.access_token == "new_access_token"
    assert result.id_token == "new_id_token"
    assert result.refresh_token == "new_refresh_token"

    # Verify expiration calculation (3600 - 60 buffer = 3540 seconds)
    expected_expires_in = 3600 - 60  # token_expiration_buffer
    expected_expires_at = int((1000000 + expected_expires_in) * 1000)
    assert result.expires_in == expected_expires_in
    assert result.expires_at == expected_expires_at


@pytest.mark.asyncio
async def test_refresh_token_if_expired_success_with_custom_buffer(auth_config, mock_token_response):
    """Test successful token refresh with custom expiration buffer."""
    # Set custom buffer
    auth_config.token_expiration_buffer = 120
    wristband_auth = WristbandAuth(auth_config)

    # Use a timestamp that's in the past (Unix epoch)
    past_timestamp = 1000  # Very old timestamp

    with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
        with patch("time.time", return_value=1000000):
            result = await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Add assertion that result is not None first
    assert result is not None, "Token refresh should have been triggered"

    # Verify custom buffer was applied (3600 - 120 = 3480)
    expected_expires_in = 3600 - 120
    assert result.expires_in == expected_expires_in


@pytest.mark.asyncio
async def test_refresh_token_if_expired_success_with_zero_buffer(auth_config, mock_token_response):
    """Test successful token refresh with zero expiration buffer."""
    # Set zero buffer
    auth_config.token_expiration_buffer = 0
    wristband_auth = WristbandAuth(auth_config)

    # Use a timestamp that's definitely in the past (Unix epoch)
    past_timestamp = 1000  # Very old timestamp

    with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
        with patch("time.time", return_value=1000000):
            result = await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Add assertion that result is not None first
    assert result is not None, "Token refresh should have been triggered"

    # Verify no buffer was applied
    assert result.expires_in == 3600


########################################
# ERROR HANDLING TESTS
########################################


@pytest.mark.asyncio
async def test_refresh_token_if_expired_invalid_grant_error(wristband_auth):
    """Test that InvalidGrantError is immediately raised without retry."""
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    # Mock InvalidGrantError
    mock_error = InvalidGrantError("Refresh token expired")
    with patch.object(wristband_auth._wristband_api, "refresh_token", side_effect=mock_error) as mock_refresh:
        with pytest.raises(InvalidGrantError) as exc_info:
            await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Verify API was called only once (no retry for InvalidGrantError)
    mock_refresh.assert_called_once_with("refresh_token")
    assert exc_info.value.error == "invalid_grant"


@pytest.mark.asyncio
async def test_refresh_token_if_expired_4xx_error(wristband_auth):
    """Test that 4xx HTTP errors raise WristbandError without retry."""
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    # Mock 4xx HTTP error
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"error_description": "Unauthorized client"}

    http_error = httpx.HTTPStatusError("401 Unauthorized", request=Mock(), response=mock_response)

    with patch.object(wristband_auth._wristband_api, "refresh_token", side_effect=http_error) as mock_refresh:
        with pytest.raises(WristbandError) as exc_info:
            await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Verify API was called only once (no retry for 4xx errors)
    mock_refresh.assert_called_once_with("refresh_token")
    assert exc_info.value.error == "invalid_refresh_token"
    assert exc_info.value.error_description == "Unauthorized client"


@pytest.mark.asyncio
async def test_refresh_token_if_expired_4xx_error_no_json(wristband_auth):
    """Test that 4xx HTTP errors without JSON response use default error description."""
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    # Mock 4xx HTTP error without valid JSON
    mock_response = Mock()
    mock_response.status_code = 400
    mock_response.json.side_effect = Exception("Invalid JSON")

    http_error = httpx.HTTPStatusError("400 Bad Request", request=Mock(), response=mock_response)

    with patch.object(wristband_auth._wristband_api, "refresh_token", side_effect=http_error):
        with pytest.raises(WristbandError) as exc_info:
            await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    assert exc_info.value.error == "invalid_refresh_token"
    assert exc_info.value.error_description == "Invalid Refresh Token"


@pytest.mark.asyncio
async def test_refresh_token_if_expired_5xx_error_with_retries(wristband_auth):
    """Test that 5xx errors are retried up to the maximum attempts."""
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    # Mock 5xx HTTP error
    mock_response = Mock()
    mock_response.status_code = 500
    http_error = httpx.HTTPStatusError("500 Internal Server Error", request=Mock(), response=mock_response)

    with patch.object(wristband_auth._wristband_api, "refresh_token", side_effect=http_error) as mock_refresh:
        with patch("time.sleep") as mock_sleep:  # Mock sleep to speed up test
            with pytest.raises(WristbandError) as exc_info:
                await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Verify API was called maximum number of times (3 attempts: initial + 2 retries)
    assert mock_refresh.call_count == 3
    mock_refresh.assert_called_with("refresh_token")

    # Verify sleep was called for retries (2 times)
    assert mock_sleep.call_count == 2
    mock_sleep.assert_called_with(0.1)  # _token_refresh_retry_timeout

    assert exc_info.value.error == "unexpected_error"
    assert exc_info.value.error_description == "Unexpected Error"


@pytest.mark.asyncio
async def test_refresh_token_if_expired_5xx_error_eventual_success(wristband_auth, mock_token_response):
    """Test that 5xx errors are retried and eventually succeed."""
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    # Mock 5xx HTTP error for first two attempts, then success
    mock_response = Mock()
    mock_response.status_code = 500
    http_error = httpx.HTTPStatusError("500 Internal Server Error", request=Mock(), response=mock_response)

    with patch.object(
        wristband_auth._wristband_api, "refresh_token", side_effect=[http_error, http_error, mock_token_response]
    ) as mock_refresh:
        with patch("time.sleep") as mock_sleep:
            with patch("time.time", return_value=1000000):
                result = await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Verify API was called 3 times (2 failures + 1 success)
    assert mock_refresh.call_count == 3

    # Verify sleep was called 2 times (for the 2 retries)
    assert mock_sleep.call_count == 2

    # Verify successful result
    assert result is not None
    assert isinstance(result, TokenData)
    assert result.access_token == "new_access_token"


@pytest.mark.asyncio
async def test_refresh_token_if_expired_other_exception_with_retries(wristband_auth):
    """Test that other exceptions are retried up to the maximum attempts."""
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    # Mock a generic exception (not HTTPStatusError or InvalidGrantError)
    generic_error = Exception("Network error")

    with patch.object(wristband_auth._wristband_api, "refresh_token", side_effect=generic_error) as mock_refresh:
        with patch("time.sleep") as mock_sleep:
            with pytest.raises(WristbandError) as exc_info:
                await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Verify API was called maximum number of times
    assert mock_refresh.call_count == 3

    # Verify sleep was called for retries
    assert mock_sleep.call_count == 2

    assert exc_info.value.error == "unexpected_error"
    assert exc_info.value.error_description == "Unexpected Error"


########################################
# EDGE CASE AND INTEGRATION TESTS
########################################


@pytest.mark.asyncio
async def test_refresh_token_if_expired_timestamp_boundary(wristband_auth):
    """Test behavior at the exact expiration timestamp boundary."""
    # Set expires_at to exactly current time
    with patch("wristband.fastapi_auth.auth.datetime") as mock_datetime:
        mock_now = Mock()
        mock_now.timestamp.return_value = 1000000  # Fixed timestamp
        mock_datetime.now.return_value = mock_now
        
        current_timestamp = int(1000000 * 1000)  # Same timestamp in milliseconds
        result = await wristband_auth.refresh_token_if_expired("refresh_token", current_timestamp)

    # Should return None since token is not yet expired (>= check)
    assert result is None


@pytest.mark.asyncio
async def test_refresh_token_if_expired_milliseconds_precision(wristband_auth, mock_token_response):
    """Test that millisecond precision is handled correctly."""
    # Set expires_at to 1 millisecond in the past
    past_timestamp = int(datetime.now().timestamp() * 1000) - 1

    with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
        with patch("time.time", return_value=1000000):
            result = await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Should refresh since token is expired by 1ms
    assert result is not None


@pytest.mark.asyncio
async def test_refresh_token_if_expired_retry_configuration(wristband_auth):
    """Test that retry configuration is respected."""
    # Verify the retry configuration constants
    assert wristband_auth._token_refresh_retries == 2
    assert wristband_auth._token_refresh_retry_timeout == 0.1


@pytest.mark.asyncio
async def test_refresh_token_if_expired_concurrent_calls(wristband_auth, mock_token_response):
    """Test behavior with concurrent refresh attempts."""
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response) as mock_refresh:
        with patch("time.time", return_value=1000000):
            # Simulate concurrent calls
            import asyncio

            tasks = [
                wristband_auth.refresh_token_if_expired("refresh_token1", past_timestamp),
                wristband_auth.refresh_token_if_expired("refresh_token2", past_timestamp),
            ]

            results = await asyncio.gather(*tasks)

    # Both calls should succeed
    assert len(results) == 2
    assert all(result is not None for result in results)
    assert all(isinstance(result, TokenData) for result in results)

    # API should be called twice (once for each token)
    assert mock_refresh.call_count == 2


@pytest.mark.asyncio
async def test_refresh_token_if_expired_token_data_structure(wristband_auth, mock_token_response):
    """Test that returned TokenData has correct structure and values."""
    past_timestamp = int((datetime.now().timestamp() - 100) * 1000)

    with patch.object(wristband_auth._wristband_api, "refresh_token", return_value=mock_token_response):
        with patch("time.time", return_value=1000000):
            result = await wristband_auth.refresh_token_if_expired("refresh_token", past_timestamp)

    # Verify all fields are present and correct type
    assert hasattr(result, "access_token")
    assert hasattr(result, "id_token")
    assert hasattr(result, "expires_in")
    assert hasattr(result, "expires_at")
    assert hasattr(result, "refresh_token")

    assert isinstance(result.access_token, str)
    assert isinstance(result.id_token, str)
    assert isinstance(result.expires_in, int)
    assert isinstance(result.expires_at, int)
    assert isinstance(result.refresh_token, str)

    # Verify values match expected calculations
    assert result.access_token == mock_token_response.access_token
    assert result.id_token == mock_token_response.id_token
    assert result.refresh_token == mock_token_response.refresh_token
