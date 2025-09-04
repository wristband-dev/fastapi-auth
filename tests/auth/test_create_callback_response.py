import pytest

from tests.utilities import TEST_LOGIN_STATE_SECRET, assert_redirect_no_cache, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import AuthConfig


class TestWristbandAuthCreateCallbackResponse:
    """Test cases for create_callback_response method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            token_expiration_buffer=60,
        )
        self.wristband_auth = WristbandAuth(self.auth_config)

    @pytest.mark.asyncio
    async def test_create_callback_response_invalid_redirect_url_none(self) -> None:
        """Test raises TypeError when redirect_url is None."""
        request = create_mock_request("/callback")

        with pytest.raises(TypeError, match="redirect_url cannot be null or empty"):
            await self.wristband_auth.create_callback_response(request, None)  # type: ignore

    @pytest.mark.asyncio
    async def test_create_callback_response_invalid_redirect_url_empty(self) -> None:
        """Test raises TypeError when redirect_url is empty string."""
        request = create_mock_request("/callback")

        with pytest.raises(TypeError, match="redirect_url cannot be null or empty"):
            await self.wristband_auth.create_callback_response(request, "")

    @pytest.mark.asyncio
    async def test_create_callback_response_invalid_redirect_url_whitespace(self) -> None:
        """Test raises TypeError when redirect_url is only whitespace."""
        request = create_mock_request("/callback")

        with pytest.raises(TypeError, match="redirect_url cannot be null or empty"):
            await self.wristband_auth.create_callback_response(request, "   ")

    @pytest.mark.asyncio
    async def test_create_callback_response_valid_redirect_no_cookie(self) -> None:
        """Test successful response creation when no login state cookie exists."""
        request = create_mock_request("/callback", query_params={"state": "test_state"})
        redirect_url = "https://app.example.com/dashboard"

        response = await self.wristband_auth.create_callback_response(request, redirect_url)

        assert_redirect_no_cache(response, redirect_url)

        # Verify no cookies are set (since none existed to clear)
        set_cookie_header = response.headers.get("set-cookie")
        assert set_cookie_header is None, "No cookies should be set when none exist to clear"

    @pytest.mark.asyncio
    async def test_create_callback_response_valid_redirect_with_cookie(self) -> None:
        """Test successful response creation when login state cookie exists and gets cleared."""
        request = create_mock_request(
            "/callback",
            query_params={"state": "test_state"},
            cookies={"login#test_state#1640995200000": "encrypted_data"},
        )
        redirect_url = "https://app.example.com/dashboard"

        response = await self.wristband_auth.create_callback_response(request, redirect_url)

        # Validate redirect response
        assert_redirect_no_cache(response, redirect_url)

        # Check that the cookie was cleared by looking at Set-Cookie header
        set_cookie_header = response.headers.get("set-cookie")

        assert set_cookie_header is not None, "Login cookie should be cleared"

        # Verify cookie deletion properties
        assert "login#test_state#1640995200000=" in set_cookie_header  # Empty value
        assert "max-age=0" in set_cookie_header.lower()  # Expires immediately
        assert "path=/" in set_cookie_header.lower()
        assert "httponly" in set_cookie_header.lower()
        assert "secure" in set_cookie_header.lower()  # Default secure cookies enabled

    @pytest.mark.asyncio
    async def test_create_callback_response_complex_redirect_url(self) -> None:
        """Test response creation with complex redirect URL containing query parameters."""
        request = create_mock_request("/callback", query_params={"state": "test_state"})
        redirect_url = "https://app.example.com/dashboard?user=123&tab=profile&return_to=%2Fsettings"

        response = await self.wristband_auth.create_callback_response(request, redirect_url)

        assert_redirect_no_cache(response, redirect_url)

    @pytest.mark.asyncio
    async def test_create_callback_response_secure_cookies_disabled(self) -> None:
        """Test response creation with secure cookies disabled."""
        config_insecure = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            dangerously_disable_secure_cookies=True,
        )
        wristband_auth = WristbandAuth(config_insecure)

        request = create_mock_request(
            "/callback",
            query_params={"state": "test_state"},
            cookies={"login#test_state#1640995200000": "encrypted_data"},
        )
        redirect_url = "https://app.example.com/dashboard"

        response = await wristband_auth.create_callback_response(request, redirect_url)

        assert_redirect_no_cache(response, redirect_url)

        # Check that the cookie was cleared and secure=False
        set_cookie_header = response.headers.get("set-cookie")

        assert set_cookie_header is not None, "Login cookie should be cleared"
        assert "secure" not in set_cookie_header.lower()  # Should NOT have secure attribute

    @pytest.mark.asyncio
    async def test_create_callback_response_no_state_parameter(self) -> None:
        """Test response creation when no state parameter exists in request."""
        request = create_mock_request("/callback", cookies={"login#some_state#1640995200000": "encrypted_data"})
        redirect_url = "https://app.example.com/dashboard"

        response = await self.wristband_auth.create_callback_response(request, redirect_url)

        assert_redirect_no_cache(response, redirect_url)

    @pytest.mark.asyncio
    async def test_create_callback_response_multiple_matching_cookies(self) -> None:
        """Test response creation when multiple cookies match the state."""
        request = create_mock_request(
            "/callback",
            query_params={"state": "test_state"},
            cookies={
                "login#test_state#1640995200000": "encrypted_data_1",
                "login#test_state#1640995300000": "encrypted_data_2",
                "other_cookie": "other_value",
            },
        )
        redirect_url = "https://app.example.com/dashboard"

        response = await self.wristband_auth.create_callback_response(request, redirect_url)

        assert_redirect_no_cache(response, redirect_url)

    @pytest.mark.asyncio
    async def test_create_callback_response_headers_set_correctly(self) -> None:
        """Test that Cache-Control and Pragma headers are set correctly."""
        request = create_mock_request("/callback", query_params={"state": "test_state"})
        redirect_url = "https://app.example.com/dashboard"

        response = await self.wristband_auth.create_callback_response(request, redirect_url)

        assert response.headers.get("Cache-Control") == "no-store"
        assert response.headers.get("Pragma") == "no-cache"
        assert response.status_code == 302
        assert response.headers.get("location") == redirect_url
