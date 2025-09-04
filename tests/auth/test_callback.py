from unittest.mock import AsyncMock, patch

import pytest

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.exceptions import InvalidGrantError, WristbandError
from wristband.fastapi_auth.models import AuthConfig, CallbackResultType, LoginState, TokenResponse, UserInfo


class TestWristbandAuthCallback:
    """Test cases for WristbandAuth callback method."""

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
    async def test_callback_missing_state_raises_error(self) -> None:
        """Test callback raises TypeError when state parameter is missing."""
        request = create_mock_request("/callback", query_params={"code": "auth_code", "tenant_domain": "tenant1"})

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):
            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            with pytest.raises(
                TypeError, match="Invalid query parameter \\[state\\] passed from Wristband during callback"
            ):
                await self.wristband_auth.callback(request)

    @pytest.mark.asyncio
    async def test_callback_empty_state_raises_error(self) -> None:
        """Test callback raises TypeError when state parameter is empty."""
        request = create_mock_request(
            "/callback", query_params={"code": "auth_code", "state": "", "tenant_domain": "tenant1"}
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):
            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            with pytest.raises(
                TypeError, match="Invalid query parameter \\[state\\] passed from Wristband during callback"
            ):
                await self.wristband_auth.callback(request)

    @pytest.mark.asyncio
    async def test_callback_missing_tenant_domain_with_subdomain_parsing_raises_error(self) -> None:
        """Test callback raises WristbandError when tenant subdomain missing with subdomain parsing enabled."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = create_mock_request(
            "/callback", query_params={"code": "auth_code", "state": "test_state"}, host="invalid.domain.com"
        )

        with (
            patch.object(wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock) as mock_login_url,
            patch.object(
                wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://{tenant_domain}.auth.example.com/login"
            mock_parse_tenant.return_value = "auth.example.com"

            with pytest.raises(WristbandError) as exc_info:
                await wristband_auth.callback(request)

        # Check the error message contains expected content
        assert "missing_tenant_subdomain" in str(exc_info.value)
        assert "tenant subdomain" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_callback_missing_tenant_domain_without_subdomain_parsing_raises_error(self) -> None:
        """Test callback raises WristbandError when tenant_domain param missing without subdomain parsing."""
        request = create_mock_request("/callback", query_params={"code": "auth_code", "state": "test_state"})

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            with pytest.raises(WristbandError) as exc_info:
                await self.wristband_auth.callback(request)

        assert "missing_tenant_domain" in str(exc_info.value)
        assert "tenant_domain" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_callback_with_error_login_required_returns_redirect(self) -> None:
        """Test callback returns redirect when error=login_required."""
        request = create_mock_request(
            "/callback", query_params={"error": "login_required", "state": "test_state", "tenant_domain": "tenant1"}
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await self.wristband_auth.callback(request)

        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.callback_data is None
        assert result.redirect_url == "https://auth.example.com/login?tenant_domain=tenant1"

    @pytest.mark.asyncio
    async def test_callback_with_other_error_raises_wristband_error(self) -> None:
        """Test callback raises WristbandError for non-login_required errors."""
        # Create a valid login state cookie so the error gets raised instead of redirected
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={
                "error": "access_denied",
                "error_description": "User denied access",
                "state": "test_state",
                "tenant_domain": "tenant1",
            },
            cookies=cookies,
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            with pytest.raises(WristbandError) as exc_info:
                await self.wristband_auth.callback(request)

        # Check that the error contains the expected content
        assert "access_denied" in str(exc_info.value)
        assert "User denied access" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_callback_with_error_no_description_uses_empty_string(self) -> None:
        """Test callback uses empty description when error_description missing."""
        # Create a valid login state cookie so the error gets raised instead of redirected
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={"error": "access_denied", "state": "test_state", "tenant_domain": "tenant1"},
            cookies=cookies,
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            with pytest.raises(WristbandError) as exc_info:
                await self.wristband_auth.callback(request)

        # Check that the error contains the expected content
        assert "access_denied" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_callback_no_login_state_cookie_returns_redirect(self) -> None:
        """Test callback returns redirect when no valid login state cookie found."""
        request = create_mock_request(
            "/callback", query_params={"code": "auth_code", "state": "test_state", "tenant_domain": "tenant1"}
        )
        # No cookies set on request

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await self.wristband_auth.callback(request)

        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.callback_data is None
        assert result.redirect_url == "https://auth.example.com/login?tenant_domain=tenant1"

    @pytest.mark.asyncio
    async def test_callback_mismatched_state_returns_redirect(self) -> None:
        """Test callback returns redirect when state from cookie doesn't match param."""
        # Set cookie with different state using actual LoginState object
        login_state = LoginState(
            state="cookie_state",  # Different from param_state
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#param_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={"code": "auth_code", "state": "param_state", "tenant_domain": "tenant1"},
            cookies=cookies,
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await self.wristband_auth.callback(request)

        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.callback_data is None
        assert result.redirect_url == "https://auth.example.com/login?tenant_domain=tenant1"

    @pytest.mark.asyncio
    async def test_callback_missing_code_after_validation_raises_error(self) -> None:
        """Test callback raises ValueError when code is missing after state validation."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback", query_params={"state": "test_state", "tenant_domain": "tenant1"}, cookies=cookies
        )  # No code param

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            with pytest.raises(
                ValueError, match="Invalid query parameter \\[code\\] passed from Wristband during callback"
            ):
                await self.wristband_auth.callback(request)

    @pytest.mark.asyncio
    async def test_callback_successful_token_exchange_returns_completed(self) -> None:
        """Test callback successfully exchanges code for tokens and returns completed result."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url="https://app.example.com/dashboard",
            custom_state={"user": "123"},
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={"code": "auth_code", "state": "test_state", "tenant_domain": "tenant1"},
            cookies=cookies,
        )

        # Mock token response
        mock_token_response = TokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        # Mock user info
        mock_user_info = UserInfo(sub="user_123", email="user@example.com", email_verified=True, username="testuser")

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response),
            patch.object(self.wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info),
            patch("time.time", return_value=1640995200.0),
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await self.wristband_auth.callback(request)

        assert result.type == CallbackResultType.COMPLETED
        assert result.redirect_url is None
        assert result.callback_data is not None

        # Verify callback data
        callback_data = result.callback_data
        assert callback_data.access_token == "access_token_123"
        assert callback_data.id_token == "id_token_123"
        assert callback_data.expires_in == 3540  # 3600 - 60 (buffer)
        assert callback_data.expires_at == int((1640995200.0 + 3540) * 1000)
        assert callback_data.tenant_domain_name == "tenant1"
        assert callback_data.user_info == mock_user_info
        assert callback_data.custom_state == {"user": "123"}
        assert callback_data.refresh_token == "refresh_token_123"
        assert callback_data.return_url == "https://app.example.com/dashboard"
        assert callback_data.tenant_custom_domain is None

    @pytest.mark.asyncio
    async def test_callback_with_tenant_custom_domain_param(self) -> None:
        """Test callback includes tenant_custom_domain in callback data when present."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={
                "code": "auth_code",
                "state": "test_state",
                "tenant_domain": "tenant1",
                "tenant_custom_domain": "custom.tenant.com",
            },
            cookies=cookies,
        )

        mock_token_response = TokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(sub="user_123", email="user@example.com", email_verified=True, username="testuser")

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response),
            patch.object(self.wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info),
            patch("time.time", return_value=1640995200.0),
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await self.wristband_auth.callback(request)

        assert result.type == CallbackResultType.COMPLETED
        assert result.callback_data is not None
        assert result.callback_data.tenant_custom_domain == "custom.tenant.com"

    @pytest.mark.asyncio
    async def test_callback_with_no_token_expiration_buffer(self) -> None:
        """Test callback handles missing token expiry buffer correctly."""
        config_no_buffer = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
        )
        wristband_auth = WristbandAuth(config_no_buffer)

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={"code": "auth_code", "state": "test_state", "tenant_domain": "tenant1"},
            cookies=cookies,
        )

        mock_token_response = TokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(sub="user_123", email="user@example.com", email_verified=True, username="testuser")

        with (
            patch.object(wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock) as mock_login_url,
            patch.object(
                wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response),
            patch.object(wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info),
            patch("time.time", return_value=1640995200.0),
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await wristband_auth.callback(request)

        # Should use default buffer of 60 (from __init__)
        assert result.callback_data is not None
        assert result.callback_data.expires_in == 3540  # 3600 - 60 (default buffer)
        assert result.callback_data.expires_at == int((1640995200.0 + 3540) * 1000)

    @pytest.mark.asyncio
    async def test_callback_invalid_grant_error_returns_redirect(self) -> None:
        """Test callback returns redirect when InvalidGrantError occurs during token exchange."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={"code": "invalid_code", "state": "test_state", "tenant_domain": "tenant1"},
            cookies=cookies,
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "get_tokens") as mock_get_tokens,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""
            mock_get_tokens.side_effect = InvalidGrantError("Invalid authorization code")

            result = await self.wristband_auth.callback(request)

        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.callback_data is None
        assert result.redirect_url == "https://auth.example.com/login?tenant_domain=tenant1"

    @pytest.mark.asyncio
    async def test_callback_other_exception_gets_raised(self) -> None:
        """Test callback re-raises other exceptions that occur during token exchange."""
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = self.wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={"code": "auth_code", "state": "test_state", "tenant_domain": "tenant1"},
            cookies=cookies,
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "get_tokens") as mock_get_tokens,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""
            mock_get_tokens.side_effect = Exception("Network error")

            with pytest.raises(Exception, match="Network error"):
                await self.wristband_auth.callback(request)

    @pytest.mark.asyncio
    async def test_callback_duplicate_query_parameters_raise_error(self) -> None:
        """Test callback raises TypeError for duplicate query parameters."""
        # Create mock with multiple code values
        mock_request = create_mock_request("/callback")
        mock_request.query_params.getlist = lambda key: {
            "code": ["auth_code", "duplicate_code"],
            "state": ["test_state"],
            "tenant_domain": ["tenant1"],
        }.get(key, [])

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):
            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            with pytest.raises(
                TypeError, match="Duplicate query parameter \\[code\\] passed from Wristband during callback"
            ):
                await self.wristband_auth.callback(mock_request)

    @pytest.mark.asyncio
    async def test_callback_with_subdomain_parsing_extracts_tenant_correctly(self) -> None:
        """Test callback extracts tenant domain from subdomain when subdomain parsing enabled."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            token_expiration_buffer=60,
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://tenant1.app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={"code": "auth_code", "state": "test_state"},
            cookies=cookies,
            host="tenant1.auth.example.com",
        )

        mock_token_response = TokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(sub="user_123", email="user@example.com", email_verified=True, username="testuser")

        with (
            patch.object(wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock) as mock_login_url,
            patch.object(
                wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response),
            patch.object(wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info),
            patch("time.time", return_value=1640995200.0),
        ):

            mock_login_url.return_value = "https://{tenant_domain}.auth.example.com/login"
            mock_parse_tenant.return_value = "auth.example.com"

            result = await wristband_auth.callback(request)

        assert result.type == CallbackResultType.COMPLETED
        assert result.callback_data is not None
        assert result.callback_data.tenant_domain_name == "tenant1"

    @pytest.mark.asyncio
    async def test_callback_builds_tenant_login_url_with_custom_domain(self) -> None:
        """Test callback builds correct tenant login URL with custom domain for redirects."""
        request = create_mock_request(
            "/callback",
            query_params={
                "error": "login_required",
                "state": "test_state",
                "tenant_domain": "tenant1",
                "tenant_custom_domain": "custom.tenant.com",
            },
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await self.wristband_auth.callback(request)

        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert (
            result.redirect_url
            == "https://auth.example.com/login?tenant_domain=tenant1&tenant_custom_domain=custom.tenant.com"
        )

    @pytest.mark.asyncio
    async def test_callback_builds_tenant_login_url_with_subdomain_parsing(self) -> None:
        """Test callback builds correct tenant login URL with subdomain parsing for redirects."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = create_mock_request(
            "/callback",
            query_params={"error": "login_required", "state": "test_state"},
            host="tenant1.auth.example.com",
        )

        with (
            patch.object(wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock) as mock_login_url,
            patch.object(
                wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_login_url.return_value = "https://{tenant_domain}.auth.example.com/login"
            mock_parse_tenant.return_value = "auth.example.com"

            result = await wristband_auth.callback(request)

        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.redirect_url == "https://tenant1.auth.example.com/login"

    @pytest.mark.asyncio
    async def test_callback_with_zero_token_expiration_buffer(self) -> None:
        """Test callback handles zero token expiry buffer correctly."""
        config_zero_buffer = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            token_expiration_buffer=0,  # Zero buffer
        )
        wristband_auth = WristbandAuth(config_zero_buffer)

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None,
        )
        encrypted_cookie = wristband_auth._encrypt_login_state(login_state)
        cookies = {"login#test_state#1640995200000": encrypted_cookie}

        request = create_mock_request(
            "/callback",
            query_params={"code": "auth_code", "state": "test_state", "tenant_domain": "tenant1"},
            cookies=cookies,
        )

        mock_token_response = TokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )

        mock_user_info = UserInfo(sub="user_123", email="user@example.com", email_verified=True, username="testuser")

        with (
            patch.object(wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock) as mock_login_url,
            patch.object(
                wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(wristband_auth._wristband_api, "get_tokens", return_value=mock_token_response),
            patch.object(wristband_auth._wristband_api, "get_userinfo", return_value=mock_user_info),
            patch("time.time", return_value=1640995200.0),
        ):

            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await wristband_auth.callback(request)

        # Should not apply any buffer (3600 - 0 = 3600)
        assert result.callback_data is not None
        assert result.callback_data.expires_in == 3600  # No buffer applied
        assert result.callback_data.expires_at == int((1640995200.0 + 3600) * 1000)
