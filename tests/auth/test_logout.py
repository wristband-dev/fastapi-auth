from unittest.mock import patch

import pytest

from tests.utilities import TEST_LOGIN_STATE_SECRET, assert_redirect_no_cache, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import AuthConfig, LogoutConfig


class TestWristbandAuthLogout:
    """Test cases for WristbandAuth logout method."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_config = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
        )
        self.wristband_auth = WristbandAuth(self.auth_config)

    @pytest.mark.asyncio
    async def test_logout_with_config_tenant_custom_domain_priority_1(self) -> None:
        """Test logout uses config tenant custom domain as highest priority."""
        request = create_mock_request(
            "/logout", query_params={"tenant_domain": "tenant1", "tenant_custom_domain": "tenant1.custom.com"}
        )
        logout_config = LogoutConfig(
            tenant_custom_domain="config.custom.com",
            tenant_domain_name="config-tenant",
            redirect_url="https://app.example.com/logged-out",
        )

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        # Should use config tenant custom domain (priority 1)
        expected_url = (
            "https://config.custom.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/logged-out"
        )
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_config_tenant_domain_priority_2(self) -> None:
        """Test logout uses config tenant domain as second priority."""
        request = create_mock_request(
            "/logout", query_params={"tenant_domain": "tenant1", "tenant_custom_domain": "tenant1.custom.com"}
        )
        logout_config = LogoutConfig(
            tenant_domain_name="config-tenant", redirect_url="https://app.example.com/logged-out"
        )

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        # Should use config tenant domain (priority 2)
        expected_url = (
            "https://config-tenant-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/logged-out"
        )
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_query_tenant_custom_domain_priority_3(self) -> None:
        """Test logout uses query tenant custom domain as third priority."""
        request = create_mock_request(
            "/logout", query_params={"tenant_domain": "tenant1", "tenant_custom_domain": "tenant1.custom.com"}
        )
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        # Should use query tenant custom domain (priority 3)
        expected_url = "https://tenant1.custom.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_query_tenant_domain_priority_4(self) -> None:
        """Test logout uses query tenant domain as fourth priority."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        # Should use query tenant domain (priority 4)
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_subdomain_parsing_priority_4a(self) -> None:
        """Test logout uses subdomain parsing when enabled."""
        config_with_subdomain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://{tenant_domain}.auth.example.com/login",
            redirect_uri="https://{tenant_domain}.app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            parse_tenant_from_root_domain="auth.example.com",
            is_application_custom_domain_active=True,  # Uses "." separator
        )
        wristband_auth = WristbandAuth(config_with_subdomain)

        request = create_mock_request("/logout", host="tenant1.auth.example.com")
        logout_config = LogoutConfig()

        with patch.object(wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await wristband_auth.logout(request, logout_config)

        # Should use subdomain with "." separator
        expected_url = "https://tenant1.auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_fallback_to_app_login_when_no_tenant_info(self) -> None:
        """Test logout falls back to app login URL when no tenant info available."""
        request = create_mock_request("/logout")
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        # Should fallback to app login URL
        expected_url = (
            f"https://{self.auth_config.wristband_application_vanity_domain}/login"
            f"?client_id={self.auth_config.client_id}"
        )
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_fallback_to_custom_application_login_page(self) -> None:
        """Test logout falls back to custom application login page when configured."""
        custom_url = "https://custom.example.com/login"
        config_with_custom = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            custom_application_login_page_url=custom_url,
        )
        wristband_auth = WristbandAuth(config_with_custom)

        request = create_mock_request("/logout")
        logout_config = LogoutConfig()

        with patch.object(wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await wristband_auth.logout(request, logout_config)

        # Should use custom login page as fallback
        expected_url = f"{custom_url}?client_id={config_with_custom.client_id}"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_config_redirect_url_overrides_fallback(self) -> None:
        """Test logout uses config redirect_url to override fallback when no tenant info."""
        request = create_mock_request("/logout")
        logout_config = LogoutConfig(redirect_url="https://app.example.com/goodbye")

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        # Should use config redirect_url instead of app login fallback
        expected_url = "https://app.example.com/goodbye"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_refresh_token_revokes_successfully(self) -> None:
        """Test logout revokes refresh token when provided."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(refresh_token="valid_refresh_token")

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token") as mock_revoke:
            response = await self.wristband_auth.logout(request, logout_config)

        # Should call revoke_refresh_token
        mock_revoke.assert_called_once_with("valid_refresh_token")

        # Should still redirect properly
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_refresh_token_revoke_fails_continues_logout(self) -> None:
        """Test logout continues even if refresh token revocation fails."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(refresh_token="invalid_refresh_token")

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token") as mock_revoke:
            mock_revoke.side_effect = Exception("Revocation failed")

            # Should not raise exception, just log warning
            response = await self.wristband_auth.logout(request, logout_config)

        # Should still redirect properly despite revocation failure
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_without_refresh_token_skips_revocation(self) -> None:
        """Test logout skips revocation when no refresh token provided."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token") as mock_revoke:
            response = await self.wristband_auth.logout(request, logout_config)

        # Should not call revoke_refresh_token
        mock_revoke.assert_not_called()

        # Should still redirect properly
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_builds_logout_path_with_redirect_url(self) -> None:
        """Test logout builds correct path with redirect_url parameter."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(redirect_url="https://app.example.com/farewell")

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/farewell"
        )
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_builds_logout_path_without_redirect_url(self) -> None:
        """Test logout builds correct path without redirect_url parameter."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_application_custom_domain_uses_dot_separator(self) -> None:
        """Test logout uses dot separator when application custom domain is active."""
        config_with_custom_domain = AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
            wristband_application_vanity_domain="auth.example.com",
            is_application_custom_domain_active=True,
        )
        wristband_auth = WristbandAuth(config_with_custom_domain)

        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig()

        with patch.object(wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await wristband_auth.logout(request, logout_config)

        # Should use "." separator instead of "-"
        expected_url = "https://tenant1.auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_sets_cache_control_headers(self) -> None:
        """Test logout sets proper cache control headers."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig()

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        # Verify security headers are set (case-insensitive check)
        assert response.headers.get("cache-control") == "no-store"
        assert response.headers.get("pragma") == "no-cache"

    @pytest.mark.asyncio
    async def test_logout_empty_config_values_are_ignored(self) -> None:
        """Test logout ignores empty string values in config."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(
            tenant_custom_domain="",  # Empty string should be ignored
            tenant_domain_name="   ",  # Whitespace only should be ignored
        )

        with patch.object(self.wristband_auth.wristband_api, "revoke_refresh_token"):
            response = await self.wristband_auth.logout(request, logout_config)

        # Should fall back to query parameter since config values are empty/whitespace
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)
