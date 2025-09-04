from unittest.mock import AsyncMock, patch

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

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

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

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

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

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        # Should use query tenant custom domain (priority 3)
        expected_url = "https://tenant1.custom.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_query_tenant_domain_priority_4(self) -> None:
        """Test logout uses query tenant domain as fourth priority."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig()

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

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

        with (
            patch.object(
                wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = True
            mock_parse_tenant.return_value = "auth.example.com"

            response = await wristband_auth.logout(request, logout_config)

        # Should use subdomain with "." separator
        expected_url = "https://tenant1.auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_fallback_to_app_login_when_no_tenant_info(self) -> None:
        """Test logout falls back to app login URL when no tenant info available."""
        request = create_mock_request("/logout")
        logout_config = LogoutConfig()

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

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
        request = create_mock_request("/logout")
        logout_config = LogoutConfig()

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = custom_url
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        # Should use custom login page as fallback
        expected_url = f"{custom_url}?client_id={self.auth_config.client_id}"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_config_redirect_url_overrides_fallback(self) -> None:
        """Test logout uses config redirect_url to override fallback when no tenant info."""
        request = create_mock_request("/logout")
        logout_config = LogoutConfig(redirect_url="https://app.example.com/goodbye")

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        # Should use config redirect_url instead of app login fallback
        expected_url = "https://app.example.com/goodbye"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_state_parameter(self) -> None:
        """Test logout includes state parameter in logout URL."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(state="custom_logout_state_123", redirect_url="https://app.example.com/logged-out")

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/logged-out&state=custom_logout_state_123"
        )
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_state_parameter_only(self) -> None:
        """Test logout with only state parameter (no redirect_url)."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(state="logout_state_only")

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id" "&state=logout_state_only"
        )
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_without_state_parameter(self) -> None:
        """Test logout without state parameter doesn't include it in URL."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(redirect_url="https://app.example.com/logged-out")

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/logged-out"
        )
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_state_exceeds_512_characters_raises_error(self) -> None:
        """Test logout raises ValueError when state exceeds 512 characters."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        # Create a state that's 513 characters long
        long_state = "a" * 513
        logout_config = LogoutConfig(state=long_state)

        # Need to mock config resolver even though we expect early exit due to validation
        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            with pytest.raises(ValueError, match="The \\[state\\] logout config cannot exceed 512 characters."):
                await self.wristband_auth.logout(request, logout_config)

    @pytest.mark.asyncio
    async def test_logout_state_exactly_512_characters_succeeds(self) -> None:
        """Test logout succeeds when state is exactly 512 characters."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        # Create a state that's exactly 512 characters long
        max_state = "b" * 512
        logout_config = LogoutConfig(state=max_state)

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        expected_url = f"https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id" f"&state={max_state}"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_empty_state_is_ignored(self) -> None:
        """Test logout ignores empty string state parameter."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(state="", redirect_url="https://app.example.com/logged-out")

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        # Empty state should not be included in URL
        expected_url = (
            "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/logged-out"
        )
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_refresh_token_revokes_successfully(self) -> None:
        """Test logout revokes refresh token when provided."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(refresh_token="valid_refresh_token")

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token") as mock_revoke,
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

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

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token") as mock_revoke,
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""
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

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token") as mock_revoke,
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

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

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

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

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_application_custom_domain_uses_dot_separator(self) -> None:
        """Test logout uses dot separator when application custom domain is active."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig()

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = True  # Custom domain active
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        # Should use "." separator instead of "-"
        expected_url = "https://tenant1.auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_sets_cache_control_headers(self) -> None:
        """Test logout sets proper cache control headers."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig()

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

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

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token"),
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        # Should fall back to query parameter since config values are empty/whitespace
        expected_url = "https://tenant1-auth.example.com/api/v1/logout?client_id=test_client_id"
        assert_redirect_no_cache(response, expected_url)

    @pytest.mark.asyncio
    async def test_logout_with_all_parameters_combined(self) -> None:
        """Test logout with all parameters combined (state, redirect_url, refresh_token)."""
        request = create_mock_request("/logout", query_params={"tenant_domain": "tenant1"})
        logout_config = LogoutConfig(
            state="combined_test_state",
            redirect_url="https://app.example.com/complete-logout",
            refresh_token="test_refresh_token",
            tenant_domain_name="config-tenant",  # Should take precedence over query param
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_custom_application_login_page_url", new_callable=AsyncMock
            ) as mock_custom_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_is_application_custom_domain_active", new_callable=AsyncMock
            ) as mock_custom_domain,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(self.wristband_auth._wristband_api, "revoke_refresh_token") as mock_revoke,
        ):

            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, logout_config)

        # Should call revoke_refresh_token
        mock_revoke.assert_called_once_with("test_refresh_token")

        # Should use config tenant domain and include both state and redirect_url
        expected_url = (
            "https://config-tenant-auth.example.com/api/v1/logout?client_id=test_client_id"
            "&redirect_url=https://app.example.com/complete-logout&state=combined_test_state"
        )
        assert_redirect_no_cache(response, expected_url)
