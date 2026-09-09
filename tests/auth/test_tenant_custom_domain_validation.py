from unittest.mock import AsyncMock, patch

import pytest

from tests.utilities import TEST_LOGIN_STATE_SECRET, assert_redirect_no_cache, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import AuthConfig, LogoutConfig, RedirectRequiredCallbackResult


class TestLoginTenantCustomDomainValidation:
    """Test cases for tenant custom domain validation during login()."""

    def setup_method(self) -> None:
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
    async def test_login_uses_verified_tenant_custom_domain(self) -> None:
        """A verified tenant custom domain is used directly in the authorize URL."""
        request = create_mock_request("/login", query_params={"tenant_custom_domain": "tenant.custom.com"})

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
            patch.object(
                self.wristband_auth._config_resolver, "get_redirect_uri", new_callable=AsyncMock
            ) as mock_redirect_uri,
            patch.object(
                self.wristband_auth._wristband_api,
                "validate_tenant_custom_domain",
                new_callable=AsyncMock,
                return_value=True,
            ) as mock_validate,
        ):
            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""
            mock_redirect_uri.return_value = "https://app.example.com/callback"

            response = await self.wristband_auth.login(request)

        mock_validate.assert_called_once_with("tenant.custom.com")
        assert response.status_code == 302
        assert response.headers["location"].startswith("https://tenant.custom.com/api/v1/oauth2/authorize")

    @pytest.mark.asyncio
    async def test_login_skips_unverified_tenant_custom_domain_and_falls_back_to_tenant_name(self) -> None:
        """An unverified/invalid tenant custom domain is skipped, falling back to tenant_name."""
        request = create_mock_request(
            "/login", query_params={"tenant_custom_domain": "bogus.custom.com", "tenant_name": "tenant1"}
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
            patch.object(
                self.wristband_auth._config_resolver, "get_redirect_uri", new_callable=AsyncMock
            ) as mock_redirect_uri,
            patch.object(
                self.wristband_auth._wristband_api,
                "validate_tenant_custom_domain",
                new_callable=AsyncMock,
                return_value=False,
            ) as mock_validate,
        ):
            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""
            mock_redirect_uri.return_value = "https://app.example.com/callback"

            response = await self.wristband_auth.login(request)

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert response.status_code == 302
        # Falls through to tenant subdomain resolution instead of the bogus custom domain.
        assert response.headers["location"].startswith("https://tenant1-auth.example.com/api/v1/oauth2/authorize")

    @pytest.mark.asyncio
    async def test_login_skips_unverified_tenant_custom_domain_and_falls_back_to_app_login(self) -> None:
        """When no other tenant info is available, an unverified domain falls back to app-level login."""
        request = create_mock_request("/login", query_params={"tenant_custom_domain": "bogus.custom.com"})

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
            patch.object(
                self.wristband_auth._config_resolver, "get_redirect_uri", new_callable=AsyncMock
            ) as mock_redirect_uri,
            patch.object(
                self.wristband_auth._wristband_api,
                "validate_tenant_custom_domain",
                new_callable=AsyncMock,
                return_value=False,
            ) as mock_validate,
        ):
            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""
            mock_redirect_uri.return_value = "https://app.example.com/callback"

            response = await self.wristband_auth.login(request)

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert response.status_code == 302
        assert response.headers["location"] == "https://auth.example.com/login?client_id=test_client_id"

    @pytest.mark.asyncio
    async def test_login_does_not_validate_when_no_domain_param_present(self) -> None:
        """validate_tenant_custom_domain is never called when there's no domain param to validate."""
        request = create_mock_request("/login", query_params={"tenant_name": "tenant1"})

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
            patch.object(
                self.wristband_auth._config_resolver, "get_redirect_uri", new_callable=AsyncMock
            ) as mock_redirect_uri,
            patch.object(
                self.wristband_auth._wristband_api, "validate_tenant_custom_domain", new_callable=AsyncMock
            ) as mock_validate,
        ):
            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""
            mock_redirect_uri.return_value = "https://app.example.com/callback"

            await self.wristband_auth.login(request)

        mock_validate.assert_not_called()


class TestCallbackTenantCustomDomainValidation:
    """Test cases for tenant custom domain validation during callback()."""

    def setup_method(self) -> None:
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
    async def test_callback_missing_login_state_uses_verified_domain_in_redirect_url(self) -> None:
        """A verified tenant custom domain param is included in the tenant login redirect URL."""
        request = create_mock_request(
            "/callback",
            query_params={
                "state": "test_state",
                "tenant_name": "tenant1",
                "tenant_custom_domain": "tenant.custom.com",
            },
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(
                self.wristband_auth._wristband_api,
                "validate_tenant_custom_domain",
                new_callable=AsyncMock,
                return_value=True,
            ) as mock_validate,
        ):
            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await self.wristband_auth.callback(request)

        mock_validate.assert_called_once_with("tenant.custom.com")
        assert isinstance(result, RedirectRequiredCallbackResult)
        assert (
            result.redirect_url
            == "https://auth.example.com/login?tenant_name=tenant1&tenant_custom_domain=tenant.custom.com"
        )

    @pytest.mark.asyncio
    async def test_callback_missing_login_state_skips_unverified_domain_in_redirect_url(self) -> None:
        """An unverified tenant custom domain param is skipped in the tenant login redirect URL."""
        request = create_mock_request(
            "/callback",
            query_params={
                "state": "test_state",
                "tenant_name": "tenant1",
                "tenant_custom_domain": "bogus.custom.com",
            },
        )

        with (
            patch.object(
                self.wristband_auth._config_resolver, "get_login_url", new_callable=AsyncMock
            ) as mock_login_url,
            patch.object(
                self.wristband_auth._config_resolver, "get_parse_tenant_from_root_domain", new_callable=AsyncMock
            ) as mock_parse_tenant,
            patch.object(
                self.wristband_auth._wristband_api,
                "validate_tenant_custom_domain",
                new_callable=AsyncMock,
                return_value=False,
            ) as mock_validate,
        ):
            mock_login_url.return_value = "https://auth.example.com/login"
            mock_parse_tenant.return_value = ""

            result = await self.wristband_auth.callback(request)

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert isinstance(result, RedirectRequiredCallbackResult)
        # No tenant_custom_domain query param appended since it was invalid.
        assert result.redirect_url == "https://auth.example.com/login?tenant_name=tenant1"


class TestLogoutTenantCustomDomainValidation:
    """Test cases for tenant custom domain validation during logout()."""

    def setup_method(self) -> None:
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
    async def test_logout_uses_verified_query_tenant_custom_domain(self) -> None:
        request = create_mock_request("/logout", query_params={"tenant_custom_domain": "tenant.custom.com"})

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
            patch.object(
                self.wristband_auth._wristband_api,
                "validate_tenant_custom_domain",
                new_callable=AsyncMock,
                return_value=True,
            ) as mock_validate,
        ):
            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, LogoutConfig())

        mock_validate.assert_called_once_with("tenant.custom.com")
        assert_redirect_no_cache(response, "https://tenant.custom.com/api/v1/logout?client_id=test_client_id")

    @pytest.mark.asyncio
    async def test_logout_skips_unverified_query_tenant_custom_domain_and_falls_back_to_app_login(self) -> None:
        request = create_mock_request("/logout", query_params={"tenant_custom_domain": "bogus.custom.com"})

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
            patch.object(
                self.wristband_auth._wristband_api,
                "validate_tenant_custom_domain",
                new_callable=AsyncMock,
                return_value=False,
            ) as mock_validate,
        ):
            mock_custom_url.return_value = None
            mock_custom_domain.return_value = False
            mock_parse_tenant.return_value = ""

            response = await self.wristband_auth.logout(request, LogoutConfig())

        mock_validate.assert_called_once_with("bogus.custom.com")
        assert_redirect_no_cache(response, "https://auth.example.com/login?client_id=test_client_id")
