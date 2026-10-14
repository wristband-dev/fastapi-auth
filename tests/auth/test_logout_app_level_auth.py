"""Tests for logout() when application-level authorization requests are enabled."""

from typing import Any
from urllib.parse import urlparse

import pytest

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import AuthConfig, LogoutConfig

VANITY_DOMAIN = "app.wristband.dev"
ROOT_DOMAIN = "yourapp.io"
FALLBACK_LOGIN_URL = "https://fallback.yourapp.io/auth/login"


def _subdomain_auth(placeholder: str = "{tenant_name}", **overrides: Any) -> WristbandAuth:
    """Create a WristbandAuth that uses tenant subdomains of ROOT_DOMAIN."""
    values: dict[str, Any] = {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "login_state_secret": TEST_LOGIN_STATE_SECRET,
        "wristband_application_vanity_domain": VANITY_DOMAIN,
        "auto_configure_enabled": False,
        "login_url": f"https://{placeholder}.{ROOT_DOMAIN}/auth/login",
        "redirect_uri": f"https://{placeholder}.{ROOT_DOMAIN}/auth/callback",
        "parse_tenant_from_root_domain": ROOT_DOMAIN,
        "fallback_login_url": FALLBACK_LOGIN_URL,
        "application_authorization_requests_enabled": True,
    }
    values.update(overrides)
    return WristbandAuth(AuthConfig(**values))


def _fixed_host_auth(**overrides: Any) -> WristbandAuth:
    """Create a WristbandAuth that does not use tenant subdomains."""
    values: dict[str, Any] = {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "login_state_secret": TEST_LOGIN_STATE_SECRET,
        "wristband_application_vanity_domain": VANITY_DOMAIN,
        "auto_configure_enabled": False,
        "login_url": "https://localhost:6001/auth/login",
        "redirect_uri": "https://localhost:6001/auth/callback",
        "application_authorization_requests_enabled": True,
    }
    values.update(overrides)
    return WristbandAuth(AuthConfig(**values))


class TestLogoutAppLevelAuthTenantSubdomains:
    """logout() when login_url contains the tenant placeholder."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("placeholder", ["{tenant_domain}", "{tenant_name}"])
    async def test_falls_back_to_fallback_login_url_when_tenant_unresolvable(self, placeholder: str) -> None:
        """Test logout redirects to fallback_login_url, since login_url's placeholder can't be filled."""
        request = create_mock_request(f"https://{ROOT_DOMAIN}/auth/logout")

        response = await _subdomain_auth(placeholder).logout(request)

        assert response.status_code == 302
        assert response.headers["location"] == FALLBACK_LOGIN_URL
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"

    @pytest.mark.asyncio
    async def test_redirect_url_takes_precedence_over_app_level_fallback(self) -> None:
        """Test the LogoutConfig redirect_url still wins over the app-level fallback."""
        request = create_mock_request(f"https://{ROOT_DOMAIN}/auth/logout")

        response = await _subdomain_auth().logout(request, LogoutConfig(redirect_url="https://redirect.example.com"))

        assert response.headers["location"] == "https://redirect.example.com"

    @pytest.mark.asyncio
    async def test_resolves_tenant_level_logout_url_when_tenant_resolvable(self) -> None:
        """Test a resolvable tenant still uses the tenant-level logout URL with the flag enabled."""
        request = create_mock_request(f"https://tenanta.{ROOT_DOMAIN}/auth/logout", host=f"tenanta.{ROOT_DOMAIN}")

        response = await _subdomain_auth().logout(request)

        location = urlparse(response.headers["location"])
        assert location.netloc == f"tenanta-{VANITY_DOMAIN}"
        assert location.path == "/api/v1/logout"

    @pytest.mark.asyncio
    async def test_falls_back_to_app_level_login_page_when_disabled(self) -> None:
        """Test the flag disabled keeps the old behavior: the app-level login page."""
        request = create_mock_request(f"https://{ROOT_DOMAIN}/auth/logout")

        response = await _subdomain_auth(application_authorization_requests_enabled=False).logout(request)

        assert response.headers["location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id"


class TestLogoutAppLevelAuthFixedHost:
    """logout() when login_url has no tenant placeholder."""

    @pytest.mark.asyncio
    async def test_falls_back_to_login_url_when_tenant_unresolvable(self) -> None:
        """Test logout redirects straight to login_url when it has no placeholder."""
        request = create_mock_request("https://localhost:6001/auth/logout")

        response = await _fixed_host_auth().logout(request)

        assert response.status_code == 302
        assert response.headers["location"] == "https://localhost:6001/auth/login"

    @pytest.mark.asyncio
    async def test_ignores_custom_application_login_page_url(self) -> None:
        """Test the custom application login page is not used when the flag is enabled."""
        request = create_mock_request("https://localhost:6001/auth/logout")

        response = await _fixed_host_auth(
            custom_application_login_page_url="https://custom.example.com/discover"
        ).logout(request)

        assert response.headers["location"] == "https://localhost:6001/auth/login"

    @pytest.mark.asyncio
    async def test_falls_back_to_custom_application_login_page_when_disabled(self) -> None:
        """Test the flag disabled uses the custom application login page when one is set."""
        request = create_mock_request("https://localhost:6001/auth/logout")
        wristband_auth = _fixed_host_auth(
            application_authorization_requests_enabled=False,
            custom_application_login_page_url="https://custom.example.com/discover",
        )

        response = await wristband_auth.logout(request)

        assert response.headers["location"] == "https://custom.example.com/discover?client_id=test_client_id"
