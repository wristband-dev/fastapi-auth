"""Tests for create_callback_response() when application-level authorization requests are enabled."""

from typing import Any, List

import pytest
from fastapi import Response

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import AuthConfig

VANITY_DOMAIN = "app.wristband.dev"
ROOT_DOMAIN = "yourapp.io"
APP_HOME_URL = "https://yourapp.io/home"
LOGIN_COOKIE = {"login#state#1640995200000": "encrypted-login-state"}


def _subdomain_auth(**overrides: Any) -> WristbandAuth:
    """Create a WristbandAuth that uses tenant subdomains of ROOT_DOMAIN."""
    values: dict[str, Any] = {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "login_state_secret": TEST_LOGIN_STATE_SECRET,
        "wristband_application_vanity_domain": VANITY_DOMAIN,
        "auto_configure_enabled": False,
        "login_url": "https://{tenant_name}." + ROOT_DOMAIN + "/auth/login",
        "redirect_uri": "https://{tenant_name}." + ROOT_DOMAIN + "/auth/callback",
        "parse_tenant_from_root_domain": ROOT_DOMAIN,
        "fallback_login_url": f"https://{ROOT_DOMAIN}/auth/login",
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
        "login_url": f"https://{ROOT_DOMAIN}/auth/login",
        "redirect_uri": f"https://{ROOT_DOMAIN}/auth/callback",
        "application_authorization_requests_enabled": True,
    }
    values.update(overrides)
    return WristbandAuth(AuthConfig(**values))


def _set_cookie_headers(response: Response) -> List[str]:
    """Return the decoded set-cookie headers of a response."""
    return [value.decode() for key, value in response.raw_headers if key == b"set-cookie"]


def _assert_single_cleared_login_cookie(response: Response) -> str:
    """Assert the response redirects home and clears exactly the login state cookie, returning its header."""
    assert response.status_code == 302
    assert response.headers["location"] == APP_HOME_URL
    headers = _set_cookie_headers(response)
    assert len(headers) == 1
    assert headers[0].startswith('login#state#1640995200000="";')
    assert "Max-Age=0" in headers[0]
    return headers[0]


class TestCreateCallbackResponseAppLevelAuthTenantSubdomains:
    """create_callback_response() with tenant subdomains (parse_tenant_from_root_domain set)."""

    @pytest.mark.asyncio
    async def test_clears_cookie_with_root_domain_when_enabled(self) -> None:
        """Test the cookie set during an app-level login (on the root host) is cleared with Domain=.{root}."""
        request = create_mock_request(
            f"https://{ROOT_DOMAIN}/auth/callback", query_params={"state": "state"}, cookies=LOGIN_COOKIE
        )

        response = await _subdomain_auth().create_callback_response(request, APP_HOME_URL)

        assert f"Domain=.{ROOT_DOMAIN}" in _assert_single_cleared_login_cookie(response)

    @pytest.mark.asyncio
    async def test_clears_tenant_level_cookie_with_root_domain_when_enabled(self) -> None:
        """Test the cookie is cleared with Domain=.{root} on a tenant subdomain callback too."""
        request = create_mock_request(
            f"https://tenanta.{ROOT_DOMAIN}/auth/callback", query_params={"state": "state"}, cookies=LOGIN_COOKIE
        )

        response = await _subdomain_auth().create_callback_response(request, APP_HOME_URL)

        assert f"Domain=.{ROOT_DOMAIN}" in _assert_single_cleared_login_cookie(response)

    @pytest.mark.asyncio
    async def test_clears_tenant_level_cookie_without_domain_when_disabled(self) -> None:
        """Test the cookie is cleared as host-only on a tenant subdomain callback when the flag is disabled."""
        request = create_mock_request(
            f"https://tenanta.{ROOT_DOMAIN}/auth/callback", query_params={"state": "state"}, cookies=LOGIN_COOKIE
        )

        response = await _subdomain_auth(application_authorization_requests_enabled=False).create_callback_response(
            request, APP_HOME_URL
        )

        assert "Domain=" not in _assert_single_cleared_login_cookie(response)

    @pytest.mark.asyncio
    async def test_clears_cookie_without_domain_when_disabled(self) -> None:
        """Test the cookie is cleared as host-only on the root host when the flag is disabled."""
        request = create_mock_request(
            f"https://{ROOT_DOMAIN}/auth/callback", query_params={"state": "state"}, cookies=LOGIN_COOKIE
        )

        response = await _subdomain_auth(application_authorization_requests_enabled=False).create_callback_response(
            request, APP_HOME_URL
        )

        assert "Domain=" not in _assert_single_cleared_login_cookie(response)


class TestCreateCallbackResponseAppLevelAuthFixedHost:
    """create_callback_response() without tenant subdomains (no parse_tenant_from_root_domain)."""

    @pytest.mark.asyncio
    async def test_clears_cookie_without_domain_when_root_domain_unset(self) -> None:
        """Test the cookie is cleared as host-only when there are no tenant subdomains, even with the flag on."""
        request = create_mock_request(
            f"https://{ROOT_DOMAIN}/auth/callback", query_params={"state": "state"}, cookies=LOGIN_COOKIE
        )

        response = await _fixed_host_auth().create_callback_response(request, APP_HOME_URL)

        assert "Domain=" not in _assert_single_cleared_login_cookie(response)

    @pytest.mark.asyncio
    async def test_clears_tenant_level_cookie_without_domain_when_root_domain_unset(self) -> None:
        """Test a tenant_name callback clears a host-only cookie when there are no tenant subdomains."""
        request = create_mock_request(
            f"https://{ROOT_DOMAIN}/auth/callback",
            query_params={"state": "state", "tenant_name": "tenanta"},
            cookies=LOGIN_COOKIE,
        )

        response = await _fixed_host_auth().create_callback_response(request, APP_HOME_URL)

        assert "Domain=" not in _assert_single_cleared_login_cookie(response)

    @pytest.mark.asyncio
    async def test_no_set_cookie_when_no_login_state_cookie_present(self) -> None:
        """Test nothing is cleared when the request has no login state cookie."""
        request = create_mock_request(f"https://{ROOT_DOMAIN}/auth/callback", query_params={"state": "state"})

        response = await _fixed_host_auth().create_callback_response(request, APP_HOME_URL)

        assert response.status_code == 302
        assert response.headers["location"] == APP_HOME_URL
        assert _set_cookie_headers(response) == []
