"""Tests for login() when application-level authorization requests are enabled."""

from typing import Any, List
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Response

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import AuthConfig, LoginConfig

VANITY_DOMAIN = "app.wristband.dev"
ROOT_DOMAIN = "yourapp.io"
STALE_COOKIES = {
    "login#state1#1640995100000": "data1",  # oldest
    "login#state2#1640995200000": "data2",
    "login#state3#1640995300000": "data3",
}


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


def _set_cookie_headers(response: Response) -> List[str]:
    """Return the decoded set-cookie headers of a response."""
    return [value.decode() for key, value in response.raw_headers if key == b"set-cookie"]


def _new_login_cookies(response: Response) -> List[str]:
    """Return the set-cookie headers that create a login state cookie."""
    return [h for h in _set_cookie_headers(response) if h.startswith("login#") and "Max-Age=3600" in h]


def _deleted_login_cookies(response: Response) -> List[str]:
    """Return the set-cookie headers that delete a login state cookie."""
    return [h for h in _set_cookie_headers(response) if h.startswith("login#") and "Max-Age=0" in h]


def _cookie_value(set_cookie_header: str) -> str:
    """Extract the value from a set-cookie header."""
    return set_cookie_header.split("=", 1)[1].split(";")[0]


class TestLoginAppAuthRequestsFixedHost:
    """login() with the flag enabled and no tenant subdomains."""

    @pytest.mark.asyncio
    async def test_redirects_to_app_level_authorize_url_when_tenant_unresolvable(self) -> None:
        """Test login redirects to the app-level Authorize URL with a host-only login state cookie."""
        wristband_auth = _fixed_host_auth()

        response = await wristband_auth.login(create_mock_request(f"https://{ROOT_DOMAIN}/auth/login"))

        assert response.status_code == 302
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        location = urlparse(response.headers["location"])
        assert location.netloc == VANITY_DOMAIN
        assert location.path == "/api/v1/oauth2/authorize"
        query = parse_qs(location.query)
        assert query["client_id"] == ["test_client_id"]
        assert query["redirect_uri"] == [f"https://{ROOT_DOMAIN}/auth/callback"]
        assert query["response_type"] == ["code"]
        assert query["code_challenge_method"] == ["S256"]

        cookies = _new_login_cookies(response)
        assert len(cookies) == 1
        assert "Domain=" not in cookies[0]
        # The cookie name carries the same state as the authorize request.
        assert cookies[0].startswith(f"login#{query['state'][0]}#")

    @pytest.mark.asyncio
    async def test_login_state_cookie_preserves_return_url_and_custom_state(self) -> None:
        """Test the app-level login state cookie keeps the return URL and custom state for the callback."""
        wristband_auth = _fixed_host_auth()
        config = LoginConfig(return_url="https://yourapp.io/dashboard", custom_state={"plan": "pro"})

        response = await wristband_auth.login(create_mock_request(f"https://{ROOT_DOMAIN}/auth/login"), config)

        login_state = wristband_auth._decrypt_login_state(_cookie_value(_new_login_cookies(response)[0]))
        assert login_state.return_url == "https://yourapp.io/dashboard"
        assert login_state.custom_state == {"plan": "pro"}
        assert login_state.redirect_uri == f"https://{ROOT_DOMAIN}/auth/callback"
        assert parse_qs(urlparse(response.headers["location"]).query)["state"] == [login_state.state]

    @pytest.mark.asyncio
    async def test_ignores_custom_application_login_page_url(self) -> None:
        """Test the custom application login page is not used when the flag is enabled."""
        wristband_auth = _fixed_host_auth(custom_application_login_page_url="https://yourapp.io/discover")

        response = await wristband_auth.login(create_mock_request(f"https://{ROOT_DOMAIN}/auth/login"))

        location = urlparse(response.headers["location"])
        assert location.netloc == VANITY_DOMAIN
        assert location.path == "/api/v1/oauth2/authorize"

    @pytest.mark.asyncio
    async def test_respects_dangerously_disable_secure_cookies(self) -> None:
        """Test the app-level login state cookie omits Secure when secure cookies are disabled."""
        wristband_auth = _fixed_host_auth(dangerously_disable_secure_cookies=True)

        response = await wristband_auth.login(create_mock_request(f"https://{ROOT_DOMAIN}/auth/login"))

        cookies = _new_login_cookies(response)
        assert len(cookies) == 1
        assert "Secure" not in cookies[0]

    @pytest.mark.asyncio
    async def test_includes_login_hint_and_idp_hint(self) -> None:
        """Test login_hint and idp_hint are carried onto the app-level Authorize URL."""
        wristband_auth = _fixed_host_auth()
        request = create_mock_request(
            f"https://{ROOT_DOMAIN}/auth/login", query_params={"login_hint": "user@example.com", "idp_hint": "google"}
        )

        response = await wristband_auth.login(request)

        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query["login_hint"] == ["user@example.com"]
        assert query["idp_hint"] == ["google"]

    @pytest.mark.asyncio
    async def test_rejects_duplicate_login_hints(self) -> None:
        """Test duplicate login_hint params raise, since the app-level branch builds an authorize request."""
        wristband_auth = _fixed_host_auth()
        request = create_mock_request(f"https://{ROOT_DOMAIN}/auth/login")
        request.query_params.getlist = lambda key: ["a@example.com", "b@example.com"] if key == "login_hint" else []

        with pytest.raises(TypeError, match="More than one \\[login_hint\\] query parameter was encountered"):
            await wristband_auth.login(request)

    @pytest.mark.asyncio
    async def test_falls_back_to_app_level_login_url_when_disabled(self) -> None:
        """Test the flag disabled keeps the old behavior: app-level login page and no cookies."""
        wristband_auth = _fixed_host_auth(application_authorization_requests_enabled=False)

        response = await wristband_auth.login(create_mock_request(f"https://{ROOT_DOMAIN}/auth/login"))

        assert response.headers["location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id"
        assert _set_cookie_headers(response) == []

    @pytest.mark.asyncio
    async def test_disabled_ignores_duplicate_login_hints(self) -> None:
        """Test the flag disabled does not validate login hints, since no authorize request is built."""
        wristband_auth = _fixed_host_auth(application_authorization_requests_enabled=False)
        request = create_mock_request(f"https://{ROOT_DOMAIN}/auth/login")
        request.query_params.getlist = lambda key: ["a@example.com", "b@example.com"] if key == "login_hint" else []

        response = await wristband_auth.login(request)

        assert response.headers["location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id"

    @pytest.mark.asyncio
    async def test_clears_stale_login_state_cookies(self) -> None:
        """Test the oldest stale login state cookie is deleted before the new one is set."""
        wristband_auth = _fixed_host_auth()
        request = create_mock_request(f"https://{ROOT_DOMAIN}/auth/login", cookies=STALE_COOKIES)

        response = await wristband_auth.login(request)

        deleted = _deleted_login_cookies(response)
        assert len(deleted) == 1
        assert deleted[0].startswith("login#state1#1640995100000=")
        assert "Domain=" not in deleted[0]
        assert len(_new_login_cookies(response)) == 1

    @pytest.mark.asyncio
    async def test_tenant_level_cookie_has_no_domain_without_tenant_subdomains(self) -> None:
        """Test a resolvable tenant uses the tenant-level flow and a host-only cookie."""
        wristband_auth = _fixed_host_auth()
        request = create_mock_request(
            f"https://{ROOT_DOMAIN}/auth/login", query_params={"tenant_name": "tenanta"}, cookies=STALE_COOKIES
        )

        response = await wristband_auth.login(request)

        location = urlparse(response.headers["location"])
        assert location.netloc == f"tenanta-{VANITY_DOMAIN}"
        assert location.path == "/api/v1/oauth2/authorize"
        assert "Domain=" not in _new_login_cookies(response)[0]
        assert "Domain=" not in _deleted_login_cookies(response)[0]


class TestLoginAppAuthRequestsTenantSubdomains:
    """login() with the flag enabled and tenant subdomains (parse_tenant_from_root_domain set)."""

    @pytest.mark.asyncio
    async def test_app_level_cookie_is_scoped_to_root_domain(self) -> None:
        """Test the app-level login state cookie has Domain=.{root} so the tenant callback receives it."""
        wristband_auth = _subdomain_auth()

        response = await wristband_auth.login(create_mock_request(f"https://{ROOT_DOMAIN}/auth/login"))

        location = urlparse(response.headers["location"])
        assert location.netloc == VANITY_DOMAIN
        assert location.path == "/api/v1/oauth2/authorize"
        assert parse_qs(location.query)["redirect_uri"] == ["https://{tenant_name}." + ROOT_DOMAIN + "/auth/callback"]
        cookies = _new_login_cookies(response)
        assert len(cookies) == 1
        assert f"Domain=.{ROOT_DOMAIN}" in cookies[0]

    @pytest.mark.asyncio
    async def test_app_level_stale_cookie_deletion_uses_root_domain(self) -> None:
        """Test stale login state cookies are deleted with the same Domain they were set with."""
        wristband_auth = _subdomain_auth()
        request = create_mock_request(f"https://{ROOT_DOMAIN}/auth/login", cookies=STALE_COOKIES)

        response = await wristband_auth.login(request)

        deleted = _deleted_login_cookies(response)
        assert len(deleted) == 1
        assert deleted[0].startswith("login#state1#1640995100000=")
        assert f"Domain=.{ROOT_DOMAIN}" in deleted[0]

    @pytest.mark.asyncio
    async def test_tenant_level_cookie_is_scoped_to_root_domain(self) -> None:
        """Test a tenant-level login also uses Domain=.{root} when the flag is enabled."""
        wristband_auth = _subdomain_auth()
        request = create_mock_request(f"https://tenanta.{ROOT_DOMAIN}/auth/login", cookies=STALE_COOKIES)

        response = await wristband_auth.login(request)

        location = urlparse(response.headers["location"])
        assert location.netloc == f"tenanta-{VANITY_DOMAIN}"
        assert f"Domain=.{ROOT_DOMAIN}" in _new_login_cookies(response)[0]
        assert f"Domain=.{ROOT_DOMAIN}" in _deleted_login_cookies(response)[0]

    @pytest.mark.asyncio
    async def test_tenant_level_cookie_has_no_domain_when_disabled(self) -> None:
        """Test a tenant-level login uses a host-only cookie when the flag is disabled."""
        wristband_auth = _subdomain_auth(application_authorization_requests_enabled=False)
        request = create_mock_request(f"https://tenanta.{ROOT_DOMAIN}/auth/login", cookies=STALE_COOKIES)

        response = await wristband_auth.login(request)

        assert urlparse(response.headers["location"]).netloc == f"tenanta-{VANITY_DOMAIN}"
        assert "Domain=" not in _new_login_cookies(response)[0]
        assert "Domain=" not in _deleted_login_cookies(response)[0]

    @pytest.mark.asyncio
    async def test_falls_back_to_app_level_login_url_when_disabled(self) -> None:
        """Test the flag disabled sends an unresolvable tenant to the app-level login page with no cookies."""
        wristband_auth = _subdomain_auth(application_authorization_requests_enabled=False)

        response = await wristband_auth.login(create_mock_request(f"https://{ROOT_DOMAIN}/auth/login"))

        assert response.headers["location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id"
        assert _set_cookie_headers(response) == []
