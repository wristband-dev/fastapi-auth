from unittest.mock import AsyncMock, patch

import pytest
from fastapi import Request

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import (
    AuthConfig,
    CallbackResultType,
    CompletedCallbackResult,
    LoginState,
    RedirectRequiredCallbackResult,
    UserInfo,
    WristbandTokenResponse,
)

ROOT_DOMAIN = "myapp.com"
VANITY_DOMAIN = "auth.example.com"
INTERNAL_HOST = "internal:3000"


def _subdomain_auth(trust_proxy_headers: bool) -> WristbandAuth:
    """Create a WristbandAuth that uses tenant subdomains of ROOT_DOMAIN."""
    return WristbandAuth(
        AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            wristband_application_vanity_domain=VANITY_DOMAIN,
            auto_configure_enabled=False,
            login_url=f"https://{{tenant_name}}.{ROOT_DOMAIN}/auth/login",
            redirect_uri=f"https://{{tenant_name}}.{ROOT_DOMAIN}/auth/callback",
            parse_tenant_from_root_domain=ROOT_DOMAIN,
            trust_proxy_headers=trust_proxy_headers,
        )
    )


class TestGetRequestHost:
    """_get_request_host() and its use when resolving the tenant name from a subdomain."""

    def setup_method(self) -> None:
        self.wristband_auth = _subdomain_auth(trust_proxy_headers=False)

    def test_ignores_x_forwarded_host_when_trust_proxy_headers_false(self) -> None:
        """Test the Host header is used and X-Forwarded-Host is ignored by default."""
        request = create_mock_request(
            f"https://{INTERNAL_HOST}/auth/login", headers={"x-forwarded-host": f"acme.{ROOT_DOMAIN}"}
        )

        assert self.wristband_auth._get_request_host(request, False) == INTERNAL_HOST

    def test_uses_x_forwarded_host_when_trust_proxy_headers_true(self) -> None:
        """Test X-Forwarded-Host is used behind a trusted proxy."""
        request = create_mock_request(
            f"https://{INTERNAL_HOST}/auth/login", headers={"x-forwarded-host": f"acme.{ROOT_DOMAIN}"}
        )

        assert self.wristband_auth._get_request_host(request, True) == f"acme.{ROOT_DOMAIN}"

    def test_preserves_port_from_x_forwarded_host(self) -> None:
        """Test the port from X-Forwarded-Host is part of the host."""
        request = create_mock_request(
            f"https://{INTERNAL_HOST}/auth/login", headers={"x-forwarded-host": f"acme.{ROOT_DOMAIN}:8443"}
        )

        assert self.wristband_auth._get_request_host(request, True) == f"acme.{ROOT_DOMAIN}:8443"

    def test_uses_first_value_of_comma_separated_x_forwarded_host(self) -> None:
        """Test the first host in a comma-separated X-Forwarded-Host is used."""
        request = create_mock_request(
            f"https://{INTERNAL_HOST}/auth/login",
            headers={"x-forwarded-host": f" acme.{ROOT_DOMAIN} , other.{ROOT_DOMAIN}"},
        )

        assert self.wristband_auth._get_request_host(request, True) == f"acme.{ROOT_DOMAIN}"

    def test_uses_first_header_when_x_forwarded_host_repeated(self) -> None:
        """Test the first X-Forwarded-Host header is used when the header is sent more than once."""
        # A real request, since a header sent more than once can't be expressed through create_mock_request().
        request = Request(
            {
                "type": "http",
                "headers": [
                    (b"host", INTERNAL_HOST.encode()),
                    (b"x-forwarded-host", f"acme.{ROOT_DOMAIN}".encode()),
                    (b"x-forwarded-host", f"other.{ROOT_DOMAIN}".encode()),
                ],
            }
        )

        assert self.wristband_auth._get_request_host(request, True) == f"acme.{ROOT_DOMAIN}"

    def test_falls_back_to_host_header_when_x_forwarded_host_missing(self) -> None:
        """Test the Host header is used when X-Forwarded-Host is missing."""
        request = create_mock_request(f"https://acme.{ROOT_DOMAIN}/auth/login")

        assert self.wristband_auth._get_request_host(request, True) == f"acme.{ROOT_DOMAIN}"

    @pytest.mark.parametrize("forwarded_host", ["", "   ", " , other.myapp.com"])
    def test_falls_back_to_host_header_when_x_forwarded_host_empty(self, forwarded_host: str) -> None:
        """Test the Host header is used when the first X-Forwarded-Host value is empty."""
        request = create_mock_request(
            f"https://acme.{ROOT_DOMAIN}/auth/login", headers={"x-forwarded-host": forwarded_host}
        )

        assert self.wristband_auth._get_request_host(request, True) == f"acme.{ROOT_DOMAIN}"

    def test_returns_empty_string_when_no_host(self) -> None:
        """Test an empty string is returned when no host can be determined."""
        request = create_mock_request("/auth/login")

        assert self.wristband_auth._get_request_host(request, True) == ""

    def test_resolves_tenant_subdomain_from_x_forwarded_host_when_trust_proxy_headers_true(self) -> None:
        """Test the tenant name is parsed from the forwarded host, ignoring its port."""
        request = create_mock_request(
            f"https://{INTERNAL_HOST}/auth/login", headers={"x-forwarded-host": f"acme.{ROOT_DOMAIN}:8443"}
        )

        assert self.wristband_auth._resolve_tenant_name(request, ROOT_DOMAIN, True) == "acme"

    def test_does_not_resolve_tenant_subdomain_from_x_forwarded_host_when_trust_proxy_headers_false(self) -> None:
        """Test a spoofed X-Forwarded-Host cannot select the tenant by default."""
        request = create_mock_request(
            f"https://{INTERNAL_HOST}/auth/login", headers={"x-forwarded-host": f"acme.{ROOT_DOMAIN}"}
        )

        assert self.wristband_auth._resolve_tenant_name(request, ROOT_DOMAIN, False) == ""


class TestTrustProxyHeadersAuthFlows:
    """login(), callback(), and logout() resolve the tenant subdomain from X-Forwarded-Host behind a trusted proxy."""

    def _proxied_request(self, path: str, **kwargs) -> Request:
        """Create a request as received from a reverse proxy for the acme tenant subdomain."""
        return create_mock_request(
            f"https://{INTERNAL_HOST}{path}", headers={"x-forwarded-host": f"acme.{ROOT_DOMAIN}"}, **kwargs
        )

    @pytest.mark.asyncio
    async def test_login_uses_tenant_subdomain_from_x_forwarded_host(self) -> None:
        """Test login() sends the user to the tenant-level Authorize Endpoint for the forwarded tenant."""
        response = await _subdomain_auth(trust_proxy_headers=True).login(self._proxied_request("/auth/login"))

        assert response.status_code == 302
        assert response.headers["location"].startswith(f"https://acme-{VANITY_DOMAIN}/api/v1/oauth2/authorize")

    @pytest.mark.asyncio
    async def test_login_ignores_x_forwarded_host_when_trust_proxy_headers_false(self) -> None:
        """Test login() falls back to the app-level login page when the forwarded host isn't trusted."""
        response = await _subdomain_auth(trust_proxy_headers=False).login(self._proxied_request("/auth/login"))

        assert response.status_code == 302
        assert response.headers["location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id"

    @pytest.mark.asyncio
    async def test_callback_uses_tenant_subdomain_from_x_forwarded_host(self) -> None:
        """Test callback() resolves the forwarded tenant and allows a return URL on the forwarded host."""
        wristband_auth = _subdomain_auth(trust_proxy_headers=True)
        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri=f"https://acme.{ROOT_DOMAIN}/auth/callback",
            return_url=f"https://acme.{ROOT_DOMAIN}/dashboard",
            custom_state=None,
        )
        request = self._proxied_request(
            "/auth/callback",
            query_params={"code": "auth_code", "state": "test_state"},
            cookies={"login#test_state#1640995200000": wristband_auth._encrypt_login_state(login_state)},
        )
        mock_token_response = WristbandTokenResponse(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_in=3600,
            refresh_token="refresh_token_123",
            token_type="Bearer",
            scope="openid offline_access email",
        )
        mock_user_info = UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="user@example.com",
            email_verified=True,
        )

        with (
            patch.object(wristband_auth._wristband_api, "get_tokens", new_callable=AsyncMock) as mock_get_tokens,
            patch.object(wristband_auth._wristband_api, "get_userinfo", new_callable=AsyncMock) as mock_get_userinfo,
        ):
            mock_get_tokens.return_value = mock_token_response
            mock_get_userinfo.return_value = mock_user_info

            result = await wristband_auth.callback(request)

        assert isinstance(result, CompletedCallbackResult)
        assert result.type == CallbackResultType.COMPLETED
        assert result.callback_data.tenant_name == "acme"
        assert result.callback_data.return_url == f"https://acme.{ROOT_DOMAIN}/dashboard"

    @pytest.mark.asyncio
    async def test_callback_redirects_to_forwarded_tenant_login_url_without_login_state(self) -> None:
        """Test callback() builds the tenant login URL from the forwarded tenant."""
        request = self._proxied_request("/auth/callback", query_params={"state": "test_state"})

        result = await _subdomain_auth(trust_proxy_headers=True).callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.redirect_url == f"https://acme.{ROOT_DOMAIN}/auth/login"

    @pytest.mark.asyncio
    async def test_logout_uses_tenant_subdomain_from_x_forwarded_host(self) -> None:
        """Test logout() sends the user to the Logout Endpoint for the forwarded tenant."""
        response = await _subdomain_auth(trust_proxy_headers=True).logout(self._proxied_request("/auth/logout"))

        assert response.status_code == 302
        assert response.headers["location"] == f"https://acme-{VANITY_DOMAIN}/api/v1/logout?client_id=test_client_id"
