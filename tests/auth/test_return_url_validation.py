from typing import Dict, Optional
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import Request

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.exceptions import WristbandError
from wristband.fastapi_auth.models import (
    AuthConfig,
    CallbackData,
    CallbackResultType,
    CompletedCallbackResult,
    LoginState,
    UserInfo,
    WristbandTokenResponse,
)

ROOT_DOMAIN = "myapp.com"
TENANT_NAME = "acme"


def _auth() -> WristbandAuth:
    """Create a WristbandAuth for exercising _validate_return_url() directly."""
    return WristbandAuth(
        AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
            login_url="https://auth.example.com/login",
            redirect_uri="https://app.example.com/callback",
        )
    )


def _request(host: str, protocol: str = "https") -> Request:
    """Create a request for the given host, using the given protocol as the request URL scheme."""
    return create_mock_request(f"{protocol}://{host}/auth/callback")


def _raw_request(url: str, headers: Optional[Dict[str, str]] = None) -> Request:
    """Create a request with only the given URL and headers, for exercising protocol and host resolution."""
    return create_mock_request(url, headers=headers)


class TestValidateReturnUrlInputGuards:
    """Input guards for _validate_return_url()."""

    def setup_method(self) -> None:
        self.wristband_auth = _auth()

    def test_raises_when_tenant_name_is_empty(self) -> None:
        """Test a tenant name is required."""
        request = _request("acme.myapp.com")

        with pytest.raises(WristbandError, match="Tenant name is required to validate return_url"):
            self.wristband_auth._validate_return_url(request, "/settings", "", True, False, ROOT_DOMAIN)

    def test_raises_when_tenant_name_is_empty_even_if_return_url_is_missing(self) -> None:
        """Test the tenant name check runs before the return_url check."""
        request = _request("acme.myapp.com")

        with pytest.raises(WristbandError, match="Tenant name is required to validate return_url"):
            self.wristband_auth._validate_return_url(request, None, "", True, False, ROOT_DOMAIN)

    def test_returns_none_when_return_url_is_none(self) -> None:
        """Test a missing return_url is allowed and resolves to None."""
        request = _request("acme.myapp.com")

        assert self.wristband_auth._validate_return_url(request, None, TENANT_NAME, True, False, ROOT_DOMAIN) is None

    def test_returns_none_when_return_url_is_empty(self) -> None:
        """Test an empty return_url resolves to None."""
        request = _request("acme.myapp.com")

        assert self.wristband_auth._validate_return_url(request, "", TENANT_NAME, True, False, ROOT_DOMAIN) is None


class TestValidateReturnUrlAllowedHosts:
    """Return URLs that _validate_return_url() allows."""

    def setup_method(self) -> None:
        self.wristband_auth = _auth()

    def test_allows_relative_path_unchanged(self) -> None:
        """Test a relative path is allowed and returned unchanged."""
        request = _request("acme.myapp.com")

        result = self.wristband_auth._validate_return_url(
            request, "/settings?tab=1#top", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result == "/settings?tab=1#top"

    def test_allows_absolute_url_on_request_host(self) -> None:
        """Test an absolute URL on the same host as the request is allowed."""
        request = _request("acme.myapp.com")
        return_url = "https://acme.myapp.com/dashboard"

        assert (
            self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, True, False, ROOT_DOMAIN)
            == return_url
        )

    def test_ignores_port_when_comparing_hostnames(self) -> None:
        """Test the port is not part of the hostname comparison."""
        request = _request("acme.myapp.com")
        return_url = "https://acme.myapp.com:9999/dashboard"

        assert (
            self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, True, False, ROOT_DOMAIN)
            == return_url
        )

    def test_allows_same_host_when_parse_tenant_from_root_domain_not_set(self) -> None:
        """Test same-host URLs are allowed without tenant subdomains."""
        request = _request("app.example.com")
        return_url = "https://app.example.com/home"

        assert self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, False, False) == return_url


class TestValidateReturnUrlRejectedHosts:
    """Return URLs that _validate_return_url() rejects."""

    def setup_method(self) -> None:
        self.wristband_auth = _auth()

    @pytest.mark.parametrize(
        "return_url",
        [
            pytest.param("https://evil.com/phish", id="different_domain"),
            pytest.param("https://other.myapp.com/dashboard", id="different_tenant_subdomain"),
            pytest.param("//evil.com/phish", id="protocol_relative"),
            pytest.param("/\\evil.com/phish", id="backslash_prefixed"),
            pytest.param("https://myapp.com.evil.com/", id="lookalike_domain"),
            pytest.param("https://acme.myapp.com@evil.com/", id="userinfo_disguise"),
            pytest.param("javascript:alert(1)", id="javascript_url"),
            pytest.param("https://", id="malformed_url"),
        ],
    )
    def test_rejects_disallowed_return_url(self, return_url: str) -> None:
        """Test return URLs pointing anywhere other than an allowed host are rejected."""
        request = _request("acme.myapp.com")

        assert (
            self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, True, False, ROOT_DOMAIN) is None
        )

    def test_rejects_root_domain_when_parse_tenant_from_root_domain_not_set(self) -> None:
        """Test the root domain is only allowed when it is configured."""
        request = _request("acme.myapp.com")

        assert (
            self.wristband_auth._validate_return_url(request, "https://myapp.com/dashboard", TENANT_NAME, True, False)
            is None
        )


class TestValidateReturnUrlRootDomainTenantRewrite:
    """Rewriting root domain return URLs to the tenant subdomain."""

    def setup_method(self) -> None:
        self.wristband_auth = _auth()

    def test_prepends_tenant_subdomain_to_root_domain_url(self) -> None:
        """Test a root domain URL is rewritten to the tenant subdomain, preserving the path, query, and fragment."""
        request = _request("acme.myapp.com")

        result = self.wristband_auth._validate_return_url(
            request, "https://myapp.com/dashboard?x=1#top", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result == "https://acme.myapp.com/dashboard?x=1#top"

    def test_preserves_port_when_rewriting(self) -> None:
        """Test the port is preserved when rewriting."""
        request = _request("acme.localhost:6001", "http")

        result = self.wristband_auth._validate_return_url(
            request, "http://localhost:6001/home", TENANT_NAME, True, False, "localhost"
        )

        assert result == "http://acme.localhost:6001/home"

    def test_preserves_userinfo_when_rewriting(self) -> None:
        """Test userinfo is preserved when rewriting."""
        request = _request("acme.myapp.com")

        result = self.wristband_auth._validate_return_url(
            request, "https://user@myapp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result == "https://user@acme.myapp.com/dashboard"

    def test_lowercases_root_domain_hostname_when_rewriting(self) -> None:
        """Test a root domain hostname matches regardless of case, like it does in browsers."""
        request = _request("acme.myapp.com")

        result = self.wristband_auth._validate_return_url(
            request, "https://MyApp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result == "https://acme.myapp.com/dashboard"

    def test_does_not_rewrite_when_application_authorization_requests_disabled(self) -> None:
        """Test a root domain URL is returned unchanged when app-level authorization requests are disabled."""
        request = _request("acme.myapp.com")
        return_url = "https://myapp.com/dashboard"

        assert (
            self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, False, False, ROOT_DOMAIN)
            == return_url
        )

    def test_does_not_rewrite_relative_path(self) -> None:
        """Test a relative path is not rewritten even when rewriting is enabled."""
        request = _request("acme.myapp.com")

        assert self.wristband_auth._validate_return_url(
            request, "/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        ) == ("/dashboard")


class TestValidateReturnUrlProtocolMatching:
    """The return URL must use the same protocol as the request."""

    def setup_method(self) -> None:
        self.wristband_auth = _auth()

    def test_rejects_http_return_url_when_request_is_https(self) -> None:
        """Test an HTTPS to HTTP downgrade is rejected."""
        request = _request("acme.myapp.com")

        result = self.wristband_auth._validate_return_url(
            request, "http://acme.myapp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result is None

    def test_rejects_https_return_url_when_request_is_http(self) -> None:
        """Test a protocol mismatch is rejected in either direction."""
        request = _request("acme.localhost:6001", "http")

        result = self.wristband_auth._validate_return_url(
            request, "https://acme.localhost:6001/home", TENANT_NAME, True, False, "localhost"
        )

        assert result is None

    def test_rejects_root_domain_with_mismatched_protocol_instead_of_rewriting(self) -> None:
        """Test the protocol check runs before the root domain rewrite."""
        request = _request("acme.myapp.com")

        result = self.wristband_auth._validate_return_url(
            request, "http://myapp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result is None

    def test_rejects_non_http_protocol_on_allowed_host(self) -> None:
        """Test a non-HTTP protocol is rejected even on an allowed host."""
        request = _request("acme.myapp.com")

        result = self.wristband_auth._validate_return_url(
            request, "ftp://acme.myapp.com/file", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result is None

    def test_allows_relative_path_on_http_request(self) -> None:
        """Test a relative path inherits the request protocol."""
        request = _request("acme.localhost:6001", "http")

        assert (
            self.wristband_auth._validate_return_url(request, "/home", TENANT_NAME, True, False, "localhost") == "/home"
        )


class TestValidateReturnUrlRequestProtocolResolution:
    """Resolving the request protocol and origin used for validation."""

    def setup_method(self) -> None:
        self.wristband_auth = _auth()

    def test_uses_https_request_url_scheme(self) -> None:
        """Test an HTTPS request URL allows HTTPS return URLs."""
        request = _raw_request("https://localhost:3000/auth/callback", {"host": "acme.myapp.com"})
        return_url = "https://acme.myapp.com/dashboard"

        result = self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, True, False, ROOT_DOMAIN)

        assert result == return_url

    def test_uses_http_request_url_scheme(self) -> None:
        """Test an HTTP request URL only allows HTTP return URLs."""
        request = _raw_request("http://localhost:3000/auth/callback", {"host": "acme.myapp.com"})

        http_result = self.wristband_auth._validate_return_url(
            request, "http://acme.myapp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )
        https_result = self.wristband_auth._validate_return_url(
            request, "https://acme.myapp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert http_result == "http://acme.myapp.com/dashboard"
        assert https_result is None

    def test_ignores_x_forwarded_proto_upgrade(self) -> None:
        """Test x-forwarded-proto cannot upgrade the protocol, since the ASGI server owns proxy trust."""
        request = _raw_request(
            "http://localhost:3000/auth/callback", {"host": "acme.myapp.com", "x-forwarded-proto": "https"}
        )

        result = self.wristband_auth._validate_return_url(
            request, "https://acme.myapp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result is None

    def test_ignores_x_forwarded_proto_downgrade(self) -> None:
        """Test x-forwarded-proto cannot downgrade the protocol, since the ASGI server owns proxy trust."""
        request = _raw_request(
            "https://localhost:3000/auth/callback", {"host": "acme.myapp.com", "x-forwarded-proto": "http"}
        )

        result = self.wristband_auth._validate_return_url(
            request, "http://acme.myapp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result is None

    def test_ignores_x_forwarded_proto_when_trust_proxy_headers_enabled(self) -> None:
        """Test trust_proxy_headers only applies to the host, not the protocol."""
        request = _raw_request(
            "http://localhost:3000/auth/callback", {"host": "acme.myapp.com", "x-forwarded-proto": "https"}
        )

        result = self.wristband_auth._validate_return_url(
            request, "https://acme.myapp.com/dashboard", TENANT_NAME, True, True, ROOT_DOMAIN
        )

        assert result is None

    def test_uses_host_header_rather_than_request_url_host(self) -> None:
        """Test the Host header, not the request URL host, defines the allowed request hostname."""
        request = _raw_request("https://localhost:3000/auth/callback", {"host": "acme.myapp.com"})

        result = self.wristband_auth._validate_return_url(
            request, "https://localhost:3000/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result is None

    def test_returns_none_when_host_header_missing(self) -> None:
        """Test the request origin cannot be established without a Host header."""
        request = _raw_request("/auth/callback")

        assert (
            self.wristband_auth._validate_return_url(request, "/settings", TENANT_NAME, True, False, ROOT_DOMAIN)
            is None
        )

    def test_returns_none_when_host_header_malformed(self) -> None:
        """Test a malformed Host header is treated as unsafe."""
        request = _raw_request("/auth/callback", {"host": "[::1"})

        assert (
            self.wristband_auth._validate_return_url(request, "/settings", TENANT_NAME, True, False, ROOT_DOMAIN)
            is None
        )

    def test_allows_ipv6_request_host(self) -> None:
        """Test an IPv6 Host header with a port is parsed correctly."""
        request = _request("[::1]:8000", "http")
        return_url = "http://[::1]:8000/home"

        assert self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, False, False) == return_url


class TestValidateReturnUrlTrustedProxyHeaders:
    """Resolving the request host from X-Forwarded-Host when trust_proxy_headers is enabled."""

    def setup_method(self) -> None:
        self.wristband_auth = _auth()

    def _proxied_request(self, headers: Dict[str, str]) -> Request:
        """Create a request as received from a reverse proxy, where the Host header is the internal host."""
        return _raw_request("https://internal:3000/auth/callback", {"host": "internal:3000", **headers})

    def test_ignores_x_forwarded_host_when_trust_proxy_headers_false(self) -> None:
        """Test X-Forwarded-Host is not trusted by default."""
        request = self._proxied_request({"x-forwarded-host": "acme.myapp.com"})

        result = self.wristband_auth._validate_return_url(
            request, "https://acme.myapp.com/dashboard", TENANT_NAME, True, False, ROOT_DOMAIN
        )

        assert result is None

    def test_allows_url_on_forwarded_host_when_trust_proxy_headers_true(self) -> None:
        """Test a return URL on the forwarded host is allowed behind a trusted proxy."""
        request = self._proxied_request({"x-forwarded-host": "acme.myapp.com"})
        return_url = "https://acme.myapp.com/dashboard"

        result = self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, True, True, ROOT_DOMAIN)

        assert result == return_url

    def test_rejects_url_on_host_header_host_when_trust_proxy_headers_true(self) -> None:
        """Test the Host header host is no longer allowed once the forwarded host is used."""
        request = self._proxied_request({"x-forwarded-host": "acme.myapp.com"})

        result = self.wristband_auth._validate_return_url(
            request, "https://internal:3000/dashboard", TENANT_NAME, True, True, ROOT_DOMAIN
        )

        assert result is None

    def test_still_rejects_different_domain_when_trust_proxy_headers_true(self) -> None:
        """Test external hosts are still rejected behind a trusted proxy."""
        request = self._proxied_request({"x-forwarded-host": "acme.myapp.com"})

        result = self.wristband_auth._validate_return_url(
            request, "https://evil.com/phish", TENANT_NAME, True, True, ROOT_DOMAIN
        )

        assert result is None

    def test_falls_back_to_host_header_when_x_forwarded_host_missing(self) -> None:
        """Test the Host header is used when the proxy doesn't send X-Forwarded-Host."""
        request = _request("acme.myapp.com")
        return_url = "https://acme.myapp.com/dashboard"

        result = self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, True, True, ROOT_DOMAIN)

        assert result == return_url


class TestValidateReturnUrlBrowserParsingParity:
    """
    Return URLs that urllib would otherwise parse differently than browsers (WHATWG URL Standard).
    The validated host must be the host the browser actually redirects to.
    """

    def setup_method(self) -> None:
        self.wristband_auth = _auth()

    @pytest.mark.parametrize(
        "return_url",
        [
            pytest.param("////evil.com/phish", id="extra_leading_slashes"),
            pytest.param("https:///evil.com/phish", id="extra_slashes_after_scheme"),
            pytest.param("https:\\\\evil.com/phish", id="backslashes_after_scheme"),
            pytest.param("\\\\evil.com/phish", id="leading_backslashes"),
            pytest.param("/\t/evil.com/phish", id="tab_between_slashes"),
            pytest.param("/\n/evil.com/phish", id="newline_between_slashes"),
            pytest.param(" //evil.com/phish", id="leading_space"),
            pytest.param("\x00//evil.com/phish", id="leading_control_character"),
            pytest.param("HTTPS://evil.com/phish", id="uppercase_scheme"),
            pytest.param("https:///", id="empty_host_after_extra_slashes"),
            pytest.param("https://acme.myapp.com:abc/dashboard", id="malformed_port"),
        ],
    )
    def test_rejects_urls_browsers_resolve_to_another_host(self, return_url: str) -> None:
        """Test return URLs that browsers resolve to a disallowed or invalid host are rejected."""
        request = _request("acme.myapp.com")

        assert (
            self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, True, False, ROOT_DOMAIN) is None
        )

    @pytest.mark.parametrize(
        "return_url",
        [
            pytest.param("HTTPS://acme.myapp.com/dashboard", id="uppercase_scheme"),
            pytest.param("https://ACME.myapp.com/dashboard", id="uppercase_hostname"),
            pytest.param("https:dashboard", id="scheme_without_slashes"),
            pytest.param("https:/dashboard", id="scheme_with_single_slash"),
            pytest.param("dashboard?tab=1", id="path_relative"),
        ],
    )
    def test_allows_urls_browsers_resolve_to_request_host(self, return_url: str) -> None:
        """Test return URLs that browsers resolve to the request host are allowed and returned unchanged."""
        request = _request("acme.myapp.com")

        assert (
            self.wristband_auth._validate_return_url(request, return_url, TENANT_NAME, True, False, ROOT_DOMAIN)
            == return_url
        )


class TestCallbackReturnUrlValidation:
    """callback() validates the return URL from the login state before returning it."""

    root_domain = "business.invotastic.com"

    async def _run_callback_with_return_url(
        self,
        return_url: str,
        use_tenant_subdomains: bool,
        application_authorization_requests_enabled: bool = False,
    ) -> CallbackData:
        """
        Run a successful callback with the given return URL in the login state and return the callback data.
        With tenant subdomains, the tenant comes from the host; without, it comes from the tenant_name query param.
        """
        host = f"devs4you.{self.root_domain}" if use_tenant_subdomains else self.root_domain
        tenant_prefix = "{tenant_name}." if use_tenant_subdomains else ""
        redirect_uri = f"https://{tenant_prefix}{self.root_domain}/auth/callback"

        wristband_auth = WristbandAuth(
            AuthConfig(
                client_id="test_client_id",
                client_secret="test_client_secret",
                login_state_secret=TEST_LOGIN_STATE_SECRET,
                login_url=f"https://{tenant_prefix}{self.root_domain}/auth/login",
                redirect_uri=redirect_uri,
                parse_tenant_from_root_domain=self.root_domain if use_tenant_subdomains else None,
                application_authorization_requests_enabled=application_authorization_requests_enabled,
                # Required by config validation when app-level authorization requests are enabled
                # and login_url contains the {tenant_name} placeholder.
                fallback_login_url=(
                    f"https://{self.root_domain}/auth/login"
                    if application_authorization_requests_enabled and use_tenant_subdomains
                    else None
                ),
                wristband_application_vanity_domain="auth.example.com",
                auto_configure_enabled=False,
            )
        )

        login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri=redirect_uri,
            return_url=return_url,
            custom_state=None,
        )
        query_params = {"code": "auth_code", "state": "test_state"}
        if not use_tenant_subdomains:
            query_params["tenant_name"] = "devs4you"

        request = create_mock_request(
            f"https://{host}/auth/callback",
            query_params=query_params,
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
        return result.callback_data

    @pytest.mark.asyncio
    async def test_allows_relative_path_return_url(self) -> None:
        """Test a relative path return URL is passed through."""
        callback_data = await self._run_callback_with_return_url("/settings?tab=billing", False)
        assert callback_data.return_url == "/settings?tab=billing"

    @pytest.mark.asyncio
    async def test_allows_absolute_return_url_on_request_host(self) -> None:
        """Test an absolute return URL on the request host is passed through."""
        callback_data = await self._run_callback_with_return_url(f"https://{self.root_domain}/dashboard", False)
        assert callback_data.return_url == f"https://{self.root_domain}/dashboard"

    @pytest.mark.asyncio
    async def test_rejects_off_site_return_url(self) -> None:
        """Test an off-site return URL is dropped."""
        callback_data = await self._run_callback_with_return_url("https://evil.com/phish", False)
        assert callback_data.return_url is None

    @pytest.mark.asyncio
    async def test_rejects_protocol_relative_return_url_to_another_host(self) -> None:
        """Test a protocol-relative return URL to another host is dropped."""
        callback_data = await self._run_callback_with_return_url("//evil.com/phish", False)
        assert callback_data.return_url is None

    @pytest.mark.asyncio
    async def test_rejects_return_url_with_mismatched_protocol(self) -> None:
        """Test a return URL that downgrades the protocol is dropped."""
        callback_data = await self._run_callback_with_return_url(f"http://{self.root_domain}/dashboard", False)
        assert callback_data.return_url is None

    @pytest.mark.asyncio
    async def test_allows_return_url_on_current_tenant_subdomain(self) -> None:
        """Test a return URL on the current tenant subdomain is passed through."""
        callback_data = await self._run_callback_with_return_url(f"https://devs4you.{self.root_domain}/dashboard", True)
        assert callback_data.return_url == f"https://devs4you.{self.root_domain}/dashboard"

    @pytest.mark.asyncio
    async def test_rejects_return_url_on_different_tenant_subdomain(self) -> None:
        """Test a return URL on another tenant's subdomain is dropped."""
        callback_data = await self._run_callback_with_return_url(f"https://other.{self.root_domain}/dashboard", True)
        assert callback_data.return_url is None

    @pytest.mark.asyncio
    async def test_allows_root_domain_return_url_unchanged_when_app_level_auth_disabled(self) -> None:
        """Test a root domain return URL is not rewritten when app-level authorization requests are disabled."""
        callback_data = await self._run_callback_with_return_url(f"https://{self.root_domain}/dashboard", True, False)
        assert callback_data.return_url == f"https://{self.root_domain}/dashboard"

    @pytest.mark.asyncio
    async def test_rewrites_root_domain_return_url_to_tenant_subdomain_when_app_level_auth_enabled(self) -> None:
        """Test a root domain return URL is rewritten to the tenant subdomain when app-level auth is enabled."""
        callback_data = await self._run_callback_with_return_url(
            f"https://{self.root_domain}/dashboard?x=1#top", True, True
        )
        assert callback_data.return_url == f"https://devs4you.{self.root_domain}/dashboard?x=1#top"

    @pytest.mark.asyncio
    async def test_does_not_rewrite_return_url_already_on_tenant_subdomain_when_app_level_auth_enabled(self) -> None:
        """Test a return URL already on the tenant subdomain is passed through when app-level auth is enabled."""
        callback_data = await self._run_callback_with_return_url(
            f"https://devs4you.{self.root_domain}/dashboard", True, True
        )
        assert callback_data.return_url == f"https://devs4you.{self.root_domain}/dashboard"

    @pytest.mark.asyncio
    async def test_does_not_rewrite_relative_path_when_app_level_auth_enabled(self) -> None:
        """Test a relative path return URL is passed through when app-level auth is enabled."""
        callback_data = await self._run_callback_with_return_url("/dashboard", True, True)
        assert callback_data.return_url == "/dashboard"

    @pytest.mark.asyncio
    async def test_still_rejects_off_site_return_url_when_app_level_auth_enabled(self) -> None:
        """Test an off-site return URL is dropped when app-level auth is enabled."""
        callback_data = await self._run_callback_with_return_url("https://evil.com/phish", True, True)
        assert callback_data.return_url is None
