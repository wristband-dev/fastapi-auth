"""Tests for the redirect response that callback() returns and the redirect URL resolver it calls."""

from typing import Any, Callable, Dict, List, Optional
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, Response

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request, resolve_test_redirect_url
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.exceptions import InvalidGrantError
from wristband.fastapi_auth.models import (
    AuthConfig,
    CallbackData,
    CallbackFailureReason,
    CallbackResult,
    CallbackResultType,
    CompletedCallbackResult,
    LoginState,
    RedirectRequiredCallbackResult,
    UserInfo,
    WristbandTokenResponse,
)

VANITY_DOMAIN = "app.wristband.dev"
ROOT_DOMAIN = "yourapp.io"
APP_HOME_URL = f"https://{ROOT_DOMAIN}/home"
LOGIN_COOKIE_NAME = "login#state#1640995200000"

TOKEN_RESPONSE = WristbandTokenResponse(
    access_token="access_token_123",
    id_token="id_token_123",
    expires_in=3600,
    refresh_token="refresh_token_123",
    token_type="Bearer",
    scope="openid offline_access email",
)
USER_INFO = UserInfo(
    user_id="user_123",
    tenant_id="tenant_123",
    application_id="app_123",
    identity_provider_name="Wristband",
    email="user@example.com",
    email_verified=True,
)


def _fixed_host_auth(**overrides: Any) -> WristbandAuth:
    """Create a WristbandAuth that does not use tenant subdomains, so the tenant comes from tenant_name."""
    values: Dict[str, Any] = {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret",
        "login_state_secret": TEST_LOGIN_STATE_SECRET,
        "wristband_application_vanity_domain": VANITY_DOMAIN,
        "auto_configure_enabled": False,
        "login_url": f"https://{ROOT_DOMAIN}/auth/login",
        "redirect_uri": f"https://{ROOT_DOMAIN}/auth/callback",
        "application_authorization_requests_enabled": False,
    }
    values.update(overrides)
    return WristbandAuth(AuthConfig(**values))


def _subdomain_auth(**overrides: Any) -> WristbandAuth:
    """Create a WristbandAuth that uses tenant subdomains of ROOT_DOMAIN."""
    values: Dict[str, Any] = {
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


def _callback_request(
    wristband_auth: WristbandAuth,
    host: str = ROOT_DOMAIN,
    query_params: Optional[Dict[str, str]] = None,
    return_url: Optional[str] = None,
    with_login_state_cookie: bool = True,
) -> Request:
    """Create a callback request, with a valid login state cookie unless told otherwise."""
    cookies: Dict[str, str] = {}
    if with_login_state_cookie:
        login_state = LoginState(
            state="state",
            code_verifier="code_verifier",
            redirect_uri=f"https://{host}/auth/callback",
            return_url=return_url,
            custom_state=None,
        )
        cookies[LOGIN_COOKIE_NAME] = wristband_auth._encrypt_login_state(login_state)

    params = {"code": "auth_code", "state": "state"}
    if host == ROOT_DOMAIN:
        # Without a tenant subdomain in the host, the tenant comes from the tenant_name query param.
        params["tenant_name"] = "tenanta"
    params.update(query_params or {})

    return create_mock_request(f"https://{host}/auth/callback", query_params=params, cookies=cookies)


async def _run_callback(
    wristband_auth: WristbandAuth,
    request: Request,
    resolve_redirect_url: Callable[..., Any] = resolve_test_redirect_url,
    get_tokens: Optional[AsyncMock] = None,
) -> CallbackResult:
    """Run callback() with the Wristband token and userinfo APIs mocked."""
    with (
        patch.object(
            wristband_auth._wristband_api,
            "get_tokens",
            get_tokens or AsyncMock(return_value=TOKEN_RESPONSE),
        ),
        patch.object(wristband_auth._wristband_api, "get_userinfo", AsyncMock(return_value=USER_INFO)),
    ):
        return await wristband_auth.callback(request, resolve_redirect_url)


def _set_cookie_headers(response: Response) -> List[str]:
    """Return the decoded set-cookie headers of a response."""
    return [value.decode() for key, value in response.raw_headers if key == b"set-cookie"]


def _assert_redirect(response: Response, location: str) -> None:
    """Assert the response is a no-cache 302 redirect to the given location."""
    assert response.status_code == 302
    assert response.headers["location"] == location
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def _assert_single_cleared_login_cookie(response: Response) -> str:
    """Assert the response clears exactly the login state cookie, returning its set-cookie header."""
    headers = _set_cookie_headers(response)
    assert len(headers) == 1
    assert headers[0].startswith(f'{LOGIN_COOKIE_NAME}="";')
    assert "Max-Age=0" in headers[0]
    assert "Path=/" in headers[0]
    assert "HttpOnly" in headers[0]
    assert "SameSite=lax" in headers[0]
    return headers[0]


class TestCallbackResolverValidation:
    """callback() requires resolve_redirect_url to be a function."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("resolve_redirect_url", [None, "https://yourapp.io/home"])
    async def test_raises_before_any_wristband_api_call_when_resolver_not_a_function(
        self, resolve_redirect_url: Any
    ) -> None:
        """Test a missing or non-function resolver is rejected before any Wristband API call."""
        wristband_auth = _fixed_host_auth()
        get_tokens = AsyncMock(return_value=TOKEN_RESPONSE)

        with pytest.raises(TypeError, match="resolve_redirect_url must be a function"):
            await _run_callback(wristband_auth, _callback_request(wristband_auth), resolve_redirect_url, get_tokens)

        get_tokens.assert_not_called()


class TestCallbackRedirectUrlResolution:
    """The completed callback response redirects to the URL returned by resolve_redirect_url."""

    @pytest.mark.asyncio
    async def test_redirects_to_url_returned_by_resolver(self) -> None:
        """Test the completed response redirects to the resolver's URL."""
        wristband_auth = _fixed_host_auth()

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth), lambda req, data: APP_HOME_URL)

        assert isinstance(result, CompletedCallbackResult)
        assert result.type == CallbackResultType.COMPLETED
        _assert_redirect(result.response, APP_HOME_URL)

    @pytest.mark.asyncio
    async def test_supports_async_resolver(self) -> None:
        """Test an async resolver is awaited."""
        wristband_auth = _fixed_host_auth()

        async def resolve_redirect_url(request: Request, callback_data: CallbackData) -> str:
            return APP_HOME_URL

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth), resolve_redirect_url)

        assert isinstance(result, CompletedCallbackResult)
        _assert_redirect(result.response, APP_HOME_URL)

    @pytest.mark.asyncio
    async def test_passes_request_and_callback_data_to_resolver(self) -> None:
        """Test the resolver receives the request and the same callback data returned in the result."""
        wristband_auth = _fixed_host_auth()
        request = _callback_request(wristband_auth)
        resolve_redirect_url = Mock(return_value=APP_HOME_URL)

        result = await _run_callback(wristband_auth, request, resolve_redirect_url)

        assert isinstance(result, CompletedCallbackResult)
        resolve_redirect_url.assert_called_once_with(request, result.callback_data)
        assert result.callback_data.tenant_name == "tenanta"
        assert result.callback_data.user_info == USER_INFO

    @pytest.mark.asyncio
    async def test_redirects_to_validated_return_url_when_resolver_returns_it(self) -> None:
        """Test the resolver can send the user to the validated return URL."""
        wristband_auth = _fixed_host_auth()
        request = _callback_request(wristband_auth, return_url=f"https://{ROOT_DOMAIN}/settings")

        result = await _run_callback(wristband_auth, request, lambda req, data: data.return_url or APP_HOME_URL)

        assert isinstance(result, CompletedCallbackResult)
        _assert_redirect(result.response, f"https://{ROOT_DOMAIN}/settings")

    @pytest.mark.asyncio
    async def test_keeps_relative_path_as_relative_redirect(self) -> None:
        """Test a relative path is sent as-is, which browsers resolve against the URL they requested."""
        wristband_auth = _fixed_host_auth()

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth), lambda req, data: "/home")

        assert isinstance(result, CompletedCallbackResult)
        _assert_redirect(result.response, "/home")

    @pytest.mark.asyncio
    async def test_preserves_query_params_in_redirect_url(self) -> None:
        """Test a redirect URL with query params is preserved."""
        wristband_auth = _fixed_host_auth()
        redirect_url = f"https://{ROOT_DOMAIN}/dashboard?user=123&tab=profile&return_to=%2Fsettings"

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth), lambda req, data: redirect_url)

        assert isinstance(result, CompletedCallbackResult)
        _assert_redirect(result.response, redirect_url)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("redirect_url", ["", "   ", None])
    async def test_raises_when_resolver_returns_empty_url(self, redirect_url: Any) -> None:
        """Test the resolver must return a non-empty URL."""
        wristband_auth = _fixed_host_auth()

        with pytest.raises(TypeError, match="resolve_redirect_url must return a non-empty URL"):
            await _run_callback(wristband_auth, _callback_request(wristband_auth), lambda req, data: redirect_url)

    @pytest.mark.asyncio
    async def test_raises_when_async_resolver_returns_empty_url(self) -> None:
        """Test an async resolver must also return a non-empty URL."""
        wristband_auth = _fixed_host_auth()

        async def resolve_redirect_url(request: Request, callback_data: CallbackData) -> str:
            return ""

        with pytest.raises(TypeError, match="resolve_redirect_url must return a non-empty URL"):
            await _run_callback(wristband_auth, _callback_request(wristband_auth), resolve_redirect_url)

    @pytest.mark.asyncio
    async def test_propagates_resolver_errors(self) -> None:
        """Test an error raised by the resolver is not swallowed."""
        wristband_auth = _fixed_host_auth()

        def resolve_redirect_url(request: Request, callback_data: CallbackData) -> str:
            raise RuntimeError("lookup failed")

        with pytest.raises(RuntimeError, match="lookup failed"):
            await _run_callback(wristband_auth, _callback_request(wristband_auth), resolve_redirect_url)

    @pytest.mark.asyncio
    async def test_clears_login_state_cookie_on_completed_response(self) -> None:
        """Test the completed response clears the login state cookie with secure attributes."""
        wristband_auth = _fixed_host_auth()

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth))

        cleared_cookie = _assert_single_cleared_login_cookie(result.response)
        assert "Secure" in cleared_cookie

    @pytest.mark.asyncio
    async def test_clears_login_state_cookie_without_secure_when_secure_cookies_disabled(self) -> None:
        """Test the Secure attribute is left off when secure cookies are disabled."""
        wristband_auth = _fixed_host_auth(dangerously_disable_secure_cookies=True)

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth))

        assert "Secure" not in _assert_single_cleared_login_cookie(result.response)


class TestCallbackRedirectRequiredResponse:
    """The redirect required response redirects to the Login Endpoint without calling the resolver."""

    @pytest.mark.asyncio
    async def test_missing_login_state_redirects_to_login_without_clearing_cookie(self) -> None:
        """Test nothing is cleared when the request has no login state cookie."""
        wristband_auth = _fixed_host_auth()
        resolve_redirect_url = Mock(return_value=APP_HOME_URL)

        result = await _run_callback(
            wristband_auth, _callback_request(wristband_auth, with_login_state_cookie=False), resolve_redirect_url
        )

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.reason == CallbackFailureReason.MISSING_LOGIN_STATE
        _assert_redirect(result.response, f"https://{ROOT_DOMAIN}/auth/login?tenant_name=tenanta")
        assert _set_cookie_headers(result.response) == []
        resolve_redirect_url.assert_not_called()

    @pytest.mark.asyncio
    async def test_login_required_redirects_to_login_and_clears_cookie(self) -> None:
        """Test a login_required error redirects to login and clears the login state cookie."""
        wristband_auth = _fixed_host_auth()
        request = _callback_request(wristband_auth, query_params={"error": "login_required"})
        resolve_redirect_url = Mock(return_value=APP_HOME_URL)

        result = await _run_callback(wristband_auth, request, resolve_redirect_url)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.LOGIN_REQUIRED
        _assert_redirect(result.response, f"https://{ROOT_DOMAIN}/auth/login?tenant_name=tenanta")
        _assert_single_cleared_login_cookie(result.response)
        resolve_redirect_url.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_grant_redirects_to_login_and_clears_cookie(self) -> None:
        """Test an invalid grant redirects to login and clears the login state cookie."""
        wristband_auth = _fixed_host_auth()
        resolve_redirect_url = Mock(return_value=APP_HOME_URL)
        get_tokens = AsyncMock(side_effect=InvalidGrantError("Invalid grant"))

        result = await _run_callback(
            wristband_auth, _callback_request(wristband_auth), resolve_redirect_url, get_tokens
        )

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.INVALID_GRANT
        _assert_redirect(result.response, f"https://{ROOT_DOMAIN}/auth/login?tenant_name=tenanta")
        _assert_single_cleared_login_cookie(result.response)
        resolve_redirect_url.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_login_state_redirects_to_tenant_login_url_and_clears_cookie(self) -> None:
        """Test a state mismatch redirects to the tenant subdomain login URL and clears the login state cookie."""
        wristband_auth = _subdomain_auth()
        request = _callback_request(wristband_auth, host=f"tenanta.{ROOT_DOMAIN}")
        login_state = LoginState(
            state="other_state",
            code_verifier="code_verifier",
            redirect_uri=f"https://tenanta.{ROOT_DOMAIN}/auth/callback",
            return_url=None,
            custom_state=None,
        )
        request.cookies[LOGIN_COOKIE_NAME] = wristband_auth._encrypt_login_state(login_state)
        resolve_redirect_url = Mock(return_value=APP_HOME_URL)

        result = await _run_callback(wristband_auth, request, resolve_redirect_url)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.INVALID_LOGIN_STATE
        _assert_redirect(result.response, f"https://tenanta.{ROOT_DOMAIN}/auth/login")
        assert f"Domain=.{ROOT_DOMAIN}" in _assert_single_cleared_login_cookie(result.response)
        resolve_redirect_url.assert_not_called()


class TestCallbackLoginStateCookieDomain:
    """callback() clears the login state cookie with the same Domain that login() set it with."""

    @pytest.mark.asyncio
    async def test_clears_cookie_with_root_domain_when_app_level_auth_enabled(self) -> None:
        """Test the cookie is cleared with Domain=.{root} on a tenant subdomain callback."""
        wristband_auth = _subdomain_auth()

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth, host=f"tenanta.{ROOT_DOMAIN}"))

        assert isinstance(result, CompletedCallbackResult)
        assert f"Domain=.{ROOT_DOMAIN}" in _assert_single_cleared_login_cookie(result.response)

    @pytest.mark.asyncio
    async def test_clears_cookie_without_domain_when_app_level_auth_disabled(self) -> None:
        """Test the cookie is cleared as host-only on a tenant subdomain callback when the flag is disabled."""
        wristband_auth = _subdomain_auth(application_authorization_requests_enabled=False)

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth, host=f"tenanta.{ROOT_DOMAIN}"))

        assert isinstance(result, CompletedCallbackResult)
        assert "Domain=" not in _assert_single_cleared_login_cookie(result.response)

    @pytest.mark.asyncio
    async def test_clears_cookie_without_domain_when_root_domain_unset(self) -> None:
        """Test the cookie is cleared as host-only when there are no tenant subdomains, even with the flag on."""
        wristband_auth = _fixed_host_auth(application_authorization_requests_enabled=True)

        result = await _run_callback(wristband_auth, _callback_request(wristband_auth))

        assert isinstance(result, CompletedCallbackResult)
        assert "Domain=" not in _assert_single_cleared_login_cookie(result.response)

    @pytest.mark.asyncio
    async def test_no_set_cookie_when_no_login_state_cookie_present(self) -> None:
        """Test nothing is cleared when the request has no login state cookie, regardless of the domain logic."""
        wristband_auth = _subdomain_auth()
        request = _callback_request(wristband_auth, host=f"tenanta.{ROOT_DOMAIN}", with_login_state_cookie=False)

        result = await _run_callback(wristband_auth, request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert _set_cookie_headers(result.response) == []
