import time
from typing import List, Optional
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Response

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import (
    AuthConfig,
    CallbackFailureReason,
    CallbackResultType,
    CompletedCallbackResult,
    LoginConfig,
    LoginState,
    LogoutConfig,
    RedirectRequiredCallbackResult,
    UserInfo,
    WristbandTokenResponse,
)

VANITY_DOMAIN = "auth.example.com"
ROOT_DOMAIN = "business.invotastic.com"


def create_auth(
    use_tenant_subdomains: bool = True,
    application_authorization_requests_enabled: Optional[bool] = True,
    custom_application_login_page_url: Optional[str] = None,
) -> WristbandAuth:
    host = f"{{tenant_name}}.{ROOT_DOMAIN}" if use_tenant_subdomains else ROOT_DOMAIN
    return WristbandAuth(
        AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            login_url=f"https://{host}/api/auth/login",
            redirect_uri=f"https://{host}/api/auth/callback",
            wristband_application_vanity_domain=VANITY_DOMAIN,
            application_authorization_requests_enabled=application_authorization_requests_enabled,
            custom_application_login_page_url=custom_application_login_page_url,
            auto_configure_enabled=False,
        )
    )


def get_login_cookie_headers(response: Response) -> List[str]:
    return [
        value.decode("latin-1")
        for key, value in response.raw_headers
        if key.decode("latin-1").lower() == "set-cookie" and "login#" in value.decode("latin-1")
    ]


def encrypt_cookie(auth: WristbandAuth, return_url: Optional[str] = None, state: str = "test_state") -> dict:
    login_state = LoginState(
        state=state,
        code_verifier="test_verifier",
        redirect_uri=f"https://devs4you.{ROOT_DOMAIN}/api/auth/callback",
        return_url=return_url,
        custom_state=None,
    )
    return {f"login#{state}#1640995200000": auth._encrypt_login_state(login_state)}


MOCK_TOKENS = WristbandTokenResponse(
    access_token="access_token",
    id_token="id_token",
    expires_in=3600,
    refresh_token="refresh_token",
    token_type="Bearer",
    scope="openid offline_access email",
)
MOCK_USERINFO = UserInfo(user_id="user", tenant_id="tenant", application_id="app", identity_provider_name="Wristband")


class TestLoginApplicationLevelAuthorizationRequests:
    @pytest.mark.asyncio
    async def test_unresolved_tenant_redirects_to_app_level_authorize_endpoint(self) -> None:
        auth = create_auth()
        request = create_mock_request(
            f"https://{ROOT_DOMAIN}/api/auth/login",
            query_params={"return_url": "/settings", "login_hint": "user@example.com"},
        )

        response = await auth.login(request, LoginConfig(custom_state={"flow": "signup"}))

        location = urlparse(response.headers["location"])
        query = parse_qs(location.query)
        assert f"{location.scheme}://{location.netloc}{location.path}" == (
            f"https://{VANITY_DOMAIN}/api/v1/oauth2/authorize"
        )
        assert query["client_id"] == ["test_client_id"]
        assert query["redirect_uri"] == [f"https://{{tenant_name}}.{ROOT_DOMAIN}/api/auth/callback"]
        assert query["login_hint"] == ["user@example.com"]
        assert query["code_challenge_method"] == ["S256"]

        # The login state cookie is set on the root domain so the tenant subdomain callback can read it.
        cookies = get_login_cookie_headers(response)
        assert len(cookies) == 1
        assert f"Domain=.{ROOT_DOMAIN}" in cookies[0]
        assert cookies[0].startswith(f"login#{query['state'][0]}#")

        # The return URL and custom state are preserved in the login state cookie.
        cookie_value = cookies[0].split("=", 1)[1].split(";")[0]
        login_state = auth._decrypt_login_state(cookie_value)
        assert login_state is not None
        assert login_state.return_url == "/settings"
        assert login_state.custom_state == {"flow": "signup"}

    @pytest.mark.asyncio
    async def test_unresolved_tenant_without_tenant_subdomains_sets_host_only_cookie(self) -> None:
        auth = create_auth(use_tenant_subdomains=False)
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/login")

        response = await auth.login(request)

        assert response.headers["location"].startswith(f"https://{VANITY_DOMAIN}/api/v1/oauth2/authorize?")
        cookies = get_login_cookie_headers(response)
        assert len(cookies) == 1
        assert "Domain=" not in cookies[0]

    @pytest.mark.asyncio
    async def test_custom_application_login_page_url_has_no_effect_when_enabled(self) -> None:
        auth = create_auth(custom_application_login_page_url="https://custom.example.com/login")
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/login")

        response = await auth.login(request)

        assert response.headers["location"].startswith(f"https://{VANITY_DOMAIN}/api/v1/oauth2/authorize?")

    @pytest.mark.asyncio
    async def test_resolved_tenant_uses_tenant_level_flow_with_root_domain_cookie(self) -> None:
        auth = create_auth()
        request = create_mock_request(f"https://devs4you.{ROOT_DOMAIN}/api/auth/login")

        response = await auth.login(request)

        assert response.headers["location"].startswith(f"https://devs4you-{VANITY_DOMAIN}/api/v1/oauth2/authorize?")
        cookies = get_login_cookie_headers(response)
        assert len(cookies) == 1
        assert f"Domain=.{ROOT_DOMAIN}" in cookies[0]

    @pytest.mark.asyncio
    async def test_resolved_tenant_sets_host_only_cookie_when_disabled(self) -> None:
        auth = create_auth(application_authorization_requests_enabled=False)
        request = create_mock_request(f"https://devs4you.{ROOT_DOMAIN}/api/auth/login")

        response = await auth.login(request)

        cookies = get_login_cookie_headers(response)
        assert len(cookies) == 1
        assert "Domain=" not in cookies[0]

    @pytest.mark.asyncio
    async def test_stale_login_state_cookies_are_cleared_on_the_root_domain(self) -> None:
        auth = create_auth()
        existing = {
            "login#a#1000": "x",
            "login#b#2000": "y",
            "login#c#3000": "z",
        }
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/login", cookies=existing)

        response = await auth.login(request)

        cookies = get_login_cookie_headers(response)
        cleared = [c for c in cookies if c.startswith("login#a#1000=")]
        assert len(cleared) == 1
        assert f"Domain=.{ROOT_DOMAIN}" in cleared[0]
        assert "Max-Age=0" in cleared[0]

    @pytest.mark.asyncio
    async def test_unresolved_tenant_redirects_to_app_login_page_with_return_url_when_disabled(self) -> None:
        auth = create_auth(application_authorization_requests_enabled=False)
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/login", query_params={"return_url": "/a?b=c"})

        response = await auth.login(request)

        assert (
            response.headers["location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id&state=/a%3Fb%3Dc"
        )
        assert get_login_cookie_headers(response) == []


class TestCallbackApplicationLevelAuthorizationRequests:
    async def _run_callback(self, auth: WristbandAuth, return_url: Optional[str], host: str, scheme: str = "https"):
        request = create_mock_request(
            f"{scheme}://{host}/api/auth/callback",
            query_params={"code": "code", "state": "test_state"},
            cookies=encrypt_cookie(auth, return_url),
        )
        with (
            patch.object(auth._wristband_api, "get_tokens", return_value=MOCK_TOKENS),
            patch.object(auth._wristband_api, "get_userinfo", return_value=MOCK_USERINFO),
        ):
            return await auth.callback(request)

    @pytest.mark.asyncio
    async def test_root_domain_return_url_is_rewritten_to_tenant_subdomain(self) -> None:
        auth = create_auth()
        result = await self._run_callback(auth, f"https://{ROOT_DOMAIN}/dashboard?tab=1", f"devs4you.{ROOT_DOMAIN}")
        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.return_url == f"https://devs4you.{ROOT_DOMAIN}/dashboard?tab=1"

    @pytest.mark.asyncio
    async def test_root_domain_return_url_is_not_rewritten_when_disabled(self) -> None:
        auth = create_auth(application_authorization_requests_enabled=False)
        result = await self._run_callback(auth, f"https://{ROOT_DOMAIN}/dashboard", f"devs4you.{ROOT_DOMAIN}")
        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.return_url == f"https://{ROOT_DOMAIN}/dashboard"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "return_url,expected",
        [
            ("/settings?tab=billing", "/settings?tab=billing"),
            (f"https://devs4you.{ROOT_DOMAIN}/dashboard", f"https://devs4you.{ROOT_DOMAIN}/dashboard"),
            ("https://evil.com/phish", None),
            ("//evil.com/phish", None),
            (f"https://other.{ROOT_DOMAIN}/dashboard", None),
            (f"http://devs4you.{ROOT_DOMAIN}/dashboard", None),
        ],
    )
    async def test_return_url_validation(self, return_url, expected) -> None:
        auth = create_auth()
        result = await self._run_callback(auth, return_url, f"devs4you.{ROOT_DOMAIN}")
        assert isinstance(result, CompletedCallbackResult)
        assert result.callback_data.return_url == expected

    @pytest.mark.asyncio
    async def test_undecryptable_cookie_returns_invalid_login_state(self) -> None:
        auth = create_auth()
        other_auth = WristbandAuth(
            AuthConfig(
                client_id="test_client_id",
                client_secret="test_client_secret",
                login_state_secret="z" * 32,
                login_url=f"https://{{tenant_name}}.{ROOT_DOMAIN}/api/auth/login",
                redirect_uri=f"https://{{tenant_name}}.{ROOT_DOMAIN}/api/auth/callback",
                wristband_application_vanity_domain=VANITY_DOMAIN,
                auto_configure_enabled=False,
            )
        )
        request = create_mock_request(
            f"https://devs4you.{ROOT_DOMAIN}/api/auth/callback",
            query_params={"code": "code", "state": "test_state"},
            cookies=encrypt_cookie(other_auth),
        )

        result = await auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.reason == CallbackFailureReason.INVALID_LOGIN_STATE
        assert result.redirect_url == f"https://devs4you.{ROOT_DOMAIN}/api/auth/login"

    @pytest.mark.asyncio
    async def test_expired_cookie_returns_invalid_login_state(self) -> None:
        auth = create_auth()
        cookies = encrypt_cookie(auth)
        request = create_mock_request(
            f"https://devs4you.{ROOT_DOMAIN}/api/auth/callback",
            query_params={"code": "code", "state": "test_state"},
            cookies=cookies,
        )

        with patch("cryptography.fernet.time.time", return_value=time.time() + 3600 + 61):
            result = await auth.callback(request)

        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.INVALID_LOGIN_STATE

    @pytest.mark.asyncio
    async def test_create_callback_response_clears_cookie_on_root_domain(self) -> None:
        auth = create_auth()
        request = create_mock_request(
            f"https://devs4you.{ROOT_DOMAIN}/api/auth/callback",
            query_params={"state": "test_state"},
            cookies={"login#test_state#1640995200000": "value"},
        )

        response = await auth.create_callback_response(request, "/home")

        cookies = get_login_cookie_headers(response)
        assert len(cookies) == 1
        assert f"Domain=.{ROOT_DOMAIN}" in cookies[0]
        assert "Max-Age=0" in cookies[0]


class TestLogoutApplicationLevelAuthorizationRequests:
    @pytest.mark.asyncio
    async def test_unresolved_tenant_redirects_to_login_url_without_tenant_subdomain(self) -> None:
        auth = create_auth()
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/logout")

        response = await auth.logout(request)

        assert response.headers["location"] == f"https://{ROOT_DOMAIN}/api/auth/login"

    @pytest.mark.asyncio
    async def test_unresolved_tenant_redirects_to_login_url_without_tenant_subdomains(self) -> None:
        auth = create_auth(use_tenant_subdomains=False)
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/logout")

        response = await auth.logout(request)

        assert response.headers["location"] == f"https://{ROOT_DOMAIN}/api/auth/login"

    @pytest.mark.asyncio
    async def test_redirect_url_takes_precedence_over_app_level_fallback(self) -> None:
        auth = create_auth()
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/logout")

        response = await auth.logout(request, LogoutConfig(redirect_url="https://redirect.example.com"))

        assert response.headers["location"] == "https://redirect.example.com"

    @pytest.mark.asyncio
    async def test_custom_application_login_page_url_has_no_effect_when_enabled(self) -> None:
        auth = create_auth(custom_application_login_page_url="https://custom.example.com/login")
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/logout")

        response = await auth.logout(request)

        assert response.headers["location"] == f"https://{ROOT_DOMAIN}/api/auth/login"

    @pytest.mark.asyncio
    async def test_unresolved_tenant_redirects_to_app_login_page_when_disabled(self) -> None:
        auth = create_auth(application_authorization_requests_enabled=False)
        request = create_mock_request(f"https://{ROOT_DOMAIN}/api/auth/logout")

        response = await auth.logout(request)

        assert response.headers["location"] == f"https://{VANITY_DOMAIN}/login?client_id=test_client_id"
