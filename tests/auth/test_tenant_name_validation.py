from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request, resolve_test_redirect_url
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.exceptions import WristbandError
from wristband.fastapi_auth.models import AuthConfig, LoginConfig, LogoutConfig

VANITY_DOMAIN = "yourapp-yourcompany.us.wristband.dev"
APP_LEVEL_LOGIN_URL = f"https://{VANITY_DOMAIN}/login?client_id=test_client_id"

# Values that aren't a single DNS label. Each one would change the host of a URL like https://{tenant_name}-{vanity}.
UNSAFE_TENANT_NAMES = [
    "evil.com#",
    "evil.com",
    "evil.com/",
    "evil.com?",
    "user@evil.com",
    "evil.com:443",
    "-customer01",
    "customer01-",
    "customer01\n",
    "customer 01",
    "a" * 64,
    "K",  # Kelvin sign, which matches [a-z] under re.IGNORECASE
]

UNSAFE_DOMAIN_NAMES = [
    "evil.com#",
    "evil.com/path",
    "evil.com:443",
    "user@evil.com",
    "localhost",
    ".evil.com",
    "evil.com.",
    "evil..com",
    "tenant.example.com\n",
]


class TestTenantNameValidation:
    """Tenant names and tenant custom domains that aren't valid DNS names are ignored, as if not passed."""

    def setup_method(self) -> None:
        self.wristband_auth = WristbandAuth(
            AuthConfig(
                auto_configure_enabled=False,
                client_id="test_client_id",
                client_secret="test_client_secret",
                login_state_secret=TEST_LOGIN_STATE_SECRET,
                login_url="https://app.example.com/auth/login",
                redirect_uri="https://app.example.com/auth/callback",
                wristband_application_vanity_domain=VANITY_DOMAIN,
            )
        )

    # ---------------------------------------------------------------------------------------------
    # LOGIN
    # ---------------------------------------------------------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tenant_name", UNSAFE_TENANT_NAMES)
    async def test_login_ignores_unsafe_tenant_name_param(self, tenant_name: str) -> None:
        request = create_mock_request("https://app.example.com/auth/login", query_params={"tenant_name": tenant_name})

        response = await self.wristband_auth.login(request)

        assert response.headers["location"] == APP_LEVEL_LOGIN_URL

    @pytest.mark.asyncio
    async def test_login_open_redirect_link_stays_on_wristband(self) -> None:
        """The link from the discrepancy report: https://yourapp.io/auth/login?tenant_name=evil.com%23"""
        request = create_mock_request("https://app.example.com/auth/login", query_params={"tenant_name": "evil.com#"})

        response = await self.wristband_auth.login(request)

        assert urlparse(response.headers["location"]).hostname == VANITY_DOMAIN

    @pytest.mark.asyncio
    async def test_login_accepts_valid_tenant_name_param(self) -> None:
        request = create_mock_request("https://app.example.com/auth/login", query_params={"tenant_name": "Customer-01"})

        response = await self.wristband_auth.login(request)

        assert urlparse(response.headers["location"]).hostname == f"Customer-01-{VANITY_DOMAIN}".lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tenant_name", UNSAFE_TENANT_NAMES)
    async def test_login_ignores_unsafe_default_tenant_name(self, tenant_name: str) -> None:
        request = create_mock_request("https://app.example.com/auth/login")

        response = await self.wristband_auth.login(request, LoginConfig(default_tenant_name=tenant_name))

        assert response.headers["location"] == APP_LEVEL_LOGIN_URL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("domain", UNSAFE_DOMAIN_NAMES)
    async def test_login_ignores_unsafe_default_tenant_custom_domain(self, domain: str) -> None:
        request = create_mock_request("https://app.example.com/auth/login")

        response = await self.wristband_auth.login(request, LoginConfig(default_tenant_custom_domain=domain))

        assert response.headers["location"] == APP_LEVEL_LOGIN_URL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("domain", UNSAFE_DOMAIN_NAMES)
    async def test_login_skips_custom_domain_api_call_for_unsafe_param(self, domain: str) -> None:
        request = create_mock_request(
            "https://app.example.com/auth/login", query_params={"tenant_custom_domain": domain}
        )

        with patch.object(
            self.wristband_auth._wristband_api, "validate_tenant_custom_domain", new_callable=AsyncMock
        ) as mock_validate:
            response = await self.wristband_auth.login(request)

        mock_validate.assert_not_called()
        assert response.headers["location"] == APP_LEVEL_LOGIN_URL

    @pytest.mark.asyncio
    async def test_login_validates_safe_custom_domain_param_with_api(self) -> None:
        request = create_mock_request(
            "https://app.example.com/auth/login", query_params={"tenant_custom_domain": "auth.customer01.com"}
        )

        with patch.object(
            self.wristband_auth._wristband_api,
            "validate_tenant_custom_domain",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_validate:
            response = await self.wristband_auth.login(request)

        mock_validate.assert_called_once_with("auth.customer01.com")
        assert urlparse(response.headers["location"]).hostname == "auth.customer01.com"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("subdomain", ["-customer01", "customer01-", "a" * 64])
    async def test_login_ignores_unsafe_tenant_subdomain(self, subdomain: str) -> None:
        request = create_mock_request(
            f"https://{subdomain}.app.example.com/auth/login", host=f"{subdomain}.app.example.com"
        )

        with patch.object(
            self.wristband_auth._config_resolver,
            "get_parse_tenant_from_root_domain",
            new_callable=AsyncMock,
            return_value="app.example.com",
        ):
            response = await self.wristband_auth.login(request)

        assert response.headers["location"] == APP_LEVEL_LOGIN_URL

    # ---------------------------------------------------------------------------------------------
    # LOGOUT
    # ---------------------------------------------------------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tenant_name", UNSAFE_TENANT_NAMES)
    async def test_logout_ignores_unsafe_tenant_name_param(self, tenant_name: str) -> None:
        request = create_mock_request("https://app.example.com/auth/logout", query_params={"tenant_name": tenant_name})

        response = await self.wristband_auth.logout(request)

        assert response.headers["location"] == APP_LEVEL_LOGIN_URL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tenant_name", UNSAFE_TENANT_NAMES)
    async def test_logout_ignores_unsafe_config_tenant_name(self, tenant_name: str) -> None:
        request = create_mock_request("https://app.example.com/auth/logout")

        response = await self.wristband_auth.logout(request, LogoutConfig(tenant_name=tenant_name))

        assert response.headers["location"] == APP_LEVEL_LOGIN_URL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("domain", UNSAFE_DOMAIN_NAMES)
    async def test_logout_ignores_unsafe_config_tenant_custom_domain(self, domain: str) -> None:
        request = create_mock_request("https://app.example.com/auth/logout")

        response = await self.wristband_auth.logout(request, LogoutConfig(tenant_custom_domain=domain))

        assert response.headers["location"] == APP_LEVEL_LOGIN_URL

    @pytest.mark.asyncio
    async def test_logout_falls_through_unsafe_config_tenant_name_to_next_priority(self) -> None:
        request = create_mock_request("https://app.example.com/auth/logout", query_params={"tenant_name": "customer01"})

        response = await self.wristband_auth.logout(request, LogoutConfig(tenant_name="evil.com#"))

        assert urlparse(response.headers["location"]).hostname == f"customer01-{VANITY_DOMAIN}"

    # ---------------------------------------------------------------------------------------------
    # CALLBACK
    # ---------------------------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_callback_treats_unsafe_tenant_name_as_missing(self) -> None:
        request = create_mock_request(
            "https://app.example.com/auth/callback",
            query_params={"state": "test_state", "code": "code", "tenant_name": "evil.com#"},
        )

        with pytest.raises(WristbandError) as exc_info:
            await self.wristband_auth.callback(request, resolve_test_redirect_url)

        assert exc_info.value.error == "missing_tenant_name"

    @pytest.mark.asyncio
    async def test_callback_drops_unsafe_tenant_custom_domain_from_login_redirect(self) -> None:
        request = create_mock_request(
            "https://app.example.com/auth/callback",
            query_params={"state": "test_state", "tenant_name": "customer01", "tenant_custom_domain": "evil.com#"},
        )

        with patch.object(
            self.wristband_auth._wristband_api, "validate_tenant_custom_domain", new_callable=AsyncMock
        ) as mock_validate:
            result = await self.wristband_auth.callback(request, resolve_test_redirect_url)

        mock_validate.assert_not_called()
        location = result.response.headers["location"]
        assert parse_qs(urlparse(location).query) == {"tenant_name": ["customer01"]}
