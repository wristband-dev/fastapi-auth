import asyncio
import re
from typing import Optional
from unittest.mock import AsyncMock, Mock, patch

import pytest

from wristband.fastapi_auth.config_resolver import (
    ConfigResolver,
    _derive_fallback_login_url,
    _derive_tenant_root_domain,
    _is_tenant_placeholder_position_valid,
)
from wristband.fastapi_auth.exceptions import WristbandError
from wristband.fastapi_auth.models import AuthConfig, SdkConfiguration


class TestConfigResolverValidation:
    """Test cases for ConfigResolver validation logic."""

    def test_validate_client_id_empty(self):
        """Test validation fails with empty client_id."""
        config = AuthConfig(
            client_id="",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with pytest.raises(TypeError, match="The \\[client_id\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_client_id_whitespace(self):
        """Test validation fails with whitespace-only client_id."""
        config = AuthConfig(
            client_id="   ",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with pytest.raises(TypeError, match="The \\[client_id\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_client_secret_empty(self):
        """Test validation fails with empty client_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with pytest.raises(TypeError, match="The \\[client_secret\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_client_secret_whitespace(self):
        """Test validation fails with whitespace-only client_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="   ",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with pytest.raises(TypeError, match="The \\[client_secret\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_login_state_secret_too_short(self):
        """Test validation fails with short login_state_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_state_secret="short",
        )

        with pytest.raises(
            TypeError, match="The \\[login_state_secret\\] config must have a value of at least 32 characters."
        ):
            ConfigResolver(config)

    def test_validate_login_state_secret_none_allowed(self):
        """Test validation passes with None login_state_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_state_secret=None,
        )

        # Should not raise
        ConfigResolver(config)

    def test_validate_vanity_domain_empty(self):
        """Test validation fails with empty vanity domain."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="",
        )

        with pytest.raises(TypeError, match="The \\[wristband_application_vanity_domain\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_vanity_domain_whitespace(self):
        """Test validation fails with whitespace-only vanity domain."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="   ",
        )

        with pytest.raises(TypeError, match="The \\[wristband_application_vanity_domain\\] config must have a value."):
            ConfigResolver(config)

    def test_validate_token_expiration_buffer_negative(self):
        """Test validation fails with negative token_expiration_buffer."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            token_expiration_buffer=-1,
        )

        with pytest.raises(
            TypeError, match="The \\[token_expiration_buffer\\] config must be greater than or equal to 0."
        ):
            ConfigResolver(config)

    def test_validate_auto_configure_disabled_missing_login_url(self):
        """Test validation fails when auto-configure disabled and login_url missing."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
        )

        with pytest.raises(
            TypeError, match="The \\[login_url\\] config must have a value when auto-configure is disabled."
        ):
            ConfigResolver(config)

    def test_validate_auto_configure_disabled_missing_redirect_uri(self):
        """Test validation fails when auto-configure disabled and redirect_uri missing."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://test.com/login",
        )

        with pytest.raises(
            TypeError, match="The \\[redirect_uri\\] config must have a value when auto-configure is disabled."
        ):
            ConfigResolver(config)

    def _strict_config(self, login_url: str, redirect_uri: str) -> AuthConfig:
        """Create an AuthConfig with auto-configure disabled and the given URLs."""
        return AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url=login_url,
            redirect_uri=redirect_uri,
        )

    def test_strict_requires_placeholder_in_redirect_uri_when_login_url_has_it(self):
        """Test redirect_uri must contain the placeholder when login_url contains it."""
        config = self._strict_config("https://{tenant_name}.test.com/login", "https://test.com/callback")

        with pytest.raises(
            TypeError,
            match=re.escape(
                'The [redirect_uri] must contain the "{tenant_name}" placeholder when the [login_url] contains it.'
            ),
        ):
            ConfigResolver(config)

    def test_strict_rejects_placeholder_in_redirect_uri_when_login_url_does_not_have_it(self):
        """Test redirect_uri cannot contain the placeholder when login_url doesn't contain it."""
        config = self._strict_config("https://test.com/login", "https://{tenant_name}.test.com/callback")

        with pytest.raises(
            TypeError,
            match=re.escape(
                'The [redirect_uri] cannot contain the "{tenant_name}" placeholder when the [login_url] '
                "does not contain it."
            ),
        ):
            ConfigResolver(config)

    @pytest.mark.parametrize(
        "login_url",
        [
            pytest.param("https://app.{tenant_name}.test.com/login", id="not_leftmost"),
            pytest.param("https://test.com/{tenant_name}/login", id="in_path"),
            pytest.param("https://{tenant_name}.test.com/{tenant_name}/login", id="twice"),
            pytest.param("https://{tenant_name}-app.test.com/login", id="not_whole_label"),
            pytest.param("{tenant_name}.test.com/login", id="missing_scheme"),
        ],
    )
    def test_strict_rejects_login_url_with_misplaced_placeholder(self, login_url):
        """Test login_url can only contain the placeholder once, as the leftmost part of its hostname."""
        config = self._strict_config(login_url, "https://{tenant_name}.test.com/callback")

        with pytest.raises(
            TypeError,
            match=re.escape(
                'The [login_url] can only contain the "{tenant_name}" placeholder once, '
                "as the leftmost part of its hostname."
            ),
        ):
            ConfigResolver(config)

    def test_strict_rejects_redirect_uri_with_misplaced_placeholder(self):
        """Test redirect_uri can only contain the placeholder once, as the leftmost part of its hostname."""
        config = self._strict_config("https://{tenant_name}.test.com/login", "https://test.com/{tenant_name}/callback")

        with pytest.raises(
            TypeError,
            match=re.escape(
                'The [redirect_uri] can only contain the "{tenant_name}" placeholder once, '
                "as the leftmost part of its hostname."
            ),
        ):
            ConfigResolver(config)

    @pytest.mark.parametrize(
        "login_url,redirect_uri",
        [
            pytest.param("https://{tenant_name}.test.com/login", "https://{tenant_name}.test.com/callback", id="both"),
            pytest.param(
                "http://{tenant_name}.localhost:6001/login", "http://{tenant_name}.localhost:6001/cb", id="port"
            ),
            pytest.param("https://test.com/login", "https://test.com/callback", id="neither"),
        ],
    )
    def test_strict_valid_configuration_passes(self, login_url, redirect_uri):
        """Test valid configurations with and without tenant subdomains pass validation."""
        resolver = ConfigResolver(self._strict_config(login_url, redirect_uri))
        assert resolver is not None

    def _partial_config(self, **overrides) -> AuthConfig:
        """Create an AuthConfig with auto-configure enabled and the given manual URL overrides."""
        return AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            **overrides,
        )

    def test_partial_requires_placeholder_in_manual_redirect_uri_when_manual_login_url_has_it(self):
        """Test a manual redirect_uri must contain the placeholder when the manual login_url contains it."""
        config = self._partial_config(
            login_url="https://{tenant_name}.test.com/login", redirect_uri="https://test.com/callback"
        )

        with pytest.raises(TypeError, match=re.escape("when the [login_url] contains it.")):
            ConfigResolver(config)

    def test_partial_rejects_placeholder_in_manual_redirect_uri_when_manual_login_url_does_not_have_it(self):
        """Test a manual redirect_uri cannot contain the placeholder when the manual login_url doesn't."""
        config = self._partial_config(
            login_url="https://test.com/login", redirect_uri="https://{tenant_name}.test.com/callback"
        )

        with pytest.raises(TypeError, match=re.escape("when the [login_url] does not contain it.")):
            ConfigResolver(config)

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"login_url": "https://{tenant_name}.test.com/login"}, id="only_login_url_with_placeholder"),
            pytest.param({"login_url": "https://test.com/login"}, id="only_login_url_without_placeholder"),
            pytest.param({"redirect_uri": "https://{tenant_name}.test.com/callback"}, id="only_redirect_uri"),
        ],
    )
    def test_partial_defers_placeholder_comparison_when_only_one_url_provided(self, overrides):
        """Test the placeholder comparison waits for the SDK config when only one URL is provided manually."""
        resolver = ConfigResolver(self._partial_config(**overrides))
        assert resolver is not None

    def test_partial_rejects_manual_login_url_with_misplaced_placeholder(self):
        """Test a manual login_url can only contain the placeholder as the leftmost part of its hostname."""
        config = self._partial_config(login_url="https://app.{tenant_name}.test.com/login")

        with pytest.raises(TypeError, match=re.escape("The [login_url] can only contain the")):
            ConfigResolver(config)

    def test_partial_rejects_manual_redirect_uri_with_misplaced_placeholder(self):
        """Test a manual redirect_uri can only contain the placeholder as the leftmost part of its hostname."""
        config = self._partial_config(redirect_uri="https://test.com/callback/{tenant_name}")

        with pytest.raises(TypeError, match=re.escape("The [redirect_uri] can only contain the")):
            ConfigResolver(config)

    def test_partial_valid_manual_overrides_pass(self):
        """Test valid manual URL overrides pass validation."""
        config = self._partial_config(
            login_url="https://{tenant_name}.test.com/login",
            redirect_uri="https://{tenant_name}.test.com/callback",
            login_state_secret="a" * 32,
        )

        resolver = ConfigResolver(config)
        assert resolver is not None


class TestConfigResolverStaticConfigurations:
    """Test cases for static configuration getters."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_state_secret="a" * 32,
            dangerously_disable_secure_cookies=True,
            scopes=["custom", "scopes"],
            token_expiration_buffer=120,
        )
        self.resolver = ConfigResolver(self.config)

    def test_get_client_id(self):
        """Test get_client_id returns correct value."""
        assert self.resolver.get_client_id() == "test_client"

    def test_get_client_secret(self):
        """Test get_client_secret returns correct value."""
        assert self.resolver.get_client_secret() == "test_secret"

    def test_get_login_state_secret_custom(self):
        """Test get_login_state_secret returns custom value when provided."""
        assert self.resolver.get_login_state_secret() == "a" * 32

    def test_get_login_state_secret_fallback(self):
        """Test get_login_state_secret falls back to client_secret."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_login_state_secret() == "test_secret"

    def test_get_wristband_application_vanity_domain(self):
        """Test get_wristband_application_vanity_domain returns correct value."""
        assert self.resolver.get_wristband_application_vanity_domain() == "test.wristband.dev"

    def test_get_dangerously_disable_secure_cookies_true(self):
        """Test get_dangerously_disable_secure_cookies when set to True."""
        assert self.resolver.get_dangerously_disable_secure_cookies() is True

    def test_get_dangerously_disable_secure_cookies_default(self):
        """Test get_dangerously_disable_secure_cookies default value."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_dangerously_disable_secure_cookies() is False

    def test_get_scopes_custom(self):
        """Test get_scopes returns custom scopes."""
        assert self.resolver.get_scopes() == ["custom", "scopes"]

    def test_get_scopes_default(self):
        """Test get_scopes returns default scopes."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_scopes() == ["openid", "offline_access", "email"]

    def test_get_scopes_empty_list_uses_default(self):
        """Test get_scopes uses defaults when empty list provided."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            scopes=[],
        )
        resolver = ConfigResolver(config)
        assert resolver.get_scopes() == ["openid", "offline_access", "email"]

    def test_get_auto_configure_enabled_default(self):
        """Test get_auto_configure_enabled returns default True."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_auto_configure_enabled() is True

    def test_get_auto_configure_enabled_false(self):
        """Test get_auto_configure_enabled when set to False."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://test.com/login",
            redirect_uri="https://test.com/callback",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_auto_configure_enabled() is False

    def test_get_token_expiration_buffer_custom(self):
        """Test get_token_expiration_buffer returns custom value."""
        assert self.resolver.get_token_expiration_buffer() == 120

    def test_get_token_expiration_buffer_default(self):
        """Test get_token_expiration_buffer returns default value."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = ConfigResolver(config)
        assert resolver.get_token_expiration_buffer() == 60

    def test_get_trust_proxy_headers_default(self):
        """Test get_trust_proxy_headers returns default False."""
        assert self.resolver.get_trust_proxy_headers() is False

    @pytest.mark.parametrize("trust_proxy_headers", [True, False])
    def test_get_trust_proxy_headers_when_set(self, trust_proxy_headers):
        """Test get_trust_proxy_headers returns the configured value."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            trust_proxy_headers=trust_proxy_headers,
        )
        resolver = ConfigResolver(config)
        assert resolver.get_trust_proxy_headers() is trust_proxy_headers


class TestConfigResolverDynamicConfigurations:
    """Test cases for dynamic configuration getters."""

    def setup_method(self):
        """Set up test fixtures."""
        self.valid_sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            custom_application_login_page_url="https://sdk.example.com/custom-login",
            is_application_custom_domain_active=True,
            login_url_tenant_domain_suffix=None,
        )

    @pytest.mark.asyncio
    async def test_manual_config_takes_precedence(self):
        """Test that manual configuration takes precedence over auto-config."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_name}.manual.com/login",  # Fixed: Added tenant token
            redirect_uri="https://{tenant_name}.manual.com/callback",  # Fixed: Added tenant token
            custom_application_login_page_url="https://manual.com/custom",
            is_application_custom_domain_active=False,
        )
        sdk_config = self.valid_sdk_config.model_copy(
            update={
                "login_url_tenant_domain_suffix": "sdk.example.com",
                "fallback_login_url": "https://sdk.example.com",
            }
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            assert await resolver.get_login_url() == "https://{tenant_name}.manual.com/login"
            assert await resolver.get_redirect_uri() == "https://{tenant_name}.manual.com/callback"
            assert await resolver.get_custom_application_login_page_url() == "https://manual.com/custom"
            assert await resolver.get_is_application_custom_domain_active() is False
            # Derived from the manual login_url rather than taken from the SDK config
            assert await resolver.get_parse_tenant_from_root_domain() == "manual.com"
            assert await resolver.get_fallback_login_url() == "https://manual.com/login"

    @pytest.mark.asyncio
    async def test_auto_config_fallback(self):
        """Test auto-configuration fallback when manual values not provided."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=True,
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            assert await resolver.get_login_url() == "https://sdk.example.com/login"
            assert await resolver.get_redirect_uri() == "https://sdk.example.com/callback"
            assert await resolver.get_custom_application_login_page_url() == "https://sdk.example.com/custom-login"
            assert await resolver.get_is_application_custom_domain_active() is True
            assert await resolver.get_parse_tenant_from_root_domain() == ""

    def _create_resolver(self, config: AuthConfig, sdk_config: SdkConfiguration) -> ConfigResolver:
        """Create a resolver whose SDK config fetch returns the given SdkConfiguration."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client
            return ConfigResolver(config)

    def _app_auth_sdk_config(self, enabled: bool, fallback_login_url: Optional[str]) -> SdkConfiguration:
        """Create an SdkConfiguration with the given app-level authorization request values."""
        return SdkConfiguration(
            application_authorization_requests_enabled=enabled,
            fallback_login_url=fallback_login_url,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

    @pytest.mark.asyncio
    async def test_app_auth_requests_enabled_manual_true(self):
        """Test that a manual True is returned for application_authorization_requests_enabled."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            application_authorization_requests_enabled=True,
        )
        resolver = self._create_resolver(config, self._app_auth_sdk_config(False, None))

        assert await resolver.get_application_authorization_requests_enabled() is True

    @pytest.mark.asyncio
    async def test_app_auth_requests_enabled_manual_false_overrides_sdk_true(self):
        """Test that a manual False is not overridden by an auto-configured True."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            application_authorization_requests_enabled=False,
        )
        resolver = self._create_resolver(config, self._app_auth_sdk_config(True, None))

        assert await resolver.get_application_authorization_requests_enabled() is False

    @pytest.mark.asyncio
    async def test_app_auth_requests_enabled_unset_uses_sdk_config(self):
        """Test that application_authorization_requests_enabled falls back to the SDK config when unset."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = self._create_resolver(config, self._app_auth_sdk_config(True, None))

        assert await resolver.get_application_authorization_requests_enabled() is True

    @pytest.mark.asyncio
    async def test_app_auth_requests_enabled_unset_with_auto_config_disabled(self):
        """Test that application_authorization_requests_enabled defaults to False when auto-config is disabled."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://manual.com/login",
            redirect_uri="https://manual.com/callback",
        )
        resolver = self._create_resolver(config, self._app_auth_sdk_config(True, None))

        assert await resolver.get_application_authorization_requests_enabled() is False

    def _tenant_sdk_config(self) -> SdkConfiguration:
        """Create an SdkConfiguration that uses tenant subdomains of sdk.example.com."""
        return SdkConfiguration(
            application_authorization_requests_enabled=True,
            fallback_login_url="https://sdk.example.com/login",
            login_url="https://{tenant_name}.sdk.example.com/login",
            login_url_tenant_domain_suffix="sdk.example.com",
            redirect_uri="https://{tenant_name}.sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

    def _manual_login_url_config(self, login_url: str) -> AuthConfig:
        """Create an AuthConfig with auto-configure enabled and a manual login_url (and matching redirect_uri)."""
        return AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url=login_url,
            redirect_uri=login_url.replace("/login", "/callback"),
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "login_url,expected_root_domain",
        [
            pytest.param("https://{tenant_name}.manual.com/auth/login", "manual.com", id="root_domain"),
            pytest.param("http://{tenant_name}.localhost:6001/auth/login", "localhost", id="port_removed"),
            pytest.param("https://{tenant_name}.Manual.COM/auth/login", "manual.com", id="lowercased"),
            pytest.param("https://manual.com/auth/login", "", id="no_placeholder"),
        ],
    )
    async def test_parse_tenant_from_root_domain_derived_from_manual_login_url(self, login_url, expected_root_domain):
        """Test the root domain is derived from the manual login_url over the SDK config's tenant domain suffix."""
        resolver = self._create_resolver(self._manual_login_url_config(login_url), self._tenant_sdk_config())

        assert await resolver.get_parse_tenant_from_root_domain() == expected_root_domain

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "login_url,expected_fallback_login_url",
        [
            pytest.param(
                "https://{tenant_name}.manual.com/auth/login?x=1", "https://manual.com/auth/login?x=1", id="root_domain"
            ),
            pytest.param(
                "http://{tenant_name}.localhost:6001/auth/login", "http://localhost:6001/auth/login", id="port_kept"
            ),
            pytest.param("https://manual.com/auth/login", "", id="no_placeholder"),
        ],
    )
    async def test_fallback_login_url_derived_from_manual_login_url(self, login_url, expected_fallback_login_url):
        """Test the fallback login URL is derived from the manual login_url over the SDK config's value."""
        resolver = self._create_resolver(self._manual_login_url_config(login_url), self._tenant_sdk_config())

        assert await resolver.get_fallback_login_url() == expected_fallback_login_url

    @pytest.mark.asyncio
    @pytest.mark.parametrize("login_url", [None, ""])
    async def test_derived_configs_use_sdk_config_without_manual_login_url(self, login_url):
        """Test both values come from the SDK config when login_url isn't provided manually."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url=login_url,
        )
        resolver = self._create_resolver(config, self._tenant_sdk_config())

        assert await resolver.get_parse_tenant_from_root_domain() == "sdk.example.com"
        assert await resolver.get_fallback_login_url() == "https://sdk.example.com/login"

    @pytest.mark.asyncio
    async def test_derived_configs_empty_when_auto_config_disabled_and_login_url_absent(self):
        """Test both values default to an empty string without a login_url or auto-configuration."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://{tenant_name}.manual.com/login",
            redirect_uri="https://{tenant_name}.manual.com/callback",
        )
        resolver = ConfigResolver(config)
        # Validation requires login_url when auto-configure is disabled, so remove it after construction.
        resolver.auth_config.login_url = None

        assert await resolver.get_parse_tenant_from_root_domain() == ""
        assert await resolver.get_fallback_login_url() == ""

    @pytest.mark.asyncio
    async def test_fallback_login_url_sdk_none_returns_empty_string(self):
        """Test that a null fallbackLoginUrl from the SDK config resolves to an empty string."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        resolver = self._create_resolver(config, self._app_auth_sdk_config(False, None))

        assert await resolver.get_fallback_login_url() == ""

    @pytest.mark.asyncio
    async def test_auto_config_disabled_fallbacks(self):
        """Test fallback values when auto-config is disabled."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://manual.com/login",
            redirect_uri="https://manual.com/callback",
        )
        resolver = ConfigResolver(config)

        assert await resolver.get_custom_application_login_page_url() == ""
        assert await resolver.get_is_application_custom_domain_active() is False
        assert await resolver.get_parse_tenant_from_root_domain() == ""
        assert await resolver.get_fallback_login_url() == ""

    @pytest.mark.asyncio
    async def test_auto_config_none_values(self):
        """Test handling of None values from auto-config."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            custom_application_login_page_url=None,
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix=None,
        )

        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=True,
        )

        with patch.object(ConfigResolver, "_load_sdk_config") as mock_load:
            mock_load.return_value = sdk_config
            resolver = ConfigResolver(config)

            assert await resolver.get_custom_application_login_page_url() == ""
            assert await resolver.get_is_application_custom_domain_active() is False
            assert await resolver.get_parse_tenant_from_root_domain() == ""


class TestConfigResolverSdkConfigFetching:
    """Test cases for SDK configuration fetching and caching."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        self.valid_sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=True,
        )

    @pytest.mark.asyncio
    async def test_sdk_config_caching(self):
        """Test that SDK config is cached after first fetch."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            # First call should fetch
            result1 = await resolver.get_login_url()
            assert result1 == "https://sdk.example.com/login"

            # Second call should use cache
            result2 = await resolver.get_redirect_uri()
            assert result2 == "https://sdk.example.com/callback"

            # Should only have called the API once
            mock_client.get_sdk_configuration.assert_called_once()

    @pytest.mark.asyncio
    async def test_sdk_config_fetch_success_passthrough(self):
        """Test that a successful fetch is returned as-is (no retry loop at this layer)."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            result = await resolver.get_login_url()
            assert result == "https://sdk.example.com/login"
            # Retrying on transient failures is handled one layer down by
            # WristbandApiClient (see with_retry() in retry.py), so a single
            # successful call here should only ever hit the API once.
            assert mock_client.get_sdk_configuration.call_count == 1

    @pytest.mark.asyncio
    async def test_sdk_config_fetch_failure_does_not_retry_at_this_layer(self):
        """Test that a fetch failure surfaces immediately without retrying here."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(side_effect=Exception("Persistent network error"))
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_login_url()

            assert exc_info.value.error == "sdk_config_fetch_failed"
            assert "Failed to fetch SDK configuration: Persistent network error" == exc_info.value.error_description
            # Retrying on transient failures is handled one layer down by
            # WristbandApiClient (see with_retry() in retry.py), so a failure here
            # should only hit the API once at this layer.
            assert mock_client.get_sdk_configuration.call_count == 1

    @pytest.mark.asyncio
    async def test_preload_sdk_config(self):
        """Test preload_sdk_config method."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            # Preload config
            await resolver.preload_sdk_config()
            assert mock_client.get_sdk_configuration.call_count == 1

            # Subsequent calls should use cache
            result = await resolver.get_login_url()
            assert result == "https://sdk.example.com/login"
            assert mock_client.get_sdk_configuration.call_count == 1

    @pytest.mark.asyncio
    async def test_task_deduplication(self):
        """Test that concurrent requests are deduplicated."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()

            # Add delay to simulate network request
            async def delayed_response():
                await asyncio.sleep(0.1)
                return self.valid_sdk_config

            mock_client.get_sdk_configuration = AsyncMock(side_effect=delayed_response)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            # Make concurrent requests
            tasks = [
                resolver.get_login_url(),
                resolver.get_redirect_uri(),
                resolver.get_custom_application_login_page_url(),
            ]

            results = await asyncio.gather(*tasks)

            # Should only have made one API call
            mock_client.get_sdk_configuration.assert_called_once()
            assert results[0] == "https://sdk.example.com/login"
            assert results[1] == "https://sdk.example.com/callback"

    @pytest.mark.asyncio
    async def test_error_retry_after_failure(self):
        """Test that errors reset the task to allow retry."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(
                side_effect=[
                    Exception("First error"),
                    self.valid_sdk_config,  # Success on retry
                ]
            )
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            # First attempt should fail immediately (no retry loop at this layer)
            with pytest.raises(WristbandError):
                await resolver.get_login_url()
            assert mock_client.get_sdk_configuration.call_count == 1

            # Second attempt should succeed
            result = await resolver.get_redirect_uri()
            assert result == "https://sdk.example.com/callback"
            assert mock_client.get_sdk_configuration.call_count == 2


class TestConfigResolverDynamicValidation:
    """Test cases for dynamic configuration validation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

    @pytest.mark.asyncio
    async def test_validate_missing_login_url_in_sdk_config(self):
        """Test validation fails when SDK config missing login_url."""
        invalid_sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=invalid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_login_url()

            assert exc_info.value.error == "sdk_config_invalid"
            assert "missing required field: login_url" in exc_info.value.error_description

    @pytest.mark.asyncio
    async def test_validate_missing_redirect_uri_in_sdk_config(self):
        """Test validation fails when SDK config missing redirect_uri."""
        invalid_sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="",
            is_application_custom_domain_active=False,
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=invalid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_redirect_uri()

            assert exc_info.value.error == "sdk_config_invalid"
            assert (
                "The [redirect_uri] could not be resolved. Provide it explicitly in your SDK config "
                "or ensure your Wristband OAuth2 Client has a single redirect URI configured."
                in exc_info.value.error_description
            )

    @pytest.mark.asyncio
    async def test_manual_redirect_uri_overrides_missing_sdk_redirect_uri(self):
        """Test that manual redirect_uri succeeds even when SDK config returns empty redirect_uri."""
        invalid_sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="",
            is_application_custom_domain_active=False,
        )

        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            redirect_uri="https://manual.example.com/callback",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=invalid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)
            result = await resolver.get_redirect_uri()
            assert result == "https://manual.example.com/callback"

    @pytest.mark.asyncio
    async def test_resolved_redirect_uri_requires_placeholder_when_manual_login_url_has_it(self):
        """Test the resolved redirect_uri must contain the placeholder when the manual login_url contains it."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_name}.test.com/login",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.preload_sdk_config()

            assert exc_info.value.error == "config_validation_error"
            assert exc_info.value.error_description == (
                'The resolved [redirect_uri] must contain the "{tenant_name}" placeholder when the resolved '
                "[login_url] contains it."
            )

    @pytest.mark.asyncio
    async def test_trusts_sdk_config_placeholders_when_both_urls_come_from_sdk(self):
        """Test placeholders aren't compared when both URLs come from the SDK Auto-Configuration Endpoint."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://{tenant_name}.sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            assert await resolver.get_login_url() == "https://{tenant_name}.sdk.example.com/login"
            assert await resolver.get_redirect_uri() == "https://sdk.example.com/callback"


class TestConfigResolverEdgeCases:
    """Test cases for edge cases and integration scenarios."""

    @pytest.mark.asyncio
    async def test_boolean_handling_for_custom_domain_active(self):
        """Test proper boolean handling for is_application_custom_domain_active."""
        # Test explicit False
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            is_application_custom_domain_active=False,
        )
        resolver = ConfigResolver(config)
        assert await resolver.get_is_application_custom_domain_active() is False

        # Test explicit True
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            is_application_custom_domain_active=True,
        )
        resolver = ConfigResolver(config)
        assert await resolver.get_is_application_custom_domain_active() is True

        # Test None with auto-config False
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)
            assert await resolver.get_is_application_custom_domain_active() is False

    @pytest.mark.asyncio
    async def test_empty_string_values(self):
        """Test handling of empty string values."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            custom_application_login_page_url=None,
            is_application_custom_domain_active=True,
        )

        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            custom_application_login_page_url="",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)
            assert await resolver.get_custom_application_login_page_url() == ""
            assert await resolver.get_parse_tenant_from_root_domain() == ""

    @pytest.mark.asyncio
    async def test_mixed_manual_and_auto_config(self):
        """Test mixed manual and auto-configuration."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            custom_application_login_page_url=None,
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix=None,
        )

        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://manual.example.com/login",  # Manual override
            # redirect_uri will come from auto-config
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            assert await resolver.get_login_url() == "https://manual.example.com/login"  # Manual
            assert await resolver.get_redirect_uri() == "https://sdk.example.com/callback"  # Auto-config
            assert await resolver.get_custom_application_login_page_url() == ""  # Auto-config empty
            assert await resolver.get_parse_tenant_from_root_domain() == ""  # Auto-config empty

    @pytest.mark.asyncio
    async def test_error_preserves_original_message(self):
        """Test that error messages preserve original exception details."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            original_error = Exception("Network connection failed")
            mock_client.get_sdk_configuration = AsyncMock(side_effect=original_error)
            mock_client_class.return_value = mock_client

            config = AuthConfig(
                client_id="test_client",
                client_secret="test_secret",
                wristband_application_vanity_domain="test.wristband.dev",
            )
            resolver = ConfigResolver(config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_login_url()

            assert "Network connection failed" in str(exc_info.value.error_description)

    @pytest.mark.asyncio
    async def test_validate_resolved_config_precedence(self):
        """Test that manual config values take precedence in validation."""
        # Manual config has correct tenant name token
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_name}.manual.com/login",
        )

        # SDK config would fail validation if used
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",  # No tenant token
            redirect_uri="https://{tenant_name}.sdk.com/callback",
            is_application_custom_domain_active=True,
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            # Should not raise validation error because manual login_url is used
            result = await resolver.get_login_url()
            assert result == "https://{tenant_name}.manual.com/login"

    def test_wristband_api_client_initialization(self):
        """Test that WristbandApiClient is initialized correctly."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            ConfigResolver(config)
            mock_client_class.assert_called_once_with("test.wristband.dev", "test_client", "test_secret")

    @pytest.mark.asyncio
    async def test_concurrent_preload_and_get_requests(self):
        """Test concurrent preload and getter requests."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()

            # Add delay to simulate network request
            async def delayed_response():
                await asyncio.sleep(0.1)
                return sdk_config

            mock_client.get_sdk_configuration = AsyncMock(side_effect=delayed_response)
            mock_client_class.return_value = mock_client

            config = AuthConfig(
                client_id="test_client",
                client_secret="test_secret",
                wristband_application_vanity_domain="test.wristband.dev",
            )
            resolver = ConfigResolver(config)

            # Start preload and getter concurrently
            tasks = [
                resolver.preload_sdk_config(),
                resolver.get_login_url(),
                resolver.get_redirect_uri(),
            ]

            results = await asyncio.gather(*tasks)

            # Should only make one API call
            mock_client.get_sdk_configuration.assert_called_once()

            # Preload returns None
            assert results[0] is None
            # Getters return values
            assert results[1] == "https://sdk.example.com/login"
            assert results[2] == "https://sdk.example.com/callback"

    def test_tenant_token_in_redirect_uri_without_parsing(self):
        """Test redirect_uri validation without parsing."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://test.com/login",
            redirect_uri="https://{tenant_name}.test.com/callback",
        )

        with pytest.raises(TypeError, match=re.escape('cannot contain the "{tenant_name}" placeholder')):
            ConfigResolver(config)

    @pytest.mark.asyncio
    async def test_resolved_manual_redirect_uri_requires_placeholder_when_sdk_login_url_has_it(self):
        """Test a manual redirect_uri must contain the placeholder when the auto-configured login_url contains it."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://{tenant_name}.sdk.example.com/login",
            redirect_uri="https://{tenant_name}.sdk.example.com/callback",
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix="sdk.example.com",
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            redirect_uri="https://test.com/callback",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.preload_sdk_config()

            assert "must contain the" in exc_info.value.error_description
            assert "redirect_uri" in exc_info.value.error_description

    @pytest.mark.asyncio
    async def test_resolved_manual_redirect_uri_rejects_placeholder_when_sdk_login_url_does_not_have_it(self):
        """Test a manual redirect_uri cannot contain the placeholder when the auto-configured login_url doesn't."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            redirect_uri="https://{tenant_name}.test.com/callback",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.preload_sdk_config()

            assert exc_info.value.error_description == (
                'The resolved [redirect_uri] cannot contain the "{tenant_name}" placeholder when the resolved '
                "[login_url] does not contain it."
            )

    @pytest.mark.asyncio
    async def test_resolved_manual_redirect_uri_and_sdk_login_url_both_with_placeholder_pass(self):
        """Test a manual redirect_uri and auto-configured login_url that both have the placeholder pass."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=False,
            login_url="https://{tenant_name}.sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            redirect_uri="https://{tenant_name}.test.com/callback",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            assert await resolver.get_redirect_uri() == "https://{tenant_name}.test.com/callback"
            assert await resolver.get_login_url() == "https://{tenant_name}.sdk.example.com/login"


class TestConfigResolverDerivedFallbackLoginUrl:
    """fallback_login_url is no longer configured, so app-level authorization requests need no extra config."""

    def test_strict_app_level_auth_with_placeholder_login_url_needs_no_fallback_config(self):
        """Test app-level auth with a tenant placeholder login_url passes validation and derives the fallback."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            application_authorization_requests_enabled=True,
            login_url="https://{tenant_name}.example.com/login",
            redirect_uri="https://{tenant_name}.example.com/callback",
        )

        resolver = ConfigResolver(config)

        assert asyncio.run(resolver.get_fallback_login_url()) == "https://example.com/login"

    @pytest.mark.asyncio
    async def test_resolved_app_level_auth_with_sdk_placeholder_login_url_needs_no_fallback(self):
        """Test an auto-configured placeholder login_url with app-level auth no longer requires a fallback."""
        sdk_config = SdkConfiguration(
            application_authorization_requests_enabled=True,
            fallback_login_url=None,
            login_url="https://{tenant_name}.sdk.example.com/login",
            redirect_uri="https://{tenant_name}.sdk.example.com/callback",
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix="sdk.example.com",
        )
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            await ConfigResolver(config).preload_sdk_config()


class TestDeriveFallbackLoginUrl:
    """Test cases for deriving the fallback login URL from the login URL."""

    @pytest.mark.parametrize(
        "login_url,expected",
        [
            pytest.param(
                "https://{tenant_name}.myapp.com/api/auth/login", "https://myapp.com/api/auth/login", id="leading"
            ),
            pytest.param(
                "http://{tenant_name}.localhost:6001/api/auth/login?x=1",
                "http://localhost:6001/api/auth/login?x=1",
                id="port_path_query",
            ),
            pytest.param(
                "https://{tenant_name}.business.myapp.com/login", "https://business.myapp.com/login", id="nested"
            ),
            pytest.param("https://myapp.com/api/auth/login", "", id="no_placeholder"),
            pytest.param("", "", id="empty"),
            pytest.param(None, "", id="none"),
        ],
    )
    def test_derive_fallback_login_url(self, login_url, expected):
        """Test the fallback login URL is the login URL with the leading placeholder removed."""
        assert _derive_fallback_login_url(login_url) == expected


class TestDeriveTenantRootDomain:
    """Test cases for deriving the tenant root domain from the login URL."""

    @pytest.mark.parametrize(
        "login_url,expected",
        [
            pytest.param("https://{tenant_name}.myapp.com/api/auth/login", "myapp.com", id="leading"),
            pytest.param("http://{tenant_name}.localhost:6001/api/auth/login", "localhost", id="port_excluded"),
            pytest.param("https://{tenant_name}.business.myapp.com/login", "business.myapp.com", id="nested"),
            pytest.param("https://myapp.com/api/auth/login", "", id="no_placeholder"),
            pytest.param("", "", id="empty"),
            pytest.param(None, "", id="none"),
        ],
    )
    def test_derive_tenant_root_domain(self, login_url, expected):
        """Test the root domain is the login URL's hostname with the leading placeholder removed."""
        assert _derive_tenant_root_domain(login_url) == expected


class TestIsTenantPlaceholderPositionValid:
    """Test cases for checking the position of the tenant placeholder."""

    @pytest.mark.parametrize(
        "url,expected",
        [
            pytest.param("https://myapp.com/api/auth/login", True, id="no_placeholder"),
            pytest.param("https://{tenant_name}.myapp.com/api/auth/login", True, id="leftmost_https"),
            pytest.param("http://{tenant_name}.localhost:6001/api/auth/login", True, id="leftmost_http"),
            pytest.param("https://app.{tenant_name}.myapp.com/api/auth/login", False, id="not_leftmost"),
            pytest.param("https://myapp.com/{tenant_name}/api/auth/login", False, id="in_path"),
            pytest.param("https://{tenant_name}/api/auth/login", False, id="entire_hostname"),
            pytest.param("https://{tenant_name}.myapp.com/{tenant_name}/login", False, id="more_than_once"),
        ],
    )
    def test_is_tenant_placeholder_position_valid(self, url, expected):
        """Test the placeholder is only valid once, as the leftmost part of the hostname."""
        assert _is_tenant_placeholder_position_valid(url) is expected
