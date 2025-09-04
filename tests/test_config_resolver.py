import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from wristband.fastapi_auth.config_resolver import ConfigResolver
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

    def test_validate_tenant_domain_token_missing_in_login_url(self):
        """Test validation fails when tenant domain token missing from login_url."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://test.com/login",
            redirect_uri="https://{tenant_domain}.test.com/callback",
            parse_tenant_from_root_domain="test.com",
        )

        with pytest.raises(TypeError, match='The \\[login_url\\] must contain the "\\{tenant_domain\\}" token'):
            ConfigResolver(config)

    def test_validate_tenant_domain_token_missing_in_redirect_uri(self):
        """Test validation fails when tenant domain token missing from redirect_uri."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://{tenant_domain}.test.com/login",
            redirect_uri="https://test.com/callback",
            parse_tenant_from_root_domain="test.com",
        )

        with pytest.raises(TypeError, match='The \\[redirect_uri\\] must contain the "\\{tenant_domain\\}" token'):
            ConfigResolver(config)

    def test_validate_tenant_domain_token_present_without_parsing(self):
        """Test validation fails when tenant domain token present but parsing disabled."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://{tenant_domain}.test.com/login",
            redirect_uri="https://test.com/callback",
        )

        with pytest.raises(TypeError, match='The \\[login_url\\] cannot contain the "\\{tenant_domain\\}" token'):
            ConfigResolver(config)

    def test_validate_partial_url_configs_with_auto_configure(self):
        """Test validation of partial URL configs when auto-configure is enabled."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=True,
            login_url="https://test.com/login",
            parse_tenant_from_root_domain="test.com",
        )

        with pytest.raises(TypeError, match='The \\[login_url\\] must contain the "\\{tenant_domain\\}" token'):
            ConfigResolver(config)

    def test_valid_configuration_passes(self):
        """Test that valid configuration passes validation."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            auto_configure_enabled=False,
            login_url="https://{tenant_domain}.test.com/login",
            redirect_uri="https://{tenant_domain}.test.com/callback",
            parse_tenant_from_root_domain="test.com",
            login_state_secret="a" * 32,
        )

        # Should not raise
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


class TestConfigResolverDynamicConfigurations:
    """Test cases for dynamic configuration getters."""

    def setup_method(self):
        """Set up test fixtures."""
        self.valid_sdk_config = SdkConfiguration(
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
            login_url="https://{tenant_domain}.manual.com/login",  # Fixed: Added tenant token
            redirect_uri="https://{tenant_domain}.manual.com/callback",  # Fixed: Added tenant token
            custom_application_login_page_url="https://manual.com/custom",
            is_application_custom_domain_active=False,
            parse_tenant_from_root_domain="manual.com",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=self.valid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            assert await resolver.get_login_url() == "https://{tenant_domain}.manual.com/login"
            assert await resolver.get_redirect_uri() == "https://{tenant_domain}.manual.com/callback"
            assert await resolver.get_custom_application_login_page_url() == "https://manual.com/custom"
            assert await resolver.get_is_application_custom_domain_active() is False
            assert await resolver.get_parse_tenant_from_root_domain() == "manual.com"

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

    @pytest.mark.asyncio
    async def test_auto_config_none_values(self):
        """Test handling of None values from auto-config."""
        sdk_config = SdkConfiguration(
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
    async def test_sdk_config_retry_logic(self):
        """Test retry logic for SDK config fetching."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            # Fail twice, succeed on third attempt
            mock_client.get_sdk_configuration = AsyncMock(
                side_effect=[Exception("Network error 1"), Exception("Network error 2"), self.valid_sdk_config]
            )
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            result = await resolver.get_login_url()
            assert result == "https://sdk.example.com/login"
            assert mock_client.get_sdk_configuration.call_count == 3

    @pytest.mark.asyncio
    async def test_sdk_config_fetch_failure_after_max_retries(self):
        """Test failure after maximum retry attempts."""
        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(side_effect=Exception("Persistent network error"))
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_login_url()

            assert exc_info.value.error == "sdk_config_fetch_failed"
            assert "Failed to fetch SDK configuration after 3 attempts" in exc_info.value.error_description
            assert mock_client.get_sdk_configuration.call_count == 3

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
                    Exception("Second error"),
                    Exception("Third error"),
                    self.valid_sdk_config,  # Success on retry
                ]
            )
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            # First attempt should fail after 3 retries
            with pytest.raises(WristbandError):
                await resolver.get_login_url()
            assert mock_client.get_sdk_configuration.call_count == 3

            # Second attempt should succeed
            result = await resolver.get_redirect_uri()
            assert result == "https://sdk.example.com/callback"
            assert mock_client.get_sdk_configuration.call_count == 4


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
            login_url="", redirect_uri="https://sdk.example.com/callback", is_application_custom_domain_active=False
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
            login_url="https://sdk.example.com/login", redirect_uri="", is_application_custom_domain_active=False
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=invalid_sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_redirect_uri()

            assert exc_info.value.error == "sdk_config_invalid"
            assert "missing required field: redirect_uri" in exc_info.value.error_description

    @pytest.mark.asyncio
    async def test_validate_resolved_config_with_tenant_domain(self):
        """Test validation of resolved config with tenant domain parsing."""
        # SDK config without tenant tokens
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

        # Manual config with tenant domain parsing
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            parse_tenant_from_root_domain="test.com",
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_login_url()

            assert exc_info.value.error == "config_validation_error"
            assert "must contain the" in exc_info.value.error_description
            assert "tenant_domain" in exc_info.value.error_description

    @pytest.mark.asyncio
    async def test_validate_resolved_config_without_tenant_domain(self):
        """Test validation fails when tenant token present but parsing disabled."""
        # SDK config with tenant tokens
        sdk_config = SdkConfiguration(
            login_url="https://{tenant_domain}.sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",
            is_application_custom_domain_active=False,
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(self.config)

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_login_url()

            assert exc_info.value.error == "config_validation_error"
            assert "cannot contain the" in exc_info.value.error_description
            assert "tenant_domain" in exc_info.value.error_description


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
            parse_tenant_from_root_domain="",
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
        # Manual config has correct tenant domain token
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_domain}.manual.com/login",
            parse_tenant_from_root_domain="manual.com",
        )

        # SDK config would fail validation if used
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",  # No tenant token
            redirect_uri="https://{tenant_domain}.sdk.com/callback",
            is_application_custom_domain_active=True,
        )

        with patch("wristband.fastapi_auth.config_resolver.WristbandApiClient") as mock_client_class:
            mock_client = Mock()
            mock_client.get_sdk_configuration = AsyncMock(return_value=sdk_config)
            mock_client_class.return_value = mock_client

            resolver = ConfigResolver(config)

            # Should not raise validation error because manual login_url is used
            result = await resolver.get_login_url()
            assert result == "https://{tenant_domain}.manual.com/login"

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
            redirect_uri="https://{tenant_domain}.test.com/callback",
        )

        with pytest.raises(TypeError, match='cannot contain the "\\{tenant_domain\\}" token'):
            ConfigResolver(config)

    def test_tenant_token_in_login_url_partial_validation(self):
        """Test partial validation login_url without parsing."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            login_url="https://{tenant_domain}.test.com/login",
        )

        with pytest.raises(TypeError, match='cannot contain the "\\{tenant_domain\\}" token'):
            ConfigResolver(config)

    def test_tenant_token_missing_in_redirect_uri_partial_validation(self):
        """Test partial validation when redirect_uri missing tenant token but parsing enabled."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            redirect_uri="https://test.com/callback",  # no tenant token
            parse_tenant_from_root_domain="test.com",  # parsing enabled
        )

        with pytest.raises(TypeError, match='must contain the "\\{tenant_domain\\}" token'):
            ConfigResolver(config)

    def test_redirect_uri_token_present_without_parsing(self):
        """Test redirect_uri has tenant token but parsing disabled."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            wristband_application_vanity_domain="test.wristband.dev",
            redirect_uri="https://{tenant_domain}.test.com/callback",  # has tenant token
            # parse_tenant_from_root_domain is None/empty - parsing disabled
        )

        with pytest.raises(TypeError, match='cannot contain the "\\{tenant_domain\\}" token'):
            ConfigResolver(config)

    @pytest.mark.asyncio
    async def test_validate_resolved_redirect_uri_missing_token_lines(self):
        """Test resolved config validation when redirect_uri missing tenant token."""
        sdk_config = SdkConfiguration(
            login_url="https://{tenant_domain}.sdk.example.com/login",
            redirect_uri="https://sdk.example.com/callback",  # missing tenant token
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix="example.com",  # This enables tenant parsing
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

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_redirect_uri()  # This should trigger the validation

            assert "must contain the" in exc_info.value.error_description
            assert "redirect_uri" in exc_info.value.error_description

    @pytest.mark.asyncio
    async def test_validate_resolved_redirect_uri_has_token_without_parsing(self):
        """Test resolved config validation when redirect_uri has token but parsing disabled."""
        sdk_config = SdkConfiguration(
            login_url="https://sdk.example.com/login",  # no tenant token
            redirect_uri="https://{tenant_domain}.sdk.example.com/callback",  # has tenant token
            is_application_custom_domain_active=False,
            login_url_tenant_domain_suffix=None,  # No tenant parsing (falsy)
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

            with pytest.raises(WristbandError) as exc_info:
                await resolver.get_redirect_uri()

            assert "cannot contain the" in exc_info.value.error_description
            assert "redirect_uri" in exc_info.value.error_description
