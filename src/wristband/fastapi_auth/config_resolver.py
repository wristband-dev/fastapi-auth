import asyncio
from typing import Optional

from .client import WristbandApiClient
from .exceptions import WristbandError
from .models import AuthConfig, SdkConfiguration
from .utils import (
    TENANT_PLACEHOLDER_MSG,
    TENANT_PLACEHOLDER_PATTERN,
    derive_fallback_login_url,
    derive_tenant_root_domain,
    is_tenant_placeholder_position_valid,
)

_default_scopes = ["openid", "offline_access", "email"]


class ConfigResolver:
    """
    Resolves and validates Wristband authentication configuration, supporting both
    manual configuration and auto-configuration via the Wristband SDK configuration endpoint.
    """

    def __init__(self, auth_config: AuthConfig) -> None:
        self.auth_config = auth_config
        self.sdk_config_cache: Optional[SdkConfiguration] = None
        self.config_task: Optional[asyncio.Task[SdkConfiguration]] = None
        self._config_lock = asyncio.Lock()

        # Always validate required configs
        self._validate_required_auth_configs()

        if self.get_auto_configure_enabled():
            # Only validate manually provided values when auto-configure is enabled
            self._validate_partial_url_auth_configs()
        else:
            # Validate all URL configs if auto-configure is disabled
            self._validate_strict_url_auth_configs()

        self.wristband_api = WristbandApiClient(
            auth_config.wristband_application_vanity_domain,
            auth_config.client_id,
            auth_config.client_secret,
        )

    async def preload_sdk_config(self) -> None:
        """Preload SDK configuration (eager loading)."""
        await self._load_sdk_config()

    async def _load_sdk_config(self) -> SdkConfiguration:
        """Load SDK configuration with caching and concurrent request handling."""
        # Return cached config if available
        if self.sdk_config_cache:
            return self.sdk_config_cache

        async with self._config_lock:
            # Return existing task if already fetching
            if self.config_task:
                return await self.config_task

            try:
                self.config_task = asyncio.create_task(self._fetch_sdk_configuration())
                self.sdk_config_cache = await self.config_task
                self._validate_all_dynamic_configs(self.sdk_config_cache)
                return self.sdk_config_cache
            except Exception:
                # Reset task on error so retry is possible
                self.config_task = None
                raise

    async def _fetch_sdk_configuration(self) -> SdkConfiguration:
        """
        Fetch SDK configuration.

        Retrying on transient failures (5xx errors, network errors) is already handled
        one layer down by WristbandApiClient -- see with_retry() in retry.py. By the
        time an error surfaces here, retries (if any applied) have already been exhausted.
        """
        try:
            return await self.wristband_api.get_sdk_configuration()
        except Exception as error:
            raise WristbandError("sdk_config_fetch_failed", f"Failed to fetch SDK configuration: {str(error)}")

    def _validate_required_auth_configs(self) -> None:
        """Validate required authentication configuration fields."""
        if not self.auth_config.client_id or not self.auth_config.client_id.strip():
            raise TypeError("The [client_id] config must have a value.")
        if not self.auth_config.client_secret or not self.auth_config.client_secret.strip():
            raise TypeError("The [client_secret] config must have a value.")
        if self.auth_config.login_state_secret and len(self.auth_config.login_state_secret) < 32:
            raise TypeError("The [login_state_secret] config must have a value of at least 32 characters.")
        if (
            not self.auth_config.wristband_application_vanity_domain
            or not self.auth_config.wristband_application_vanity_domain.strip()
        ):
            raise TypeError("The [wristband_application_vanity_domain] config must have a value.")
        if self.auth_config.token_expiration_buffer < 0:
            raise TypeError("The [token_expiration_buffer] config must be greater than or equal to 0.")

    def _validate_tenant_placeholder_position(self, config_name: str, url: str) -> None:
        """Validate that a URL only contains the {tenant_name} placeholder once, as the leftmost part of its host."""
        if not is_tenant_placeholder_position_valid(url):
            raise TypeError(
                f"The [{config_name}] can only contain the {TENANT_PLACEHOLDER_MSG} once, "
                "as the leftmost part of its hostname."
            )

    def _validate_matching_tenant_placeholders(self, login_url: str, redirect_uri: str) -> None:
        """Validate that either both URLs contain the {tenant_name} placeholder or neither does."""
        login_url_has_placeholder = bool(TENANT_PLACEHOLDER_PATTERN.search(login_url))
        redirect_uri_has_placeholder = bool(TENANT_PLACEHOLDER_PATTERN.search(redirect_uri))
        if login_url_has_placeholder and not redirect_uri_has_placeholder:
            raise TypeError(
                f"The [redirect_uri] must contain the {TENANT_PLACEHOLDER_MSG} when the [login_url] contains it."
            )
        if not login_url_has_placeholder and redirect_uri_has_placeholder:
            raise TypeError(
                f"The [redirect_uri] cannot contain the {TENANT_PLACEHOLDER_MSG} when the [login_url] "
                "does not contain it."
            )

    def _validate_strict_url_auth_configs(self) -> None:
        """
        Validate URL configuration when auto-configure is disabled.

        With auto-configure disabled, the SDK has no other source for [login_url] and [redirect_uri], so both are
        required. Each URL can only contain the {tenant_name} placeholder once, as the leftmost part of its hostname,
        and either both URLs contain the placeholder or neither does.
        """
        if not self.auth_config.login_url or not self.auth_config.login_url.strip():
            raise TypeError("The [login_url] config must have a value when auto-configure is disabled.")
        if not self.auth_config.redirect_uri or not self.auth_config.redirect_uri.strip():
            raise TypeError("The [redirect_uri] config must have a value when auto-configure is disabled.")

        self._validate_tenant_placeholder_position("login_url", self.auth_config.login_url)
        self._validate_tenant_placeholder_position("redirect_uri", self.auth_config.redirect_uri)
        self._validate_matching_tenant_placeholders(self.auth_config.login_url, self.auth_config.redirect_uri)

    def _validate_partial_url_auth_configs(self) -> None:
        """
        Validate manually provided URL configuration when auto-configure is enabled.

        Only the values that are provided are checked. When only one of the two URLs is provided, the placeholder
        comparison happens in _validate_all_dynamic_configs() instead, once the other URL is available from the
        SDK Auto-Configuration Endpoint.
        """
        if self.auth_config.login_url:
            self._validate_tenant_placeholder_position("login_url", self.auth_config.login_url)
        if self.auth_config.redirect_uri:
            self._validate_tenant_placeholder_position("redirect_uri", self.auth_config.redirect_uri)
        if self.auth_config.login_url and self.auth_config.redirect_uri:
            self._validate_matching_tenant_placeholders(self.auth_config.login_url, self.auth_config.redirect_uri)

    def _validate_all_dynamic_configs(self, sdk_configuration: SdkConfiguration) -> None:
        """
        Validate the final resolved URL configs after the SDK Auto-Configuration Endpoint responds.

        When at least one of [login_url] and [redirect_uri] was provided manually, either both resolved URLs must
        contain the {tenant_name} placeholder or neither does. When both URLs come from the SDK Auto-Configuration
        Endpoint, their placeholders are trusted as-is.
        """

        # Use manual config values if provided, otherwise use SDK config values
        login_url = self.auth_config.login_url or sdk_configuration.login_url
        redirect_uri = self.auth_config.redirect_uri or sdk_configuration.redirect_uri

        # Validate that required fields are present in the SDK config response
        if not login_url:
            raise WristbandError("sdk_config_invalid", "SDK configuration response missing required field: login_url")
        if not redirect_uri:
            raise WristbandError(
                "sdk_config_invalid",
                "The [redirect_uri] could not be resolved. Provide it explicitly in your SDK config "
                "or ensure your Wristband OAuth2 Client has a single redirect URI configured.",
            )

        # Only one of login_url and redirect_uri may have come from the manual config, so compare the final
        # resolved values. Values that both come from the SDK Auto-Configuration Endpoint are trusted as-is.
        if self.auth_config.login_url or self.auth_config.redirect_uri:
            login_url_has_placeholder = bool(TENANT_PLACEHOLDER_PATTERN.search(login_url))
            redirect_uri_has_placeholder = bool(TENANT_PLACEHOLDER_PATTERN.search(redirect_uri))
            if login_url_has_placeholder and not redirect_uri_has_placeholder:
                raise WristbandError(
                    "config_validation_error",
                    f"The resolved [redirect_uri] must contain the {TENANT_PLACEHOLDER_MSG} when the resolved "
                    "[login_url] contains it.",
                )
            if not login_url_has_placeholder and redirect_uri_has_placeholder:
                raise WristbandError(
                    "config_validation_error",
                    f"The resolved [redirect_uri] cannot contain the {TENANT_PLACEHOLDER_MSG} when the resolved "
                    "[login_url] does not contain it.",
                )

    # ////////////////////////////////////
    #  STATIC CONFIGURATIONS
    # ////////////////////////////////////

    def get_client_id(self) -> str:
        """Get the client ID."""
        return self.auth_config.client_id

    def get_client_secret(self) -> str:
        """Get the client secret."""
        return self.auth_config.client_secret

    def get_login_state_secret(self) -> str:
        """Get the login state secret, falling back to client secret if not provided."""
        return self.auth_config.login_state_secret or self.auth_config.client_secret

    def get_wristband_application_vanity_domain(self) -> str:
        """Get the Wristband application vanity domain."""
        return self.auth_config.wristband_application_vanity_domain

    def get_dangerously_disable_secure_cookies(self) -> bool:
        """Get whether to disable secure cookies (for development only)."""
        return self.auth_config.dangerously_disable_secure_cookies

    def get_scopes(self) -> list[str]:
        """Get the OAuth scopes, using defaults if not provided."""
        return self.auth_config.scopes if self.auth_config.scopes else _default_scopes

    def get_auto_configure_enabled(self) -> bool:
        """Get whether auto-configuration is enabled."""
        return self.auth_config.auto_configure_enabled

    def get_token_expiration_buffer(self) -> int:
        """Get the token expiration buffer in seconds."""
        return self.auth_config.token_expiration_buffer

    # ////////////////////////////////////
    #  DYNAMIC CONFIGURATIONS
    # ////////////////////////////////////

    async def get_custom_application_login_page_url(self) -> str:
        """Get the custom application login page URL."""
        # 1. Check if manually provided in authConfig
        if self.auth_config.custom_application_login_page_url:
            return self.auth_config.custom_application_login_page_url

        # 2. If auto-configure is enabled, get from SDK config
        if self.get_auto_configure_enabled():
            sdk_config = await self._load_sdk_config()
            return sdk_config.custom_application_login_page_url or ""

        # 3. Default fallback
        return ""

    async def get_is_application_custom_domain_active(self) -> bool:
        """Get whether application custom domain is active."""
        # 1. Check if manually provided in authConfig
        if self.auth_config.is_application_custom_domain_active is not None:
            return self.auth_config.is_application_custom_domain_active

        # 2. If auto-configure is enabled, get from SDK config
        if self.get_auto_configure_enabled():
            sdk_config = await self._load_sdk_config()
            return sdk_config.is_application_custom_domain_active

        # 3. Default fallback
        return False

    async def get_login_url(self) -> str:
        """Get the login URL."""
        # 1. Check if manually provided in authConfig
        if self.auth_config.login_url:
            return self.auth_config.login_url

        # 2. If auto-configure is enabled, get from SDK config
        if self.get_auto_configure_enabled():
            sdk_config = await self._load_sdk_config()
            return sdk_config.login_url

        # 3. This should not happen if validation is done properly
        raise TypeError("The [login_url] config must have a value")

    async def get_parse_tenant_from_root_domain(self) -> str:
        """Get the root domain for parsing tenant subdomains."""
        # 1. Derive from the manually provided login_url
        if self.auth_config.login_url:
            return derive_tenant_root_domain(self.auth_config.login_url)

        # 2. If auto-configure is enabled, get from SDK config
        if self.get_auto_configure_enabled():
            sdk_config = await self._load_sdk_config()
            return sdk_config.login_url_tenant_domain_suffix or ""

        # 3. Default fallback
        return ""

    async def get_redirect_uri(self) -> str:
        """Get the redirect URI."""
        # 1. Check if manually provided in authConfig
        if self.auth_config.redirect_uri:
            return self.auth_config.redirect_uri

        # 2. If auto-configure is enabled, get from SDK config
        if self.get_auto_configure_enabled():
            sdk_config = await self._load_sdk_config()
            return sdk_config.redirect_uri or ""

        # 3. This should not happen if validation is done properly
        raise TypeError("The [redirect_uri] config must have a value")

    async def get_application_authorization_requests_enabled(self) -> bool:
        """Get whether application-level authorization requests are enabled."""
        # 1. Check if manually provided in authConfig
        if self.auth_config.application_authorization_requests_enabled is not None:
            return self.auth_config.application_authorization_requests_enabled

        # 2. If auto-configure is enabled, get from SDK config
        if self.get_auto_configure_enabled():
            sdk_config = await self._load_sdk_config()
            return sdk_config.application_authorization_requests_enabled

        # 3. Default fallback
        return True

    async def get_fallback_login_url(self) -> str:
        """Get the login URL without the {tenant_name} subdomain, used when a tenant cannot be resolved."""
        # 1. Derive from the manually provided login_url
        if self.auth_config.login_url:
            return derive_fallback_login_url(self.auth_config.login_url)

        # 2. If auto-configure is enabled, get from SDK config
        if self.get_auto_configure_enabled():
            sdk_config = await self._load_sdk_config()
            return sdk_config.fallback_login_url or ""

        # 3. Default fallback
        return ""
