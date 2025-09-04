import asyncio
from typing import Optional

from .client import WristbandApiClient
from .exceptions import WristbandError
from .models import AuthConfig, SdkConfiguration

_default_scopes = ["openid", "offline_access", "email"]
_max_fetch_attempts = 3
_attempt_delay_seconds = 0.1  # 100 milliseconds
_tenant_domain_token: str = "{tenant_domain}"


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
        """Fetch SDK configuration with retry logic."""
        last_error: Optional[Exception] = None

        for attempt in range(1, _max_fetch_attempts + 1):
            try:
                config = await self.wristband_api.get_sdk_configuration()
                return config
            except Exception as error:
                last_error = error

                # Final attempt failed, break and throw
                if attempt == _max_fetch_attempts:
                    break

                # Wait before retrying
                await asyncio.sleep(_attempt_delay_seconds)

        error_message = f"Failed to fetch SDK configuration after {_max_fetch_attempts} attempts"
        if last_error:
            error_message += f": {str(last_error)}"
        else:
            error_message += ": Unknown error"

        raise WristbandError("sdk_config_fetch_failed", error_message)

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

    def _validate_strict_url_auth_configs(self) -> None:
        """Validate URL configuration when auto-configure is disabled."""
        if not self.auth_config.login_url or not self.auth_config.login_url.strip():
            raise TypeError("The [login_url] config must have a value when auto-configure is disabled.")
        if not self.auth_config.redirect_uri or not self.auth_config.redirect_uri.strip():
            raise TypeError("The [redirect_uri] config must have a value when auto-configure is disabled.")

        if self.auth_config.parse_tenant_from_root_domain:
            if _tenant_domain_token not in self.auth_config.login_url:
                raise TypeError(
                    'The [login_url] must contain the "{tenant_domain}" token when using the '
                    "[parse_tenant_from_root_domain] config."
                )
            if _tenant_domain_token not in self.auth_config.redirect_uri:
                raise TypeError(
                    'The [redirect_uri] must contain the "{tenant_domain}" token when using the '
                    "[parse_tenant_from_root_domain] config."
                )
        else:
            if _tenant_domain_token in self.auth_config.login_url:
                raise TypeError(
                    'The [login_url] cannot contain the "{tenant_domain}" token when the '
                    "[parse_tenant_from_root_domain] is absent."
                )
            if _tenant_domain_token in self.auth_config.redirect_uri:
                raise TypeError(
                    'The [redirect_uri] cannot contain the "{tenant_domain}" token when the '
                    "[parse_tenant_from_root_domain] is absent."
                )

    def _validate_partial_url_auth_configs(self) -> None:
        """Validate manually provided URL configuration when auto-configure is enabled."""
        if self.auth_config.login_url:
            if (
                self.auth_config.parse_tenant_from_root_domain
                and _tenant_domain_token not in self.auth_config.login_url
            ):
                raise TypeError(
                    'The [login_url] must contain the "{tenant_domain}" token when using the '
                    "[parse_tenant_from_root_domain] config."
                )
            if (
                not self.auth_config.parse_tenant_from_root_domain
                and _tenant_domain_token in self.auth_config.login_url
            ):
                raise TypeError(
                    'The [login_url] cannot contain the "{tenant_domain}" token when the '
                    "[parse_tenant_from_root_domain] is absent."
                )

        if self.auth_config.redirect_uri:
            if (
                self.auth_config.parse_tenant_from_root_domain
                and _tenant_domain_token not in self.auth_config.redirect_uri
            ):
                raise TypeError(
                    'The [redirect_uri] must contain the "{tenant_domain}" token when using the '
                    "[parse_tenant_from_root_domain] config."
                )
            if (
                not self.auth_config.parse_tenant_from_root_domain
                and _tenant_domain_token in self.auth_config.redirect_uri
            ):
                raise TypeError(
                    'The [redirect_uri] cannot contain the "{tenant_domain}" token when the '
                    "[parse_tenant_from_root_domain] is absent."
                )

    def _validate_all_dynamic_configs(self, sdk_configuration: SdkConfiguration) -> None:
        """Validate all dynamic configurations after SDK config is loaded."""
        # Validate that required fields are present in the SDK config response
        if not sdk_configuration.login_url:
            raise WristbandError("sdk_config_invalid", "SDK configuration response missing required field: login_url")
        if not sdk_configuration.redirect_uri:
            raise WristbandError(
                "sdk_config_invalid", "SDK configuration response missing required field: redirect_uri"
            )

        # Use manual config values if provided, otherwise use SDK config values
        login_url = self.auth_config.login_url or sdk_configuration.login_url
        redirect_uri = self.auth_config.redirect_uri or sdk_configuration.redirect_uri
        parse_tenant_from_root_domain = (
            self.auth_config.parse_tenant_from_root_domain or sdk_configuration.login_url_tenant_domain_suffix or ""
        )

        # Validate the tenant domain token logic with final resolved values
        if parse_tenant_from_root_domain:
            if _tenant_domain_token not in login_url:
                raise WristbandError(
                    "config_validation_error",
                    'The resolved [login_url] must contain the "{tenant_domain}" token when using '
                    "[parse_tenant_from_root_domain].",
                )
            if _tenant_domain_token not in redirect_uri:
                raise WristbandError(
                    "config_validation_error",
                    'The resolved [redirect_uri] must contain the "{tenant_domain}" token when using '
                    "[parse_tenant_from_root_domain].",
                )
        else:
            if _tenant_domain_token in login_url:
                raise WristbandError(
                    "config_validation_error",
                    'The resolved [login_url] cannot contain the "{tenant_domain}" token when '
                    "[parse_tenant_from_root_domain] is absent.",
                )
            if _tenant_domain_token in redirect_uri:
                raise WristbandError(
                    "config_validation_error",
                    'The resolved [redirect_uri] cannot contain the "{tenant_domain}" token when '
                    "[parse_tenant_from_root_domain] is absent.",
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
        # 1. Check if manually provided in authConfig
        if self.auth_config.parse_tenant_from_root_domain:
            return self.auth_config.parse_tenant_from_root_domain

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
            return sdk_config.redirect_uri

        # 3. This should not happen if validation is done properly
        raise TypeError("The [redirect_uri] config must have a value")
