import base64
import hashlib
import logging
import re
import secrets
import time
from datetime import datetime
from typing import Any, Awaitable, Callable, List, Literal, Optional, Tuple, cast
from urllib.parse import quote, urlencode

import httpx
from fastapi import HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from wristband.python_jwt import (
    JWTPayload,
    JwtValidationResult,
    WristbandJwtValidator,
    WristbandJwtValidatorConfig,
    create_wristband_jwt_validator,
)

from .client import WristbandApiClient
from .config_resolver import ConfigResolver
from .csrf import is_csrf_token_valid
from .exceptions import InvalidGrantError, WristbandError
from .models import (
    AuthConfig,
    AuthResult,
    AuthStrategy,
    CallbackData,
    CallbackFailureReason,
    CallbackResult,
    CallbackResultType,
    CompletedCallbackResult,
    JWTAuthConfig,
    JWTAuthResult,
    LoginConfig,
    LoginState,
    LogoutConfig,
    OAuthAuthorizeUrlConfig,
    RedirectRequiredCallbackResult,
    Session,
    SessionAuthConfig,
    TokenData,
    UserInfo,
    WristbandTokenResponse,
)
from .utils import DataEncryptor

_logger: logging.Logger = logging.getLogger(__name__)


class WristbandAuth:
    """
    WristbandAuth provides methods for seamless interaction with Wristband for authenticating application users.
    It can handle the following:
    - Initiate a login request by redirecting to Wristband.
    - Receive callback requests from Wristband to complete a login request.
    - Retrive all necessary JWT tokens and userinfo to start an application session.
    - Logout a user from the application by revoking refresh tokens and redirecting to Wristband.
    - Checking for expired access tokens and refreshing them automatically, if necessary.
    """

    _cookie_prefix: str = "login#"
    _login_state_cookie_separator: str = "#"
    _return_url_char_max_len = 450
    _token_refresh_retries = 2
    _token_refresh_retry_timeout = 0.1  # 100ms
    _tenant_placeholder_pattern = re.compile(r"\{tenant_(?:domain|name)\}")

    def __init__(self, auth_config: AuthConfig) -> None:
        self._config_resolver = ConfigResolver(auth_config)
        self._jwt_validator: Optional[WristbandJwtValidator] = None
        self._wristband_api = WristbandApiClient(
            wristband_application_vanity_domain=self._config_resolver.get_wristband_application_vanity_domain(),
            client_id=self._config_resolver.get_client_id(),
            client_secret=self._config_resolver.get_client_secret(),
        )
        self._login_state_encryptor = DataEncryptor(secret_key=self._config_resolver.get_login_state_secret())

    #################################
    #  DISCOVER
    #################################

    async def discover(self) -> None:
        """
        Immediately fetch and resolve all auto-configuration values from the Wristband SDK Configuration Endpoint.
        This is useful when you want to fail fast if auto-configuration is unavailable, or when you need configuration
        values resolved before making any auth method calls. Manual configuration values take precedence over
        auto-configured values.
        """
        if not self._config_resolver.get_auto_configure_enabled():
            raise WristbandError(
                "Cannot preload configs when auto_configure_enabled is false. " "Use create_wristband_auth() instead."
            )

        await self._config_resolver.preload_sdk_config()

    #################################
    #  LOGIN
    #################################

    async def login(self, request: Request, config: LoginConfig = LoginConfig()) -> Response:
        """
        Initiates a login request by redirecting to Wristband. Constructs an OAuth2 Authorization
        Request to begin the Authorization Code flow.

        The incoming FastAPI request can include Wristband-specific query parameters:
        - login_hint: A hint about the user's preferred login identifier. This is passed as a query
          parameter in the redirect to the Authorize URL.
        - return_url: The URL to redirect the user to after authentication.
        - tenant_custom_domain: The tenant-specific custom domain, if applicable. Used as the domain
          for the Authorize URL when present.
        - tenant_name: The tenant's name. Used as a subdomain or vanity domain in the
          Authorize URL if not using tenant custom domains.

        Args:
            request (Request): The FastAPI request object.
            config (LoginConfig, optional): Additional configuration for the login request.

        Returns:
            Response: A FastAPI Response object that redirects the user to the Wristband
            Authorize endpoint.
        """

        # Fetch our SDK configs
        client_id = self._config_resolver.get_client_id()
        custom_application_login_page_url = await self._config_resolver.get_custom_application_login_page_url()
        dangerously_disable_secure_cookies = self._config_resolver.get_dangerously_disable_secure_cookies()
        is_application_custom_domain_active = await self._config_resolver.get_is_application_custom_domain_active()
        parse_tenant_from_root_domain = await self._config_resolver.get_parse_tenant_from_root_domain()
        redirect_uri = await self._config_resolver.get_redirect_uri()
        scopes = self._config_resolver.get_scopes()
        wristband_application_vanity_domain = self._config_resolver.get_wristband_application_vanity_domain()

        # Determine which domain-related values are present as it will be needed for the authorize URL.
        tenant_custom_domain: str = self._resolve_tenant_custom_domain_param(request)
        tenant_name: str = self._resolve_tenant_name(request, parse_tenant_from_root_domain)
        default_tenant_custom_domain: Optional[str] = config.default_tenant_custom_domain
        default_tenant_name: Optional[str] = config.default_tenant_name

        resovled_return_url: Optional[str] = self._resolve_return_url(request, config.return_url)

        # In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
        if not any(
            [
                tenant_custom_domain,
                tenant_name,
                default_tenant_custom_domain,
                default_tenant_name,
            ]
        ):
            app_login_url: str = (
                custom_application_login_page_url or f"https://{wristband_application_vanity_domain}/login"
            )
            state_param = f"&state={quote(resovled_return_url)}" if resovled_return_url else ""
            app_login_response: Response = RedirectResponse(
                url=f"{app_login_url}?client_id={client_id}{state_param}", status_code=302
            )
            app_login_response.headers["Cache-Control"] = "no-store"
            app_login_response.headers["Pragma"] = "no-cache"
            return app_login_response

        # Create the login state which will be cached in a cookie so that it can be accessed in the callback.
        login_state: LoginState = self._create_login_state(redirect_uri, config.custom_state, resovled_return_url)

        # Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
        authorize_url: str = self._get_oauth_authorize_url(
            request=request,
            config=OAuthAuthorizeUrlConfig(
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_verifier=login_state.code_verifier,
                scopes=scopes,
                state=login_state.state,
                default_tenant_custom_domain=default_tenant_custom_domain,
                default_tenant_name=default_tenant_name,
                tenant_custom_domain=tenant_custom_domain,
                tenant_name=tenant_name,
                is_application_custom_domain_active=is_application_custom_domain_active,
                wristband_application_vanity_domain=wristband_application_vanity_domain,
            ),
        )

        # Create the redirect response
        authorize_response: Response = RedirectResponse(url=authorize_url, status_code=302)
        authorize_response.headers["Cache-Control"] = "no-store"
        authorize_response.headers["Pragma"] = "no-cache"

        # Clear any stale login state cookies and add a new one for the current request.
        self._clear_oldest_login_state_cookie(request, authorize_response, dangerously_disable_secure_cookies)
        encrypted_login_state: str = self._encrypt_login_state(login_state)

        # Create the login state cookie
        self._create_login_state_cookie(
            res=authorize_response,
            state=login_state.state,
            encrypted_login_state=encrypted_login_state,
            disable_secure=dangerously_disable_secure_cookies,
        )

        # Perform the redirect to Wristband's Authorize Endpoint.
        return authorize_response

    #################################
    #  CALLBACK
    #################################

    async def callback(self, request: Request) -> CallbackResult:
        """
        Handles the OAuth2 callback from Wristband. Exchanges the authorization code for tokens
        and retrieves user information for the authenticated user.

        The incoming FastAPI request can include Wristband-specific query parameters:
        - code: The authorization code returned from Wristband after a successful login.
        - error: An error identifier indicating a problem occurred during login.
        - error_description: A human-readable explanation of the error that occurred.
        - state: The original state value sent during the authorization request, used to validate the response.
        - tenant_custom_domain: The tenant's custom domain, if defined. If a redirect to the Login Endpoint
          is needed, this value should be passed along in the redirect.
        - tenant_name: The tenant's name. Used when redirecting to the Login Endpoint in setups
          that don't rely on tenant subdomains or custom domains.

        Args:
            request (Request): The FastAPI request object containing the callback query parameters.

        Returns:
            CallbackResult: An object representing the outcome of the callback process,
            including login state, user info, or redirect behavior.
        """

        # Fetch our SDK configs
        login_url = await self._config_resolver.get_login_url()
        parse_tenant_from_root_domain = await self._config_resolver.get_parse_tenant_from_root_domain()
        token_expiration_buffer = self._config_resolver.get_token_expiration_buffer()

        # Extract and validate Query Params from wristband callback
        code: Optional[str] = self._assert_single_param(request, "code")
        param_state: Optional[str] = self._assert_single_param(request, "state")
        error: Optional[str] = self._assert_single_param(request, "error")
        error_description: Optional[str] = self._assert_single_param(request, "error_description")
        tenant_custom_domain_param: Optional[str] = self._assert_single_param(request, "tenant_custom_domain")

        if not param_state or not isinstance(param_state, str):
            raise TypeError("Invalid query parameter [state] passed from Wristband during callback")
        if code and not isinstance(code, str):
            raise TypeError("Invalid query parameter [code] passed from Wristband during callback")
        if error and not isinstance(error, str):
            raise TypeError("Invalid query parameter [error] passed from Wristband during callback")
        if error_description and not isinstance(error_description, str):
            raise TypeError("Invalid query parameter [error_description] passed from Wristband during callback")
        if tenant_custom_domain_param and not isinstance(tenant_custom_domain_param, str):
            raise TypeError("Invalid query parameter [tenant_custom_domain] passed from Wristband during callback")

        # Resolve and validate tenant name
        resolved_tenant_name: str = self._resolve_tenant_name(request, parse_tenant_from_root_domain)
        if not resolved_tenant_name:
            if parse_tenant_from_root_domain:
                raise WristbandError("missing_tenant_subdomain", "Callback request URL is missing a tenant subdomain")
            else:
                raise WristbandError("missing_tenant_name", "Callback request is missing the [tenant_name] param")

        # Build the tenant login URL in case we need to redirect
        if parse_tenant_from_root_domain:
            tenant_login_url: str = self._tenant_placeholder_pattern.sub(resolved_tenant_name, login_url)
        else:
            tenant_login_url = f"{login_url}?tenant_name={resolved_tenant_name}"

        # If the tenant_custom_domain is set, add that query param
        if tenant_custom_domain_param:
            # If we already used "?" above, use "&"" instead
            connector: Literal["&", "?"] = "&" if "?" in tenant_login_url else "?"
            tenant_login_url = f"{tenant_login_url}{connector}tenant_custom_domain={tenant_custom_domain_param}"

        # Retrieve and decrypt the login state cookie
        _, login_state_cookie_val = self._get_login_state_cookie(request)

        # No valid cookie, we cannot verify the request
        if not login_state_cookie_val:
            return RedirectRequiredCallbackResult(
                type=CallbackResultType.REDIRECT_REQUIRED,
                redirect_url=tenant_login_url,
                reason=CallbackFailureReason.MISSING_LOGIN_STATE,
            )

        login_state: LoginState = self._decrypt_login_state(login_state_cookie_val)

        # Validate the state from the cookie matches the incoming state param
        if param_state != login_state.state:
            return RedirectRequiredCallbackResult(
                type=CallbackResultType.REDIRECT_REQUIRED,
                redirect_url=tenant_login_url,
                reason=CallbackFailureReason.INVALID_LOGIN_STATE,
            )

        if error:
            # If we specifically got a 'login_required' error, go back to the login
            if error.lower() == "login_required":
                return RedirectRequiredCallbackResult(
                    type=CallbackResultType.REDIRECT_REQUIRED,
                    redirect_url=tenant_login_url,
                    reason=CallbackFailureReason.LOGIN_REQUIRED,
                )
            # Otherwise raise an exception
            raise WristbandError(error, error_description or "")

        if code is None:
            raise ValueError("Invalid query parameter [code] passed from Wristband during callback")

        try:
            # Call Wristband Token API
            token_response: WristbandTokenResponse = await self._wristband_api.get_tokens(
                code=code,
                redirect_uri=login_state.redirect_uri,
                code_verifier=login_state.code_verifier,
            )

            # Call Wristband Userinfo API
            userinfo: UserInfo = await self._wristband_api.get_userinfo(token_response.access_token)

            # Calculate token expiration buffer
            expires_in = token_response.expires_in - token_expiration_buffer
            expires_at = int((time.time() + expires_in) * 1000)

            # Return the callback data and result
            return CompletedCallbackResult(
                type=CallbackResultType.COMPLETED,
                callback_data=CallbackData(
                    access_token=token_response.access_token,
                    id_token=token_response.id_token,
                    expires_at=expires_at,
                    expires_in=expires_in,
                    tenant_name=resolved_tenant_name,
                    user_info=userinfo,
                    custom_state=login_state.custom_state,
                    refresh_token=token_response.refresh_token,
                    return_url=login_state.return_url,
                    tenant_custom_domain=tenant_custom_domain_param,
                ),
            )
        except InvalidGrantError:
            return RedirectRequiredCallbackResult(
                type=CallbackResultType.REDIRECT_REQUIRED,
                redirect_url=tenant_login_url,
                reason=CallbackFailureReason.INVALID_GRANT,
            )
        except Exception as ex:
            raise ex

    #################################
    #  CREATE CALLBACK RESPONSE
    #################################

    async def create_callback_response(self, request: Request, redirect_url: str) -> Response:
        """
        Constructs the redirect response to your application and cleans up the login state.

        Args:
            request (Request): The FastAPI request object.
            redirect_url (str): The location for your application that you want to send users to.

        Returns:
            Response: The FastAPI Response that is performing the URL redirect to your desired application URL.
        """

        # Fetch our SDK configs
        dangerously_disable_secure_cookies = self._config_resolver.get_dangerously_disable_secure_cookies()

        if not redirect_url or not redirect_url.strip():
            raise TypeError("redirect_url cannot be null or empty")

        redirect_response = RedirectResponse(redirect_url, status_code=302)
        redirect_response.headers["Cache-Control"] = "no-store"
        redirect_response.headers["Pragma"] = "no-cache"

        login_state_cookie_name, _ = self._get_login_state_cookie(request)
        if login_state_cookie_name:
            self._clear_login_state_cookie(
                res=redirect_response,
                cookie_name=login_state_cookie_name,
                dangerously_disable_secure_cookies=dangerously_disable_secure_cookies,
            )

        return redirect_response

    #################################
    #  LOGOUT
    #################################

    async def logout(self, request: Request, config: LogoutConfig = LogoutConfig()) -> Response:
        """
        Logs the user out by revoking their refresh token (if provided) and constructing a redirect
        URL to Wristband's Logout Endpoint.

        Args:
            request (Request): The FastAPI request object containing user session or token data.
            config (LogoutConfig, optional): Optional configuration parameters for the logout process,
            such as a custom return URL or tenant name.

        Returns:
            Response: A FastAPI redirect response to Wristband's Logout Endpoint.
        """

        # Fetch our SDK configs
        client_id = self._config_resolver.get_client_id()
        custom_application_login_page_url = await self._config_resolver.get_custom_application_login_page_url()
        is_application_custom_domain_active = await self._config_resolver.get_is_application_custom_domain_active()
        parse_tenant_from_root_domain = await self._config_resolver.get_parse_tenant_from_root_domain()
        wristband_application_vanity_domain = self._config_resolver.get_wristband_application_vanity_domain()

        # Revoke refresh token, if present
        if config.refresh_token:
            try:
                await self._wristband_api.revoke_refresh_token(config.refresh_token)
            except Exception as e:
                # No need to block logout execution if revoking fails
                _logger.warning(f"Revoking the refresh token failed during logout: {e}")

        if config.state and len(config.state) > 512:
            raise ValueError("The [state] logout config cannot exceed 512 characters.")

        # Get host and determine tenant domain
        tenant_name: str = self._resolve_tenant_name(request, parse_tenant_from_root_domain)
        tenant_custom_domain: str = self._resolve_tenant_custom_domain_param(request)

        separator: Literal[".", "-"] = "." if is_application_custom_domain_active else "-"
        redirect_url = f"&redirect_url={config.redirect_url}" if config.redirect_url else ""
        state = f"&state={config.state}" if config.state else ""
        logout_path = f"/api/v1/logout?client_id={client_id}{redirect_url}{state}"

        # make response to return to client
        res = RedirectResponse(url=request.url, status_code=302)
        res.headers["Cache-Control"] = "no-store"
        res.headers["Pragma"] = "no-cache"

        # Domain priority order resolution:
        # 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
        if config.tenant_custom_domain and config.tenant_custom_domain.strip():
            res.headers["Location"] = f"https://{config.tenant_custom_domain}{logout_path}"
            return res

        # 2) If the LogoutConfig has a tenant name defined, then use that.
        if config.tenant_name and config.tenant_name.strip():
            res.headers["Location"] = (
                f"https://{config.tenant_name}{separator}{wristband_application_vanity_domain}{logout_path}"
            )
            return res

        # 3) If the tenant_custom_domain query param exists, then use that.
        if tenant_custom_domain and tenant_custom_domain.strip():
            res.headers["Location"] = f"https://{tenant_custom_domain}{logout_path}"
            return res

        # 4a) If tenant subdomains are enabled, get the tenant name from the host.
        # 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_name query param.
        if tenant_name and tenant_name.strip():
            res.headers["Location"] = (
                f"https://{tenant_name}{separator}{wristband_application_vanity_domain}{logout_path}"
            )
            return res

        # Otherwise, fallback to app login URL (or custom logout redirect URL) if tenant cannot be determined.
        app_login_url: str = custom_application_login_page_url or f"https://{wristband_application_vanity_domain}/login"
        res.headers["Location"] = config.redirect_url or f"{app_login_url}?client_id={client_id}"
        return res

    #################################
    #  REFRESH TOKEN IF EXPIRED
    #################################

    async def refresh_token_if_expired(
        self, refresh_token: Optional[str], expires_at: Optional[int]
    ) -> Optional[TokenData]:
        """
        Checks if the user's access token has expired and refreshes the token, if necessary.

        Args:
            refresh_token (Optional[str]): The refresh token used to obtain a new access token.
            expires_at (Optional[int]): Unix timestamp in milliseconds indicating when the current access token expires.

        Returns:
            Optional[TokenData]: The refreshed token data if a new token was obtained, otherwise None.
        """

        # Fetch our SDK configs
        token_expiration_buffer = self._config_resolver.get_token_expiration_buffer()

        if not refresh_token or not refresh_token.strip():
            raise TypeError("Refresh token must be a valid string")
        if not expires_at or expires_at < 0:
            raise TypeError("The expiresAt field must be an integer greater than 0")

        # Nothing to do here if the access token is still valid
        if expires_at >= int(datetime.now().timestamp() * 1000):
            return None

        # Try up to 3 times to perform a token refresh
        for attempt in range(self._token_refresh_retries + 1):
            try:
                token_response: WristbandTokenResponse = await self._wristband_api.refresh_token(refresh_token)

                # Calculate token expiration buffer
                expires_in = token_response.expires_in - token_expiration_buffer
                expires_at = int((time.time() + expires_in) * 1000)

                return TokenData(
                    access_token=token_response.access_token,
                    id_token=token_response.id_token,
                    expires_in=expires_in,
                    expires_at=expires_at,
                    refresh_token=token_response.refresh_token,
                )
            except InvalidGrantError as e:
                # Do not retry, bail immediately
                raise e
            except httpx.HTTPStatusError as e:
                # Only 4xx errors should short-circuit the retry loop early.
                if 400 <= e.response.status_code < 500:
                    try:
                        error_description = e.response.json().get("error_description", "Invalid Refresh Token")
                    except Exception:
                        error_description = "Invalid Refresh Token"
                    raise WristbandError("invalid_refresh_token", error_description)

                # On last attempt, raise the error
                if attempt == self._token_refresh_retries:
                    raise WristbandError("unexpected_error", "Unexpected Error")

                # Wait before retrying
                time.sleep(self._token_refresh_retry_timeout)
            except Exception:
                # Handle all other exceptions with retry logic. On last attempt, raise the error.
                if attempt == self._token_refresh_retries:
                    raise WristbandError("unexpected_error", "Unexpected Error")

                # Wait before retrying.
                time.sleep(self._token_refresh_retry_timeout)

        # Safety check that should never happen
        raise WristbandError("unexpected_error", "Unexpected Error")

    #################################
    #  SESSION AUTH DEPENDENCY
    #################################

    def create_session_auth_dependency(
        self,
        enable_csrf_protection: bool = False,
        csrf_header_name: str = "X-CSRF-TOKEN",
    ) -> Callable[[Request], Awaitable[Session]]:
        """
        Creates a session authentication dependency for this WristbandAuth instance.

        Args:
            enable_csrf_protection: Whether to validate CSRF tokens (default: False)
            csrf_header_name: The HTTP header name to read the CSRF token from, if enabled (default: "X-CSRF-TOKEN")

        Returns:
            An async dependency function for FastAPI route protection.

        Raises:
            RuntimeError: If SessionMiddleware is not registered in the application.
            HTTPException: 401 if the session is not authenticated or token refresh fails.
            HTTPException: 403 if CSRF validation fails (when enable_csrf_protection is True).

        Example:
            ```python
            session_auth = wristband_auth.create_session_auth_dependency(
                enable_csrf_protection=True,
                csrf_header_name="X-CSRF-TOKEN"
            )

            @app.get("/protected")
            async def protected_route(session: Session = Depends(session_auth)):
                return { "user_id": session.user_id }
            ```
        """

        async def require_session_auth(request: Request) -> Session:
            """Session authentication dependency for routes."""
            _logger.debug(f"Executing session auth for: {request.method} {request.url.path}...")
            return await self._validate_session_auth(request, enable_csrf_protection, csrf_header_name)

        return require_session_auth

    #####################################################
    #  JWT AUTH DEPENDENCY
    #####################################################

    def create_jwt_auth_dependency(
        self, jwks_cache_max_size: Optional[int] = None, jwks_cache_ttl: Optional[int] = None
    ) -> Callable[[Request], Awaitable[JWTAuthResult]]:
        """
        Creates a JWT authentication dependency for FastAPI routes.

        This dependency validates Bearer tokens in the Authorization header using
        Wristband's JWKS endpoint. The JWT validator is lazily initialized on the
        first request and cached for the lifetime of the application.

        Args:
            jwks_cache_max_size: Maximum number of JWKS to cache. Defaults to 20 if not specified.
            jwks_cache_ttl: Time-to-live for cached JWKS in milliseconds.
                           Defaults to 3600000 (1 hour) if not specified.

        Returns:
            A callable dependency that returns a JWTAuthResult containing the decoded
            payload and raw token string.

        Raises:
            HTTPException: 401 if the token is missing, malformed, invalid, or expired.

        Example:
            ```python
            require_jwt_auth = wristband_auth.create_jwt_auth_dependency()

            @app.get("/protected")
            async def protected_route(auth: JWTAuthResult = Depends(require_jwt_auth)):
                user_id = auth.payload.sub
                raw_token = auth.jwt
                return { "user_id": user_id }
            ```
        """
        # Capture config in closure
        cache_max_size = jwks_cache_max_size
        cache_ttl = jwks_cache_ttl

        async def require_jwt_auth(request: Request) -> JWTAuthResult:
            _logger.debug(f"Executing JWT auth for: {request.method} {request.url.path}...")
            return await self._validate_jwt_auth(request, cache_max_size, cache_ttl)

        return require_jwt_auth

    #####################################################
    #  MULTI-STRATEGY AUTH DEPENDENCY
    #####################################################

    def create_auth_dependency(
        self,
        strategies: List[AuthStrategy],
        session_config: Optional[SessionAuthConfig] = None,
        jwt_config: Optional[JWTAuthConfig] = None,
    ) -> Callable[[Request], Awaitable[AuthResult]]:
        """
        Creates a multi-strategy authentication dependency that tries strategies in order.

        Tries each strategy sequentially until one succeeds. Use this when you need
        to support multiple authentication methods (e.g., sessions for web apps and
        JWT tokens for API clients or automated testing).

        Args:
            strategies: List of auth strategies to try in order (e.g., [AuthStrategy.SESSION, AuthStrategy.JWT])
            session_config: Configuration for session authentication (optional, only used with AuthStrategy.SESSION)
            jwt_config: Configuration for JWT authentication (optional, only used with AuthStrategy.JWT)

        Returns:
            A callable dependency that returns AuthResult indicating which strategy succeeded
            and containing the appropriate authentication data.

        Raises:
            ValueError: If strategies list is empty, contains invalid strategies, or contains
                        invalid strategy-specific configuration values.
            HTTPException: 401 if all strategies fail to authenticate

        Example:
            ```python
                    from wristband.fastapi_auth import AuthStrategy, SessionAuthConfig, JWTAuthConfig

                    # Try SESSION first, fall back to JWT for API clients
                    require_auth = wristband_auth.create_auth_dependency(
                        strategies=[AuthStrategy.SESSION, AuthStrategy.JWT],
                        session_config=SessionAuthConfig(
                            enable_csrf_protection=True,
                            csrf_header_name="X-CSRF-TOKEN"
                        ),
                        jwt_config=JWTAuthConfig(
                            jwks_cache_max_size=50
                        )
                    )

                    @app.get("/protected")
                    async def protected(auth: AuthResult = Depends(require_auth)):
                        # Handle different auth strategies
                        if auth.strategy == AuthStrategy.SESSION:
                            user_id = auth.session.user_id
                        elif auth.strategy == AuthStrategy.JWT:
                            user_id = auth.jwt_result.payload.sub

                        return {"user_id": user_id, "auth_method": auth.strategy.value}
            ```
        """
        # Validate that at least one strategy is provided
        if not strategies:
            raise ValueError("At least one authentication strategy must be provided")

        # Validate no duplicates
        if len(strategies) != len(set(strategies)):
            raise ValueError("Duplicate authentication strategies are not allowed")

        # Runtime validation: ensure all strategies are AuthStrategy enum members
        # Run here during dependency creation instead of on every request.
        for strategy in strategies:
            if not isinstance(strategy, AuthStrategy):
                raise ValueError(f"Invalid authentication strategy: {strategy}.")

        async def require_auth(request: Request) -> AuthResult:
            """Multi-strategy authentication dependency."""
            _logger.debug(f"Executing multi-strategy auth for: {request.method} {request.url.path}...")

            last_exception: Optional[Exception] = None

            # Try each strategy in the order specified
            for strategy in strategies:
                try:
                    if strategy == AuthStrategy.SESSION:
                        _logger.debug("Trying SESSION authentication...")
                        enable_csrf = (session_config or {}).get("enable_csrf_protection", False)
                        csrf_header = (session_config or {}).get("csrf_header_name", "X-CSRF-TOKEN")
                        session = await self._validate_session_auth(request, enable_csrf, csrf_header)
                        return AuthResult(strategy=AuthStrategy.SESSION, session=session)

                    elif strategy == AuthStrategy.JWT:
                        _logger.debug("Trying JWT authentication...")
                        jwks_cache_max_size = (jwt_config or {}).get("jwks_cache_max_size")
                        jwks_cache_ttl = (jwt_config or {}).get("jwks_cache_ttl")
                        jwt_result = await self._validate_jwt_auth(request, jwks_cache_max_size, jwks_cache_ttl)
                        return AuthResult(strategy=AuthStrategy.JWT, jwt_result=jwt_result)

                except HTTPException as e:
                    # This strategy failed with an HTTP error, try the next strategy
                    _logger.debug(f"{strategy.value} authentication failed with status {e.status_code}")
                    last_exception = e
                    continue
                except Exception as e:
                    # This strategy failed with an unexpected error, try the next strategy
                    _logger.debug(f"{strategy.value} authentication failed with error: {e}")
                    last_exception = e
                    continue

            # All strategies failed - raise the last exception
            _logger.debug("All authentication strategies failed")
            raise last_exception  # type: ignore[misc]

        return require_auth

    #####################################################
    #  HELPER METHODS
    #####################################################

    def _resolve_tenant_custom_domain_param(self, request: Request) -> str:
        tenant_custom_domain_param = request.query_params.getlist("tenant_custom_domain")

        if tenant_custom_domain_param and len(tenant_custom_domain_param) > 1:
            raise TypeError("More than one [tenant_custom_domain] query parameter was encountered")

        return tenant_custom_domain_param[0] if tenant_custom_domain_param else ""

    def _resolve_tenant_name(self, request: Request, parse_tenant_from_root_domain: Optional[str]) -> str:
        if parse_tenant_from_root_domain and parse_tenant_from_root_domain.strip():
            host = str(request.url.netloc)

            # Strip off the port if it exists
            hostname = host.split(":")[0]

            # Extract everything after the first dot
            if "." not in hostname:
                return ""

            root_domain = hostname[hostname.index(".") + 1 :]

            # Check if the root domain matches
            if root_domain != parse_tenant_from_root_domain:
                return ""

            # Extract subdomain (everything before the first dot)
            subdomain: str = hostname[: hostname.index(".")]
            return subdomain or ""

        tenant_name_param_list = request.query_params.getlist("tenant_name")
        if len(tenant_name_param_list) > 1:
            raise TypeError("More than one [tenant_name] query parameter was encountered")

        return tenant_name_param_list[0] if tenant_name_param_list else ""

    def _resolve_return_url(self, request: Request, return_url: Optional[str] = None) -> Optional[str]:
        """Resolve return URL source (if any) and validate length"""
        return_url_list = request.query_params.getlist("return_url")
        if len(return_url_list) > 1:
            raise TypeError("More than one [return_url] query parameter was encountered")

        # LoginConfig takes precedence over the request query param for return URLs.
        resolved_return_url = return_url or (return_url_list[0] if return_url_list else None)

        if resolved_return_url and len(resolved_return_url) > self._return_url_char_max_len:
            _logger.debug(f"Return URL exceeds {self._return_url_char_max_len} characters: {resolved_return_url}")
            return None

        return resolved_return_url

    def _create_login_state(
        self,
        redirect_uri: str,
        custom_state: Optional[dict[str, Any]] = None,
        return_url: Optional[str] = None,
    ) -> LoginState:
        return LoginState(
            state=self._generate_random_string(),
            code_verifier=self._generate_random_string(64),
            redirect_uri=redirect_uri,
            return_url=return_url,
            custom_state=custom_state,
        )

    def _clear_login_state_cookie(
        self, res: Response, cookie_name: str, dangerously_disable_secure_cookies: bool
    ) -> None:
        res.set_cookie(
            key=cookie_name,
            value="",
            path="/",
            httponly=True,
            samesite="lax",
            max_age=0,
            secure=not dangerously_disable_secure_cookies,
        )

    def _generate_random_string(self, length: int = 32) -> str:
        random_bytes = secrets.token_bytes(length)
        random_string = base64.urlsafe_b64encode(random_bytes).decode("utf-8")
        return random_string.rstrip("=")[:length]

    def _clear_oldest_login_state_cookie(
        self, request: Request, res: Response, dangerously_disable_secure_cookies: bool
    ) -> None:
        cookies = request.cookies
        login_cookie_names = [name for name in cookies if name.startswith(self._cookie_prefix)]

        if len(login_cookie_names) >= 3:
            timestamps = []
            for name in login_cookie_names:
                parts = name.split(self._login_state_cookie_separator)
                if len(parts) > 2:
                    timestamps.append(parts[2])

            newest_timestamps = sorted(timestamps, reverse=True)[:2]

            for cookie_name in login_cookie_names:
                parts = cookie_name.split(self._login_state_cookie_separator)
                if len(parts) > 2 and parts[2] not in newest_timestamps:
                    res.delete_cookie(
                        cookie_name, httponly=True, secure=not dangerously_disable_secure_cookies, path="/"
                    )

    def _encrypt_login_state(self, login_state: LoginState) -> str:
        encrypted_str = self._login_state_encryptor.encrypt(login_state.model_dump())

        if len(encrypted_str.encode("utf-8")) > 4096:
            raise TypeError("Login state cookie exceeds 4kB in size.")

        return encrypted_str

    def _create_login_state_cookie(
        self,
        res: Response,
        state: str,
        encrypted_login_state: str,
        disable_secure: bool = False,
    ) -> None:
        res.set_cookie(
            key=f"{self._cookie_prefix}{state}{self._login_state_cookie_separator}{str(int(1000 * time.time()))}",
            value=encrypted_login_state,
            max_age=3600,
            path="/",
            secure=not disable_secure,
            httponly=True,
            samesite="lax",
        )

    def _generate_code_challenge(self, code_verifier: str) -> str:
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    def _get_oauth_authorize_url(self, request: Request, config: OAuthAuthorizeUrlConfig) -> str:
        login_hint_list = request.query_params.getlist("login_hint")
        if len(login_hint_list) > 1:
            raise TypeError("More than one [login_hint] query parameter was encountered")

        # Assemble necessary query params for authorization request
        query_params: dict[str, str] = {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "state": config.state,
            "scope": " ".join(config.scopes),
            "code_challenge": self._generate_code_challenge(config.code_verifier),
            "code_challenge_method": "S256",
            "nonce": self._generate_random_string(),
        }
        if login_hint_list:
            query_params["login_hint"] = login_hint_list[0]

        # Separator changes to a period if using an app-level custom domain with tenant subdomains
        separator: Literal[".", "-"] = "." if config.is_application_custom_domain_active else "-"
        path_and_query: str = f"/api/v1/oauth2/authorize?{urlencode(query_params)}"

        # Domain priority order resolution:
        # 1)  tenant_custom_domain query param
        # 2a) tenant subdomain
        # 2b) tenant_name query param
        # 3)  default_tenant_custom_domain login config
        # 4)  default_tenant_name login config
        if config.tenant_custom_domain:
            return f"https://{config.tenant_custom_domain}{path_and_query}"
        if config.tenant_name:
            return (
                f"https://{config.tenant_name}"
                f"{separator}{config.wristband_application_vanity_domain}"
                f"{path_and_query}"
            )
        if config.default_tenant_custom_domain:
            return f"https://{config.default_tenant_custom_domain}{path_and_query}"

        # By this point, we know the tenant name has already resolved properly, so just return the default.
        return (
            f"https://{config.default_tenant_name}"
            f"{separator}{config.wristband_application_vanity_domain}"
            f"{path_and_query}"
        )

    def _assert_single_param(self, request: Request, param: str) -> Optional[str]:
        values = request.query_params.getlist(param)
        if len(values) > 1:
            raise TypeError(f"Duplicate query parameter [{param}] passed from Wristband during callback")
        return values[0] if values else None

    def _get_login_state_cookie(self, request: Request) -> Tuple[Optional[str], Optional[str]]:
        cookies: dict[str, str] = request.cookies
        state: Optional[str] = request.query_params.get("state")
        param_state: str = state if state else ""

        matching_login_cookie_names: list[str] = [
            cookie_name
            for cookie_name in cookies
            if cookie_name.startswith(f"{self._cookie_prefix}{param_state}{self._login_state_cookie_separator}")
        ]

        if matching_login_cookie_names:
            cookie_name: str = matching_login_cookie_names[0]
            return cookie_name, cookies[cookie_name]

        return None, None

    def _decrypt_login_state(self, login_state_cookie: str) -> LoginState:
        login_state_dict = self._login_state_encryptor.decrypt(login_state_cookie)
        return LoginState(**login_state_dict)

    def _get_jwt_validator(
        self, jwks_cache_max_size: Optional[int], jwks_cache_ttl: Optional[int]
    ) -> WristbandJwtValidator:
        """
        Lazy initialize and cache the JWT validator.

        The validator is created once on the first request and reused for all
        subsequent requests. Configuration is captured at dependency creation time.

        Args:
            jwks_cache_max_size: Maximum JWKS cache size (passed to validator config)
            jwks_cache_ttl: JWKS cache TTL in milliseconds (passed to validator config)

        Returns:
            The cached WristbandJwtValidator instance
        """
        if self._jwt_validator is None:
            config = WristbandJwtValidatorConfig(
                wristband_application_vanity_domain=self._config_resolver.get_wristband_application_vanity_domain(),
                jwks_cache_max_size=jwks_cache_max_size,
                jwks_cache_ttl=jwks_cache_ttl,
            )
            self._jwt_validator = create_wristband_jwt_validator(config)

        return self._jwt_validator

    async def _validate_session_auth(
        self, request: Request, enable_csrf_protection: bool, csrf_header_name: str
    ) -> Session:
        """
        Shared session validation logic used by both single and multi-strategy auth.

        Validates the session exists, is authenticated, passes CSRF checks (if enabled),
        and automatically refreshes expired access tokens.

        Args:
            request: The FastAPI request object
            enable_csrf_protection: Whether to validate CSRF tokens
            csrf_header_name: Name of the CSRF token header

        Returns:
            The validated and refreshed Session object

        Raises:
            RuntimeError: If SessionMiddleware is not registered
            HTTPException: 401 if not authenticated or token refresh fails
            HTTPException: 403 if CSRF validation fails
        """
        # Ensure SessionMiddleware has attached a session to request.state
        if not hasattr(request.state, "session"):
            raise RuntimeError("Session not found. Ensure SessionMiddleware is registered in your app.")

        # Check if the session contains an authenticated user
        if not request.state.session.is_authenticated:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        # Validate CSRF token if protection is enabled
        if enable_csrf_protection and not is_csrf_token_valid(request, csrf_header_name):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

        refresh_token = request.state.session.refresh_token
        expires_at = request.state.session.expires_at
        if refresh_token is not None and expires_at is not None:
            try:
                # Attempt to refresh the access token if it has expired
                new_token_data: Optional[TokenData] = await self.refresh_token_if_expired(refresh_token, expires_at)

                # Update session with new tokens if refresh occurred
                if new_token_data:
                    request.state.session.access_token = new_token_data.access_token
                    request.state.session.refresh_token = new_token_data.refresh_token
                    request.state.session.expires_at = new_token_data.expires_at

            except Exception as e:
                # Log the error and return 401 for any token refresh failures
                _logger.exception(f"Session auth error during token refresh: {str(e)}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        # Always save the session to update cookies (rolling session expiration)
        request.state.session.save()
        return cast(Session, request.state.session)

    async def _validate_jwt_auth(
        self, request: Request, jwks_cache_max_size: Optional[int], jwks_cache_ttl: Optional[int]
    ) -> JWTAuthResult:
        """
        Shared JWT validation logic used by both single and multi-strategy auth.

        Validates Bearer tokens from the Authorization header using Wristband's JWKS endpoint.

        Args:
            request: The FastAPI request object
            jwks_cache_max_size: Maximum number of JWKS to cache
            jwks_cache_ttl: Time-to-live for cached JWKS in milliseconds

        Returns:
            JWTAuthResult containing the decoded payload and raw token

        Raises:
            HTTPException: 401 if token is missing, invalid, or expired
        """
        # Get or lazily initialize the JWT validator (cached forever)
        jwt_validator = self._get_jwt_validator(jwks_cache_max_size, jwks_cache_ttl)

        # Extract the Authorization header
        auth_header = request.headers.get("authorization")
        if not auth_header:
            _logger.debug("JWT auth failed: Missing Authorization header")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        # Extract the Bearer token from the header
        token = jwt_validator.extract_bearer_token(auth_header)
        if not token:
            _logger.debug("JWT auth failed: Invalid Authorization header format. Expected 'Bearer <token>'")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        # Validate the JWT token
        result: JwtValidationResult = jwt_validator.validate(token)
        if not result.is_valid:
            _logger.debug("JWT auth failed: Invalid or expired token")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        # Return the decoded payload and raw token wrapped in JWTAuthResult
        payload = cast(JWTPayload, result.payload)
        return JWTAuthResult(jwt=token, payload=payload)
