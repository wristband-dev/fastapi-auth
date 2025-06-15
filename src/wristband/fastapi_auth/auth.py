import base64
from datetime import datetime
import secrets
import time
from typing import Any, Literal, Optional
from urllib.parse import urlencode
import hashlib
import logging

import httpx
from fastapi import Request, Response
from fastapi.responses import RedirectResponse

from .client import WristbandApiClient
from .exception import InvalidGrantError, WristbandError
from .models import (
    CallbackData,
    CallbackResult,
    CallbackResultType,
    LoginConfig,
    LoginState,
    AuthConfig,
    LogoutConfig,
    OAuthAuthorizeUrlConfig,
    TokenData,
    TokenResponse,
    UserInfo,
)
from .utils import SessionEncryptor

_logger: logging.Logger = logging.getLogger(__name__)
_tenant_domain_token: str = "{tenant_domain}"


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
    _token_refresh_retries = 2
    _token_refresh_retry_timeout = 0.1  # 100ms

    def __init__(self, auth_config: AuthConfig) -> None:
        if not auth_config.client_id or not auth_config.client_id.strip():
            raise ValueError("The [client_id] config must have a value.")
        if not auth_config.client_secret or not auth_config.client_secret.strip():
            raise ValueError("The [client_secret] config must have a value.")
        if (
            not auth_config.wristband_application_vanity_domain
            or not auth_config.wristband_application_vanity_domain.strip()
        ):
            raise ValueError("The [wristband_application_vanity_domain] config must have a value.")
        if (
            not auth_config.login_state_secret
            or not auth_config.login_state_secret.strip()
            or len(auth_config.login_state_secret) < 32
        ):
            raise ValueError("The [login_state_secret] config must have a value of at least 32 characters.")
        if not auth_config.login_url or not auth_config.login_url.strip():
            raise ValueError("The [login_url] config must have a value.")
        if not auth_config.redirect_uri or not auth_config.redirect_uri.strip():
            raise ValueError("The [redirect_uri] config must have a value.")
        if auth_config.parse_tenant_from_root_domain and auth_config.parse_tenant_from_root_domain.strip():
            if _tenant_domain_token not in auth_config.login_url:
                raise ValueError(
                    "The [login_url] must contain the '{tenant_domain}' token when using "
                    "[parse_tenant_from_root_domain]."
                )
            if _tenant_domain_token not in auth_config.redirect_uri:
                raise ValueError(
                    "The [redirect_uri] must contain the '{tenant_domain}' token when using "
                    "[parse_tenant_from_root_domain]."
                )
        else:
            if _tenant_domain_token in auth_config.login_url:
                raise ValueError(
                    "The [login_url] cannot contain the '{tenant_domain}' token when "
                    "[parse_tenant_from_root_domain] is not set."
                )
            if _tenant_domain_token in auth_config.redirect_uri:
                raise ValueError(
                    "The [redirect_uri] cannot contain the '{tenant_domain}' token when "
                    "[parse_tenant_from_root_domain] is not set."
                )

        self.client_id: str = auth_config.client_id
        self.client_secret: str = auth_config.client_secret
        self.login_state_secret: str = auth_config.login_state_secret
        self.login_url: str = auth_config.login_url
        self.redirect_uri: str = auth_config.redirect_uri
        self.wristband_application_vanity_domain: str = auth_config.wristband_application_vanity_domain
        self.custom_application_login_page_url: Optional[str] = auth_config.custom_application_login_page_url
        self.is_application_custom_domain_active: bool = (
            auth_config.is_application_custom_domain_active
            if auth_config.is_application_custom_domain_active is not None
            else False
        )
        self.dangerously_disable_secure_cookies: bool = (
            auth_config.dangerously_disable_secure_cookies
            if auth_config.dangerously_disable_secure_cookies is not None
            else False
        )
        self.parse_tenant_from_root_domain: Optional[str] = auth_config.parse_tenant_from_root_domain
        self.scopes: list[str] = auth_config.scopes

        self.wristband_api = WristbandApiClient(
            wristband_application_vanity_domain=self.wristband_application_vanity_domain,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

        self._login_state_encryptor = SessionEncryptor(secret_key=auth_config.login_state_secret)

    async def login(self, req: Request, config: LoginConfig = LoginConfig()) -> Response:
        """
        Initiates a login request by redirecting to Wristband. Constructs an OAuth2 Authorization
        Request to begin the Authorization Code flow.

        The incoming FastAPI request can include Wristband-specific query parameters:
        - login_hint: A hint about the user's preferred login identifier. This is passed as a query
          parameter in the redirect to the Authorize URL.
        - return_url: The URL to redirect the user to after authentication.
        - tenant_custom_domain: The tenant-specific custom domain, if applicable. Used as the domain
          for the Authorize URL when present.
        - tenant_domain: The tenant's domain name. Used as a subdomain or vanity domain in the
          Authorize URL if not using tenant custom domains.

        Args:
            req (Request): The FastAPI request object.
            config (LoginConfig, optional): Additional configuration for the login request,
                including default tenant domain and custom state.

        Returns:
            Response: A FastAPI Response object that redirects the user to the Wristband
            Authorize endpoint.
        """
        # Determine which domain-related values are present as it will be needed for the authorize URL.
        tenant_custom_domain: str = self._resolve_tenant_custom_domain_param(req)
        tenant_domain_name: str = self._resolve_tenant_domain_name(req, self.parse_tenant_from_root_domain)
        default_tenant_custom_domain: Optional[str] = config.default_tenant_custom_domain
        default_tenant_domain_name: Optional[str] = config.default_tenant_domain

        # In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
        if not any(
            [
                tenant_custom_domain,
                tenant_domain_name,
                default_tenant_custom_domain,
                default_tenant_domain_name,
            ]
        ):
            app_login_url: str = (
                self.custom_application_login_page_url
                or f"https://{self.wristband_application_vanity_domain}/login"
            )
            app_login_response: Response = RedirectResponse(
                url=f"{app_login_url}?client_id={self.client_id}", status_code=302
            )
            app_login_response.headers['Cache-Control'] = 'no-store'
            app_login_response.headers['Pragma'] = 'no-cache'
            return app_login_response

        # Create the login state which will be cached in a cookie so that it can be accessed in the callback.
        login_state: LoginState = self._create_login_state(req, self.redirect_uri, config.custom_state)

        # Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
        authorize_url: str = self._get_oauth_authorize_url(
            req,
            config=OAuthAuthorizeUrlConfig(
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                code_verifier=login_state.code_verifier,
                scopes=self.scopes,
                state=login_state.state,
                default_tenant_custom_domain=default_tenant_custom_domain,
                default_tenant_domain_name=default_tenant_domain_name,
                tenant_custom_domain=tenant_custom_domain,
                tenant_domain_name=tenant_domain_name,
                is_application_custom_domain_active=self.is_application_custom_domain_active,
                wristband_application_vanity_domain=self.wristband_application_vanity_domain,
            )
        )

        # Create the redirect response
        authorize_response: Response = RedirectResponse(url=authorize_url, status_code=302)
        authorize_response.headers['Cache-Control'] = 'no-store'
        authorize_response.headers['Pragma'] = 'no-cache'

        # Clear any stale login state cookies and add a new one for the current request.
        self._clear_oldest_login_state_cookie(req, authorize_response, self.dangerously_disable_secure_cookies)
        encrypted_login_state: str = self._encrypt_login_state(login_state)

        # Create the login state cookie
        self._create_login_state_cookie(
            authorize_response,
            login_state.state,
            encrypted_login_state,
            self.dangerously_disable_secure_cookies,
        )

        # Perform the redirect to Wristband's Authorize Endpoint.
        return authorize_response

    async def callback(self, req: Request) -> CallbackResult:
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
        - tenant_domain: The tenant's domain name. Used when redirecting to the Login Endpoint in setups
          that don't rely on tenant subdomains or custom domains.

        Args:
            req (Request): The FastAPI request object containing the callback query parameters.

        Returns:
            CallbackResult: An object representing the outcome of the callback process,
            including login state, user info, or redirect behavior.
        """
        # Extract and validate Query Params from wristband callback
        code: str | None = self._assert_single_param(req, "code")
        param_state: str | None = self._assert_single_param(req, "state")
        error: str | None = self._assert_single_param(req, "error")
        error_description: str | None = self._assert_single_param(req, "error_description")
        tenant_custom_domain_param: str | None = self._assert_single_param(req, "tenant_custom_domain")

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

        # Resolve and validate tenant domain name
        resolved_tenant_domain_name: str = self._resolve_tenant_domain_name(req, self.parse_tenant_from_root_domain)
        if not resolved_tenant_domain_name:
            if self.parse_tenant_from_root_domain:
                raise WristbandError("missing_tenant_subdomain", "Callback request URL is missing a tenant subdomain")
            else:
                raise WristbandError("missing_tenant_domain", "Callback request is missing the [tenant_domain] param")

        # Build the tenant login URL in case we need to redirect
        if self.parse_tenant_from_root_domain:
            tenant_login_url: str = self.login_url.replace("{tenant_domain}", resolved_tenant_domain_name)
        else:
            tenant_login_url = (f"{self.login_url}?tenant_domain={resolved_tenant_domain_name}")

        # If the tenant_custom_domain is set, add that query param
        if tenant_custom_domain_param:
            # If we already used "?" above, use "&"" instead
            connector: Literal["&"] | Literal["?"] = "&" if "?" in tenant_login_url else "?"
            tenant_login_url = f"{tenant_login_url}{connector}tenant_custom_domain={tenant_custom_domain_param}"

        # Retrieve and decrypt the login state cookie
        _, login_state_cookie_val = self._get_login_state_cookie(req)

        # Create a redirect result in the event of any edge cases.
        redirect_callback_result = CallbackResult(
            type=CallbackResultType.REDIRECT_REQUIRED,
            callback_data=None,
            redirect_url=tenant_login_url,
        )

        # No valid cookie, we cannot verify the request
        if not login_state_cookie_val:
            return redirect_callback_result

        login_state: LoginState = self._decrypt_login_state(login_state_cookie_val)

        # Validate the state from the cookie matches the incoming state param
        if param_state != login_state.state:
            return redirect_callback_result

        if error:
            # If we specifically got a 'login_required' error, go back to the login
            if error.lower() == "login_required":
                return redirect_callback_result
            # Otherwise raise an exception
            raise WristbandError(error, error_description or "")

        if code is None:
            raise ValueError("Invalid query parameter [code] passed from Wristband during callback")

        try:
            # Call Wristband Token API
            token_response: TokenResponse = await self.wristband_api.get_tokens(
                code=code,
                redirect_uri=login_state.redirect_uri,
                code_verifier=login_state.code_verifier,
            )

            # Call Wristband Userinfo API
            userinfo: UserInfo = await self.wristband_api.get_userinfo(token_response.access_token)

            # Return the callback data and result
            return CallbackResult(
                type=CallbackResultType.COMPLETED,
                redirect_url=None,
                callback_data=CallbackData(
                    access_token=token_response.access_token,
                    id_token=token_response.id_token,
                    expires_in=token_response.expires_in,
                    tenant_domain_name=resolved_tenant_domain_name,
                    user_info=userinfo,
                    custom_state=login_state.custom_state,
                    refresh_token=token_response.refresh_token,
                    return_url=login_state.return_url,
                    tenant_custom_domain=tenant_custom_domain_param,
                ),
            )
        except InvalidGrantError:
            return redirect_callback_result
        except Exception as ex:
            raise ex

    async def create_callback_response(self, req: Request, redirect_url: str) -> Response:
        """
        Constructs the redirect response to your application and cleans up the login state.

        Args:
            req (Request): The FastAPI request object.
            redirect_url (str): The location for your application that you want to send users to.

        Returns:
            Response: The FastAPI Response that is performing the URL redirect to your desired application URL.
        """
        if not redirect_url:
            raise TypeError("redirect_url cannot be null or empty")

        redirect_response = RedirectResponse(redirect_url, status_code=302)
        redirect_response.headers["Cache-Control"] = "no-store"
        redirect_response.headers["Pragma"] = "no-cache"

        login_state_cookie_name, _ = self._get_login_state_cookie(req)
        if login_state_cookie_name:
            self._clear_login_state_cookie(
                redirect_response,
                login_state_cookie_name,
                self.dangerously_disable_secure_cookies,
            )

        return redirect_response

    async def logout(self, req: Request, config: LogoutConfig = LogoutConfig()) -> Response:
        """
        Logs the user out by revoking their refresh token (if provided) and constructing a redirect
        URL to Wristband's Logout Endpoint.

        Args:
            req (Request): The FastAPI request object containing user session or token data.
            config (LogoutConfig, optional): Optional configuration parameters for the logout process,
            such as a custom return URL or tenant domain.

        Returns:
            Response: A FastAPI redirect response to Wristband's Logout Endpoint.
        """
        # Revoke refresh token, if present
        if config.refresh_token:
            try:
                await self.wristband_api.revoke_refresh_token(config.refresh_token)
            except Exception as e:
                # No need to block logout execution if revoking fails
                _logger.warning(f"Revoking the refresh token failed during logout: {e}")

        # Get host and determine tenant domain
        tenant_domain_name: str = self._resolve_tenant_domain_name(req, self.parse_tenant_from_root_domain)
        tenant_custom_domain: str = self._resolve_tenant_custom_domain_param(req)
        separator: Literal["."] | Literal["-"] = "." if self.is_application_custom_domain_active else "-"
        redirect_url = f"&redirect_url={config.redirect_url}" if config.redirect_url else ""
        logout_path = f"/api/v1/logout?client_id={self.client_id}{redirect_url}"

        # make response to return to client
        res = RedirectResponse(url=req.url, status_code=302)
        res.headers["Cache-Control"] = "no-store"
        res.headers["Pragma"] = "no-cache"

        # Domain priority order resolution:
        # 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
        if config.tenant_custom_domain and config.tenant_custom_domain.strip():
            res.headers["Location"] = f"https://{config.tenant_custom_domain}{logout_path}"
            return res

        # 2) If the LogoutConfig has a tenant domain defined, then use that.
        if config.tenant_domain_name and config.tenant_domain_name.strip():
            res.headers["Location"] = (
                f"https://{config.tenant_domain_name}{separator}{self.wristband_application_vanity_domain}{logout_path}"
            )
            return res

        # 3) If the tenant_custom_domain query param exists, then use that.
        if tenant_custom_domain and tenant_custom_domain.strip():
            res.headers["Location"] = f"https://{tenant_custom_domain}{logout_path}"
            return res

        # 4a) If tenant subdomains are enabled, get the tenant domain from the host.
        # 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_domain query param.
        if tenant_domain_name and tenant_domain_name.strip():
            res.headers["Location"] = (
                f"https://{tenant_domain_name}{separator}{self.wristband_application_vanity_domain}{logout_path}"
            )
            return res

        # Otherwise, fallback to app login URL (or custom logout redirect URL) if tenant cannot be determined.
        app_login_url: str = (
            self.custom_application_login_page_url
            or f"https://{self.wristband_application_vanity_domain}/login"
        )
        res.headers["Location"] = config.redirect_url or f"{app_login_url}?client_id={self.client_id}"
        return res

    async def refresh_token_if_expired(
        self, refresh_token: Optional[str], expires_at: Optional[int]
    ) -> TokenData | None:
        """
        Checks if the user's access token has expired and refreshes the token, if necessary.

        Args:
            refresh_token (Optional[str]): The refresh token used to obtain a new access token.
            expires_at (Optional[int]): Unix timestamp in milliseconds indicating when the current access token expires.

        Returns:
            TokenData | None: The refreshed token data if a new token was obtained, otherwise None.
        """
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
                token_response: TokenResponse = await self.wristband_api.refresh_token(refresh_token)
                return TokenData.from_token_response(token_response)
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

        # Safety check that should never happen
        raise WristbandError("unexpected_error", "Unexpected Error")

    #####################################################
    # --------------- Helper Functions ---------------- #
    #####################################################

    def _resolve_tenant_custom_domain_param(self, request: Request) -> str:
        tenant_custom_domain_param = request.query_params.getlist("tenant_custom_domain")

        if tenant_custom_domain_param and len(tenant_custom_domain_param) > 1:
            raise TypeError("More than one [tenant_custom_domain] query parameter was encountered")

        return tenant_custom_domain_param[0] if tenant_custom_domain_param else ""

    def _resolve_tenant_domain_name(self, req: Request, parse_tenant_from_root_domain: Optional[str]) -> str:
        if parse_tenant_from_root_domain and parse_tenant_from_root_domain.strip():
            host = str(req.url.netloc)

            if not host.endswith(parse_tenant_from_root_domain):
                return ""

            subdomain: str = host[: -len(parse_tenant_from_root_domain)].rstrip(".")
            return subdomain or ""

        tenant_domain_param_list = req.query_params.getlist("tenant_domain")
        if len(tenant_domain_param_list) > 1:
            raise TypeError("More than one [tenant_domain] query parameter was encountered")

        return tenant_domain_param_list[0] if tenant_domain_param_list else ""

    def _create_login_state(
        self, req: Request, redirect_uri: str, custom_state: Optional[dict[str, Any]] = None
    ) -> LoginState:
        return_url_list = req.query_params.getlist("return_url")
        if len(return_url_list) > 1:
            raise TypeError("More than one [return_url] query parameter was encountered")

        return LoginState(
            state=self._generate_random_string(),
            code_verifier=self._generate_random_string(64),
            redirect_uri=redirect_uri,
            return_url=return_url_list[0] if return_url_list else None,
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
            secure=not dangerously_disable_secure_cookies
        )

    def _generate_random_string(self, length: int = 32) -> str:
        random_bytes = secrets.token_bytes(length)
        random_string = base64.urlsafe_b64encode(random_bytes).decode("utf-8")
        return random_string.rstrip("=")[:length]

    def _clear_oldest_login_state_cookie(
        self, req: Request, res: Response, dangerously_disable_secure_cookies: bool
    ) -> None:
        cookies = req.cookies
        login_cookie_names = [
            name for name in cookies if name.startswith(self._cookie_prefix)
        ]

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
                        cookie_name,
                        httponly=True,
                        secure=not dangerously_disable_secure_cookies,
                        path="/"
                    )

    def _encrypt_login_state(self, login_state: LoginState) -> str:
        encrypted_str = self._login_state_encryptor.encrypt(login_state.to_dict())

        if len(encrypted_str.encode("utf-8")) > 4096:
            raise TypeError("Login state cookie exceeds 4kB in size.")

        return encrypted_str

    def _create_login_state_cookie(
        self,
        res: Response,
        state: str,
        encrypted_login_state: str,
        disable_secure: bool = False,
    ):
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

    def _get_oauth_authorize_url(self, req: Request, config: OAuthAuthorizeUrlConfig) -> str:
        login_hint_list = req.query_params.getlist("login_hint")
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
        separator: Literal["."] | Literal["-"] = "." if config.is_application_custom_domain_active else "-"
        path_and_query: str = f"/api/v1/oauth2/authorize?{urlencode(query_params)}"

        # Domain priority order resolution:
        # 1)  tenant_custom_domain query param
        # 2a) tenant subdomain
        # 2b) tenant_domain query param
        # 3)  defaultTenantCustomDomain login config
        # 4)  defaultTenantDomainName login config
        if config.tenant_custom_domain:
            return f"https://{config.tenant_custom_domain}{path_and_query}"
        if config.tenant_domain_name:
            return (
                f"https://{config.tenant_domain_name}"
                f"{separator}{config.wristband_application_vanity_domain}"
                f"{path_and_query}"
            )
        if config.default_tenant_custom_domain:
            return f"https://{config.default_tenant_custom_domain}{path_and_query}"

        # By this point, we know the tenant domain name has already resolved properly, so just return the default.
        return (
            f"https://{config.default_tenant_domain_name}"
            f"{separator}{config.wristband_application_vanity_domain}"
            f"{path_and_query}"
        )

    def _assert_single_param(self, req: Request, param: str) -> str | None:
        values = req.query_params.getlist(param)
        if len(values) > 1:
            raise TypeError(f"Duplicate query parameter [{param}] passed from Wristband during callback")
        return values[0] if values else None

    def _get_login_state_cookie(self, req: Request) -> tuple[str | None, str | None]:
        cookies: dict[str, str] = req.cookies
        state: str | None = req.query_params.get("state")
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
