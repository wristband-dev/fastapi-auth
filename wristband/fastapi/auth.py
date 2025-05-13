import base64
from datetime import datetime
import secrets
import time
import json
from typing import Any, Literal, Optional
from urllib.parse import urlencode
import hashlib
from cryptography.fernet import Fernet
import logging

import requests
from fastapi import Request, Response
from starlette.responses import RedirectResponse
from starlette.datastructures import MutableHeaders

logger: logging.Logger = logging.getLogger(__name__)

from wristband.models import TokenData, TokenResponse
from wristband.api import WristbandError, Api
from wristband.enums import CallbackResultType
from wristband.models import (
    CallbackData,
    CallbackResult,
    LoginConfig,
    LoginState,
    AuthConfig,
    LogoutConfig,
)


class Auth:
    """
    static values shared by all instances of classes
    """

    _cookie_prefix: str = "login#"
    _login_state_cookie_separator: str = "#"

    def __init__(self, auth_config: AuthConfig) -> None:
        """
        dynamic values of auth config
        """
        self.client_id: str = auth_config.client_id
        self.client_secret: str = auth_config.client_secret
        self.login_state_secret: str = auth_config.login_state_secret
        self.login_url: str = auth_config.login_url
        self.redirect_uri: str = auth_config.redirect_uri
        self.wristband_application_domain: str = (
            auth_config.wristband_application_domain
        )
        self.custom_application_login_page_url: Optional[str] = (
            auth_config.custom_application_login_page_url
        )
        self.dangerously_disable_secure_cookies: bool = (
            auth_config.dangerously_disable_secure_cookies
        )
        self.root_domain: Optional[str] = auth_config.root_domain
        self.scopes: list[str] = auth_config.scopes
        self.use_custom_domains: bool = auth_config.use_custom_domains
        self.use_tenant_subdomains: bool = auth_config.use_tenant_subdomains

        self.api = Api(
            wristband_application_domain=self.wristband_application_domain,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

    def login(self, req: Request, config: LoginConfig = LoginConfig()) -> Response:
        """
        Initiates the login process by redirecting the user to the OAuth2 authorization endpoint.

        Args:
            req (Request): The FastAPI request object.
            config (LoginConfig, optional): Configuration for the login process. Defaults to LoginConfig().

        Returns:
            Response: The FastAPI response object with the appropriate redirection headers set.
        """

        # Determine which domain-related values are present as it will be needed for the authorize URL.
        tenant_custom_domain: str = self._resolve_tenant_custom_domain_param(req)
        tenant_domain_name: str = self._resolve_tenant_domain_name(
            req, self.root_domain
        )
        default_tenant_custom_domain: Optional[str] = (
            config.default_tenant_custom_domain
        )
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
            applogin_url: str = (
                self.custom_application_login_page_url
                or f"https://{self.wristband_application_domain}/login"
            )
            return RedirectResponse(url=applogin_url, status_code=302)

        # Create the login state which will be cached in a cookie so that it can be accessed in the callback.
        login_state: LoginState = self._create_login_state(
            req, self.redirect_uri, config.custom_state
        )

        # Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
        authorize_url: str = self._get_oauth_authorize_url(
            req,
            login_state,
            tenant_custom_domain,
            tenant_domain_name,
            default_tenant_custom_domain,
            default_tenant_domain_name,
        )

        # Create the redirect response
        res: Response = RedirectResponse(url=authorize_url, status_code=302)

        # Clear any stale login state cookies and add a new one fo rthe current request.
        self._clear_oldest_login_state_cookie(req, res)
        encrypted_login_state: bytes = self._encrypt_login_state(
            login_state, self.login_state_secret
        )

        # Create the login state cookie
        self._create_login_state_cookie(
            res,
            login_state.state,
            encrypted_login_state,
            self.dangerously_disable_secure_cookies,
        )

        # Perform the redirect to Wristband's Authorize Endpoint.
        return res

    def callback(self, req: Request) -> CallbackResult:
        """ """
        # 1) Extract Query Params from wristband callback
        code: str | None = req.query_params.get("code")
        param_state: str | None = req.query_params.get("state")
        error: str | None = req.query_params.get("error")

        error_description: str | None = req.query_params.get("error_description")
        tenant_custom_domain_param: str | None = req.query_params.get(
            "tenant_custom_domain"
        )

        # 2) Validate basic query params
        if not param_state:
            raise TypeError("Invalid or missing query parameter [state].")

        if not code:
            raise TypeError("Invalid query parameter [code].")

        if error:
            raise TypeError("Invalid query parameter [error].")

        if error_description:
            raise TypeError("Invalid query parameter [error_description].")

        if tenant_custom_domain_param:
            raise TypeError("Invalid query parameter [tenant_custom_domain].")

        # 3) Resolve tenant domain name
        resolved_tenant_domain_name: str = self._resolve_tenant_domain_name(
            req, self.root_domain
        )
        if not resolved_tenant_domain_name:
            # useTenantSubdomains is a design choice; adapt as needed
            if self.use_tenant_subdomains:
                raise ValueError(
                    "missing_tenant_subdomain: Callback request URL is missing a tenant subdomain"
                )
            else:
                raise ValueError(
                    "missing_tenant_domain: Callback request is missing the [tenant_domain] param"
                )

        # 4) Build the tenant login URL in case we need to redirect
        if self.use_tenant_subdomains:
            tenant_login_url: str = self.login_url.replace(
                "{tenant_domain}", resolved_tenant_domain_name
            )
        else:
            # fallback, append ?tenant_domain=...
            tenant_login_url: str = (
                f"{self.login_url}?tenant_domain={resolved_tenant_domain_name}"
            )

        # If the tenant_custom_domain is set, add that param
        if tenant_custom_domain_param:
            # If we already used ? above, use & now, etc.
            connector: Literal["&"] | Literal["?"] = (
                "&" if "?" in tenant_login_url else "?"
            )
            tenant_login_url: str = (
                f"{tenant_login_url}{connector}tenant_custom_domain={tenant_custom_domain_param}"
            )

        # Create a login redirect response for bad cases
        login_redirect_res = RedirectResponse(url=tenant_login_url, status_code=302)
        login_redirect_res.headers["Cache-Control"] = "no-store"
        login_redirect_res.headers["Pragma"] = "no-cache"

        # 5) Retrieve and decrypt the login state cookie
        login_state_cookie_name, login_state_cookie_val = self._get_login_state_cookie(
            req
        )

        if not login_state_cookie_val:
            # No valid cookie => We cannot verify the request => redirect to login
            return CallbackResult(
                type=CallbackResultType.REDIRECT_REQUIRED,
                callback_data=None,
                redirect_response=login_redirect_res,
            )

        try:
            login_state: LoginState = self._decrypt_login_state(
                login_state_cookie_val, self.login_state_secret
            )
        except Exception as e:
            print(e)
            # If decryption fails, redirect to login
            return CallbackResult(
                type=CallbackResultType.REDIRECT_REQUIRED,
                callback_data=None,
                redirect_response=login_redirect_res,
            )

        # 6) Validate the state from the cookie matches the incoming state param
        if param_state != login_state.state:
            # Mismatch => redirect
            return CallbackResult(
                type=CallbackResultType.REDIRECT_REQUIRED,
                callback_data=None,
                redirect_response=login_redirect_res,
            )

        if error:
            # If we specifically got a 'login_required' error, go back to the login
            if error.lower() == "login_required":
                return CallbackResult(
                    type=CallbackResultType.REDIRECT_REQUIRED,
                    callback_data=None,
                    redirect_response=login_redirect_res,
                )
            # Otherwise raise an exception
            raise ValueError(f"OAuth error: {error}. Description: {error_description}")

        #    Here you would call your Wristband token endpoint. Example:
        token_response: TokenResponse = self.api.get_tokens(
            code=code,
            redirect_uri=login_state.redirect_uri,
            code_verifier=login_state.code_verifier,
        )

        # 10) Fetch userinfo (again, depends on your own implementation)
        userinfo: dict[str, Any] = self.api.get_userinfo(
            token_response.access_token
        )

        callback_data: CallbackData = CallbackData(
            access_token=token_response.access_token,
            id_token=token_response.id_token,
            expires_in=token_response.expires_in,
            tenant_domain_name=resolved_tenant_domain_name,
            user_info=userinfo,
            custom_state=login_state.custom_state,
            refresh_token=token_response.refresh_token,
            return_url=login_state.return_url,
            tenant_custom_domain=tenant_custom_domain_param,
        )

        return CallbackResult(
            type=CallbackResultType.COMPLETED,
            callback_data=callback_data,
            redirect_response=None,
        )

    def logout(self, req: Request, config: Optional[LogoutConfig] = None) -> Response:
        # make response to return to client
        res = RedirectResponse(url=req.url, status_code=302)

        res.headers["Cache-Control"] = "no-store"
        res.headers["Pragma"] = "no-cache"

        # Revoke refresh token if present
        """
        The developer could opt to not pass in the refresh token
            - in that case don't revoke, and the refresh token will remain valid (not ideal)
        """
        refresh_token: Optional[str] = config.refresh_token if config else None
        if refresh_token:
            try:
                self._revoke_refresh_token(refresh_token)
            except Exception as e:
                logger.debug(f"Revoking the refresh token failed during logout: {e}")

        # Build query parameters
        query_params: dict[str, str] = {
            "client_id": self.client_id,
        }
        if config and config.redirect_url:
            query_params["redirect_url"] = config.redirect_url

        query_string: str = urlencode({k: v for k, v in query_params.items() if v})

        # Get host and determine tenant domain
        host: str = str(req.url.netloc)
        tenant_custom_domain: Optional[str] = (
            config.tenant_custom_domain if config else None
        )
        tenant_domain_name: Optional[str] = (
            config.tenant_domain_name if config else None
        )

        # Construct app login URL
        app_login_url: str = (
            self.custom_application_login_page_url
            or f"https://{self.wristband_application_domain}/login"
        )

        # Handle cases where we should redirect to app login
        if not tenant_custom_domain:
            host_root_domain: str = host.split(".")[-1]
            if self.use_tenant_subdomains and not host_root_domain == self.root_domain:
                res.headers["Location"] = (
                    f"{app_login_url}?client_id={self.client_id}"
                )
                return res
            if not self.use_tenant_subdomains and not tenant_domain_name:
                res.headers["Location"] = (
                    f"{app_login_url}?client_id={self.client_id}"
                )
                return res

        # Determine tenant domain to use
        if self.use_tenant_subdomains:
            tenant_domain_name = host.split(".")[0]

        separator: Literal["."] | Literal["-"] = "." if self.use_custom_domains else "-"
        tenant_domain_to_use: str = (
            tenant_custom_domain
            or f"{tenant_domain_name}{separator}{self.wristband_application_domain}"
        )

        # Perform logout redirect
        res.headers["Location"] = (
            f"https://{tenant_domain_to_use}/api/v1/logout?{query_string}"
        )

        return res

    def refresh_token_if_expired(
        self, refresh_token: Optional[str], expires_at: Optional[int]
    ) -> None | TokenData:

        # Safety checks
        if not refresh_token:
            raise TypeError("Refresh token must be a valid string")
        if not expires_at or expires_at < 0:
            raise TypeError("The expiresAt field must be an integer greater than 0")

        # Nothing to do here if the access token is still valid
        if not self.is_expired(expires_at):
            return None

        # Try up to 3 times to perform a token refresh
        retries = 2
        timeout = 0.1  # 100ms

        for attempt in range(retries + 1):
            try:
                token_response: TokenResponse = self.api.refresh_token(
                    refresh_token
                )
                break
            except requests.exceptions.RequestException as error:

                # Handle 4xx errors - don't retry these
                if error.response and 400 <= error.response.status_code < 500:
                    error_description: Any | Literal["Invalid Refresh Token"] = (
                        error.response.json().get(
                            "error_description", "Invalid Refresh Token"
                        )
                        if hasattr(error.response, "json")
                        else "Invalid Refresh Token"
                    )

                    raise WristbandError("invalid_refresh_token", error_description)

                # On last attempt, raise the error
                if attempt == retries:
                    raise WristbandError("unexpected_error", "Unexpected Error")

                # Wait before retrying
                time.sleep(timeout)

        if token_response:
            return TokenData.from_token_response(token_response)

        # Safety check that should never happen
        raise WristbandError("unexpected_error", "Unexpected Error")

    # --------- Login State Cookie Management --------- #
    def _resolve_tenant_custom_domain_param(self, req: Request) -> str:
        tenant_custom_domain = req.query_params.get("tenant_custom_domain")
        if tenant_custom_domain and isinstance(tenant_custom_domain, list):
            raise TypeError(
                "More than one [tenant_custom_domain] query parameter was encountered"
            )
        return tenant_custom_domain or ""

    def _resolve_tenant_domain_name(
        self, req: Request, root_domain: Optional[str]
    ) -> str:

        def parse_tenant_subdomain(
            req: Request, root_domain: Optional[str]
        ) -> Optional[str]:
            host = str(req.url.netloc)
            if root_domain is None or not host.endswith(root_domain):
                return None

            subdomain = host[: -len(root_domain)].rstrip(".")
            if subdomain:
                return subdomain

            return None

        if self.use_tenant_subdomains:
            return parse_tenant_subdomain(req, root_domain) or ""

        tenant_domain_param = req.query_params.get("tenant_domain")
        if tenant_domain_param and isinstance(tenant_domain_param, list):
            raise TypeError(
                "More than one [tenant_domain] query parameter was encountered"
            )

        return tenant_domain_param or ""

    def _create_login_state(
        self, req: Request, redirect_uri: str, custom_state: Optional[dict[str, str]]
    ) -> LoginState:

        return_url: str | None = req.query_params.get("return_url")
        if isinstance(return_url, list):
            raise TypeError(
                "More than one [return_url] query parameter was encountered"
            )

        return LoginState(
            state=self._generate_random_string(32),
            code_verifier=self._generate_random_string(64),
            redirect_uri=redirect_uri,
            return_url=return_url if return_url else None,
            custom_state=custom_state,
        )

    def _clear_login_state_cookie(
        self, res: Response, cookie_name: str, dangerously_disable_secure_cookies: bool
    ) -> None:
        # Use the Response API to set an expired cookie instead of manually appending to headers
        res.set_cookie(
            key=cookie_name,
            value="",
            path="/",
            httponly=True,
            samesite="lax",
            max_age=0,
            expires="Thu, 01 Jan 1970 00:00:00 GMT",
            secure=not dangerously_disable_secure_cookies
        )

    def _create_callback_response(self, req: Request, redirect_url: str) -> Response:
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

    def _generate_random_string(self, length: int) -> str:
        random_bytes = secrets.token_bytes(length)
        random_string = base64.urlsafe_b64encode(random_bytes).decode("utf-8")
        return random_string.rstrip("=")[:length]

    def _clear_oldest_login_state_cookie(self, req: Request, res: Response):
        cookies = req.cookies

        login_cookie_names = [
            name for name in cookies if name.startswith(self._cookie_prefix)
        ]
        if len(login_cookie_names) >= 3:
            timestamps = [
                name.split(self._login_state_cookie_separator)[2]
                for name in login_cookie_names
            ]
            newest_timestamps = sorted(timestamps, reverse=True)[:2]
            for cookie_name in login_cookie_names:
                timestamp = cookie_name.split(self._login_state_cookie_separator)[2]
                if timestamp not in newest_timestamps:
                    res.delete_cookie(cookie_name)

    def _encrypt_login_state(
        self, login_state: LoginState, login_state_secret: str
    ) -> bytes:
        key: bytes = base64.urlsafe_b64encode(
            login_state_secret.encode().ljust(32)[:32]
        )
        f: Fernet = Fernet(key)  # Must be a 32-byte URL-safe key
        encrypted: bytes = f.encrypt(json.dumps(login_state.to_dict()).encode("utf-8"))
        if len(encrypted) > 4096:
            raise TypeError("Login state cookie exceeds 4kB in size.")
        return encrypted

    def _create_login_state_cookie(
        self,
        res: Response,
        state: str,
        encrypted_login_state: bytes,
        disable_secure: bool = False,
    ):
        encrypted_str: str = encrypted_login_state.decode("utf-8")
        cookie_name: str = (
            f"{self._cookie_prefix}{state}{self._login_state_cookie_separator}{str(int(1000 * time.time()))}"
        )

        res.set_cookie(
            key=cookie_name,
            value=encrypted_str,
            max_age=3600,
            secure=not disable_secure,
            httponly=True,
            samesite="lax",
        )

    def _get_oauth_authorize_url(
        self,
        req: Request,
        login_state: LoginState,
        tenant_custom_domain: str,
        tenant_domain_name: str,
        default_tenant_custom_domain: Optional[str],
        default_tenant_domain_name: Optional[str],
    ) -> str:

        def base64_url_encode(data: bytes) -> str:
            b64: str = base64.b64encode(data).decode()
            return b64.replace("+", "-").replace("/", "_").replace("=", "")

        login_hint: str | None = req.query_params.get("login_hint")

        if isinstance(login_hint, list):
            raise TypeError(
                "More than one [login_hint] query parameter was encountered"
            )

        query_params: dict[str, str] = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": login_state.state,
            "scope": " ".join(self.scopes),
            "code_challenge": base64_url_encode(
                hashlib.sha256(login_state.code_verifier.encode()).digest()
            ),
            "code_challenge_method": "S256",
            "nonce": self._generate_random_string(32),
        }

        if login_hint:
            query_params["login_hint"] = login_hint

        separator: Literal["."] | Literal["-"] = "." if self.use_custom_domains else "-"

        if tenant_custom_domain:
            return f"https://{tenant_custom_domain}/api/v1/oauth2/authorize?{urlencode(query_params)}"
        elif tenant_domain_name:
            return f"https://{tenant_domain_name}{separator}{self.wristband_application_domain}/api/v1/oauth2/authorize?{urlencode(query_params)}"
        elif default_tenant_custom_domain:
            return f"https://{default_tenant_custom_domain}/api/v1/oauth2/authorize?{urlencode(query_params)}"
        else:
            return f"https://{default_tenant_domain_name}{separator}{self.wristband_application_domain}/api/v1/oauth2/authorize?{urlencode(query_params)}"

    def _get_login_state_cookie(self, req: Request) -> tuple[str | None, str | None]:
        cookies: dict[str, str] = req.cookies
        state: str | None = req.query_params.get("state")
        param_state: str = state if state else ""

        matching_login_cookie_names: list[str] = [
            cookie_name
            for cookie_name in cookies
            if cookie_name.startswith(
                f"{self._cookie_prefix}{param_state}{self._login_state_cookie_separator}"
            )
        ]

        if matching_login_cookie_names:
            cookie_name: str = matching_login_cookie_names[0]
            return cookie_name, cookies[cookie_name]

        return None, None

    def _decrypt_login_state(
        self, login_state_cookie: str, login_state_secret: str
    ) -> LoginState:
        key = base64.urlsafe_b64encode(login_state_secret.encode().ljust(32)[:32])
        f = Fernet(key)
        decrypted = f.decrypt(login_state_cookie.encode("utf-8"))
        login_state_dict = json.loads(decrypted.decode("utf-8"))
        return LoginState(**login_state_dict)

    def _revoke_refresh_token(self, refresh_token: str) -> None:
        self.api.revoke_refresh_token(refresh_token)

    def is_expired(self, expires_at: int) -> bool:
        return expires_at < int(datetime.now().timestamp() * 1000)
