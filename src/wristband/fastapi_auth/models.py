from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field

########################################
# AUTH CONFIG MODELS
########################################


class AuthConfig(BaseModel):
    """
    Represents the configuration for Wristband authentication.

    Attributes:
        auto_configure_enabled: Flag that tells the SDK to automatically set some of the SDK configuration values by
            calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take
            precedence over the configs returned from the endpoint. Auto-configure is enabled by default. When disabled,
            if manual configurations are not provided, then an error will be thrown.
        client_id: The client ID for the application.
        client_secret: The client secret for the application.
        login_state_secret: A secret (32 or more characters in length) used for encryption and decryption of login state
            cookies. If not provided, it will default to using the client secret. For enhanced security, it is
            recommended to provide a value that is unique from the client secret.
        login_url: The URL for initiating the login request. This field is auto-configurable. Required when
            auto-configure is disabled.
        redirect_uri: The redirect URI for callback after authentication. This field is auto-configurable. Required
            when auto-configure is disabled.
        wristband_application_vanity_domain: The vanity domain of the Wristband application.
        custom_application_login_page_url: Custom application login (tenant discovery) page URL if you are
            self-hosting the application login/tenant discovery UI. This field is auto-configurable.
        dangerously_disable_secure_cookies: If set to True, the "Secure" attribute will not be
            included in any cookie settings. This should only be done when testing in local
            development (if necessary).
        is_application_custom_domain_active: Indicates whether an application-level custom domain
            is active in your Wristband application. This field is auto-configurable.
        parse_tenant_from_root_domain: The root domain for your application from which to parse
            out the tenant domain name. Indicates whether tenant subdomains are used for authentication.
            This field is auto-configurable.
        scopes: The scopes required for authentication.
        token_expiration_buffer: Buffer time (in seconds) to subtract from the access token’s expiration time.
            This causes the token to be treated as expired before its actual expiration, helping to avoid token
            expiration during API calls. Defaults to 60 seconds.
    """

    client_id: str
    client_secret: str
    wristband_application_vanity_domain: str
    auto_configure_enabled: bool = True
    custom_application_login_page_url: Optional[str] = None
    dangerously_disable_secure_cookies: bool = False
    is_application_custom_domain_active: Optional[bool] = None
    login_state_secret: Optional[str] = None
    login_url: Optional[str] = None
    parse_tenant_from_root_domain: Optional[str] = None
    redirect_uri: Optional[str] = None
    scopes: List[str] = Field(default=["openid", "offline_access", "email"])
    token_expiration_buffer: int = 60


class SdkConfiguration(BaseModel):
    """
    Represents the SDK configuration returned from Wristband's SDK Auto-Configuration Endpoint.

    Attributes:
        custom_application_login_page_url: Custom application login (tenant discovery) page URL if you are
            self-hosting the application login/tenant discovery UI.
        is_application_custom_domain_active: Indicates whether an application-level custom domain
            is active in your Wristband application.
        login_url: The URL for initiating the login request.
        login_url_tenant_domain_suffix: The tenant domain suffix for the login URL when using tenant subdomains.
        redirect_uri: The redirect URI for callback after authentication.
    """

    login_url: str
    redirect_uri: str
    is_application_custom_domain_active: bool
    custom_application_login_page_url: Optional[str] = None
    login_url_tenant_domain_suffix: Optional[str] = None

    @staticmethod
    def from_api_response(response: dict[str, Any]) -> "SdkConfiguration":
        """
        Creates an SdkConfiguration instance from an API response dictionary.

        Args:
            response: The raw API response containing SDK configuration data.

        Returns:
            An SdkConfiguration instance with the parsed configuration data.
        """
        return SdkConfiguration(
            login_url=response["loginUrl"],
            redirect_uri=response["redirectUri"],
            is_application_custom_domain_active=response.get("isApplicationCustomDomainActive", False),
            custom_application_login_page_url=response.get("customApplicationLoginPageUrl"),
            login_url_tenant_domain_suffix=response.get("loginUrlTenantDomainSuffix"),
        )


########################################
# LOGIN MODELS
########################################


class LoginConfig(BaseModel):
    """
    Represents the configuration for login.

    Attributes:
        custom_state: Custom state data for the login request.
        default_tenant_custom_domain: An optional default tenant custom domain to use for the
            login request in the event the tenant custom domain cannot be found in the
            "tenant_custom_domain" request query parameter.
        default_tenant_domain: An optional default tenant domain name to use for the login
            request in the event the tenant domain cannot be found in either the subdomain or
            the "tenant_domain" request query parameter (depending on your subdomain configuration).
        return_url: The URL to return to after authentication is completed. If a value is provided,
            then it takes precence over the `return_url` request query parameter.
    """

    custom_state: Optional[dict[str, Any]] = None
    default_tenant_custom_domain: Optional[str] = None
    default_tenant_domain: Optional[str] = None
    return_url: Optional[str] = None


class OAuthAuthorizeUrlConfig(BaseModel):
    """
    Represents the configuration for building OAuth authorization URLs.

    Attributes:
        client_id: The client ID for the application.
        code_verifier: The code verifier for PKCE (Proof Key for Code Exchange).
        redirect_uri: The redirect URI for callback after authentication.
        scopes: The scopes required for authentication.
        state: The state parameter for OAuth security.
        wristband_application_vanity_domain: The vanity domain of the Wristband application.
        default_tenant_custom_domain: An optional default tenant custom domain to use for the
            login request in the event the tenant custom domain cannot be found in the
            "tenant_custom_domain" request query parameter.
        default_tenant_domain_name: An optional default tenant domain name to use for the
            login request in the event the tenant domain cannot be found in either the subdomain
            or the "tenant_domain" request query parameter (depending on your subdomain configuration).
        tenant_custom_domain: The tenant custom domain for the current login request.
        tenant_domain_name: The domain name of the tenant for the current login request.
        is_application_custom_domain_active: Indicates whether an application-level custom domain
            is active in your Wristband application.
    """

    client_id: str
    code_verifier: str
    redirect_uri: str
    scopes: List[str]
    state: str
    wristband_application_vanity_domain: str
    default_tenant_custom_domain: Optional[str] = None
    default_tenant_domain_name: Optional[str] = None
    tenant_custom_domain: Optional[str] = None
    tenant_domain_name: Optional[str] = None
    is_application_custom_domain_active: Optional[bool] = False


class LoginState(BaseModel):
    """
    Represents all possible state for the current login request, which is stored in the login state cookie.

    Attributes:
        state: The state of the login process.
        code_verifier: The code verifier for PKCE.
        redirect_uri: The redirect URI for callback after authentication.
        return_url: The URL to return to after authentication.
        custom_state: Custom state data for the login state.
    """

    state: str
    code_verifier: str
    redirect_uri: str
    return_url: Optional[str]
    custom_state: Optional[dict[str, Any]]


########################################
# CALLBACK MODELS
########################################


class CallbackResultType(Enum):
    """
    Enum representing different possible results from the execution of the callback handler.

    Values:
        COMPLETED: Indicates that the callback is successfully completed and data is available
            for creating a session.
        REDIRECT_REQUIRED: Indicates that a redirect is required, generally to a login route or page.
    """

    COMPLETED = "COMPLETED"
    REDIRECT_REQUIRED = "REDIRECT_REQUIRED"


UserInfo = dict[str, Any]
"""
Represents user information for the user who is authenticating.

Note: Refer to the Wristband userinfo endpoint documentation to see the full list of possible
claims that can be returned, depending on your scopes.
"""


class CallbackData(BaseModel):
    """
    Represents the callback data received after authentication.

    Attributes:
        access_token: The access token.
        id_token: The ID token.
        expires_at: The absolute expiration time of the access token in milliseconds since Unix epoch
        expires_in: The duration from the current time until the access token is expired (in seconds).
        tenant_domain_name: The domain name of the tenant the user belongs to.
        user_info: User information received in the callback.
        custom_state: Custom state data received in the callback.
        refresh_token: The refresh token.
        return_url: The URL to return to after authentication.
        tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to.
    """

    access_token: str
    id_token: str
    expires_at: int
    expires_in: int
    tenant_domain_name: str
    user_info: UserInfo
    custom_state: Optional[dict[str, Any]]
    refresh_token: Optional[str]
    return_url: Optional[str]
    tenant_custom_domain: Optional[str]


class TokenData(BaseModel):
    """
    Represents the token data received after authentication.

    Attributes:
        access_token: The access token.
        id_token: The ID token.
        expires_at: The absolute expiration time of the access token in milliseconds since Unix epoch
        expires_in: The duration from the current time until the access token is expired (in seconds).
        refresh_token: The refresh token.
    """

    access_token: str
    id_token: str
    expires_at: int
    expires_in: int
    refresh_token: str


class CallbackResult(BaseModel):
    """
    Represents the result of the callback execution after authentication. It can include the set of
    callback data necessary for creating an authenticated session in the event a redirect is not required.

    Attributes:
        callback_data: The callback data received after authentication (COMPLETED only).
        type: Enum representing the end result of callback execution.
        redirect_url: The URL to redirect to (REDIRECT_REQUIRED only).
    """

    callback_data: Optional[CallbackData]
    type: CallbackResultType
    redirect_url: Optional[str]


class TokenResponse(BaseModel):
    """
    Represents the token response received from the Wristband token endpoint.

    Attributes:
        access_token: The access token.
        token_type: The type of token.
        expires_in: The expiration time of the access token (in seconds).
        refresh_token: The refresh token.
        id_token: The ID token.
        scope: The scope of the access token.
    """

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    id_token: str
    scope: str

    @staticmethod
    def from_api_response(response: dict[str, Any]) -> "TokenResponse":
        """
        Creates a TokenResponse instance from an API response dictionary.

        Args:
            response: The raw API response containing token information.

        Returns:
            A TokenResponse instance with the parsed token data.
        """
        return TokenResponse(
            access_token=response["access_token"],
            token_type=response["token_type"],
            expires_in=response["expires_in"],
            refresh_token=response["refresh_token"],
            id_token=response["id_token"],
            scope=response["scope"],
        )


########################################
# LOGOUT MODELS
########################################


class LogoutConfig(BaseModel):
    """
    Represents the configuration for logout.

    Attributes:
        redirect_url: Optional URL that the logout endpoint will redirect to after completing
            the logout operation.
        refresh_token: The refresh token to revoke during logout.
        state: Optional value that will be appended as a query parameter to the resolved logout URL, if provided.
            This is used to preserve any desired state throughout the logout flow.
        tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to
            (if applicable).
        tenant_domain_name: The domain name of the tenant the user belongs to.
    """

    redirect_url: Optional[str] = None
    refresh_token: Optional[str] = None
    state: Optional[str] = None
    tenant_custom_domain: Optional[str] = None
    tenant_domain_name: Optional[str] = None
