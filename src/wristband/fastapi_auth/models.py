from enum import Enum
from typing import Annotated, Any, Dict, Iterator, List, Optional, Protocol, TypedDict, Union

from pydantic import BaseModel, ConfigDict, Field
from wristband.python_jwt import JWTPayload

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
            out the tenant name. Indicates whether tenant subdomains are used for authentication.
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
        default_tenant_name: An optional default tenant name to use for the login request in the
            event the name cannot be found in either the subdomain or the "tenant_name" request
            query parameter (depending on your subdomain configuration).
        return_url: The URL to return to after authentication is completed. If a value is provided,
            then it takes precence over the `return_url` request query parameter.
    """

    custom_state: Optional[dict[str, Any]] = None
    default_tenant_custom_domain: Optional[str] = None
    default_tenant_name: Optional[str] = None
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
        default_tenant_name: An optional default tenant name to use for the login request in the event
            the name cannot be found in either the subdomain or the "tenant_name" request query
            parameter (depending on your subdomain configuration).
        tenant_custom_domain: The tenant custom domain for the current login request.
        tenant_name: The name of the tenant for the current login request.
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
    default_tenant_name: Optional[str] = None
    tenant_custom_domain: Optional[str] = None
    tenant_name: Optional[str] = None
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

    COMPLETED = "completed"
    REDIRECT_REQUIRED = "redirect_required"


class CallbackFailureReason(Enum):
    """
    Reason why callback processing failed and requires a redirect to retry authentication.

    Attributes:
        MISSING_LOGIN_STATE: Login state cookie was not found (cookie expired or bookmarked callback URL)
        INVALID_LOGIN_STATE: Login state validation failed (possible CSRF attack or cookie tampering)
        LOGIN_REQUIRED: Wristband returned a login_required error (session expired or max_age elapsed)
        INVALID_GRANT: Authorization code was invalid, expired, or already used
    """

    MISSING_LOGIN_STATE = "missing_login_state"
    INVALID_LOGIN_STATE = "invalid_login_state"
    LOGIN_REQUIRED = "login_required"
    INVALID_GRANT = "invalid_grant"


class UserInfoRole(BaseModel):
    """
    User Info Role model.

    Represents a role assigned to a user in Wristband. This is a subset of the
    fields from the Role entity in Wristband's Resource Management API.

    Attributes:
        id (str): Globally unique ID of the role.
        name (str): The role name (e.g., "app:app-name:admin").
        display_name (str): The human-readable display name for the role.

    Serializes to:
        {
            "id": "x25rpgafgvgedcvjw52ooul3xm",
            "name": "app:app-name:admin",
            "displayName": "Admin Role"
        }
    """

    model_config = ConfigDict(serialize_by_alias=True, populate_by_name=True)

    id: str
    name: str
    display_name: str = Field(validation_alias="displayName", serialization_alias="displayName")


class RawUserInfo(BaseModel):
    """
    Raw User Info model with original OIDC claim names.

    This internal model represents user information returned directly from
    Wristband's OIDC-compliant UserInfo endpoint using the original OIDC
    claim names. Use this model for internal SDK operations when working
    with the raw API response.

    For external/public use, use the UserInfo model which maps claim names
    to match Wristband's User entity field names.

    Attributes:
        sub (str): Subject identifier - ID of the user.
        tnt_id (str): Tenant ID.
        app_id (str): Application ID.
        idp_name (str): Identity provider name.
        name (Optional[str]): Full name.
        given_name (Optional[str]): Given/first name.
        family_name (Optional[str]): Family/last name.
        middle_name (Optional[str]): Middle name.
        nickname (Optional[str]): Nickname.
        preferred_username (Optional[str]): Preferred username.
        picture (Optional[str]): Profile picture URL.
        email (Optional[str]): Email address.
        email_verified (Optional[bool]): Email verification status.
        gender (Optional[str]): Gender.
        birthdate (Optional[str]): Birthdate in YYYY-MM-DD format.
        zoneinfo (Optional[str]): Time zone.
        locale (Optional[str]): Locale.
        phone_number (Optional[str]): Phone number.
        phone_number_verified (Optional[bool]): Phone verification status.
        updated_at (Optional[int]): Last update timestamp.
        roles (Optional[list[UserInfoRole]]): User roles.
        custom_claims (Optional[dict[str, Any]]): Custom claims.
    """

    model_config = ConfigDict(populate_by_name=True)

    # Always returned
    sub: str
    tnt_id: str
    app_id: str
    idp_name: str

    # Profile scope
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    middle_name: Optional[str] = None
    nickname: Optional[str] = None
    preferred_username: Optional[str] = None
    picture: Optional[str] = None
    gender: Optional[str] = None
    birthdate: Optional[str] = None
    zoneinfo: Optional[str] = None
    locale: Optional[str] = None
    updated_at: Optional[int] = None

    # Email scope
    email: Optional[str] = None
    email_verified: Optional[bool] = None

    # Phone scope
    phone_number: Optional[str] = None
    phone_number_verified: Optional[bool] = None

    # Roles scope
    roles: Optional[list[UserInfoRole]] = None

    # Custom claims
    custom_claims: Optional[dict[str, Any]] = None


class UserInfo(BaseModel):
    """
    User Info model representing claims from the Wristband UserInfo endpoint.

    This model represents user information returned from Wristband's OIDC-compliant
    UserInfo endpoint, with field names mapped to match the User entity field names
    in Wristband's Resource Management API. The claims returned depend on the scopes
    requested during authorization.

    Always returned claims: user_id, tenant_id, application_id, identity_provider_name

    Scope-dependent claims:
    - profile: full_name, given_name, family_name, middle_name, nickname, display_name,
               picture_url, gender, birthdate, time_zone, locale, updated_at
    - email: email, email_verified
    - phone: phone_number, phone_number_verified
    - roles: roles

    Attributes:
        user_id (str): ID of the user (mapped from "sub" claim).
        tenant_id (str): ID of the tenant that the user belongs to (mapped from "tnt_id").
        application_id (str): ID of the application that the user belongs to (mapped from "app_id").
        identity_provider_name (str): Name of the identity provider (mapped from "idp_name").
        full_name (Optional[str]): End-User's full name in displayable form (mapped from "name").
        given_name (Optional[str]): Given name(s) or first name(s) of the End-User.
        family_name (Optional[str]): Surname(s) or last name(s) of the End-User.
        middle_name (Optional[str]): Middle name(s) of the End-User.
        nickname (Optional[str]): Casual name of the End-User.
        display_name (Optional[str]): Shorthand name by which the End-User wishes to be referred
                                      (mapped from "preferred_username").
        picture_url (Optional[str]): URL of the End-User's profile picture (mapped from "picture").
        email (Optional[str]): End-User's preferred email address.
        email_verified (Optional[bool]): True if the End-User's email address has been verified.
        gender (Optional[str]): End-User's gender.
        birthdate (Optional[str]): End-User's birthday in YYYY-MM-DD format.
        time_zone (Optional[str]): End-User's time zone (mapped from "zoneinfo").
        locale (Optional[str]): End-User's locale as BCP47 language tag (e.g., "en-US").
        phone_number (Optional[str]): End-User's telephone number in E.164 format.
        phone_number_verified (Optional[bool]): True if the End-User's phone number has been verified.
        updated_at (Optional[int]): Time the End-User's information was last updated (Unix timestamp).
        roles (Optional[list[UserInfoRole]]): The roles assigned to the user.
        custom_claims (Optional[dict[str, Any]]): Object containing any configured custom claims.

    Serializes to:
        {
            "userId": "x25rpgafgvgedcvjw52ooul3xm",
            "tenantId": "lu4a47jcm2ejayovsgbgbpkihb",
            "applicationId": "hblu4a47jcm2ejayovsgbgbpki",
            "identityProviderName": "Wristband",
            "fullName": "Bob Jay Smith",
            "givenName": "Bob",
            "familyName": "Smith",
            "email": "bob@example.com",
            "emailVerified": true,
            "roles": [
                {
                    "id": "x25rpgafgvgedcvjw52ooul3xm",
                    "name": "app:app-name:admin",
                    "displayName": "Admin Role"
                }
            ],
            "customClaims": {
                "fieldA": "a",
                "fieldB": "b"
            }
        }
    """

    model_config = ConfigDict(serialize_by_alias=True, populate_by_name=True)

    # Always returned - mapped from OIDC standard claims
    user_id: str = Field(validation_alias="userId", serialization_alias="userId")
    tenant_id: str = Field(validation_alias="tenantId", serialization_alias="tenantId")
    application_id: str = Field(validation_alias="applicationId", serialization_alias="applicationId")
    identity_provider_name: str = Field(
        validation_alias="identityProviderName", serialization_alias="identityProviderName"
    )

    # Profile scope - mapped to User entity field names
    full_name: Optional[str] = Field(default=None, validation_alias="fullName", serialization_alias="fullName")
    given_name: Optional[str] = Field(default=None, validation_alias="givenName", serialization_alias="givenName")
    family_name: Optional[str] = Field(default=None, validation_alias="familyName", serialization_alias="familyName")
    middle_name: Optional[str] = Field(default=None, validation_alias="middleName", serialization_alias="middleName")
    nickname: Optional[str] = None
    display_name: Optional[str] = Field(default=None, validation_alias="displayName", serialization_alias="displayName")
    picture_url: Optional[str] = Field(default=None, validation_alias="pictureUrl", serialization_alias="pictureUrl")
    gender: Optional[str] = None
    birthdate: Optional[str] = None
    time_zone: Optional[str] = Field(default=None, validation_alias="timeZone", serialization_alias="timeZone")
    locale: Optional[str] = None
    updated_at: Optional[int] = Field(default=None, validation_alias="updatedAt", serialization_alias="updatedAt")

    # Email scope
    email: Optional[str] = None
    email_verified: Optional[bool] = Field(
        default=None, validation_alias="emailVerified", serialization_alias="emailVerified"
    )

    # Phone scope
    phone_number: Optional[str] = Field(default=None, validation_alias="phoneNumber", serialization_alias="phoneNumber")
    phone_number_verified: Optional[bool] = Field(
        default=None, validation_alias="phoneNumberVerified", serialization_alias="phoneNumberVerified"
    )

    # Roles scope
    roles: Optional[List[UserInfoRole]] = None

    # Custom claims
    custom_claims: Optional[Dict[str, Any]] = Field(
        default=None, validation_alias="customClaims", serialization_alias="customClaims"
    )


class CallbackData(BaseModel):
    """
    Represents the callback data received after authentication.

    Attributes:
        access_token: The access token.
        id_token: The ID token.
        expires_at: The absolute expiration time of the access token in milliseconds since Unix epoch
        expires_in: The duration from the current time until the access token is expired (in seconds).
        tenant_name: The name of the tenant the user belongs to.
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
    tenant_name: str
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


class CompletedCallbackResult(BaseModel):
    """Callback successfully completed with data for creating a session."""

    type: CallbackResultType = Field(CallbackResultType.COMPLETED, frozen=True)
    """Discriminator field indicating successful completion."""
    callback_data: CallbackData
    """Data returned from successful callback processing, used to create user session."""


class RedirectRequiredCallbackResult(BaseModel):
    """Redirect is required, generally to a login route or page."""

    type: CallbackResultType = Field(CallbackResultType.REDIRECT_REQUIRED, frozen=True)
    """Discriminator field indicating redirect is required."""
    redirect_url: str
    """URL to redirect the user to retry authentication."""
    reason: CallbackFailureReason
    """Specific reason why the callback failed and requires redirect."""


CallbackResult = Annotated[Union[CompletedCallbackResult, RedirectRequiredCallbackResult], Field(discriminator="type")]
"""
Union type representing the result of OAuth callback processing.

The discriminator field 'type' is used to determine which variant:
- CallbackResultType.COMPLETED: Callback succeeded, contains callback_data
- CallbackResultType.REDIRECT_REQUIRED: Callback failed, contains redirect_url and reason
"""


class WristbandTokenResponse(BaseModel):
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
    def from_api_response(response: dict[str, Any]) -> "WristbandTokenResponse":
        """
        Creates a WristbandTokenResponse instance from an API response dictionary.

        Args:
            response: The raw API response containing token information.

        Returns:
            A WristbandTokenResponse instance with the parsed token data.
        """
        return WristbandTokenResponse(
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
        tenant_name: The name of the tenant the user belongs to.
    """

    redirect_url: Optional[str] = None
    refresh_token: Optional[str] = None
    state: Optional[str] = None
    tenant_custom_domain: Optional[str] = None
    tenant_name: Optional[str] = None


########################################
# SESSION/TOKEN ENDPOINT MODELS
########################################


class SessionResponse(BaseModel):
    """
    Response model for session endpoints.

    This model is used to return session information including tenant ID, user ID,
    and any additional metadata associated with the session. The metadata field
    accepts a dictionary of JSON-serializable values. The response format
    matches what Wristband frontend SDKs expect for session endpoints.

    Serializes to:
        {
            "tenantId": "tenant_abc123",
            "userId": "user_xyz789",
            "metadata": {
                # your metadata JSON...
            }
        }

    Attributes:
        tenant_id (str): The tenant identifier for the authenticated user's organization.
        user_id (str): The unique identifier for the authenticated user.
        metadata (dict[str, Any]): Additional session data as key-value pairs. Values must be JSON-serializable.
    """

    model_config = ConfigDict(serialize_by_alias=True)

    tenant_id: str = Field(serialization_alias="tenantId")
    user_id: str = Field(serialization_alias="userId")
    metadata: Dict[str, Any]


class TokenResponse(BaseModel):
    """
    Token response model for the Token Endpoint.

    This model is used by applications to expose token data to Wristband frontend SDKs.
    The serialization aliases ensure compatibility with the expected JSON structure.

    Serializes to:
        {
            "accessToken": "eyJhbGc...",
            "expiresAt": 1234567890
        }

    Attributes:
        access_token: The JWT access token for authenticating API requests
        expires_at: Unix timestamp in milliseconds when the token expires
    """

    model_config = ConfigDict(serialize_by_alias=True)

    access_token: str = Field(serialization_alias="accessToken")
    expires_at: int = Field(serialization_alias="expiresAt")


########################################
# SESSION MIDDLEWARE MODELS
########################################


class SameSiteOption(Enum):
    """
    Represents the SameSite attribute for cookies, which controls if cookies are sent along with cross-site requests.

    Values:
        STRICT: Cookies are only sent for same-site requests (best CSRF protection).
        LAX: Cookies are sent for same-site requests and top-level navigation GET requests (default in most browsers).
        NONE: Cookies are sent in all contexts, including cross-site requests. Must be used with
              secure=True in modern browsers.
    """

    STRICT = "strict"
    """Cookies only sent for same-site requests (best CSRF protection)."""

    LAX = "lax"
    """Cookies sent for same-site + top-level navigation GET requests (default)."""

    NONE = "none"
    """Cookies sent for all requests (requires secure=True)."""


class Session(Protocol):
    """
    Protocol for type-safe session access.

    This protocol defines the interface for session objects created by SessionMiddleware.
    Extend this protocol to add type hints for your custom session fields.

    Base fields (automatically set by from_callback()):
        is_authenticated: Whether the user is authenticated
        access_token: JWT access token for API calls
        expires_at: Token expiration timestamp (milliseconds since Unix epoch)
        user_id: Unique identifier for the authenticated user
        tenant_id: Unique identifier for the user's tenant
        tenant_name: Name of the user's tenant
        identity_provider_name: Name of the identity provider that the user belongs to.
        refresh_token: Optional refresh token (requires 'offline_access' scope)
        tenant_custom_domain: Optional custom domain for the tenant

    Other session fields:
        csrf_token: CSRF token for request validation (only present if enable_csrf_protection=True)

    Example - Using base fields only:
        from fastapi import Depends
        from wristband.fastapi_auth import get_session, Session

        @router.get("/profile")
        async def get_profile(session: Session = Depends(get_session)):
            user_id = session.user_id  # Base fields available
            return {"userId": user_id}

    Example - Adding custom typed fields:
        from typing import cast, Protocol
        from wristband.fastapi_auth import get_session, SessionProtocol

        class MySession(SessionProtocol, Protocol):
            role: str
            preferences: dict
            last_login: int

        @router.get("/profile")
        async def get_profile(session: MySession = Depends(get_session)):  # type: ignore[assignment]
            # All fields are now typed
            user_id = session.user_id  # Base field
            role = session.role  # Custom field
            return {"userId": user_id, "role": role}

        # Or use cast():
        @router.get("/profile")
        async def get_profile(request: Request):
            session = cast(MySession, get_session(request))
            role = session.role  # Fully typed!
    """

    # ============================================================================
    # BASE SESSION FIELDS
    # ============================================================================

    is_authenticated: Optional[bool]
    """
    Whether the user is authenticated. Set to True by from_callback().
    """

    access_token: Optional[str]
    """
    JWT access token for making authenticated API calls to Wristband and other services.
    """

    expires_at: Optional[int]
    """
    Token expiration time as Unix timestamp in milliseconds.
    Accounts for token_expiration_buffer from SDK config.
    """

    user_id: Optional[str]
    """
    Unique identifier for the authenticated user.
    """

    tenant_id: Optional[str]
    """
    Unique identifier for the tenant that the user belongs to.
    """

    tenant_name: Optional[str]
    """
    Name of the tenant that the user belongs to.
    """

    identity_provider_name: Optional[str]
    """
    Name of the identity provider that the user belongs to.
    """

    csrf_token: Optional[str]
    """
    CSRF token for request validation. Automatically generated when save() is called
    if enable_csrf_protection is True.
    """

    refresh_token: Optional[str]
    """
    Refresh token for obtaining new access tokens when they expire.
    Only present if 'offline_access' scope was requested during authentication.
    """

    tenant_custom_domain: Optional[str]
    """
    Custom domain for the tenant, if configured.
    Only present if a tenant custom domain was used during authentication.
    """

    # ============================================================================
    # DICTIONARY-STYLE ACCESS METHODS
    # ============================================================================

    def __getattr__(self, key: str) -> Any:
        """
        Allow attribute-style access to session data.

        This enables both base fields and custom fields to be accessed as attributes.

        Args:
            key: The attribute name to access

        Returns:
            The value associated with the key, or None if not found

        Example:
            user_id = session.user_id  # Base field
            role = session.role  # Custom field (if extended protocol)
        """
        ...

    def __setattr__(self, key: str, value: Any) -> None:
        """
        Allow attribute-style setting of session data.

        Args:
            key: The attribute name to set
            value: The value to store (must be JSON-serializable)

        Raises:
            ValueError: If value is not JSON-serializable

        Example:
            session.user_id = "123"
            session.role = "admin"
        """
        ...

    def __getitem__(self, key: str) -> Any:
        """
        Get session value by key (dict-style access).

        Args:
            key: The session key to retrieve

        Returns:
            The value associated with key

        Raises:
            KeyError: If key doesn't exist

        Example:
            user_id = session['user_id']
        """
        ...

    def __setitem__(self, key: str, value: Any) -> None:
        """
        Set session value by key (dict-style access).

        Args:
            key: The session key to set
            value: The value to store (must be JSON-serializable)

        Raises:
            ValueError: If value is not JSON-serializable

        Example:
            session['cart'] = {'items': [], 'total': 0}
        """
        ...

    def __delitem__(self, key: str) -> None:
        """
        Delete session value by key.

        Args:
            key: The session key to delete

        Raises:
            KeyError: If key doesn't exist

        Example:
            del session['temporary_data']
        """
        ...

    def __contains__(self, key: str) -> bool:
        """
        Check if key exists in session.

        Args:
            key: The session key to check

        Returns:
            True if key exists, False otherwise

        Example:
            if 'cart' in session:
                cart = session['cart']
        """
        ...

    def __len__(self) -> int:
        """
        Return number of items in session.

        Returns:
            Count of session keys

        Example:
            item_count = len(session)
        """
        ...

    def __iter__(self) -> Iterator[str]:
        """
        Iterate over session keys.

        Returns:
            Iterator over session keys

        Example:
            for key in session:
                print(f"{key}: {session[key]}")
        """
        ...

    # ============================================================================
    # SESSION LIFECYCLE METHODS
    # ============================================================================

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a session value with optional default.

        Args:
            key: The session key to retrieve
            default: Value to return if key doesn't exist

        Returns:
            The value associated with key, or default if not found

        Example:
            cart = session.get('cart', {'items': []})
            theme = session.get('theme', 'light')
        """
        ...

    def to_dict(self) -> Dict[str, Any]:
        """
        Get a shallow copy of all session data as a dictionary.

        Returns:
            Dictionary containing all session key-value pairs

        Example:
            session_data = session.to_dict()
            return {"session": session_data}
        """
        ...

    def from_callback(self, callback_data: CallbackData, custom_fields: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize session from Wristband authentication callback data.

        This convenience method populates the session with authentication data
        after successful login. It automatically extracts user info, tokens, and
        tenant data from the callback and marks the session for persistence.

        Args:
            callback_data: Authentication data returned from wristband_auth.callback()
            custom_fields: Optional additional fields to store (must be JSON-serializable)

        Raises:
            ValueError: If callback_data is None, user_info is missing, or
                       custom_fields aren't JSON-serializable

        Fields automatically set:
            - is_authenticated (True)
            - access_token
            - expires_at
            - user_id (from user_info.user_id)
            - tenant_id (from user_info.tenant_id)
            - tenant_name
            - identity_provider_name (from user_info.identity_provider_name)
            - refresh_token (if present in callback_data)
            - tenant_custom_domain (if present in callback_data)

        Example:
            # Basic usage
            callback_result = await wristband_auth.callback(request)
            request.state.session.from_callback(callback_result.callback_data)

            # With custom fields
            request.state.session.from_callback(
                callback_result.callback_data,
                custom_fields={
                    "role": "admin",
                    "preferences": {"theme": "dark"},
                    "last_login": 1735689600000
                }
            )
        """
        ...

    def save(self) -> None:
        """
        Mark session for persistence and refresh cookie expiration (rolling sessions).

        This defers the actual cookie write until after the route completes. Call
        this after modifying session data or to extend the session lifetime for
        active users (rolling session pattern).

        The session cookie's expiry is refreshed each time save() is called, keeping
        active users logged in without requiring re-authentication.

        If enable_csrf_protection is True and no CSRF token exists in the session,
        a new token will be automatically generated and stored.

        Example:
            # After modifying session data
            session['last_activity'] = time.time()
            session.save()

            # Or just extend session for authenticated users (rolling sessions)
            if session.is_authenticated:
                session.save()
        """
        ...

    def clear(self) -> None:
        """
        Delete the session and clear all cookies.

        Resets the session to empty state and marks session cookie for deletion.
        If enable_csrf_protection is True, also marks CSRF cookie for deletion.
        Use this when logging out users.

        This operation takes precedence over save() - calling clear() will delete
        the session even if save() was called earlier in the request.

        Example:
            @router.get("/logout")
            async def logout(request: Request):
                request.state.session.clear()
                return RedirectResponse("/login")
        """
        ...

    # ============================================================================
    # WRISTBAND FRONTEND SDK INTEGRATION
    # ============================================================================

    def get_session_response(self, metadata: Optional[Dict[str, Any]] = None) -> SessionResponse:
        """
        Create a SessionResponse for Wristband frontend SDKs.

        This method formats session data in the structure expected by Wristband's
        frontend SDKs for session validation endpoints.

        Args:
            metadata: Optional custom metadata to include (must be JSON-serializable).
                     Defaults to empty dict if not provided.

        Returns:
            SessionResponse containing tenant_id, user_id, and metadata

        Raises:
            HTTPException: 401 Unauthorized if tenant_id or user_id are missing

        Example:
            @router.get("/api/v1/session", dependencies=[Depends(require_session_auth)])
            async def get_session(session: Session = Depends(get_session)) -> SessionResponse:
                return session.get_session_response(
                    metadata={
                        "name": session.get("full_name"),
                        "role": session.get("role")
                    }
                )
        """
        ...

    def get_token_response(self) -> TokenResponse:
        """
        Create a TokenResponse for Wristband frontend SDKs.

        This method formats token data in the structure expected by Wristband's
        frontend SDKs for token retrieval endpoints. Use this when your frontend
        needs to make direct authenticated API calls.

        Returns:
            TokenResponse containing access_token and expires_at

        Raises:
            HTTPException: 401 Unauthorized if access_token or expires_at are missing

        Example:
            @router.get("/api/v1/token", dependencies=[Depends(require_session_auth)])
            async def get_token(session: Session = Depends(get_session)) -> TokenResponse:
                return session.get_token_response()
        """
        ...


########################################
# DEPENDENCY MODELS
########################################


class JWTAuthResult:
    """
    Result of JWT authentication containing the decoded payload and raw token.
    """

    def __init__(self, jwt: str, payload: JWTPayload):
        """
        Initialize JWT auth result.

        Args:
            jwt: The raw JWT token string
            payload: Decoded JWT payload with standard and custom claims
        """
        self.jwt = jwt
        self.payload = payload


class AuthStrategy(str, Enum):
    """Available authentication strategies for multi-strategy auth."""

    SESSION = "session"
    JWT = "jwt"


class SessionAuthConfig(TypedDict, total=False):
    """
    Configuration for session-based authentication in multi-strategy auth.

    All fields are optional and have defaults.
    """

    enable_csrf_protection: bool
    """Enable CSRF token validation. Defaults to False."""

    csrf_header_name: str
    """Header name containing CSRF token. Defaults to "X-CSRF-Token"."""


class JWTAuthConfig(TypedDict, total=False):
    """
    Configuration for JWT authentication in multi-strategy auth.

    All fields are optional and have defaults.
    """

    jwks_cache_max_size: int
    """Maximum number of JWKs to cache. Defaults to 100."""

    jwks_cache_ttl: int
    """Time-to-live for cached JWKs in seconds. Defaults to 3600 (1 hour)."""


class AuthResult:
    """
    Result from multi-strategy authentication containing the strategy used and auth data.

    This wrapper allows you to determine which authentication strategy succeeded
    and access the appropriate authentication data.
    """

    def __init__(
        self, strategy: AuthStrategy, session: Optional[Session] = None, jwt_result: Optional[JWTAuthResult] = None
    ):
        """
        Initialize authentication result.

        Args:
            strategy: Which authentication strategy succeeded ("SESSION" or "JWT")
            session: Session object if SESSION strategy succeeded
            jwt_result: JWTAuthResult if JWT strategy succeeded
        """
        self.strategy = strategy
        self.session = session
        self.jwt_result = jwt_result
