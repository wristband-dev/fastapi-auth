from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

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
        default_tenant_name: An optional default tenant name to use for the login request in the
            event the name cannot be found in either the subdomain or the "tenant_domain" request
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
            the name cannot be found in either the subdomain or the "tenant_domain" request query
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

    COMPLETED = "COMPLETED"
    REDIRECT_REQUIRED = "REDIRECT_REQUIRED"


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
