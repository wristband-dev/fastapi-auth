from dataclasses import dataclass, asdict, field
from typing import Any, Optional, List
from fastapi.responses import RedirectResponse
from enum import Enum

########################################
# AUTH CONFIG MODELS
########################################


@dataclass
class AuthConfig:
    client_id: str
    client_secret: str
    login_state_secret: str
    login_url: str
    redirect_uri: str
    wristband_application_vanity_domain: str

    custom_application_login_page_url: Optional[str] = None
    dangerously_disable_secure_cookies: bool = False
    is_application_custom_domain_active: bool = False
    parse_tenant_from_root_domain: Optional[str] = None
    scopes: List[str] = field(default_factory=lambda: ['openid', 'offline_access', 'email'])


########################################
# LOGIN MODELS
########################################


@dataclass
class OAuthAuthorizeUrlConfig:
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


@dataclass
class LoginState:
    state: str
    code_verifier: str
    redirect_uri: str
    return_url: Optional[str]
    custom_state: Optional[dict[str, Any]]

    def to_dict(self) -> dict[str, str | dict[str, str]]:
        return asdict(self)


@dataclass
class LoginConfig:
    custom_state: Optional[dict[str, Any]] = None
    default_tenant_custom_domain: Optional[str] = None
    default_tenant_domain: Optional[str] = None


########################################
# CALLBACK MODELS
########################################


class CallbackResultType(Enum):
    """
    Enum representing the result type of a callback.
    """
    COMPLETED = 'COMPLETED'
    REDIRECT_REQUIRED = 'REDIRECT_REQUIRED'


UserInfo = dict[str, Any]


@dataclass
class CallbackData:
    access_token: str
    id_token: str
    expires_in: int
    tenant_domain_name: str
    user_info: UserInfo
    custom_state: Optional[dict[str, Any]]
    refresh_token: Optional[str]
    return_url: Optional[str]
    tenant_custom_domain: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TokenData:
    access_token: str
    id_token: str
    expires_in: int
    refresh_token: str

    @staticmethod
    def from_token_response(token_response: 'TokenResponse') -> 'TokenData':
        return TokenData(
            access_token=token_response.access_token,
            id_token=token_response.id_token,
            expires_in=token_response.expires_in,
            refresh_token=token_response.refresh_token
        )


@dataclass
class CallbackResult:
    callback_data: Optional[CallbackData]
    type: CallbackResultType
    redirect_response: Optional[RedirectResponse]


@dataclass
class TokenResponse:
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    id_token: str
    scope: str

    @staticmethod
    def from_api_response(response: dict[str, Any]) -> 'TokenResponse':
        return TokenResponse(
            access_token=response['access_token'],
            token_type=response['token_type'],
            expires_in=response['expires_in'],
            refresh_token=response['refresh_token'],
            id_token=response['id_token'],
            scope=response['scope']
        )


########################################
# LOGOUT MODELS
########################################


@dataclass
class LogoutConfig:
    redirect_url: Optional[str] = None
    refresh_token: Optional[str] = None
    tenant_custom_domain: Optional[str] = None
    tenant_domain_name: Optional[str] = None
