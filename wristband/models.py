from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from typing import Any, Optional, List
from fastapi.responses import RedirectResponse

from wristband.enums import CallbackResultType


@dataclass
class LoginConfig:
    custom_state: Optional[dict[str, str]] = None
    default_tenant_custom_domain: Optional[str] = None
    default_tenant_domain: Optional[str] = None


@dataclass
class LogoutConfig:
    redirect_url: Optional[str] = None
    refresh_token: Optional[str] = None
    tenant_custom_domain: Optional[str] = None
    tenant_domain_name: Optional[str] = None

@dataclass
class LoginState:
    state: str
    code_verifier: str
    redirect_uri: str
    return_url: Optional[str]
    custom_state: Optional[dict[str, str]]

    def to_dict(self) -> dict[str, str | dict[str, str]]:
        return asdict(self)

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
    root_domain: Optional[str] = None
    scopes: List[str] = field(default_factory=lambda: ['openid', 'offline_access', 'email'])
    use_custom_domains: bool = False
    use_tenant_subdomains: bool = False

@dataclass
class UserInfo:
    sub: str
    tnt_id: str
    app_id: str
    idp_name: str
    email: str
    email_verified: bool

    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'UserInfo':
        return UserInfo(**data)

@dataclass
class SessionData:
    is_authenticated: bool
    access_token: str
    expires_at: int
    tenant_domain_name: str
    tenant_custom_domain: str
    user_info: UserInfo
    refresh_token: str

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, str] = asdict(self)
        data['user_info'] = str(asdict(self.user_info))
        return data
    
    def to_session_init_data(self) -> dict[str, Any]:
        return {
            "tenantId": self.user_info.tnt_id,
            "userId": self.user_info.sub,
            "metadata": self.to_dict()
        }
    
    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'SessionData':
        user_info_data = data.pop('user_info')
        
        # If user_info_data is a string, parse it into a dictionary
        if isinstance(user_info_data, str):
            import ast
            user_info_data = ast.literal_eval(user_info_data)
            
        user_info: UserInfo = UserInfo.from_dict(user_info_data)
        return SessionData(**data, user_info=user_info)


@dataclass
class CallbackData:
    access_token: str
    id_token: str
    expires_in: int
    tenant_domain_name: str
    user_info: dict[str, Any]

    custom_state: Optional[dict[str, str]]
    refresh_token: Optional[str]
    return_url: Optional[str]
    tenant_custom_domain: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
    def to_session(self) -> dict[str, Any]:
        return SessionData(
            is_authenticated=True,
            access_token=self.access_token,
            expires_at=int((datetime.now() + timedelta(seconds=self.expires_in)).timestamp() * 1000),
            tenant_domain_name=self.tenant_domain_name,
            tenant_custom_domain=self.tenant_custom_domain or "",
            user_info=UserInfo.from_dict(self.user_info),
            refresh_token=self.refresh_token or ""
        ).to_dict()

@dataclass
class TokenData:
    access_token: str
    id_token: str
    expires_at: int
    refresh_token: str

    @staticmethod
    def from_token_response(token_response: 'TokenResponse') -> 'TokenData':
        return TokenData(
            access_token=token_response.access_token,
            id_token=token_response.id_token,
            expires_at=int((datetime.now() + timedelta(seconds=token_response.expires_in)).timestamp() * 1000),
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