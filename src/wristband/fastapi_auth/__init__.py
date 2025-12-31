from wristband.python_jwt import JWTPayload

from .auth import WristbandAuth
from .exceptions import WristbandError
from .middleware import SessionMiddleware
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
    LogoutConfig,
    RedirectRequiredCallbackResult,
    SameSiteOption,
    Session,
    SessionAuthConfig,
    SessionResponse,
    TokenData,
    TokenResponse,
    UserInfo,
    UserInfoRole,
)
from .session import get_session

# Explicitly define what's available for import
__all__ = [
    "AuthConfig",
    "AuthResult",
    "AuthStrategy",
    "CallbackData",
    "CallbackFailureReason",
    "CallbackResult",
    "CallbackResultType",
    "CompletedCallbackResult",
    "get_session",
    "JWTAuthConfig",
    "JWTAuthResult",
    "JWTPayload",
    "LoginConfig",
    "LogoutConfig",
    "RedirectRequiredCallbackResult",
    "SameSiteOption",
    "Session",
    "SessionAuthConfig",
    "SessionMiddleware",
    "SessionResponse",
    "TokenData",
    "TokenResponse",
    "UserInfo",
    "UserInfoRole",
    "WristbandAuth",
    "WristbandError",
]
