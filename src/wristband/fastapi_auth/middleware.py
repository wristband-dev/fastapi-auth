import logging
from typing import Any, Awaitable, Callable, List, Optional, Union

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .models import SameSiteOption
from .session import SessionManager
from .utils import DataEncryptor

logger = logging.getLogger(__name__)


class SessionMiddleware(BaseHTTPMiddleware):
    """
    Session middleware that provides encrypted cookie-based sessions.

    Args:
        app: The FastAPI/Starlette application instance
        secret_key: Secret key for session encryption (required)
        session_cookie_name: Name of the session cookie (default: "session")
        session_cookie_domain: Domain for session cookie (default: None)
        max_age: Cookie expiration time in seconds (default: 3600)
        path: Cookie path (default: "/")
        same_site: Cookie SameSite attribute (default: SameSiteOption.LAX)
        secure: Whether to use secure cookies (default: True)
        enable_csrf_protection: Enable CSRF token generation and validation (default: False)
        csrf_cookie_name: Name of CSRF cookie (default: "CSRF-TOKEN")
        csrf_cookie_domain: Domain for CSRF cookie (default: None)

    Usage:
        app.add_middleware(
            SessionMiddleware,
            session_cookie_name="session",
            secret_key="your-secret-key-here",
            max_age=3600,
            path="/",
            same_site=SameSiteOption.LAX,
            secure=True,
        )

    In routes:
        # Get session value
        user_id = request.state.session.get('user_id')

        # Set session value
        request.state.session['user_id'] = "123"
        request.state.session.save()

        # Delete session
        request.state.session.clear()
    """

    def __init__(
        self,
        app: Any,
        secret_key: Union[str, List[str]],
        session_cookie_name: str = "session",
        session_cookie_domain: Optional[str] = None,
        max_age: int = 3600,  # 1 hour
        path: str = "/",
        same_site: SameSiteOption = SameSiteOption.LAX,
        secure: bool = True,
        enable_csrf_protection: bool = False,
        csrf_cookie_name: str = "CSRF-TOKEN",
        csrf_cookie_domain: Optional[str] = None,
    ) -> None:
        super().__init__(app)

        # Basic validation (DataEncryptor will do full validation)
        keys = [secret_key] if isinstance(secret_key, str) else secret_key
        if not keys:
            raise ValueError("secret_key is required for session encryption")

        if not session_cookie_name or not session_cookie_name.strip():
            raise ValueError("session_cookie_name cannot be empty")
        if not csrf_cookie_name or not csrf_cookie_name.strip():
            raise ValueError("csrf_cookie_name cannot be empty")
        if max_age <= 0:
            raise ValueError("max_age must be greater than 0")
        if not path or not path.strip():
            raise ValueError("path cannot be empty")

        self._encryptor = DataEncryptor(secret_key)
        self._session_cookie_name = session_cookie_name
        self._session_cookie_domain = session_cookie_domain
        self._max_age = max_age
        self._path = path
        self._same_site: SameSiteOption = same_site
        self._secure = secure
        self._enable_csrf_protection = enable_csrf_protection
        self._csrf_cookie_name = csrf_cookie_name
        self._csrf_cookie_domain = csrf_cookie_domain or session_cookie_domain

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        session = SessionManager(
            encryptor=self._encryptor,
            session_cookie_name=self._session_cookie_name,
            session_cookie_domain=self._session_cookie_domain,
            max_age=self._max_age,
            path=self._path,
            same_site=self._same_site,
            secure=self._secure,
            enable_csrf_protection=self._enable_csrf_protection,
            csrf_cookie_name=self._csrf_cookie_name,
            csrf_cookie_domain=self._csrf_cookie_domain,
        )

        # Try to load existing session
        try:
            session_cookie = request.cookies.get(self._session_cookie_name)
            if session_cookie:
                session_data = self._encryptor.decrypt(session_cookie)
                session._load_from_dict(session_data)
            else:
                session._load_from_dict({})
        except Exception as e:
            logger.debug(f"Failed to decrypt session cookie: {str(e)}")
            session._load_from_dict({})

        # Attach session to request.state
        request.state.session = session

        # Process the request
        response = await call_next(request)

        # Persist session ONCE after route completes
        session._persist(response)

        return response
