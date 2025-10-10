import logging
from typing import Any, Awaitable, Callable, Literal, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .session import SessionManager
from .utils import DataEncryptor

logger = logging.getLogger(__name__)
SameSiteOptions = Literal["lax", "strict", "none"]


class SessionMiddleware(BaseHTTPMiddleware):
    """
    Session middleware that provides encrypted cookie-based sessions.

    Args:
        app: The FastAPI/Starlette application instance
        secret_key: Secret key for session encryption (required)
        session_cookie_name: Name of the session cookie (default: "session")
        session_cookie_domain: Domain for session cookie (default: None)
        csrf_cookie_name: Name of CSRF cookie (default: "CSRF-TOKEN")
        csrf_cookie_domain: Domain for CSRF cookie (default: None)
        max_age: Cookie expiration time in seconds (default: 3600)
        path: Cookie path (default: "/")
        same_site: Cookie SameSite attribute (default: "lax")
        secure: Whether to use secure cookies (default: True)

    Usage:
        app.add_middleware(
            SessionMiddleware,
            session_cookie_name="session",
            secret_key="your-secret-key-here",
            max_age=3600,
            path="/",
            same_site="lax",
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
        secret_key: str,
        session_cookie_name: str = "session",
        session_cookie_domain: Optional[str] = None,
        csrf_cookie_name: str = "CSRF-TOKEN",
        csrf_cookie_domain: Optional[str] = None,
        max_age: int = 3600,  # 1 hour
        path: str = "/",
        same_site: Literal["lax", "strict", "none"] = "lax",
        secure: bool = True,
    ) -> None:
        super().__init__(app)

        if not secret_key or not secret_key.strip():
            raise ValueError("secret_key is required for session encryption")
        if len(secret_key) < 32:
            raise ValueError("secret_key must be at least 32 characters long for security")
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
        self._csrf_cookie_name = csrf_cookie_name
        self._csrf_cookie_domain = csrf_cookie_domain or session_cookie_domain
        self._max_age = max_age
        self._path = path
        self._same_site: SameSiteOptions = same_site
        self._secure = secure

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        session = SessionManager(
            encryptor=self._encryptor,
            session_cookie_name=self._session_cookie_name,
            session_cookie_domain=self._session_cookie_domain,
            csrf_cookie_name=self._csrf_cookie_name,
            csrf_cookie_domain=self._csrf_cookie_domain,
            max_age=self._max_age,
            path=self._path,
            same_site=self._same_site,
            secure=self._secure,
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
