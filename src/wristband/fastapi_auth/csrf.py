import logging
import secrets
from typing import Literal, Optional

from fastapi import Request, Response

_logger: logging.Logger = logging.getLogger(__name__)

DEFAULT_CSRF_COOKIE_NAME = "CSRF-TOKEN"
DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN"
DEFAULT_HTTPONLY = False  # Must be False so frontend JavaScript can access
DEFAULT_MAX_AGE = 3600  # 1 hour
DEFAULT_PATH = "/"
DEFAULT_SAME_SITE: Literal["lax", "strict", "none"] = "lax"
DEFAULT_SECURE = True


def create_csrf_token() -> str:
    """
    Generate a cryptographically secure CSRF token.

    Returns:
        A 32-character hexadecimal CSRF token
    """
    return secrets.token_hex(16)


def update_csrf_cookie(
    response: Response,
    csrf_token: str,
    cookie_name: str = DEFAULT_CSRF_COOKIE_NAME,
    domain: Optional[str] = None,
    max_age: int = DEFAULT_MAX_AGE,
    path: str = DEFAULT_PATH,
    same_site: Literal["lax", "strict", "none"] = DEFAULT_SAME_SITE,
    secure: bool = DEFAULT_SECURE,
) -> None:
    """
    Set CSRF token cookie on the response.

    Args:
        response: FastAPI Response object
        csrf_token: The CSRF token to set
        cookie_name: Name of the CSRF cookie (default: "CSRF-TOKEN")
        domain: Cookie domain (optional)
        max_age: Cookie expiration time in seconds (default: 1 hour)
        path: Cookie path (default: "/")
        secure: Whether to use secure flag (default: True)

    Raises:
        ValueError: If csrf_token is empty or None
    """
    if not response:
        raise ValueError("response cannot be None")
    if not csrf_token:
        raise ValueError("csrf_token cannot be None or empty")

    response.set_cookie(
        key=cookie_name,
        value=csrf_token,
        domain=domain,
        httponly=DEFAULT_HTTPONLY,
        max_age=max_age,
        path=path,
        samesite=same_site,
        secure=secure,
    )


def is_csrf_token_valid(request: Request, csrf_header_name: str) -> bool:
    """
    Check if CSRF token from request header matches session token.

    Args:
        request: FastAPI Request object
        header_name: Header name to check for CSRF token

    Returns:
        True if CSRF tokens match, False otherwise
    """
    if not request:
        raise ValueError("request cannot be None")
    if not csrf_header_name:
        raise ValueError("csrf_header_name cannot be None")

    try:
        # Check both tokens exist and match
        session_csrf = request.state.session.csrf_token
        header_csrf = request.headers.get(csrf_header_name)

        if not session_csrf or not header_csrf:
            _logger.debug(
                f"CSRF validation failed - missing token. "
                f"Session token present: {session_csrf is not None}, "
                f"{csrf_header_name} Header token present: {header_csrf is not None}"
            )
            return False

        tokens_match = str(session_csrf) == str(header_csrf)
        if not tokens_match:
            _logger.debug(f"CSRF validation failed - tokens do not match. Header: {csrf_header_name}")

        return tokens_match
    except Exception:
        return False


def delete_csrf_cookie(
    response: Response,
    cookie_name: str = DEFAULT_CSRF_COOKIE_NAME,
    domain: Optional[str] = None,
    path: str = DEFAULT_PATH,
    same_site: Literal["lax", "strict", "none"] = DEFAULT_SAME_SITE,
    secure: bool = DEFAULT_SECURE,
) -> None:
    """
    Delete CSRF token cookie from the response.

    Args:
        response: FastAPI Response object
        cookie_name: Name of the CSRF cookie to delete (default: "CSRF-TOKEN")
        domain: Cookie domain (optional, should match the domain used when setting)
        path: Cookie path (default: "/")
        secure: Whether to use secure flag (default: True)
    """
    if not response:
        raise ValueError("response cannot be None")

    response.set_cookie(
        key=cookie_name,
        value="",
        max_age=0,
        domain=domain,
        path=path,
        httponly=DEFAULT_HTTPONLY,
        samesite=same_site,
        secure=secure,
    )
