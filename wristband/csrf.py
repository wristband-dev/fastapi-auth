import secrets
from fastapi import Request, Response
from starlette.middleware.sessions import SessionMiddleware


def create_csrf_token() -> str:
    """Generates a new CSRF token."""
    return secrets.token_hex(32)


def update_csrf_cookie(request: Request, response: Response) -> None:
    """Updates the CSRF cookie with the CSRF token.
    
    Args:
        request: The FastAPI request object containing the session
        response: The FastAPI response object for setting the cookie
    """
    csrf_token = request.session.get("csrfToken")
    if csrf_token:
        response.set_cookie(
            key="CSRF-TOKEN",
            value=csrf_token,
            httponly=False,  # Must be False so frontend JavaScript can access the value
            max_age=1800,    # 30 minutes in seconds
            path="/",
            samesite="lax",  # Equivalent to sameSite: true in JS
            secure=False     # Only set to True if your server is using HTTPS
        ) 