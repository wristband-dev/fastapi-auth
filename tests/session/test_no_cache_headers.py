"""End-to-end tests that responses writing or deleting session cookies are never cached."""

from typing import Optional

import httpx
import pytest
from fastapi import Depends, FastAPI, Request, Response

from tests.utilities import TEST_LOGIN_STATE_SECRET
from wristband.fastapi_auth import Session, SessionMiddleware, WristbandAuth, get_session
from wristband.fastapi_auth.models import AuthConfig

SESSION_COOKIE_NAME = "session"


def _create_app() -> FastAPI:
    """Create an app with SessionMiddleware and routes that save, clear, or only read the session."""
    wristband_auth = WristbandAuth(
        AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret=TEST_LOGIN_STATE_SECRET,
            wristband_application_vanity_domain="auth.example.com",
            auto_configure_enabled=False,
            login_url="https://app.example.com/auth/login",
            redirect_uri="https://app.example.com/auth/callback",
        )
    )
    require_session_auth = wristband_auth.create_session_auth_dependency()

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="a" * 32, session_cookie_name=SESSION_COOKIE_NAME)

    @app.get("/sign-in")
    async def sign_in(session: Session = Depends(get_session)) -> dict:
        session["is_authenticated"] = True
        session["user_id"] = "user_123"
        session.save()
        return {}

    @app.get("/sign-in-cacheable")
    async def sign_in_cacheable(response: Response, session: Session = Depends(get_session)) -> dict:
        response.headers["Cache-Control"] = "public, max-age=300"
        response.headers["Pragma"] = "cache"
        session["is_authenticated"] = True
        session.save()
        return {}

    @app.get("/sign-out")
    async def sign_out(session: Session = Depends(get_session)) -> dict:
        session.clear()
        return {}

    @app.get("/read-only")
    async def read_only(response: Response, request: Request) -> dict:
        response.headers["Cache-Control"] = "public, max-age=300"
        return {"user_id": request.state.session.get("user_id")}

    @app.get("/protected")
    async def protected(session: Session = Depends(require_session_auth)) -> dict:
        return {"user_id": session.user_id}

    return app


async def _get(app: FastAPI, path: str, session_cookie: Optional[str] = None) -> httpx.Response:
    """Send a GET request to the app, with the given session cookie if provided."""
    cookies = {SESSION_COOKIE_NAME: session_cookie} if session_cookie else None
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://app.example.com", cookies=cookies) as client:
        return await client.get(path)


def _assert_no_cache_headers(response: httpx.Response) -> None:
    """Assert the response has exactly one no-cache value for each header."""
    assert response.headers.get_list("cache-control") == ["no-store"]
    assert response.headers.get_list("pragma") == ["no-cache"]


class TestSessionNoCacheHeaders:
    """SessionMiddleware writes no-cache headers whenever a route saves or clears the session."""

    @pytest.mark.asyncio
    async def test_save_writes_no_cache_headers(self) -> None:
        """Test a route that saves the session gets the no-cache headers."""
        response = await _get(_create_app(), "/sign-in")

        assert response.status_code == 200
        assert SESSION_COOKIE_NAME in response.cookies
        _assert_no_cache_headers(response)

    @pytest.mark.asyncio
    async def test_save_replaces_route_cache_headers(self) -> None:
        """Test the no-cache headers replace caching headers the route set itself."""
        response = await _get(_create_app(), "/sign-in-cacheable")

        _assert_no_cache_headers(response)

    @pytest.mark.asyncio
    async def test_clear_writes_no_cache_headers(self) -> None:
        """Test a route that clears the session gets the no-cache headers."""
        app = _create_app()
        session_cookie = (await _get(app, "/sign-in")).cookies[SESSION_COOKIE_NAME]

        response = await _get(app, "/sign-out", session_cookie)

        assert response.status_code == 200
        _assert_no_cache_headers(response)

    @pytest.mark.asyncio
    async def test_read_only_route_keeps_its_own_cache_headers(self) -> None:
        """Test a route that only reads the session writes no cookies and keeps its own caching headers."""
        app = _create_app()
        session_cookie = (await _get(app, "/sign-in")).cookies[SESSION_COOKIE_NAME]

        response = await _get(app, "/read-only", session_cookie)

        assert response.json() == {"user_id": "user_123"}
        assert "set-cookie" not in response.headers
        assert response.headers.get_list("cache-control") == ["public, max-age=300"]
        assert "pragma" not in response.headers

    @pytest.mark.asyncio
    async def test_session_auth_dependency_writes_no_cache_headers_through_rolling_save(self) -> None:
        """Test a route protected by the session auth dependency gets the no-cache headers from its rolling save."""
        app = _create_app()
        session_cookie = (await _get(app, "/sign-in")).cookies[SESSION_COOKIE_NAME]

        response = await _get(app, "/protected", session_cookie)

        assert response.status_code == 200
        assert response.json() == {"user_id": "user_123"}
        assert SESSION_COOKIE_NAME in response.cookies
        _assert_no_cache_headers(response)

    @pytest.mark.asyncio
    async def test_session_auth_dependency_rejection_writes_no_session_headers(self) -> None:
        """Test an unauthenticated request to a protected route writes no session cookies or no-cache headers."""
        response = await _get(_create_app(), "/protected")

        assert response.status_code == 401
        assert "set-cookie" not in response.headers
        assert "pragma" not in response.headers
