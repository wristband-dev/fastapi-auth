from typing import List, Optional
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from wristband.python_jwt import JWTPayload, JwtValidationResult

from wristband.fastapi_auth import AuthConfig, AuthResult, AuthStrategy, SessionMiddleware, WristbandAuth

VALID_TOKEN = "valid_token"
EXPIRED_TOKEN = "expired_token"


def _validate(token: str) -> JwtValidationResult:
    if token == VALID_TOKEN:
        return JwtValidationResult(is_valid=True, payload=JWTPayload(payload_dict={"sub": "jwt_user"}))
    return JwtValidationResult(is_valid=False, error_message="Token expired")


def _create_client(strategies: List[AuthStrategy], enable_csrf_protection: bool = True) -> TestClient:
    wristband_auth = WristbandAuth(
        AuthConfig(
            auto_configure_enabled=False,
            client_id="test_client_id",
            client_secret="test_client_secret",
            login_state_secret="a" * 32,
            login_url="https://app.example.com/auth/login",
            redirect_uri="https://app.example.com/auth/callback",
            wristband_application_vanity_domain="auth.example.com",
        )
    )
    # Use python-jwt's real Bearer extraction, and only stub out signature/expiry validation.
    jwt_validator = wristband_auth._get_jwt_validator(None, None)
    patch.object(jwt_validator, "validate", side_effect=_validate).start()

    require_auth = wristband_auth.create_auth_dependency(strategies=strategies)
    require_session_auth = wristband_auth.create_session_auth_dependency()

    app = FastAPI()
    app.add_middleware(
        SessionMiddleware, secret_key="b" * 32, secure=False, enable_csrf_protection=enable_csrf_protection
    )

    @app.post("/test/session")
    async def create_session(request: Request) -> dict:
        request.state.session.is_authenticated = True
        request.state.session.user_id = "session_user"
        request.state.session.save()
        return {}

    @app.get("/protected")
    async def protected(auth: AuthResult = Depends(require_auth)) -> dict:
        return {"strategy": auth.strategy.value}

    @app.get("/session-protected")
    async def session_protected(request: Request, _: object = Depends(require_session_auth)) -> dict:
        return {"user_id": request.state.session.user_id}

    return TestClient(app)


def _request(
    client: TestClient, session: bool = False, csrf: Optional[str] = None, bearer: Optional[str] = None
) -> int:
    headers = {}
    if session:
        client.post("/test/session")
        csrf_token = client.cookies.get("CSRF-TOKEN")
        headers["X-CSRF-TOKEN"] = csrf_token if csrf == "valid" else "wrong"
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return client.get("/protected", headers=headers).status_code


@pytest.fixture(autouse=True)
def stop_patches():
    yield
    patch.stopall()


# The decision table from the multi-strategy rule: a strategy is skipped only when its credential is missing.
@pytest.mark.parametrize(
    "strategies, session, csrf, bearer, expected_status",
    [
        ([AuthStrategy.SESSION, AuthStrategy.JWT], True, "wrong", None, 403),
        ([AuthStrategy.SESSION, AuthStrategy.JWT], False, None, VALID_TOKEN, 200),
        ([AuthStrategy.SESSION, AuthStrategy.JWT], False, None, EXPIRED_TOKEN, 401),
        ([AuthStrategy.SESSION, AuthStrategy.JWT], True, "wrong", VALID_TOKEN, 403),
        ([AuthStrategy.JWT, AuthStrategy.SESSION], True, "valid", EXPIRED_TOKEN, 401),
        ([AuthStrategy.SESSION, AuthStrategy.JWT], False, None, None, 401),
        ([AuthStrategy.JWT, AuthStrategy.SESSION], False, None, None, 401),
        ([AuthStrategy.SESSION, AuthStrategy.JWT], True, "valid", None, 200),
    ],
)
def test_multi_strategy_decision_table(strategies, session, csrf, bearer, expected_status):
    client = _create_client(strategies)
    assert _request(client, session=session, csrf=csrf, bearer=bearer) == expected_status


@pytest.mark.parametrize(
    "strategies",
    [[AuthStrategy.JWT], [AuthStrategy.SESSION, AuthStrategy.JWT], [AuthStrategy.JWT, AuthStrategy.SESSION]],
)
def test_non_bearer_authorization_header_returns_401(strategies):
    client = _create_client(strategies)
    response = client.get("/protected", headers={"Authorization": "Basic abc123"})
    assert response.status_code == 401


def test_session_middleware_setting_turns_on_csrf_validation():
    """One setting: SessionMiddleware(enable_csrf_protection=True) also turns on validation in the dependency."""
    client = _create_client([AuthStrategy.SESSION], enable_csrf_protection=True)
    client.post("/test/session")

    assert client.get("/session-protected", headers={"X-CSRF-TOKEN": "wrong"}).status_code == 403
    assert client.get("/session-protected", headers={"X-CSRF-TOKEN": client.cookies["CSRF-TOKEN"]}).status_code == 200


def test_csrf_not_validated_when_session_middleware_setting_is_off():
    client = _create_client([AuthStrategy.SESSION], enable_csrf_protection=False)
    client.post("/test/session")

    assert "CSRF-TOKEN" not in client.cookies
    assert client.get("/session-protected").status_code == 200
