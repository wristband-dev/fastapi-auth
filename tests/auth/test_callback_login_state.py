from unittest.mock import AsyncMock, patch

import pytest

from tests.utilities import TEST_LOGIN_STATE_SECRET, create_mock_request, resolve_test_redirect_url
from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.models import (
    AuthConfig,
    CallbackFailureReason,
    LoginState,
    RedirectRequiredCallbackResult,
)
from wristband.fastapi_auth.utils import DataEncryptor

LOGIN_STATE_COOKIE_NAME = "login#test_state#1640995200000"


class TestCallbackLoginState:
    """A login state cookie that can't be trusted sends the user back to login instead of failing the callback."""

    def setup_method(self) -> None:
        self.wristband_auth = WristbandAuth(
            AuthConfig(
                auto_configure_enabled=False,
                client_id="test_client_id",
                client_secret="test_client_secret",
                login_state_secret=TEST_LOGIN_STATE_SECRET,
                login_url="https://app.example.com/auth/login",
                redirect_uri="https://app.example.com/auth/callback",
                wristband_application_vanity_domain="auth.example.com",
            )
        )
        self.login_state = LoginState(
            state="test_state",
            code_verifier="test_verifier",
            redirect_uri="https://app.example.com/auth/callback",
            return_url=None,
            custom_state=None,
        )

    def _callback_request(self, login_state_cookie: str):
        return create_mock_request(
            "https://app.example.com/auth/callback",
            query_params={"code": "auth_code", "state": "test_state", "tenant_name": "customer01"},
            cookies={LOGIN_STATE_COOKIE_NAME: login_state_cookie},
        )

    async def _assert_invalid_login_state(self, login_state_cookie: str) -> None:
        with patch.object(self.wristband_auth._wristband_api, "get_tokens", new_callable=AsyncMock) as mock_get_tokens:
            result = await self.wristband_auth.callback(
                self._callback_request(login_state_cookie), resolve_test_redirect_url
            )

        mock_get_tokens.assert_not_called()
        assert isinstance(result, RedirectRequiredCallbackResult)
        assert result.reason == CallbackFailureReason.INVALID_LOGIN_STATE
        assert result.response.headers["location"] == "https://app.example.com/auth/login?tenant_name=customer01"
        # The untrusted login state cookie is still cleared.
        assert f"{LOGIN_STATE_COOKIE_NAME}=" in result.response.headers["set-cookie"]
        assert "Max-Age=0" in result.response.headers["set-cookie"]

    @pytest.mark.asyncio
    async def test_undecryptable_login_state_cookie_returns_invalid_login_state(self) -> None:
        await self._assert_invalid_login_state("not-a-valid-fernet-token")

    @pytest.mark.asyncio
    async def test_login_state_cookie_encrypted_with_another_secret_returns_invalid_login_state(self) -> None:
        other_encryptor = DataEncryptor("another_login_state_secret_at_least_32_chars")
        await self._assert_invalid_login_state(other_encryptor.encrypt(self.login_state.model_dump()))

    @pytest.mark.asyncio
    async def test_login_state_cookie_with_invalid_contents_returns_invalid_login_state(self) -> None:
        encryptor = DataEncryptor(TEST_LOGIN_STATE_SECRET)
        await self._assert_invalid_login_state(encryptor.encrypt({"unexpected": "shape"}))

    @pytest.mark.asyncio
    async def test_login_state_cookie_older_than_one_hour_returns_invalid_login_state(self) -> None:
        # Fernet encrypts the current time into the token, so encrypt it as if it were created over an hour ago.
        with patch("time.time", return_value=1_000_000.0):
            encrypted = self.wristband_auth._encrypt_login_state(self.login_state)

        with patch("time.time", return_value=1_000_000.0 + 3601):
            await self._assert_invalid_login_state(encrypted)

    @pytest.mark.asyncio
    async def test_login_state_cookie_within_one_hour_is_accepted(self) -> None:
        with patch("time.time", return_value=1_000_000.0):
            encrypted = self.wristband_auth._encrypt_login_state(self.login_state)

        with patch("time.time", return_value=1_000_000.0 + 3599):
            assert self.wristband_auth._decrypt_login_state(encrypted) == self.login_state
