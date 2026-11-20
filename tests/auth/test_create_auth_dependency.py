from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException, Request, status
from wristband.python_jwt import JWTPayload

from wristband.fastapi_auth import (
    AuthConfig,
    AuthResult,
    AuthStrategy,
    JWTAuthConfig,
    JWTAuthResult,
    SessionAuthConfig,
    WristbandAuth,
)


class TestCreateAuthDependency:
    """Unit tests for WristbandAuth.create_auth_dependency()"""

    @pytest.fixture
    def auth_config(self) -> AuthConfig:
        """Create a basic auth config for testing"""
        return AuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret_minimum_32_characters_long",
            wristband_application_vanity_domain="test.wristband.dev",
        )

    @pytest.fixture
    def wristband_auth(self, auth_config: AuthConfig) -> WristbandAuth:
        """Create WristbandAuth instance"""
        return WristbandAuth(auth_config)

    @pytest.fixture
    def mock_session(self) -> Mock:
        """Create a mock session"""
        session = Mock()
        session.is_authenticated = True
        session.user_id = "user_123"
        session.session_cookie_name = "session"
        session.save = Mock()
        return session

    @pytest.fixture
    def mock_request(self, mock_session: Mock) -> Request:
        """Create a mock request that carries both a session cookie and an Authorization header"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.state.session = mock_session
        request.headers = {"authorization": "Bearer test_token"}
        request.cookies = {"session": "encrypted_session"}
        return request

    @pytest.fixture
    def session_only_request(self, mock_request: Request) -> Request:
        """A request that carries only a session cookie"""
        mock_request.headers = {}
        return mock_request

    @pytest.fixture
    def jwt_only_request(self, mock_request: Request) -> Request:
        """A request that carries only an Authorization header"""
        mock_request.cookies = {}
        return mock_request

    @pytest.fixture
    def no_credential_request(self, mock_request: Request) -> Request:
        """A request that carries neither a session cookie nor an Authorization header"""
        mock_request.headers = {}
        mock_request.cookies = {}
        return mock_request

    @pytest.fixture
    def mock_jwt_result(self) -> JWTAuthResult:
        """Create a mock JWT result"""
        payload_dict = {
            "sub": "user_456",
            "iss": "https://test.wristband.dev",
            "aud": "test_client_id",
            "exp": 9999999999,
            "iat": 1234567890,
        }
        payload = JWTPayload(payload_dict=payload_dict)
        return JWTAuthResult(jwt="test_token", payload=payload)

    # ============================================================================
    # VALIDATION TESTS
    # ============================================================================

    def test_raises_error_when_strategies_empty(self, wristband_auth: WristbandAuth) -> None:
        """Test that ValueError is raised when strategies list is empty"""
        with pytest.raises(ValueError) as exc_info:
            wristband_auth.create_auth_dependency(strategies=[])

        assert "At least one authentication strategy must be provided" in str(exc_info.value)

    def test_raises_error_when_strategies_contains_duplicates(self, wristband_auth: WristbandAuth) -> None:
        """Test that ValueError is raised when strategies list contains duplicates"""
        with pytest.raises(ValueError) as exc_info:
            wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.SESSION])

        assert "Duplicate authentication strategies are not allowed" in str(exc_info.value)

    def test_raises_error_when_invalid_strategy_type(self, wristband_auth: WristbandAuth) -> None:
        """Test that ValueError is raised when strategy is not AuthStrategy enum"""
        with pytest.raises(ValueError) as exc_info:
            wristband_auth.create_auth_dependency(strategies=["SESSION"])  # type: ignore[list-item]

        assert "Invalid authentication strategy" in str(exc_info.value)

    # ============================================================================
    # SESSION STRATEGY TESTS
    # ============================================================================

    @pytest.mark.asyncio
    async def test_session_strategy_succeeds(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_session: Mock
    ) -> None:
        """Test that SESSION strategy succeeds when session auth is valid"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_session

            dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION])
            result = await dependency(mock_request)

            assert isinstance(result, AuthResult)
            assert result.strategy == AuthStrategy.SESSION
            assert result.session == mock_session
            assert result.jwt_result is None

    @pytest.mark.asyncio
    async def test_session_strategy_with_config(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_session: Mock
    ) -> None:
        """Test that SESSION strategy uses provided config"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_session

            session_config = SessionAuthConfig(csrf_header_name="X-Custom-CSRF")

            dependency = wristband_auth.create_auth_dependency(
                strategies=[AuthStrategy.SESSION], session_config=session_config
            )
            await dependency(mock_request)

            # Verify config was passed to validator
            mock_validate.assert_called_once_with(mock_request, "X-Custom-CSRF")

    @pytest.mark.asyncio
    async def test_session_strategy_without_config_uses_defaults(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_session: Mock
    ) -> None:
        """Test that SESSION strategy uses defaults when no config provided"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_session

            dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION])
            await dependency(mock_request)

            # Verify defaults were used
            mock_validate.assert_called_once_with(mock_request, "X-CSRF-TOKEN")

    # ============================================================================
    # JWT STRATEGY TESTS
    # ============================================================================

    @pytest.mark.asyncio
    async def test_jwt_strategy_succeeds(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_jwt_result: JWTAuthResult
    ) -> None:
        """Test that JWT strategy succeeds when JWT auth is valid"""
        with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_jwt_result

            dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.JWT])
            result = await dependency(mock_request)

            assert isinstance(result, AuthResult)
            assert result.strategy == AuthStrategy.JWT
            assert result.jwt_result == mock_jwt_result
            assert result.session is None

    @pytest.mark.asyncio
    async def test_jwt_strategy_with_config(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_jwt_result: JWTAuthResult
    ) -> None:
        """Test that JWT strategy uses provided config"""
        with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_jwt_result

            jwt_config = JWTAuthConfig(jwks_cache_max_size=50, jwks_cache_ttl=7200)

            dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.JWT], jwt_config=jwt_config)
            await dependency(mock_request)

            # Verify config was passed to validator
            mock_validate.assert_called_once_with(mock_request, 50, 7200)

    @pytest.mark.asyncio
    async def test_jwt_strategy_without_config_uses_defaults(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_jwt_result: JWTAuthResult
    ) -> None:
        """Test that JWT strategy uses defaults when no config provided"""
        with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_jwt_result

            dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.JWT])
            await dependency(mock_request)

            # Verify defaults (None) were used
            mock_validate.assert_called_once_with(mock_request, None, None)

    # ============================================================================
    # MULTI-STRATEGY TESTS
    # ============================================================================

    @pytest.mark.asyncio
    async def test_multi_strategy_session_succeeds_first(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_session: Mock
    ) -> None:
        """Test that SESSION is tried first and succeeds in multi-strategy"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_jwt_auth:
                mock_session_auth.return_value = mock_session

                dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])
                result = await dependency(mock_request)

                # SESSION succeeded
                assert result.strategy == AuthStrategy.SESSION
                assert result.session == mock_session

                # JWT was never tried
                mock_jwt_auth.assert_not_called()

    @pytest.mark.asyncio
    async def test_multi_strategy_skips_session_without_session_cookie(
        self, wristband_auth: WristbandAuth, jwt_only_request: Request, mock_jwt_result: JWTAuthResult
    ) -> None:
        """Test that SESSION is skipped when the request has no session cookie"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_jwt_auth:
                mock_jwt_auth.return_value = mock_jwt_result

                dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])
                result = await dependency(jwt_only_request)

                assert result.strategy == AuthStrategy.JWT
                assert result.jwt_result == mock_jwt_result
                mock_session_auth.assert_not_called()

    @pytest.mark.asyncio
    async def test_multi_strategy_skips_jwt_without_authorization_header(
        self, wristband_auth: WristbandAuth, session_only_request: Request, mock_session: Mock
    ) -> None:
        """Test that JWT is skipped when the request has no Authorization header"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_jwt_auth:
                mock_session_auth.return_value = mock_session

                dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.JWT, AuthStrategy.SESSION])
                result = await dependency(session_only_request)

                assert result.strategy == AuthStrategy.SESSION
                mock_jwt_auth.assert_not_called()

    @pytest.mark.asyncio
    async def test_multi_strategy_session_failure_stops_without_trying_jwt(
        self, wristband_auth: WristbandAuth, mock_request: Request
    ) -> None:
        """Test that a failed session credential is final, even when a JWT is also present"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_jwt_auth:
                mock_session_auth.side_effect = HTTPException(status_code=status.HTTP_403_FORBIDDEN)

                dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

                with pytest.raises(HTTPException) as exc_info:
                    await dependency(mock_request)

                assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
                mock_jwt_auth.assert_not_called()

    @pytest.mark.asyncio
    async def test_multi_strategy_jwt_failure_stops_without_trying_session(
        self, wristband_auth: WristbandAuth, mock_request: Request
    ) -> None:
        """Test that a failed JWT credential is final, even when a session cookie is also present"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_jwt_auth:
                mock_jwt_auth.side_effect = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

                dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.JWT, AuthStrategy.SESSION])

                with pytest.raises(HTTPException) as exc_info:
                    await dependency(mock_request)

                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
                mock_session_auth.assert_not_called()

    @pytest.mark.asyncio
    async def test_multi_strategy_preserves_exception_details(
        self, wristband_auth: WristbandAuth, session_only_request: Request
    ) -> None:
        """Test that the failing strategy's exception is raised as-is"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            mock_session_auth.side_effect = HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed"
            )

            dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

            with pytest.raises(HTTPException) as exc_info:
                await dependency(session_only_request)

            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
            assert exc_info.value.detail == "CSRF validation failed"

    @pytest.mark.asyncio
    async def test_multi_strategy_unexpected_exceptions_propagate(
        self, wristband_auth: WristbandAuth, mock_request: Request
    ) -> None:
        """Test that unexpected exceptions aren't swallowed and don't fall through to the next strategy"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_jwt_auth:
                mock_session_auth.side_effect = RuntimeError("Database connection failed")

                dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

                with pytest.raises(RuntimeError, match="Database connection failed"):
                    await dependency(mock_request)

                mock_jwt_auth.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "strategies",
        [
            [AuthStrategy.SESSION],
            [AuthStrategy.JWT],
            [AuthStrategy.SESSION, AuthStrategy.JWT],
            [AuthStrategy.JWT, AuthStrategy.SESSION],
        ],
    )
    async def test_no_credentials_raises_401(
        self, wristband_auth: WristbandAuth, no_credential_request: Request, strategies: list
    ) -> None:
        """Test that a 401 is raised when every strategy is skipped"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_jwt_auth:
                dependency = wristband_auth.create_auth_dependency(strategies=strategies)

                with pytest.raises(HTTPException) as exc_info:
                    await dependency(no_credential_request)

                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
                mock_session_auth.assert_not_called()
                mock_jwt_auth.assert_not_called()

    @pytest.mark.asyncio
    async def test_session_strategy_raises_runtime_error_without_session_middleware(
        self, wristband_auth: WristbandAuth, mock_request: Request
    ) -> None:
        """Test that SESSION raises a RuntimeError when SessionMiddleware is not registered"""
        mock_request.state = Mock(spec=[])

        dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

        with pytest.raises(RuntimeError, match="SessionMiddleware"):
            await dependency(mock_request)

    @pytest.mark.asyncio
    async def test_multi_strategy_order_matters(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_jwt_result: JWTAuthResult, mock_session: Mock
    ) -> None:
        """Test that strategies are tried in the order specified"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_session_auth:
            with patch.object(wristband_auth, "_validate_jwt_auth", new_callable=AsyncMock) as mock_jwt_auth:
                mock_session_auth.return_value = mock_session
                mock_jwt_auth.return_value = mock_jwt_result

                # JWT first
                dependency1 = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.JWT, AuthStrategy.SESSION])
                result1 = await dependency1(mock_request)
                assert result1.strategy == AuthStrategy.JWT

                # SESSION first
                dependency2 = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])
                result2 = await dependency2(mock_request)
                assert result2.strategy == AuthStrategy.SESSION

    # ============================================================================
    # LOGGING TESTS
    # ============================================================================

    @pytest.mark.asyncio
    async def test_logs_multi_strategy_execution(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_session: Mock
    ) -> None:
        """Test that multi-strategy auth logs execution"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_session

            with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
                dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION])
                await dependency(mock_request)

                # Check logs
                debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
                assert any("Executing multi-strategy auth for:" in msg for msg in debug_calls)
                assert any("Trying SESSION authentication" in msg for msg in debug_calls)

    @pytest.mark.asyncio
    async def test_logs_skipped_strategies(self, wristband_auth: WristbandAuth, no_credential_request: Request) -> None:
        """Test that skipped strategies are logged"""
        with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
            dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION, AuthStrategy.JWT])

            with pytest.raises(HTTPException):
                await dependency(no_credential_request)

            # Check logs
            debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
            assert any("Skipping session authentication" in msg for msg in debug_calls)
            assert any("Skipping jwt authentication" in msg for msg in debug_calls)
            assert any("No authentication credentials found for any strategy" in msg for msg in debug_calls)

    # ============================================================================
    # DEPENDENCY REUSABILITY TESTS
    # ============================================================================

    @pytest.mark.asyncio
    async def test_dependency_is_reusable(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_session: Mock
    ) -> None:
        """Test that the same dependency can be used multiple times"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_session

            dependency = wristband_auth.create_auth_dependency(strategies=[AuthStrategy.SESSION])

            result1 = await dependency(mock_request)
            result2 = await dependency(mock_request)

            assert result1.strategy == AuthStrategy.SESSION
            assert result2.strategy == AuthStrategy.SESSION
            assert mock_validate.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_dependencies_with_different_configs(
        self, wristband_auth: WristbandAuth, mock_request: Request, mock_session: Mock
    ) -> None:
        """Test that multiple dependencies can be created with different configurations"""
        with patch.object(wristband_auth, "_validate_session_auth", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = mock_session

            # Different configs
            dep1 = wristband_auth.create_auth_dependency(
                strategies=[AuthStrategy.SESSION], session_config=SessionAuthConfig(csrf_header_name="X-CSRF-A")
            )
            dep2 = wristband_auth.create_auth_dependency(
                strategies=[AuthStrategy.SESSION], session_config=SessionAuthConfig(csrf_header_name="X-CSRF-B")
            )

            await dep1(mock_request)
            await dep2(mock_request)

            # Verify different configs were used
            assert mock_validate.call_count == 2
            calls = mock_validate.call_args_list
            assert calls[0][0][1] == "X-CSRF-A"
            assert calls[1][0][1] == "X-CSRF-B"
