from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException, Request, status

from wristband.fastapi_auth import AuthConfig, TokenData, WristbandAuth


class TestCreateSessionAuthDependency:
    """Unit tests for WristbandAuth.create_session_auth_dependency()"""

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
    def mock_authenticated_request(self) -> Request:
        """Create a mock authenticated request with valid session"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {"X-CSRF-TOKEN": "valid_csrf_token"}

        # Create mock session with attributes
        session = Mock()
        session.is_authenticated = True
        session.csrf_token = "valid_csrf_token"
        session.refresh_token = "valid_refresh_token"
        session.expires_at = 9999999999999
        session.access_token = "valid_access_token"
        session.save = Mock()
        request.state.session = session

        return request

    @pytest.mark.asyncio
    async def test_successful_authentication_with_valid_session(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request
    ) -> None:
        """Test that dependency passes with valid authenticated session"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()
                await dependency(mock_authenticated_request)

                mock_authenticated_request.state.session.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_successful_authentication_with_custom_csrf_header(self, wristband_auth: WristbandAuth) -> None:
        """Test that dependency works with custom CSRF header name"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {"X-Custom-CSRF": "valid_csrf_token"}

        session = Mock()
        session.is_authenticated = True
        session.csrf_token = "valid_csrf_token"
        session.refresh_token = "valid_refresh_token"
        session.expires_at = 9999999999999
        session.access_token = "valid_access_token"
        session.save = Mock()
        request.state.session = session

        with patch("wristband.fastapi_auth.auth.is_csrf_token_valid", return_value=True) as mock_csrf:
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency(
                    enable_csrf_protection=True,
                    csrf_header_name="X-Custom-CSRF",
                )
                await dependency(request)

                # Verify is_csrf_token_valid was called with custom header name
                mock_csrf.assert_called_once_with(request, "X-Custom-CSRF")
                request.state.session.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_session_middleware_missing(self, wristband_auth: WristbandAuth) -> None:
        """Test that RuntimeError is raised when SessionMiddleware is not registered"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock(spec=[])

        dependency = wristband_auth.create_session_auth_dependency()

        with pytest.raises(RuntimeError) as exc_info:
            await dependency(request)

        assert "Session not found" in str(exc_info.value)
        assert "SessionMiddleware" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_raises_401_when_not_authenticated(self, wristband_auth: WristbandAuth) -> None:
        """Test that 401 is raised when user is not authenticated"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()

        session = Mock()
        session.is_authenticated = False
        request.state.session = session

        dependency = wristband_auth.create_session_auth_dependency()

        with pytest.raises(HTTPException) as exc_info:
            await dependency(request)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_raises_403_when_csrf_token_invalid(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request
    ) -> None:
        """Test that 403 is raised when CSRF token is invalid"""
        with patch("wristband.fastapi_auth.auth.is_csrf_token_valid", return_value=False):
            dependency = wristband_auth.create_session_auth_dependency(enable_csrf_protection=True)

            with pytest.raises(HTTPException) as exc_info:
                await dependency(mock_authenticated_request)

            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_raises_403_when_custom_csrf_header_invalid(self, wristband_auth: WristbandAuth) -> None:
        """Test that 403 is raised when custom CSRF header token is invalid"""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {"X-Custom-CSRF": "wrong_token"}

        session = Mock()
        session.is_authenticated = True
        session.csrf_token = "valid_csrf_token"
        request.state.session = session

        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=False):
            dependency = wristband_auth.create_session_auth_dependency(
                enable_csrf_protection=True,
                csrf_header_name="X-Custom-CSRF",
            )

            with pytest.raises(HTTPException) as exc_info:
                await dependency(request)

            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_refreshes_expired_token(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that expired tokens are refreshed and session is updated"""
        new_token_data = TokenData(
            access_token="new_access_token",
            id_token="new_id_token",
            expires_at=9999999999999,
            expires_in=3600,
            refresh_token="new_refresh_token",
        )

        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = new_token_data

                dependency = wristband_auth.create_session_auth_dependency()
                await dependency(mock_authenticated_request)

                # Verify refresh was called with the original session values
                mock_refresh.assert_called_once_with("valid_refresh_token", 9999999999999)

                # Verify session attributes were updated
                assert mock_authenticated_request.state.session.access_token == "new_access_token"
                assert mock_authenticated_request.state.session.refresh_token == "new_refresh_token"
                assert mock_authenticated_request.state.session.expires_at == 9999999999999

                # Verify save was called
                mock_authenticated_request.state.session.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_401_when_token_refresh_fails(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that 401 is raised when token refresh fails"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.side_effect = Exception("Token refresh failed")

                dependency = wristband_auth.create_session_auth_dependency()

                with pytest.raises(HTTPException) as exc_info:
                    await dependency(mock_authenticated_request)

                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_session_save_called_even_when_no_refresh_needed(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that session.save() is called even when token doesn't need refresh (rolling sessions)"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()
                await dependency(mock_authenticated_request)

                # save() should be called with no arguments
                mock_authenticated_request.state.session.save.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_dependency_returns_session_on_success(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that dependency returns typed Session on successful authentication"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()
                result = await dependency(mock_authenticated_request)

                # Should return the session object, not None
                assert result is mock_authenticated_request.state.session
                assert result.is_authenticated is True

    @pytest.mark.asyncio
    async def test_dependency_returns_session_after_token_refresh(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that dependency returns session with updated tokens after refresh"""
        new_token_data = TokenData(
            access_token="new_access_token",
            id_token="new_id_token",
            expires_at=9999999999999,
            expires_in=3600,
            refresh_token="new_refresh_token",
        )

        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = new_token_data

                dependency = wristband_auth.create_session_auth_dependency()
                result = await dependency(mock_authenticated_request)

                # Verify returned session has the new tokens
                assert result is mock_authenticated_request.state.session
                assert result.access_token == "new_access_token"
                assert result.refresh_token == "new_refresh_token"
                assert result.expires_at == 9999999999999

    @pytest.mark.asyncio
    async def test_dependency_can_be_used_as_typed_injection(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that dependency can be used for typed session injection in FastAPI routes"""
        from wristband.fastapi_auth.session import Session

        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()
                session: Session = await dependency(mock_authenticated_request)

                # Verify we can access typed Session attributes
                assert hasattr(session, "is_authenticated")
                assert hasattr(session, "user_id")
                assert hasattr(session, "access_token")
                assert session.is_authenticated is True

    @pytest.mark.asyncio
    async def test_dependency_is_reusable(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that the same dependency can be used multiple times"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()

                await dependency(mock_authenticated_request)
                await dependency(mock_authenticated_request)

                assert mock_authenticated_request.state.session.save.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_dependencies_with_different_csrf_headers(self, wristband_auth: WristbandAuth) -> None:
        """Test that multiple dependencies can be created with different CSRF header names"""
        # Create first request with default header
        request1 = Mock(spec=Request)
        request1.method = "POST"
        request1.url = Mock()
        request1.url.path = "/api/endpoint1"
        request1.state = Mock()
        request1.headers = {"X-CSRF-TOKEN": "token1"}

        session1 = Mock()
        session1.is_authenticated = True
        session1.csrf_token = "token1"
        session1.refresh_token = "refresh1"
        session1.expires_at = 9999999999999
        session1.save = Mock()
        request1.state.session = session1

        # Create second request with custom header
        request2 = Mock(spec=Request)
        request2.method = "POST"
        request2.url = Mock()
        request2.url.path = "/api/endpoint2"
        request2.state = Mock()
        request2.headers = {"X-Custom-CSRF": "token2"}

        session2 = Mock()
        session2.is_authenticated = True
        session2.csrf_token = "token2"
        session2.refresh_token = "refresh2"
        session2.expires_at = 9999999999999
        session2.save = Mock()
        request2.state.session = session2

        with patch("wristband.fastapi_auth.auth.is_csrf_token_valid", return_value=True) as mock_csrf:
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                # Create two different dependencies
                dependency1 = wristband_auth.create_session_auth_dependency(enable_csrf_protection=True)
                dependency2 = wristband_auth.create_session_auth_dependency(
                    enable_csrf_protection=True,
                    csrf_header_name="X-Custom-CSRF",
                )

                # Use both dependencies
                await dependency1(request1)
                await dependency2(request2)

                # Verify is_csrf_token_valid was called with correct header names
                assert mock_csrf.call_count == 2
                mock_csrf.assert_any_call(request1, "X-CSRF-TOKEN")
                mock_csrf.assert_any_call(request2, "X-Custom-CSRF")

    @pytest.mark.asyncio
    async def test_only_token_fields_updated_during_refresh(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that only token-related fields are updated during refresh"""
        # Set additional session attributes
        mock_authenticated_request.state.session.user_id = "user_123"
        mock_authenticated_request.state.session.tenant_id = "tenant_456"

        new_token_data = TokenData(
            access_token="brand_new_token",
            id_token="brand_new_id_token",
            expires_at=8888888888888,
            expires_in=7200,
            refresh_token="brand_new_refresh_token",
        )

        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = new_token_data

                dependency = wristband_auth.create_session_auth_dependency()
                await dependency(mock_authenticated_request)

                # Verify token fields were updated
                assert mock_authenticated_request.state.session.access_token == "brand_new_token"
                assert mock_authenticated_request.state.session.refresh_token == "brand_new_refresh_token"
                assert mock_authenticated_request.state.session.expires_at == 8888888888888

                # Verify other fields were NOT changed
                assert mock_authenticated_request.state.session.user_id == "user_123"
                assert mock_authenticated_request.state.session.tenant_id == "tenant_456"

    @pytest.mark.asyncio
    async def test_logs_debug_message(self, wristband_auth: WristbandAuth, mock_authenticated_request: Request) -> None:
        """Test that debug logging occurs"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
                    dependency = wristband_auth.create_session_auth_dependency()
                    await dependency(mock_authenticated_request)

                    mock_logger.debug.assert_called_once()
                    log_message = mock_logger.debug.call_args[0][0]
                    assert "Executing session auth for:" in log_message
                    assert "GET" in log_message
                    assert "/api/protected" in log_message

    @pytest.mark.asyncio
    async def test_logs_exception_on_refresh_failure(
        self,
        wristband_auth: WristbandAuth,
        mock_authenticated_request: Request,
    ) -> None:
        """Test that exceptions during refresh are logged"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.side_effect = Exception("Refresh error")

                with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
                    dependency = wristband_auth.create_session_auth_dependency()

                    with pytest.raises(HTTPException):
                        await dependency(mock_authenticated_request)

                    mock_logger.exception.assert_called_once()
                    log_message = mock_logger.exception.call_args[0][0]
                    assert "Session auth error during token refresh" in log_message

    @pytest.mark.asyncio
    async def test_csrf_validation_skipped_when_disabled(self, wristband_auth: WristbandAuth) -> None:
        """Test that CSRF validation is skipped when enable_csrf_protection=False (default)"""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        # Intentionally provide NO CSRF header at all
        request.headers = {}

        session = Mock()
        session.is_authenticated = True
        session.csrf_token = "valid_csrf_token"
        session.refresh_token = "valid_refresh_token"
        session.expires_at = 9999999999999
        session.access_token = "valid_access_token"
        session.save = Mock()
        request.state.session = session

        with patch("wristband.fastapi_auth.auth.is_csrf_token_valid") as mock_csrf:
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                # Default behavior - CSRF protection disabled
                dependency = wristband_auth.create_session_auth_dependency()
                result = await dependency(request)

                # CSRF validation should NOT have been called at all
                mock_csrf.assert_not_called()

                # Request should still succeed despite missing CSRF token
                assert result is session
                session.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_csrf_validation_skipped_even_with_invalid_token_when_disabled(
        self, wristband_auth: WristbandAuth
    ) -> None:
        """Test that even an invalid CSRF token doesn't cause failure when CSRF is disabled"""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        # Provide WRONG CSRF token, but CSRF protection is disabled
        request.headers = {"X-CSRF-TOKEN": "wrong_token"}

        session = Mock()
        session.is_authenticated = True
        session.csrf_token = "correct_token"  # Different from header
        session.refresh_token = "valid_refresh_token"
        session.expires_at = 9999999999999
        session.access_token = "valid_access_token"
        session.save = Mock()
        request.state.session = session

        with patch("wristband.fastapi_auth.auth.is_csrf_token_valid") as mock_csrf:
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                # CSRF protection disabled (default)
                dependency = wristband_auth.create_session_auth_dependency()
                result = await dependency(request)

                # Should not validate CSRF at all
                mock_csrf.assert_not_called()

                # Should succeed despite mismatched tokens
                assert result is session

    @pytest.mark.asyncio
    async def test_skips_refresh_when_refresh_token_is_none(self, wristband_auth: WristbandAuth) -> None:
        """Test that token refresh is skipped when refresh_token is None"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {}

        session = Mock()
        session.is_authenticated = True
        session.refresh_token = None  # No refresh token
        session.expires_at = 9999999999999
        session.save = Mock()
        request.state.session = session

        with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
            dependency = wristband_auth.create_session_auth_dependency()
            result = await dependency(request)

            # refresh_token_if_expired should NOT have been called
            mock_refresh.assert_not_called()

            # Session should still be saved
            session.save.assert_called_once()
            assert result is session

    @pytest.mark.asyncio
    async def test_skips_refresh_when_expires_at_is_none(self, wristband_auth: WristbandAuth) -> None:
        """Test that token refresh is skipped when expires_at is None"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {}

        session = Mock()
        session.is_authenticated = True
        session.refresh_token = "valid_refresh_token"
        session.expires_at = None  # No expiration time
        session.save = Mock()
        request.state.session = session

        with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
            dependency = wristband_auth.create_session_auth_dependency()
            result = await dependency(request)

            # refresh_token_if_expired should NOT have been called
            mock_refresh.assert_not_called()

            # Session should still be saved
            session.save.assert_called_once()
            assert result is session

    @pytest.mark.asyncio
    async def test_skips_refresh_when_both_tokens_are_none(self, wristband_auth: WristbandAuth) -> None:
        """Test that token refresh is skipped when both refresh_token and expires_at are None"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {}

        session = Mock()
        session.is_authenticated = True
        session.refresh_token = None
        session.expires_at = None
        session.save = Mock()
        request.state.session = session

        with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
            dependency = wristband_auth.create_session_auth_dependency()
            result = await dependency(request)

            # refresh_token_if_expired should NOT have been called
            mock_refresh.assert_not_called()

            # Session should still be saved
            session.save.assert_called_once()
            assert result is session

    @pytest.mark.asyncio
    async def test_attempts_refresh_when_both_tokens_present(self, wristband_auth: WristbandAuth) -> None:
        """Test that token refresh is attempted when both refresh_token and expires_at are present"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {}

        session = Mock()
        session.is_authenticated = True
        session.refresh_token = "valid_refresh_token"
        session.expires_at = 9999999999999
        session.save = Mock()
        request.state.session = session

        with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
            mock_refresh.return_value = None  # No refresh needed

            dependency = wristband_auth.create_session_auth_dependency()
            result = await dependency(request)

            # refresh_token_if_expired SHOULD have been called
            mock_refresh.assert_called_once_with("valid_refresh_token", 9999999999999)

            # Session should be saved
            session.save.assert_called_once()
            assert result is session
