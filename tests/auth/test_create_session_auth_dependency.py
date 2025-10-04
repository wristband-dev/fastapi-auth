from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException, Request, Response, status

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
        session_manager = Mock()
        session_manager.is_authenticated = True
        session_manager.csrf_token = "valid_csrf_token"
        session_manager.refresh_token = "valid_refresh_token"
        session_manager.expires_at = 9999999999999
        session_manager.access_token = "valid_access_token"
        session_manager.save = Mock()
        request.state.session = session_manager

        return request

    @pytest.fixture
    def mock_response(self) -> Response:
        """Create a mock response"""
        return Mock(spec=Response)

    @pytest.mark.asyncio
    async def test_successful_authentication_with_valid_session(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
    ) -> None:
        """Test that dependency passes with valid authenticated session"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()
                await dependency(mock_authenticated_request, mock_response)

                mock_authenticated_request.state.session.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_successful_authentication_with_custom_csrf_header(
        self, wristband_auth: WristbandAuth, mock_response: Response
    ) -> None:
        """Test that dependency works with custom CSRF header name"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {"X-Custom-CSRF": "valid_csrf_token"}

        session_manager = Mock()
        session_manager.is_authenticated = True
        session_manager.csrf_token = "valid_csrf_token"
        session_manager.refresh_token = "valid_refresh_token"
        session_manager.expires_at = 9999999999999
        session_manager.access_token = "valid_access_token"
        session_manager.save = Mock()
        request.state.session = session_manager

        with patch("wristband.fastapi_auth.auth.is_csrf_token_valid", return_value=True) as mock_csrf:
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency(csrf_header_name="X-Custom-CSRF")
                await dependency(request, mock_response)

                # Verify is_csrf_token_valid was called with custom header name
                mock_csrf.assert_called_once_with(request, "X-Custom-CSRF")
                request.state.session.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_session_middleware_missing(
        self, wristband_auth: WristbandAuth, mock_response: Response
    ) -> None:
        """Test that RuntimeError is raised when SessionMiddleware is not registered"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock(spec=[])

        dependency = wristband_auth.create_session_auth_dependency()

        with pytest.raises(RuntimeError) as exc_info:
            await dependency(request, mock_response)

        assert "Session manager not found" in str(exc_info.value)
        assert "SessionMiddleware" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_raises_401_when_not_authenticated(
        self, wristband_auth: WristbandAuth, mock_response: Response
    ) -> None:
        """Test that 401 is raised when user is not authenticated"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()

        session_manager = Mock()
        session_manager.is_authenticated = False
        request.state.session = session_manager

        dependency = wristband_auth.create_session_auth_dependency()

        with pytest.raises(HTTPException) as exc_info:
            await dependency(request, mock_response)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_raises_403_when_csrf_token_invalid(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
    ) -> None:
        """Test that 403 is raised when CSRF token is invalid"""
        with patch("wristband.fastapi_auth.auth.is_csrf_token_valid", return_value=False):
            dependency = wristband_auth.create_session_auth_dependency()

            with pytest.raises(HTTPException) as exc_info:
                await dependency(mock_authenticated_request, mock_response)

            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_raises_403_when_custom_csrf_header_invalid(
        self, wristband_auth: WristbandAuth, mock_response: Response
    ) -> None:
        """Test that 403 is raised when custom CSRF header token is invalid"""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.state = Mock()
        request.headers = {"X-Custom-CSRF": "wrong_token"}

        session_manager = Mock()
        session_manager.is_authenticated = True
        session_manager.csrf_token = "valid_csrf_token"
        request.state.session = session_manager

        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=False):
            dependency = wristband_auth.create_session_auth_dependency(csrf_header_name="X-Custom-CSRF")

            with pytest.raises(HTTPException) as exc_info:
                await dependency(request, mock_response)

            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_refreshes_expired_token(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
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
                await dependency(mock_authenticated_request, mock_response)

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
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
    ) -> None:
        """Test that 401 is raised when token refresh fails"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.side_effect = Exception("Token refresh failed")

                dependency = wristband_auth.create_session_auth_dependency()

                with pytest.raises(HTTPException) as exc_info:
                    await dependency(mock_authenticated_request, mock_response)

                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_session_save_called_even_when_no_refresh_needed(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
    ) -> None:
        """Test that session.save() is called even when token doesn't need refresh (rolling sessions)"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()
                await dependency(mock_authenticated_request, mock_response)

                # save() should be called with no arguments
                mock_authenticated_request.state.session.save.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_dependency_returns_none_on_success(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
    ) -> None:
        """Test that dependency returns None on successful authentication"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()
                result = await dependency(mock_authenticated_request, mock_response)

                assert result is None

    @pytest.mark.asyncio
    async def test_dependency_is_reusable(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
    ) -> None:
        """Test that the same dependency can be used multiple times"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                dependency = wristband_auth.create_session_auth_dependency()

                await dependency(mock_authenticated_request, mock_response)
                await dependency(mock_authenticated_request, mock_response)

                assert mock_authenticated_request.state.session.save.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_dependencies_with_different_csrf_headers(
        self, wristband_auth: WristbandAuth, mock_response: Response
    ) -> None:
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
                dependency1 = wristband_auth.create_session_auth_dependency()
                dependency2 = wristband_auth.create_session_auth_dependency(csrf_header_name="X-Custom-CSRF")

                # Use both dependencies
                await dependency1(request1, mock_response)
                await dependency2(request2, mock_response)

                # Verify is_csrf_token_valid was called with correct header names
                assert mock_csrf.call_count == 2
                mock_csrf.assert_any_call(request1, "X-CSRF-TOKEN")
                mock_csrf.assert_any_call(request2, "X-Custom-CSRF")

    @pytest.mark.asyncio
    async def test_only_token_fields_updated_during_refresh(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
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
                await dependency(mock_authenticated_request, mock_response)

                # Verify token fields were updated
                assert mock_authenticated_request.state.session.access_token == "brand_new_token"
                assert mock_authenticated_request.state.session.refresh_token == "brand_new_refresh_token"
                assert mock_authenticated_request.state.session.expires_at == 8888888888888

                # Verify other fields were NOT changed
                assert mock_authenticated_request.state.session.user_id == "user_123"
                assert mock_authenticated_request.state.session.tenant_id == "tenant_456"

    @pytest.mark.asyncio
    async def test_logs_debug_message(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
    ) -> None:
        """Test that debug logging occurs"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.return_value = None

                with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
                    dependency = wristband_auth.create_session_auth_dependency()
                    await dependency(mock_authenticated_request, mock_response)

                    mock_logger.debug.assert_called_once()
                    log_message = mock_logger.debug.call_args[0][0]
                    assert "Executing session auth for:" in log_message
                    assert "GET" in log_message
                    assert "/api/protected" in log_message

    @pytest.mark.asyncio
    async def test_logs_exception_on_refresh_failure(
        self, wristband_auth: WristbandAuth, mock_authenticated_request: Request, mock_response: Response
    ) -> None:
        """Test that exceptions during refresh are logged"""
        with patch("wristband.fastapi_auth.csrf.is_csrf_token_valid", return_value=True):
            with patch.object(wristband_auth, "refresh_token_if_expired", new_callable=AsyncMock) as mock_refresh:
                mock_refresh.side_effect = Exception("Refresh error")

                with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
                    dependency = wristband_auth.create_session_auth_dependency()

                    with pytest.raises(HTTPException):
                        await dependency(mock_authenticated_request, mock_response)

                    mock_logger.exception.assert_called_once()
                    log_message = mock_logger.exception.call_args[0][0]
                    assert "Session auth error during token refresh" in log_message
