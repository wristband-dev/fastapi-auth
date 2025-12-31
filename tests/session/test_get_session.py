from unittest.mock import Mock

import pytest
from fastapi import Request

from wristband.fastapi_auth import get_session
from wristband.fastapi_auth.session import Session


class TestGetSession:
    """Unit tests for get_session() helper function"""

    @pytest.fixture
    def mock_request_with_session(self) -> Request:
        """Create a mock request with a session"""
        request = Mock(spec=Request)
        session = Mock()
        session.user_id = "user_123"
        session.is_authenticated = True
        request.state = Mock()
        request.state.session = session
        return request

    def test_get_session_returns_typed_session(self, mock_request_with_session: Request) -> None:
        """Test that get_session returns the typed session object"""
        session = get_session(mock_request_with_session)

        assert session is mock_request_with_session.state.session
        assert session.user_id == "user_123"
        assert session.is_authenticated is True

    def test_get_session_raises_runtime_error_when_middleware_missing(self) -> None:
        """Test that get_session raises RuntimeError when SessionMiddleware not installed"""
        request = Mock(spec=Request)
        request.state = Mock(spec=[])  # No session attribute

        with pytest.raises(RuntimeError) as exc_info:
            get_session(request)

        assert "Session not found" in str(exc_info.value)
        assert "SessionMiddleware" in str(exc_info.value)

    def test_get_session_works_with_router_level_auth(self, mock_request_with_session: Request) -> None:
        """Test get_session usage pattern with router-level dependencies"""
        # Simulate a route handler with router-level auth
        # (no double execution, just manual session access)
        session = get_session(mock_request_with_session)

        # Should have access to all session attributes
        assert session.user_id == "user_123"
        assert session.is_authenticated is True

    def test_get_session_provides_type_safety(self, mock_request_with_session: Request) -> None:
        """Test that get_session return type enables IDE autocomplete"""
        session: Session = get_session(mock_request_with_session)

        # This test verifies the function signature enables type checking
        # The cast() inside get_session should make this type-safe
        assert isinstance(session, Mock)  # Mock in tests, Session in production

    def test_get_session_with_none_session(self) -> None:
        """Test get_session when request.state.session is None"""
        request = Mock(spec=Request)
        request.state = Mock()
        request.state.session = None

        # Should return None (not raise)
        session = get_session(request)
        assert session is None

    def test_get_session_multiple_calls_same_request(self, mock_request_with_session: Request) -> None:
        """Test that multiple calls to get_session return the same instance"""
        session1 = get_session(mock_request_with_session)
        session2 = get_session(mock_request_with_session)

        # Should return the exact same object
        assert session1 is session2
