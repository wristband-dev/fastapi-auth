import pytest
from fastapi import HTTPException

from wristband.fastapi_auth import SessionResponse
from wristband.fastapi_auth.models import SameSiteOption
from wristband.fastapi_auth.session import Session, SessionManager
from wristband.fastapi_auth.utils import DataEncryptor


class TestSessionGetSessionResponse:
    """Unit tests for Session.get_session_response()"""

    @pytest.fixture
    def session(self) -> SessionManager:
        """Create a Session instance for testing"""
        encryptor = DataEncryptor("a" * 32)
        return SessionManager(
            encryptor=encryptor,
            session_cookie_name="session",
            session_cookie_domain=None,
            csrf_cookie_name="CSRF-TOKEN",
            csrf_cookie_domain=None,
            max_age=3600,
            path="/",
            same_site=SameSiteOption.LAX,
            secure=True,
            enable_csrf_protection=False,
        )

    def test_get_session_response_with_no_metadata(self, session: Session) -> None:
        """Test getting session response without metadata"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
                "user_id": "user_123",
            }
        )

        result = session.get_session_response()

        assert isinstance(result, SessionResponse)
        assert result.tenant_id == "tenant_456"
        assert result.user_id == "user_123"
        assert result.metadata == {}

    def test_get_session_response_with_metadata(self, session: Session) -> None:
        """Test getting session response with custom metadata"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
                "user_id": "user_123",
            }
        )

        custom_metadata = {
            "role": "admin",
            "permissions": ["read", "write"],
            "preferences": {"theme": "dark", "language": "en"},
        }

        result = session.get_session_response(metadata=custom_metadata)

        assert isinstance(result, SessionResponse)
        assert result.tenant_id == "tenant_456"
        assert result.user_id == "user_123"
        assert result.metadata == custom_metadata
        assert result.metadata["role"] == "admin"
        assert result.metadata["permissions"] == ["read", "write"]
        assert result.metadata["preferences"]["theme"] == "dark"

    def test_get_session_response_with_empty_metadata_dict(self, session: Session) -> None:
        """Test getting session response with explicitly empty metadata dict"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
                "user_id": "user_123",
            }
        )

        result = session.get_session_response(metadata={})

        assert isinstance(result, SessionResponse)
        assert result.metadata == {}

    def test_get_session_response_serialization_format(self, session: Session) -> None:
        """Test that the response serializes with correct field names"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
                "user_id": "user_123",
            }
        )

        metadata = {"custom_field": "value"}
        result = session.get_session_response(metadata=metadata)

        # Test serialization uses camelCase aliases
        serialized = result.model_dump()
        assert "tenantId" in serialized
        assert "userId" in serialized
        assert "metadata" in serialized
        assert serialized["tenantId"] == "tenant_456"
        assert serialized["userId"] == "user_123"
        assert serialized["metadata"] == metadata

    def test_get_session_response_with_different_session_data(self, session: Session) -> None:
        """Test with different session data values"""
        session._load_from_dict(
            {
                "tenant_id": "different_tenant",
                "user_id": "different_user",
            }
        )

        result = session.get_session_response()

        assert result.user_id == "different_user"
        assert result.tenant_id == "different_tenant"

    def test_get_session_response_with_complex_metadata(self, session: Session) -> None:
        """Test with complex nested metadata structure"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
                "user_id": "user_123",
            }
        )

        complex_metadata = {
            "user_settings": {
                "notifications": {
                    "email": True,
                    "push": False,
                    "frequency": "daily",
                },
                "privacy": {
                    "profile_visible": True,
                    "show_email": False,
                },
            },
            "feature_flags": ["new_ui", "beta_features"],
            "stats": {
                "login_count": 42,
                "last_login": "2025-09-30T12:00:00Z",
            },
        }

        result = session.get_session_response(metadata=complex_metadata)

        assert result.metadata == complex_metadata
        assert result.metadata["user_settings"]["notifications"]["email"] is True
        assert result.metadata["feature_flags"] == ["new_ui", "beta_features"]
        assert result.metadata["stats"]["login_count"] == 42

    def test_get_session_response_none_metadata_defaults_to_empty_dict(self, session: Session) -> None:
        """Test that None metadata defaults to empty dict"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
                "user_id": "user_123",
            }
        )

        result = session.get_session_response(metadata=None)

        assert result.metadata == {}
        assert isinstance(result.metadata, dict)

    def test_get_session_response_with_missing_tenant_id(self, session: Session) -> None:
        """Test that HTTPException is raised when tenant_id is missing"""
        session._load_from_dict(
            {
                "user_id": "user_123",
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            session.get_session_response()

        assert exc_info.value.status_code == 401

    def test_get_session_response_with_missing_user_id(self, session: Session) -> None:
        """Test that HTTPException is raised when user_id is missing"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            session.get_session_response()

        assert exc_info.value.status_code == 401

    def test_get_session_response_with_empty_tenant_id(self, session: Session) -> None:
        """Test that HTTPException is raised when tenant_id is empty string"""
        session._load_from_dict(
            {
                "tenant_id": "",
                "user_id": "user_123",
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            session.get_session_response()

        assert exc_info.value.status_code == 401

    def test_get_session_response_with_empty_user_id(self, session: Session) -> None:
        """Test that HTTPException is raised when user_id is empty string"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
                "user_id": "",
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            session.get_session_response()

        assert exc_info.value.status_code == 401

    def test_get_session_response_does_not_include_other_session_fields(self, session: Session) -> None:
        """Test that SessionResponse only includes tenant_id, user_id, and metadata"""
        session._load_from_dict(
            {
                "tenant_id": "tenant_456",
                "user_id": "user_123",
                "access_token": "secret_token",
                "csrf_token": "csrf_abc",
                "expires_at": 1735689600000,
            }
        )

        result = session.get_session_response()

        # Verify only expected fields are present (using serialization aliases)
        result_dict = result.model_dump()
        assert set(result_dict.keys()) == {"tenantId", "userId", "metadata"}
        assert "accessToken" not in result_dict
        assert "csrfToken" not in result_dict
