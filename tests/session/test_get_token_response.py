import pytest
from fastapi import HTTPException

from wristband.fastapi_auth import TokenResponse
from wristband.fastapi_auth.models import SameSiteOption
from wristband.fastapi_auth.session import Session, SessionManager
from wristband.fastapi_auth.utils import DataEncryptor


class TestSessionGetTokenResponse:
    """Unit tests for Session.get_token_response()"""

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

    def test_get_token_response_returns_correct_data(self, session: Session) -> None:
        """Test that get_token_response returns correct access token and expiration"""
        session._load_from_dict(
            {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_token",
                "expires_at": 1735689600000,
            }
        )

        result = session.get_token_response()

        assert isinstance(result, TokenResponse)
        assert result.access_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_token"
        assert result.expires_at == 1735689600000

    def test_get_token_response_serialization_format(self, session: Session) -> None:
        """Test that the response serializes with correct field names (camelCase)"""
        session._load_from_dict(
            {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_token",
                "expires_at": 1735689600000,
            }
        )

        result = session.get_token_response()

        # Test serialization uses camelCase aliases
        serialized = result.model_dump()
        assert "accessToken" in serialized
        assert "expiresAt" in serialized
        assert serialized["accessToken"] == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_token"
        assert serialized["expiresAt"] == 1735689600000

    def test_get_token_response_does_not_include_other_session_fields(self, session: Session) -> None:
        """Test that TokenResponse only includes access_token and expires_at"""
        session._load_from_dict(
            {
                "access_token": "token",
                "expires_at": 1735689600000,
                "user_id": "user_123",
                "tenant_id": "tenant_456",
                "csrf_token": "csrf_abc",
            }
        )

        result = session.get_token_response()

        # Verify only expected fields are present (using serialization aliases)
        result_dict = result.model_dump()
        assert set(result_dict.keys()) == {"accessToken", "expiresAt"}

    def test_get_token_response_with_empty_access_token(self, session: Session) -> None:
        """Test behavior when session has empty access token - should raise 401"""
        session._load_from_dict(
            {
                "access_token": "",
                "expires_at": 1735689600000,
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            session.get_token_response()

        assert exc_info.value.status_code == 401

    def test_get_token_response_with_missing_access_token(self, session: Session) -> None:
        """Test behavior when session has missing access_token - should raise 401"""
        session._load_from_dict(
            {
                "expires_at": 1735689600000,
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            session.get_token_response()

        assert exc_info.value.status_code == 401

    def test_get_token_response_with_missing_expires_at(self, session: Session) -> None:
        """Test behavior when session has missing expires_at - should raise 401"""
        session._load_from_dict(
            {
                "access_token": "valid_token",
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            session.get_token_response()

        assert exc_info.value.status_code == 401

    def test_get_token_response_with_zero_expires_at(self, session: Session) -> None:
        """Test behavior when session has zero expires_at - should raise 401"""
        session._load_from_dict(
            {
                "access_token": "valid_token",
                "expires_at": 0,
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            session.get_token_response()

        assert exc_info.value.status_code == 401

    def test_get_token_response_with_expired_token(self, session: Session) -> None:
        """Test that get_token_response returns data even if token is expired"""
        session._load_from_dict(
            {
                "access_token": "expired_token",
                "expires_at": 1000000000000,  # Past timestamp
            }
        )

        # get_token_response doesn't validate expiration, just returns data
        result = session.get_token_response()

        assert result.access_token == "expired_token"
        assert result.expires_at == 1000000000000

    def test_get_token_response_preserves_exact_expiration_value(self, session: Session) -> None:
        """Test that expires_at is returned exactly as stored in session"""
        specific_expiration = 1735689654321

        session._load_from_dict(
            {
                "access_token": "token_123",
                "expires_at": specific_expiration,
            }
        )

        result = session.get_token_response()

        # Verify exact value is preserved
        assert result.expires_at == specific_expiration

    def test_get_token_response_type_safety(self, session: Session) -> None:
        """Test that return type is TokenResponse with correct types"""
        session._load_from_dict(
            {
                "access_token": "token",
                "expires_at": 1735689600000,
            }
        )

        result = session.get_token_response()

        assert isinstance(result, TokenResponse)
        assert isinstance(result.access_token, str)
        assert isinstance(result.expires_at, int)

    def test_get_token_response_with_long_access_token(self, session: Session) -> None:
        """Test with a realistically long JWT access token"""
        long_jwt = (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1Njc4OTAifQ."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."
            "TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50"
            "aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
        )

        session._load_from_dict(
            {
                "access_token": long_jwt,
                "expires_at": 1735689600000,
            }
        )

        result = session.get_token_response()

        assert result.access_token == long_jwt
        assert len(result.access_token) > 200  # Verify it's a long token
