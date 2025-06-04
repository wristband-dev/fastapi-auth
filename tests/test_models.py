import pytest
from datetime import datetime, timedelta
import ast
from fastapi.responses import RedirectResponse

from wristband.models import (
    LoginConfig,
    LogoutConfig,
    LoginState,
    AuthConfig,
    UserInfo,
    SessionData,
    CallbackData,
    TokenData,
    CallbackResult,
    TokenResponse
)
from wristband.enums import CallbackResultType


class TestLoginState:
    def test_to_dict(self):
        login_state = LoginState(
            state="test-state",
            code_verifier="test-code-verifier",
            redirect_uri="https://example.com/callback",
            return_url="https://example.com/dashboard",
            custom_state={"test_key": "test_value"}
        )
        
        result = login_state.to_dict()
        
        assert result == {
            "state": "test-state",
            "code_verifier": "test-code-verifier",
            "redirect_uri": "https://example.com/callback",
            "return_url": "https://example.com/dashboard",
            "custom_state": {"test_key": "test_value"}
        }


class TestUserInfo:
    def test_from_dict(self):
        data = {
            "sub": "user123",
            "tnt_id": "tenant456",
            "app_id": "app789",
            "idp_name": "auth0",
            "email": "test@example.com",
            "email_verified": True
        }
        
        user_info = UserInfo.from_dict(data)
        
        assert user_info.sub == "user123"
        assert user_info.tnt_id == "tenant456"
        assert user_info.app_id == "app789"
        assert user_info.idp_name == "auth0"
        assert user_info.email == "test@example.com"
        assert user_info.email_verified is True


class TestSessionData:
    def test_to_dict(self):
        user_info = UserInfo(
            sub="user123",
            tnt_id="tenant456",
            app_id="app789",
            idp_name="auth0",
            email="test@example.com",
            email_verified=True
        )
        
        session = SessionData(
            is_authenticated=True,
            access_token="access-token",
            expires_at=1234567890,
            tenant_domain_name="example.com",
            tenant_custom_domain="custom.example.com",
            user_info=user_info,
            refresh_token="refresh-token"
        )
        
        result = session.to_dict()
        
        assert result["is_authenticated"] is True
        assert result["access_token"] == "access-token"
        assert result["expires_at"] == 1234567890
        assert result["tenant_domain_name"] == "example.com"
        assert result["tenant_custom_domain"] == "custom.example.com"
        assert isinstance(result["user_info"], str)
        assert result["refresh_token"] == "refresh-token"
        
        # Verify the user_info string can be parsed back
        user_info_dict = ast.literal_eval(result["user_info"])
        assert user_info_dict["sub"] == "user123"
        assert user_info_dict["email"] == "test@example.com"

    def test_to_session_init_data(self):
        user_info = UserInfo(
            sub="user123",
            tnt_id="tenant456",
            app_id="app789",
            idp_name="auth0",
            email="test@example.com",
            email_verified=True
        )
        
        session = SessionData(
            is_authenticated=True,
            access_token="access-token",
            expires_at=1234567890,
            tenant_domain_name="example.com",
            tenant_custom_domain="custom.example.com",
            user_info=user_info,
            refresh_token="refresh-token"
        )
        
        result = session.to_session_init_data()
        
        assert result["tenantId"] == "tenant456"
        assert result["userId"] == "user123"
        assert "metadata" in result
        assert result["metadata"]["is_authenticated"] is True

    def test_from_dict_with_string_user_info(self):
        # Simulate a session data dict with string user_info
        user_info_str = "{'sub': 'user123', 'tnt_id': 'tenant456', 'app_id': 'app789', 'idp_name': 'auth0', 'email': 'test@example.com', 'email_verified': True}"
        data = {
            "is_authenticated": True,
            "access_token": "access-token",
            "expires_at": 1234567890,
            "tenant_domain_name": "example.com",
            "tenant_custom_domain": "custom.example.com",
            "user_info": user_info_str,
            "refresh_token": "refresh-token"
        }
        
        session = SessionData.from_dict(data)
        
        assert session.is_authenticated is True
        assert session.access_token == "access-token"
        assert session.user_info.sub == "user123"
        assert session.user_info.email == "test@example.com"

    def test_from_dict_with_dict_user_info(self):
        # Simulate a session data dict with dict user_info
        user_info_dict = {
            "sub": "user123",
            "tnt_id": "tenant456",
            "app_id": "app789",
            "idp_name": "auth0",
            "email": "test@example.com",
            "email_verified": True
        }
        data = {
            "is_authenticated": True,
            "access_token": "access-token",
            "expires_at": 1234567890,
            "tenant_domain_name": "example.com",
            "tenant_custom_domain": "custom.example.com",
            "user_info": user_info_dict,
            "refresh_token": "refresh-token"
        }
        
        session = SessionData.from_dict(data)
        
        assert session.is_authenticated is True
        assert session.access_token == "access-token"
        assert session.user_info.sub == "user123"
        assert session.user_info.email == "test@example.com"


class TestCallbackData:
    def test_to_dict(self):
        callback_data = CallbackData(
            access_token="access-token",
            id_token="id-token",
            expires_in=3600,
            tenant_domain_name="example.com",
            user_info={"sub": "user123", "email": "test@example.com"},
            custom_state={"test_key": "test_value"},
            refresh_token="refresh-token",
            return_url="https://example.com/dashboard",
            tenant_custom_domain="custom.example.com"
        )
        
        result = callback_data.to_dict()
        
        assert result["access_token"] == "access-token"
        assert result["id_token"] == "id-token"
        assert result["expires_in"] == 3600
        assert result["tenant_domain_name"] == "example.com"
        assert result["user_info"] == {"sub": "user123", "email": "test@example.com"}
        assert result["custom_state"] == {"test_key": "test_value"}
        assert result["refresh_token"] == "refresh-token"
        assert result["return_url"] == "https://example.com/dashboard"
        assert result["tenant_custom_domain"] == "custom.example.com"

    def test_to_session(self):
        callback_data = CallbackData(
            access_token="access-token",
            id_token="id-token",
            expires_in=3600,
            tenant_domain_name="example.com",
            user_info={"sub": "user123", "tnt_id": "tenant456", "app_id": "app789", 
                      "idp_name": "auth0", "email": "test@example.com", "email_verified": True},
            custom_state={"test_key": "test_value"},
            refresh_token="refresh-token",
            return_url="https://example.com/dashboard",
            tenant_custom_domain="custom.example.com"
        )
        
        result = callback_data.to_session()
        
        # Check that we get a SessionData dict
        assert result["is_authenticated"] is True
        assert result["access_token"] == "access-token"
        assert isinstance(result["expires_at"], int)
        assert result["tenant_domain_name"] == "example.com"
        assert result["tenant_custom_domain"] == "custom.example.com"
        assert isinstance(result["user_info"], str)
        assert result["refresh_token"] == "refresh-token"

    def test_to_session_without_optional_fields(self):
        callback_data = CallbackData(
            access_token="access-token",
            id_token="id-token",
            expires_in=3600,
            tenant_domain_name="example.com",
            user_info={"sub": "user123", "tnt_id": "tenant456", "app_id": "app789", 
                      "idp_name": "auth0", "email": "test@example.com", "email_verified": True},
            custom_state=None,
            refresh_token=None,
            return_url=None,
            tenant_custom_domain=None
        )
        
        result = callback_data.to_session()
        
        # Check that we get a SessionData dict with default values for optional fields
        assert result["is_authenticated"] is True
        assert result["access_token"] == "access-token"
        assert result["tenant_domain_name"] == "example.com"
        assert result["tenant_custom_domain"] == ""
        assert result["refresh_token"] == ""


class TestTokenData:
    def test_from_token_response(self):
        token_response = TokenResponse(
            access_token="access-token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh-token",
            id_token="id-token",
            scope="openid profile email"
        )
        
        token_data = TokenData.from_token_response(token_response)
        
        assert token_data.access_token == "access-token"
        assert token_data.id_token == "id-token"
        assert token_data.refresh_token == "refresh-token"
        assert isinstance(token_data.expires_at, int)
        # expires_at should be around current timestamp + 3600 seconds
        now_ms = int(datetime.now().timestamp() * 1000)
        expected_expiry_ms = now_ms + 3600 * 1000
        assert abs(token_data.expires_at - expected_expiry_ms) < 5000  # Allow 5 seconds tolerance


class TestTokenResponse:
    def test_from_api_response(self):
        api_response = {
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token",
            "id_token": "id-token",
            "scope": "openid profile email"
        }
        
        token_response = TokenResponse.from_api_response(api_response)
        
        assert token_response.access_token == "access-token"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.refresh_token == "refresh-token"
        assert token_response.id_token == "id-token"
        assert token_response.scope == "openid profile email" 