import time
from datetime import datetime
from unittest import mock
import pytest
import requests

from fastapi import Request
from starlette.datastructures import URL
from starlette.responses import RedirectResponse

from wristband.fastapi.auth import Auth
from wristband.models import (
    AuthConfig, 
    LoginState, 
    CallbackData, 
    CallbackResult,
    TokenResponse,
    TokenData,
    LogoutConfig
)
from wristband.enums import CallbackResultType
from wristband.api import WristbandError


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
        
    def json(self):
        return self.json_data


@pytest.fixture
def auth_config():
    return AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        login_state_secret="test_login_state_secret_test_login_state",
        login_url="https://login.example.com/{tenant_domain}",
        redirect_uri="https://app.example.com/callback",
        wristband_application_vanity_domain="auth.example.com",
        dangerously_disable_secure_cookies=True
    )


@pytest.fixture
def auth(auth_config):
    return Auth(auth_config)


@pytest.fixture
def mock_request():
    # Create a mock request with minimal attributes needed for testing
    mock_req = mock.MagicMock(spec=Request)
    mock_req.url = URL("https://test.example.com/login")
    mock_req.query_params = {}
    mock_req.cookies = {}
    return mock_req


def test_init(auth_config):
    """Test that Auth class is initialized correctly"""
    auth = Auth(auth_config)
    
    assert auth.client_id == "test_client_id"
    assert auth.client_secret == "test_client_secret"
    assert auth.login_state_secret == "test_login_state_secret_test_login_state"
    assert auth.login_url == "https://login.example.com/{tenant_domain}"
    assert auth.redirect_uri == "https://app.example.com/callback"
    assert auth.wristband_application_vanity_domain == "auth.example.com"
    assert auth.dangerously_disable_secure_cookies is True
    assert auth.scopes == ['openid', 'offline_access', 'email']


def test_generate_random_string(auth):
    """Test random string generation"""
    # Test with different lengths
    for length in [10, 32, 64]:
        random_string = auth._generate_random_string(length)
        assert len(random_string) == length
        # Check if it's URL safe
        assert set(random_string).issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"))


def test_encrypt_decrypt_login_state(auth):
    """Test encryption and decryption of login state"""
    # Create a test login state
    login_state = LoginState(
        state="test_state",
        code_verifier="test_code_verifier",
        redirect_uri="https://app.example.com/callback",
        return_url=None,
        custom_state=None
    )
    
    # Test encryption
    encrypted = auth._encrypt_login_state(login_state, auth.login_state_secret)
    assert isinstance(encrypted, bytes)
    
    # Test decryption
    decrypted = auth._decrypt_login_state(encrypted.decode("utf-8"), auth.login_state_secret)
    assert decrypted.state == login_state.state
    assert decrypted.code_verifier == login_state.code_verifier
    assert decrypted.redirect_uri == login_state.redirect_uri
    assert decrypted.return_url == login_state.return_url
    assert decrypted.custom_state == login_state.custom_state


def test_create_login_state(auth, mock_request):
    """Test login state creation"""
    # Test without return_url or custom_state
    login_state = auth._create_login_state(mock_request, "https://app.example.com/callback", None)
    
    assert isinstance(login_state, LoginState)
    assert len(login_state.state) == 32
    assert len(login_state.code_verifier) == 64
    assert login_state.redirect_uri == "https://app.example.com/callback"
    assert login_state.return_url is None
    assert login_state.custom_state is None
    
    # Test with return_url and custom_state
    mock_request.query_params = {"return_url": "https://app.example.com/dashboard"}
    custom_state = {"test_key": "test_value"}
    
    login_state = auth._create_login_state(mock_request, "https://app.example.com/callback", custom_state)
    
    assert login_state.return_url == "https://app.example.com/dashboard"
    assert login_state.custom_state == custom_state


def test_get_oauth_authorize_url(auth, mock_request):
    """Test OAuth authorize URL generation"""
    login_state = LoginState(
        state="test_state",
        code_verifier="test_code_verifier",
        redirect_uri="https://app.example.com/callback",
        return_url=None,
        custom_state=None
    )
    
    # Test with tenant_custom_domain
    url = auth._get_oauth_authorize_url(
        mock_request,
        login_state,
        "tenant.example.com",  # tenant_custom_domain
        "",  # tenant_domain_name
        None,  # default_tenant_custom_domain
        None,  # default_tenant_domain_name
    )
    
    assert url.startswith("https://tenant.example.com/api/v1/oauth2/authorize?")
    assert "client_id=test_client_id" in url
    assert "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback" in url
    assert "response_type=code" in url
    assert "state=test_state" in url
    assert "scope=openid+offline_access+email" in url
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    
    # Test with tenant_domain_name
    url = auth._get_oauth_authorize_url(
        mock_request,
        login_state,
        "",  # tenant_custom_domain
        "tenant",  # tenant_domain_name
        None,  # default_tenant_custom_domain
        None,  # default_tenant_domain_name
    )
    
    assert url.startswith(f"https://tenant-auth.example.com/api/v1/oauth2/authorize?")


def test_login_with_tenant_custom_domain(auth, mock_request):
    """Test login method with tenant custom domain"""
    with mock.patch.object(auth, '_create_login_state') as mock_create_login_state, \
         mock.patch.object(auth, '_get_oauth_authorize_url') as mock_get_oauth_authorize_url, \
         mock.patch.object(auth, '_clear_oldest_login_state_cookie') as mock_clear_oldest, \
         mock.patch.object(auth, '_encrypt_login_state') as mock_encrypt, \
         mock.patch.object(auth, '_create_login_state_cookie') as mock_create_cookie:
        
        # Setup mocks
        mock_login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None
        )
        mock_create_login_state.return_value = mock_login_state
        mock_get_oauth_authorize_url.return_value = "https://test-auth-url.com"
        mock_encrypt.return_value = b"encrypted_data"
        
        # Add tenant_custom_domain to query params
        mock_request.query_params = {"tenant_custom_domain": "tenant.example.com"}
        
        # Call login
        response = auth.login(mock_request)
        
        # Verify results
        assert isinstance(response, RedirectResponse)
        assert response.status_code == 302
        assert response.headers.get("location") == "https://test-auth-url.com"
        
        # Verify mock calls
        mock_create_login_state.assert_called_once()
        mock_get_oauth_authorize_url.assert_called_once()
        mock_clear_oldest.assert_called_once()
        mock_encrypt.assert_called_once()
        mock_create_cookie.assert_called_once()


def test_login_with_tenant_domain(auth, mock_request):
    """Test login method with tenant domain"""
    with mock.patch.object(auth, '_create_login_state') as mock_create_login_state, \
         mock.patch.object(auth, '_get_oauth_authorize_url') as mock_get_oauth_authorize_url, \
         mock.patch.object(auth, '_clear_oldest_login_state_cookie') as mock_clear_oldest, \
         mock.patch.object(auth, '_encrypt_login_state') as mock_encrypt, \
         mock.patch.object(auth, '_create_login_state_cookie') as mock_create_cookie:
        
        # Setup mocks
        mock_login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None
        )
        mock_create_login_state.return_value = mock_login_state
        mock_get_oauth_authorize_url.return_value = "https://test-auth-url.com"
        mock_encrypt.return_value = b"encrypted_data"
        
        # Add tenant_domain to query params
        mock_request.query_params = {"tenant_domain": "tenant"}
        
        # Call login
        response = auth.login(mock_request)
        
        # Verify results
        assert isinstance(response, RedirectResponse)
        assert response.status_code == 302
        assert response.headers.get("location") == "https://test-auth-url.com"


def test_login_with_no_tenant_info(auth, mock_request):
    """Test login method with no tenant info - should redirect to app login"""
    # Call login with no tenant info
    response = auth.login(mock_request)
    
    # Should redirect to app login
    assert isinstance(response, RedirectResponse)
    assert response.status_code == 302
    assert response.headers.get("location") == f"https://{auth.wristband_application_vanity_domain}/login"


def test_get_login_state_cookie(auth, mock_request):
    """Test getting login state cookie"""
    # Setup a mock request with a login state cookie
    cookie_name = f"{auth._cookie_prefix}test_state#{int(1000 * time.time())}"
    mock_request.cookies = {cookie_name: "encrypted_cookie_value"}
    mock_request.query_params = {"state": "test_state"}
    
    # Get the cookie
    name, value = auth._get_login_state_cookie(mock_request)
    
    # Verify results
    assert name == cookie_name
    assert value == "encrypted_cookie_value"
    
    # Test with non-matching state
    mock_request.query_params = {"state": "non_matching_state"}
    name, value = auth._get_login_state_cookie(mock_request)
    assert name is None
    assert value is None


def test_callback_success(auth, mock_request):
    """Test callback method with successful flow"""
    # Setup mock request
    mock_request.query_params = {
        "code": "test_code",
        "state": "test_state",
        "tenant_custom_domain": "tenant.example.com",
        "tenant_domain": "tenant"
    }
    # Create a new URL object instead of trying to set netloc directly
    mock_request.url = URL("https://tenant.example.com/callback")
    
    # Mock methods
    with mock.patch.object(auth, '_get_login_state_cookie') as mock_get_cookie, \
         mock.patch.object(auth, '_decrypt_login_state') as mock_decrypt, \
         mock.patch.object(auth.api, 'get_tokens') as mock_get_tokens, \
         mock.patch.object(auth.api, 'get_userinfo') as mock_get_userinfo:
        
        # Setup mock returns
        login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None
        )
        token_response = TokenResponse(
            access_token="test_access_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="test_refresh_token",
            id_token="test_id_token",
            scope="openid offline_access email"
        )
        userinfo = {
            "sub": "user123",
            "email": "user@example.com",
            "tnt_id": "tenant123",
            "app_id": "app123",
            "idp_name": "test_idp",
            "email_verified": True
        }
        
        mock_get_cookie.return_value = ("cookie_name", "encrypted_cookie_value")
        mock_decrypt.return_value = login_state
        mock_get_tokens.return_value = token_response
        mock_get_userinfo.return_value = userinfo
        
        # Call callback
        result = auth.callback(mock_request)
        
        # Verify result
        assert isinstance(result, CallbackResult)
        assert result.type == CallbackResultType.COMPLETED
        assert result.redirect_response is None
        assert isinstance(result.callback_data, CallbackData)
        assert result.callback_data.access_token == "test_access_token"
        assert result.callback_data.id_token == "test_id_token"
        assert result.callback_data.tenant_domain_name == "tenant"
        assert result.callback_data.user_info == userinfo


def test_callback_missing_state_cookie(auth, mock_request):
    """Test callback with missing state cookie"""
    # Setup mock request
    mock_request.query_params = {
        "code": "test_code",
        "state": "test_state",
        "tenant_domain": "tenant"
    }
    # Create a new URL object
    mock_request.url = URL("https://tenant.example.com/callback")
    
    # Mock methods to return no cookie
    with mock.patch.object(auth, '_get_login_state_cookie', return_value=(None, None)):
        # Call callback
        result = auth.callback(mock_request)
        
        # Verify result - should be redirect
        assert isinstance(result, CallbackResult)
        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.callback_data is None
        assert isinstance(result.redirect_response, RedirectResponse)


def test_callback_state_mismatch(auth, mock_request):
    """Test callback with state mismatch"""
    # Setup mock request with state param
    mock_request.query_params = {
        "code": "test_code",
        "state": "test_state",
        "tenant_domain": "tenant"
    }
    # Create a new URL object
    mock_request.url = URL("https://tenant.example.com/callback")
    
    # Mock methods
    with mock.patch.object(auth, '_get_login_state_cookie') as mock_get_cookie, \
         mock.patch.object(auth, '_decrypt_login_state') as mock_decrypt:
        
        # Return login state with different state value
        login_state = LoginState(
            state="different_state",  # Mismatch with request state
            code_verifier="test_code_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None
        )
        
        mock_get_cookie.return_value = ("cookie_name", "encrypted_cookie_value")
        mock_decrypt.return_value = login_state
        
        # Call callback
        result = auth.callback(mock_request)
        
        # Verify result - should be redirect
        assert isinstance(result, CallbackResult)
        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        assert result.callback_data is None
        assert isinstance(result.redirect_response, RedirectResponse)


def test_callback_error_param(auth, mock_request):
    """Test callback with error in params"""
    # Setup mock request with error param
    mock_request.query_params = {
        "state": "test_state",
        "error": "login_required",
        "error_description": "User login required",
        "tenant_domain": "tenant"
    }
    # Create a new URL object
    mock_request.url = URL("https://tenant.example.com/callback")
    
    # Mock methods
    with mock.patch.object(auth, '_get_login_state_cookie') as mock_get_cookie, \
         mock.patch.object(auth, '_decrypt_login_state') as mock_decrypt:
        
        login_state = LoginState(
            state="test_state",
            code_verifier="test_code_verifier",
            redirect_uri="https://app.example.com/callback",
            return_url=None,
            custom_state=None
        )
        
        mock_get_cookie.return_value = ("cookie_name", "encrypted_cookie_value")
        mock_decrypt.return_value = login_state
        
        # Call callback - should redirect for login_required error
        result = auth.callback(mock_request)
        
        assert isinstance(result, CallbackResult)
        assert result.type == CallbackResultType.REDIRECT_REQUIRED
        
        # Change error to something else
        mock_request.query_params = {
            "state": "test_state",
            "error": "invalid_request",
            "error_description": "Some other error"
        }
        
        # Should raise an exception
        with pytest.raises(ValueError):
            auth.callback(mock_request)


def test_logout(auth, mock_request):
    """Test logout method"""
    # Setup mock_request
    mock_request.url = URL("https://app.example.com/logout")
    
    # Test with tenant_domain
    config = LogoutConfig(
        tenant_domain_name="tenant",
        refresh_token="test_refresh_token"
    )
    
    # Mock revoke method
    with mock.patch.object(auth, '_revoke_refresh_token') as mock_revoke:
        # Call logout
        response = auth.logout(mock_request, config)
        
        # Verify response
        assert isinstance(response, RedirectResponse)
        assert response.status_code == 302
        assert response.headers.get("location") == f"https://tenant-auth.example.com/api/v1/logout?client_id=test_client_id"
        
        # Verify revoke was called
        mock_revoke.assert_called_once_with("test_refresh_token")


def test_logout_with_redirect_url(auth, mock_request):
    """Test logout with redirect URL"""
    # Setup mock_request
    mock_request.url = URL("https://app.example.com/logout")
    
    # Test with tenant_domain and redirect_url
    config = LogoutConfig(
        tenant_domain_name="tenant",
        refresh_token="test_refresh_token",
        redirect_url="https://app.example.com/login"
    )
    
    # Mock revoke method
    with mock.patch.object(auth, '_revoke_refresh_token'):
        # Call logout
        response = auth.logout(mock_request, config)
        
        # Verify response includes redirect_url
        assert "redirect_url=https%3A%2F%2Fapp.example.com%2Flogin" in response.headers.get("location")


def test_logout_with_tenant_custom_domain(auth, mock_request):
    """Test logout with tenant custom domain"""
    # Setup mock_request
    mock_request.url = URL("https://app.example.com/logout")
    
    # Test with tenant_custom_domain
    config = LogoutConfig(
        tenant_custom_domain="tenant.example.com",
        refresh_token="test_refresh_token"
    )
    
    # Mock revoke method
    with mock.patch.object(auth, '_revoke_refresh_token'):
        # Call logout
        response = auth.logout(mock_request, config)
        
        # Verify response uses the custom domain
        assert response.headers.get("location") == f"https://tenant.example.com/api/v1/logout?client_id=test_client_id"


def test_refresh_token_if_expired(auth):
    """Test refresh token functionality"""
    # Test with non-expired token
    current_time = int(datetime.now().timestamp() * 1000)
    future_time = current_time + 3600000  # one hour in the future
    
    # Should return None if token is not expired
    result = auth.refresh_token_if_expired("test_refresh_token", future_time)
    assert result is None
    
    # Test with expired token
    past_time = current_time - 3600000  # one hour in the past
    
    # Mock the api.refresh_token method
    with mock.patch.object(auth.api, 'refresh_token') as mock_refresh:
        token_response = TokenResponse(
            access_token="new_access_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="new_refresh_token",
            id_token="new_id_token",
            scope="openid offline_access email"
        )
        mock_refresh.return_value = token_response
        
        # Call refresh_token_if_expired
        result = auth.refresh_token_if_expired("test_refresh_token", past_time)
        
        # Verify result
        assert isinstance(result, TokenData)
        assert result.access_token == "new_access_token"
        assert result.id_token == "new_id_token"
        assert result.refresh_token == "new_refresh_token"
        
        # Verify mock was called
        mock_refresh.assert_called_once_with("test_refresh_token")


def test_refresh_token_with_error(auth):
    """Test refresh token with error response"""
    # Test with expired token
    current_time = int(datetime.now().timestamp() * 1000)
    past_time = current_time - 3600000  # one hour in the past
    
    # Mock api.refresh_token to raise an error
    with mock.patch.object(auth.api, 'refresh_token') as mock_refresh:
        error_response = mock.MagicMock()
        error_response.status_code = 400
        error_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Invalid refresh token"
        }
        
        mock_refresh.side_effect = requests.exceptions.RequestException(
            response=error_response
        )
        
        # Call refresh_token_if_expired - should raise WristbandError
        with pytest.raises(WristbandError) as excinfo:
            auth.refresh_token_if_expired("test_refresh_token", past_time)
        
        assert "invalid_refresh_token" in str(excinfo.value)


def test_is_expired(auth):
    """Test is_expired helper function"""
    current_time = int(datetime.now().timestamp() * 1000)
    
    # Test with future time - should not be expired
    future_time = current_time + 3600000  # one hour in the future
    assert auth.is_expired(future_time) is False
    
    # Test with past time - should be expired
    past_time = current_time - 3600000  # one hour in the past
    assert auth.is_expired(past_time) is True 