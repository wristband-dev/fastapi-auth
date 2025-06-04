import base64
import json
from unittest import mock
import pytest
import requests

from wristband.api import Api, WristbandError
from wristband.models import TokenResponse


class MockResponse:
    def __init__(self, json_data, status_code=200):
        self.json_data = json_data
        self.status_code = status_code
    
    def json(self):
        return self.json_data


@pytest.fixture
def api():
    return Api(
        wristband_application_vanity_domain="auth.example.com",
        client_id="test_client_id",
        client_secret="test_client_secret"
    )


def test_init():
    """Test API initialization"""
    api = Api(
        wristband_application_vanity_domain="auth.example.com",
        client_id="test_client_id",
        client_secret="test_client_secret"
    )
    
    assert api.base_url == "https://auth.example.com/api/v1"
    assert "Authorization" in api.headers
    assert api.headers["Content-Type"] == "application/x-www-form-urlencoded"
    
    # Check Basic auth credentials are properly encoded
    auth_header = api.headers["Authorization"]
    assert auth_header.startswith("Basic ")
    encoded_part = auth_header.split(" ")[1]
    decoded = base64.b64decode(encoded_part).decode('utf-8')
    assert decoded == "test_client_id:test_client_secret"


def test_get_tokens(api):
    """Test token retrieval"""
    # Mock response data
    token_data = {
        "access_token": "test_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "test_refresh_token",
        "id_token": "test_id_token",
        "scope": "openid offline_access email"
    }
    
    # Mock the requests.post method
    with mock.patch('requests.post') as mock_post:
        mock_post.return_value = MockResponse(token_data)
        
        # Call get_tokens method
        token_response = api.get_tokens(
            code="test_code",
            redirect_uri="https://app.example.com/callback",
            code_verifier="test_code_verifier"
        )
        
        # Verify the API call
        mock_post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/token",
            data={
                'grant_type': 'authorization_code',
                'code': 'test_code',
                'redirect_uri': 'https://app.example.com/callback',
                'code_verifier': 'test_code_verifier',
            },
            headers=api.headers
        )
        
        # Verify the response
        assert isinstance(token_response, TokenResponse)
        assert token_response.access_token == "test_access_token"
        assert token_response.token_type == "Bearer"
        assert token_response.expires_in == 3600
        assert token_response.refresh_token == "test_refresh_token"
        assert token_response.id_token == "test_id_token"
        assert token_response.scope == "openid offline_access email"


def test_get_tokens_error(api):
    """Test error handling in token retrieval"""
    # Mock error response
    error_data = {
        "error": "invalid_request",
        "error_description": "Invalid authorization code"
    }
    
    # Mock the requests.post method to return an error
    with mock.patch('requests.post') as mock_post:
        mock_post.return_value = MockResponse(error_data, status_code=400)
        
        # Call get_tokens method - should raise WristbandError
        with pytest.raises(WristbandError) as excinfo:
            api.get_tokens(
                code="invalid_code",
                redirect_uri="https://app.example.com/callback",
                code_verifier="test_code_verifier"
            )
        
        # Check the error details
        assert "invalid_request" in str(excinfo.value)
        assert "Invalid authorization code" in str(excinfo.value)


def test_revoke_refresh_token(api):
    """Test revoking refresh token"""
    # Mock the requests.post method
    with mock.patch('requests.post') as mock_post:
        mock_post.return_value = MockResponse({}, status_code=200)
        
        # Call revoke_refresh_token method
        api.revoke_refresh_token("test_refresh_token")
        
        # Verify the API call
        mock_post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/revoke",
            data={'token': 'test_refresh_token'},
            headers=api.headers
        )


def test_refresh_token(api):
    """Test refreshing tokens"""
    # Mock response data
    token_data = {
        "access_token": "new_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "new_refresh_token",
        "id_token": "new_id_token",
        "scope": "openid offline_access email"
    }
    
    # Mock the requests.post method
    with mock.patch('requests.post') as mock_post:
        mock_post.return_value = MockResponse(token_data)
        
        # Call refresh_token method
        token_response = api.refresh_token("test_refresh_token")
        
        # Verify the API call
        mock_post.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/token",
            data={
                'grant_type': 'refresh_token',
                'refresh_token': 'test_refresh_token',
            },
            headers=api.headers
        )
        
        # Verify the response
        assert isinstance(token_response, TokenResponse)
        assert token_response.access_token == "new_access_token"
        assert token_response.refresh_token == "new_refresh_token"


def test_get_userinfo(api):
    """Test getting user info"""
    # Mock user info data
    userinfo_data = {
        "sub": "user123",
        "email": "user@example.com",
        "tnt_id": "tenant123",
        "app_id": "app123",
        "idp_name": "test_idp",
        "email_verified": True
    }
    
    # Mock the requests.get method
    with mock.patch('requests.get') as mock_get:
        mock_get.return_value = MockResponse(userinfo_data)
        
        # Call get_userinfo method
        userinfo = api.get_userinfo("test_access_token")
        
        # Verify the API call
        mock_get.assert_called_once_with(
            "https://auth.example.com/api/v1/oauth2/userinfo",
            headers={'Authorization': 'Bearer test_access_token'}
        )
        
        # Verify the response
        assert userinfo == userinfo_data 