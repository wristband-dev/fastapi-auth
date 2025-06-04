import pytest
from unittest.mock import MagicMock, patch
import base64
import time
import json
from datetime import datetime

from fastapi import Request, Response
from starlette.responses import RedirectResponse
from wristband.fastapi.auth import Auth
from wristband.models import (
    AuthConfig,
    LoginState,
    LoginConfig,
    LogoutConfig,
    CallbackResult,
    TokenData,
    TokenResponse
)
from wristband.enums import CallbackResultType


@pytest.fixture
def auth_config():
    return AuthConfig(
        client_id="test-client-id",
        client_secret="test-client-secret",
        login_state_secret="test-login-state-secret",
        login_url="https://{tenant_domain}.example.com/login",
        redirect_uri="https://app.example.com/callback",
        wristband_application_vanity_domain="app.example.com"
    )


@pytest.fixture
def auth(auth_config):
    return Auth(auth_config)


def test_is_expired_true(auth):
    # Set expires_at to a past time
    past_time = int(time.time() * 1000) - 3600000  # 1 hour in the past
    
    # Call the function
    result = auth.is_expired(past_time)
    
    # Should return True for past time
    assert result is True


def test_is_expired_false(auth):
    # Set expires_at to a future time
    future_time = int(time.time() * 1000) + 3600000  # 1 hour in the future
    
    # Call the function
    result = auth.is_expired(future_time)
    
    # Should return False for future time
    assert result is False


def test_resolve_tenant_custom_domain_param(auth):
    # Test with tenant_custom_domain in query params
    mock_request = MagicMock()
    mock_request.query_params = {"tenant_custom_domain": "custom.example.com"}
    
    result = auth._resolve_tenant_custom_domain_param(mock_request)
    assert result == "custom.example.com"
    
    # Test without tenant_custom_domain
    mock_request.query_params = {}
    result = auth._resolve_tenant_custom_domain_param(mock_request)
    assert result == ""


def test_resolve_tenant_domain_name_without_subdomain(auth):
    # Test without parse_tenant_from_root_domain
    mock_request = MagicMock()
    mock_request.query_params = {"tenant_domain": "tenant1"}
    
    result = auth._resolve_tenant_domain_name(mock_request, None)
    assert result == "tenant1"
    
    # Test without tenant_domain param
    mock_request.query_params = {}
    result = auth._resolve_tenant_domain_name(mock_request, None)
    assert result == ""


def test_create_login_state(auth):
    mock_request = MagicMock()
    mock_request.url.path = "/login"
    mock_request.query_params = {"return_url": "/dashboard"}
    redirect_uri = "https://app.example.com/callback"
    custom_state = {"test_key": "test_value"}
    
    # Test with return_url in query params and custom_state
    login_state = auth._create_login_state(mock_request, redirect_uri, custom_state)
    
    assert isinstance(login_state, LoginState)
    assert login_state.redirect_uri == redirect_uri
    assert login_state.return_url == "/dashboard"
    assert login_state.custom_state == custom_state
    assert len(login_state.state) > 0
    assert len(login_state.code_verifier) > 0
    
    # Test without return_url
    mock_request.query_params = {}
    login_state = auth._create_login_state(mock_request, redirect_uri, None)
    
    assert login_state.return_url is None
    assert login_state.custom_state is None


def test_create_callback_response(auth):
    mock_request = MagicMock()
    redirect_url = "https://app.example.com/dashboard"
    
    response = auth._create_callback_response(mock_request, redirect_url)
    
    assert isinstance(response, RedirectResponse)
    assert response.status_code == 302
    assert response.headers["Location"] == redirect_url
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_generate_random_string(auth):
    length = 32
    result = auth._generate_random_string(length)
    
    assert isinstance(result, str)
    assert len(result) == length
    
    # Generate another string and ensure it's different
    result2 = auth._generate_random_string(length)
    assert result != result2 