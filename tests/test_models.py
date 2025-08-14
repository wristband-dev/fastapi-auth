from dataclasses import asdict

from wristband.fastapi_auth.models import (
    AuthConfig,
    CallbackData,
    CallbackResult,
    CallbackResultType,
    LoginConfig,
    LoginState,
    LogoutConfig,
    OAuthAuthorizeUrlConfig,
    TokenData,
    TokenResponse,
    UserInfo,
)

########################################
# AUTH CONFIG TESTS
########################################


def test_auth_config_creation():
    """Test basic AuthConfig creation with required fields."""
    config = AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        login_state_secret="a" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
        wristband_application_vanity_domain="app.wristband.dev",
    )

    assert config.client_id == "test_client_id"
    assert config.client_secret == "test_client_secret"
    assert config.login_state_secret == "a" * 32
    assert config.login_url == "https://example.com/login"
    assert config.redirect_uri == "https://example.com/callback"
    assert config.wristband_application_vanity_domain == "app.wristband.dev"


def test_auth_config_defaults():
    """Test AuthConfig default values."""
    config = AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        login_state_secret="a" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
        wristband_application_vanity_domain="app.wristband.dev",
    )

    assert config.custom_application_login_page_url is None
    assert config.dangerously_disable_secure_cookies is False
    assert config.is_application_custom_domain_active is False
    assert config.parse_tenant_from_root_domain is None
    assert config.scopes == ["openid", "offline_access", "email"]
    assert config.token_expiration_buffer == 60


def test_auth_config_custom_values():
    """Test AuthConfig with custom values."""
    config = AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        login_state_secret="b" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
        wristband_application_vanity_domain="app.wristband.dev",
        custom_application_login_page_url="https://custom.com/login",
        dangerously_disable_secure_cookies=True,
        is_application_custom_domain_active=True,
        parse_tenant_from_root_domain="example.com",
        scopes=["openid", "profile"],
        token_expiration_buffer=120,
    )

    assert config.custom_application_login_page_url == "https://custom.com/login"
    assert config.dangerously_disable_secure_cookies is True
    assert config.is_application_custom_domain_active is True
    assert config.parse_tenant_from_root_domain == "example.com"
    assert config.scopes == ["openid", "profile"]
    assert config.token_expiration_buffer == 120


########################################
# LOGIN MODEL TESTS
########################################


def test_oauth_authorize_url_config_creation():
    """Test OAuthAuthorizeUrlConfig creation."""
    config = OAuthAuthorizeUrlConfig(
        client_id="test_client",
        code_verifier="test_verifier",
        redirect_uri="https://example.com/callback",
        scopes=["openid", "email"],
        state="test_state",
        wristband_application_vanity_domain="app.wristband.dev",
    )

    assert config.client_id == "test_client"
    assert config.code_verifier == "test_verifier"
    assert config.redirect_uri == "https://example.com/callback"
    assert config.scopes == ["openid", "email"]
    assert config.state == "test_state"
    assert config.wristband_application_vanity_domain == "app.wristband.dev"


def test_oauth_authorize_url_config_defaults():
    """Test OAuthAuthorizeUrlConfig default values."""
    config = OAuthAuthorizeUrlConfig(
        client_id="test_client",
        code_verifier="test_verifier",
        redirect_uri="https://example.com/callback",
        scopes=["openid"],
        state="test_state",
        wristband_application_vanity_domain="app.wristband.dev",
    )

    assert config.default_tenant_custom_domain is None
    assert config.default_tenant_domain_name is None
    assert config.tenant_custom_domain is None
    assert config.tenant_domain_name is None
    assert config.is_application_custom_domain_active is False


def test_oauth_authorize_url_config_with_optionals():
    """Test OAuthAuthorizeUrlConfig with optional parameters."""
    config = OAuthAuthorizeUrlConfig(
        client_id="test_client",
        code_verifier="test_verifier",
        redirect_uri="https://example.com/callback",
        scopes=["openid"],
        state="test_state",
        wristband_application_vanity_domain="app.wristband.dev",
        default_tenant_custom_domain="default.tenant.com",
        default_tenant_domain_name="default-tenant",
        tenant_custom_domain="tenant.com",
        tenant_domain_name="my-tenant",
        is_application_custom_domain_active=True,
    )

    assert config.default_tenant_custom_domain == "default.tenant.com"
    assert config.default_tenant_domain_name == "default-tenant"
    assert config.tenant_custom_domain == "tenant.com"
    assert config.tenant_domain_name == "my-tenant"
    assert config.is_application_custom_domain_active is True


def test_login_state_creation():
    """Test LoginState creation."""
    custom_state = {"user_preference": "dark_mode"}
    login_state = LoginState(
        state="test_state",
        code_verifier="test_verifier",
        redirect_uri="https://example.com/callback",
        return_url="https://example.com/dashboard",
        custom_state=custom_state,
    )

    assert login_state.state == "test_state"
    assert login_state.code_verifier == "test_verifier"
    assert login_state.redirect_uri == "https://example.com/callback"
    assert login_state.return_url == "https://example.com/dashboard"
    assert login_state.custom_state == custom_state


def test_login_state_to_dict():
    """Test LoginState to_dict method."""
    custom_state = {"key": "value"}
    login_state = LoginState(
        state="test_state",
        code_verifier="test_verifier",
        redirect_uri="https://example.com/callback",
        return_url="https://example.com/dashboard",
        custom_state=custom_state,
    )

    result = login_state.to_dict()
    expected = {
        "state": "test_state",
        "code_verifier": "test_verifier",
        "redirect_uri": "https://example.com/callback",
        "return_url": "https://example.com/dashboard",
        "custom_state": custom_state,
    }

    assert result == expected
    assert isinstance(result, dict)


def test_login_state_with_none_values():
    """Test LoginState with None values."""
    login_state = LoginState(
        state="test_state",
        code_verifier="test_verifier",
        redirect_uri="https://example.com/callback",
        return_url=None,
        custom_state=None,
    )

    assert login_state.return_url is None
    assert login_state.custom_state is None

    result = login_state.to_dict()
    assert result["return_url"] is None
    assert result["custom_state"] is None


def test_login_config_creation():
    """Test LoginConfig creation."""
    custom_state = {"theme": "dark"}
    config = LoginConfig(
        custom_state=custom_state, default_tenant_custom_domain="default.com", default_tenant_domain="default"
    )

    assert config.custom_state == custom_state
    assert config.default_tenant_custom_domain == "default.com"
    assert config.default_tenant_domain == "default"


def test_login_config_defaults():
    """Test LoginConfig default values."""
    config = LoginConfig()

    assert config.custom_state is None
    assert config.default_tenant_custom_domain is None
    assert config.default_tenant_domain is None


########################################
# CALLBACK MODEL TESTS
########################################


def test_callback_result_type_enum():
    """Test CallbackResultType enum values."""
    assert CallbackResultType.COMPLETED.value == "COMPLETED"
    assert CallbackResultType.REDIRECT_REQUIRED.value == "REDIRECT_REQUIRED"


def test_user_info_type_alias():
    """Test UserInfo type alias works as expected."""
    user_info: UserInfo = {"sub": "user123", "email": "user@example.com", "name": "Test User"}

    assert isinstance(user_info, dict)
    assert user_info["sub"] == "user123"
    assert user_info["email"] == "user@example.com"


def test_callback_data_creation():
    """Test CallbackData creation."""
    user_info = {"sub": "user123", "email": "test@example.com"}
    custom_state = {"theme": "dark"}

    callback_data = CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        tenant_domain_name="tenant1",
        user_info=user_info,
        custom_state=custom_state,
        refresh_token="refresh_token_123",
        return_url="https://example.com/dashboard",
        tenant_custom_domain="tenant1.example.com",
    )

    assert callback_data.access_token == "access_token_123"
    assert callback_data.id_token == "id_token_123"
    assert callback_data.expires_at == 1234567890
    assert callback_data.expires_in == 3600
    assert callback_data.tenant_domain_name == "tenant1"
    assert callback_data.user_info == user_info
    assert callback_data.custom_state == custom_state
    assert callback_data.refresh_token == "refresh_token_123"
    assert callback_data.return_url == "https://example.com/dashboard"
    assert callback_data.tenant_custom_domain == "tenant1.example.com"


def test_callback_data_to_dict():
    """Test CallbackData to_dict method."""
    user_info = {"sub": "user123"}
    callback_data = CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        tenant_domain_name="tenant1",
        user_info=user_info,
        custom_state=None,
        refresh_token=None,
        return_url=None,
        tenant_custom_domain=None,
    )

    result = callback_data.to_dict()

    assert isinstance(result, dict)
    assert result["access_token"] == "access_token_123"
    assert result["user_info"] == user_info
    assert result["custom_state"] is None


def test_callback_data_with_none_optionals():
    """Test CallbackData with None optional values."""
    user_info = {"sub": "user123"}
    callback_data = CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        tenant_domain_name="tenant1",
        user_info=user_info,
        custom_state=None,
        refresh_token=None,
        return_url=None,
        tenant_custom_domain=None,
    )

    assert callback_data.custom_state is None
    assert callback_data.refresh_token is None
    assert callback_data.return_url is None
    assert callback_data.tenant_custom_domain is None


def test_token_data_creation():
    """Test TokenData creation."""
    token_data = TokenData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        refresh_token="refresh_token_123",
    )

    assert token_data.access_token == "access_token_123"
    assert token_data.id_token == "id_token_123"
    assert token_data.expires_at == 1234567890
    assert token_data.expires_in == 3600
    assert token_data.refresh_token == "refresh_token_123"


def test_callback_result_completed():
    """Test CallbackResult with COMPLETED type."""
    user_info = {"sub": "user123"}
    callback_data = CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        tenant_domain_name="tenant1",
        user_info=user_info,
        custom_state=None,
        refresh_token=None,
        return_url=None,
        tenant_custom_domain=None,
    )

    result = CallbackResult(callback_data=callback_data, type=CallbackResultType.COMPLETED, redirect_url=None)

    assert result.callback_data == callback_data
    assert result.type == CallbackResultType.COMPLETED
    assert result.redirect_url is None


def test_callback_result_redirect_required():
    """Test CallbackResult with REDIRECT_REQUIRED type."""
    result = CallbackResult(
        callback_data=None, type=CallbackResultType.REDIRECT_REQUIRED, redirect_url="https://example.com/login"
    )

    assert result.callback_data is None
    assert result.type == CallbackResultType.REDIRECT_REQUIRED
    assert result.redirect_url == "https://example.com/login"


def test_token_response_creation():
    """Test TokenResponse creation."""
    token_response = TokenResponse(
        access_token="access_token_123",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="refresh_token_123",
        id_token="id_token_123",
        scope="openid email",
    )

    assert token_response.access_token == "access_token_123"
    assert token_response.token_type == "Bearer"
    assert token_response.expires_in == 3600
    assert token_response.refresh_token == "refresh_token_123"
    assert token_response.id_token == "id_token_123"
    assert token_response.scope == "openid email"


def test_token_response_from_api_response():
    """Test TokenResponse.from_api_response static method."""
    api_response = {
        "access_token": "access_token_123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh_token_123",
        "id_token": "id_token_123",
        "scope": "openid email profile",
    }

    token_response = TokenResponse.from_api_response(api_response)

    assert isinstance(token_response, TokenResponse)
    assert token_response.access_token == "access_token_123"
    assert token_response.token_type == "Bearer"
    assert token_response.expires_in == 3600
    assert token_response.refresh_token == "refresh_token_123"
    assert token_response.id_token == "id_token_123"
    assert token_response.scope == "openid email profile"


def test_token_response_from_api_response_exact_mapping():
    """Test that from_api_response maps all fields correctly."""
    api_response = {
        "access_token": "test_access",
        "token_type": "test_type",
        "expires_in": 1800,
        "refresh_token": "test_refresh",
        "id_token": "test_id",
        "scope": "test_scope",
    }

    result = TokenResponse.from_api_response(api_response)

    # Verify each field is mapped correctly
    assert result.access_token == api_response["access_token"]
    assert result.token_type == api_response["token_type"]
    assert result.expires_in == api_response["expires_in"]
    assert result.refresh_token == api_response["refresh_token"]
    assert result.id_token == api_response["id_token"]
    assert result.scope == api_response["scope"]


########################################
# LOGOUT MODEL TESTS
########################################


def test_logout_config_creation():
    """Test LogoutConfig creation with all parameters."""
    config = LogoutConfig(
        redirect_url="https://example.com/goodbye",
        refresh_token="refresh_token_123",
        tenant_custom_domain="tenant.example.com",
        tenant_domain_name="my-tenant",
    )

    assert config.redirect_url == "https://example.com/goodbye"
    assert config.refresh_token == "refresh_token_123"
    assert config.tenant_custom_domain == "tenant.example.com"
    assert config.tenant_domain_name == "my-tenant"


def test_logout_config_defaults():
    """Test LogoutConfig default values."""
    config = LogoutConfig()

    assert config.redirect_url is None
    assert config.refresh_token is None
    assert config.tenant_custom_domain is None
    assert config.tenant_domain_name is None


def test_logout_config_partial():
    """Test LogoutConfig with some parameters."""
    config = LogoutConfig(redirect_url="https://example.com/goodbye", tenant_domain_name="my-tenant")

    assert config.redirect_url == "https://example.com/goodbye"
    assert config.refresh_token is None
    assert config.tenant_custom_domain is None
    assert config.tenant_domain_name == "my-tenant"


########################################
# INTEGRATION TESTS
########################################


def test_dataclass_asdict_compatibility():
    """Test that all dataclasses work with asdict function."""
    # Test AuthConfig
    auth_config = AuthConfig(
        client_id="test",
        client_secret="secret",
        login_state_secret="a" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
        wristband_application_vanity_domain="app.wristband.dev",
    )
    auth_dict = asdict(auth_config)
    assert isinstance(auth_dict, dict)
    assert auth_dict["client_id"] == "test"

    # Test LoginState
    login_state = LoginState(
        state="state",
        code_verifier="verifier",
        redirect_uri="https://example.com/callback",
        return_url=None,
        custom_state=None,
    )
    login_dict = asdict(login_state)
    assert isinstance(login_dict, dict)
    assert login_dict["state"] == "state"

    # Test CallbackData
    callback_data = CallbackData(
        access_token="token",
        id_token="id_token",
        expires_at=123456,
        expires_in=3600,
        tenant_domain_name="tenant",
        user_info={"sub": "user"},
        custom_state=None,
        refresh_token=None,
        return_url=None,
        tenant_custom_domain=None,
    )
    callback_dict = asdict(callback_data)
    assert isinstance(callback_dict, dict)
    assert callback_dict["access_token"] == "token"


def test_nested_dict_handling():
    """Test models handle nested dictionaries correctly."""
    complex_custom_state = {
        "user_preferences": {"theme": "dark", "language": "en"},
        "metadata": {"source": "web", "version": "1.0"},
    }

    login_state = LoginState(
        state="test_state",
        code_verifier="verifier",
        redirect_uri="https://example.com/callback",
        return_url=None,
        custom_state=complex_custom_state,
    )

    result_dict = login_state.to_dict()
    assert result_dict["custom_state"] == complex_custom_state
    assert result_dict["custom_state"]["user_preferences"]["theme"] == "dark"  # type: ignore


def test_enum_values_are_strings():
    """Test that enum values are proper strings."""
    assert isinstance(CallbackResultType.COMPLETED.value, str)
    assert isinstance(CallbackResultType.REDIRECT_REQUIRED.value, str)

    # Test enum can be used in comparisons
    result_type = CallbackResultType.COMPLETED
    assert result_type == CallbackResultType.COMPLETED
    assert result_type != CallbackResultType.REDIRECT_REQUIRED
