from wristband.fastapi_auth.models import (
    AuthConfig,
    CallbackData,
    CallbackResult,
    CallbackResultType,
    LoginConfig,
    LoginState,
    LogoutConfig,
    OAuthAuthorizeUrlConfig,
    RawUserInfo,
    SdkConfiguration,
    SessionResponse,
    TokenData,
    TokenResponse,
    UserInfo,
    UserInfoRole,
    WristbandTokenResponse,
)

########################################
# AUTH CONFIG TESTS
########################################


def test_auth_config_creation_minimal():
    """Test basic AuthConfig creation with only required fields."""
    config = AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        wristband_application_vanity_domain="app.wristband.dev",
    )

    assert config.client_id == "test_client_id"
    assert config.client_secret == "test_client_secret"
    assert config.wristband_application_vanity_domain == "app.wristband.dev"


def test_auth_config_creation_with_optionals():
    """Test AuthConfig creation with optional fields."""
    config = AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        wristband_application_vanity_domain="app.wristband.dev",
        login_state_secret="a" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
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
        wristband_application_vanity_domain="app.wristband.dev",
    )

    assert config.auto_configure_enabled is True
    assert config.custom_application_login_page_url is None
    assert config.dangerously_disable_secure_cookies is False
    assert config.is_application_custom_domain_active is None
    assert config.login_state_secret is None
    assert config.login_url is None
    assert config.parse_tenant_from_root_domain is None
    assert config.redirect_uri is None
    assert config.scopes == ["openid", "offline_access", "email"]
    assert config.token_expiration_buffer == 60


def test_auth_config_auto_configure_disabled():
    """Test AuthConfig with auto_configure_enabled set to False."""
    config = AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        wristband_application_vanity_domain="app.wristband.dev",
        auto_configure_enabled=False,
    )

    assert config.auto_configure_enabled is False


def test_auth_config_custom_values():
    """Test AuthConfig with custom values."""
    config = AuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        wristband_application_vanity_domain="app.wristband.dev",
        auto_configure_enabled=False,
        login_state_secret="b" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
        custom_application_login_page_url="https://custom.com/login",
        dangerously_disable_secure_cookies=True,
        is_application_custom_domain_active=True,
        parse_tenant_from_root_domain="example.com",
        scopes=["openid", "profile"],
        token_expiration_buffer=120,
    )

    assert config.auto_configure_enabled is False
    assert config.custom_application_login_page_url == "https://custom.com/login"
    assert config.dangerously_disable_secure_cookies is True
    assert config.is_application_custom_domain_active is True
    assert config.parse_tenant_from_root_domain == "example.com"
    assert config.scopes == ["openid", "profile"]
    assert config.token_expiration_buffer == 120


def test_sdk_configuration_creation_minimal():
    """Test SdkConfiguration creation with only required fields."""
    config = SdkConfiguration(
        login_url="https://auth.example.com/login",
        redirect_uri="https://app.example.com/callback",
        is_application_custom_domain_active=False,
    )

    assert config.login_url == "https://auth.example.com/login"
    assert config.redirect_uri == "https://app.example.com/callback"
    assert config.custom_application_login_page_url is None
    assert config.is_application_custom_domain_active is False
    assert config.login_url_tenant_domain_suffix is None


def test_sdk_configuration_creation_with_all_fields():
    """Test SdkConfiguration creation with all fields."""
    config = SdkConfiguration(
        login_url="https://auth.example.com/login",
        redirect_uri="https://app.example.com/callback",
        custom_application_login_page_url="https://custom.example.com/login",
        is_application_custom_domain_active=True,
        login_url_tenant_domain_suffix="example.com",
    )

    assert config.login_url == "https://auth.example.com/login"
    assert config.redirect_uri == "https://app.example.com/callback"
    assert config.custom_application_login_page_url == "https://custom.example.com/login"
    assert config.is_application_custom_domain_active is True
    assert config.login_url_tenant_domain_suffix == "example.com"


def test_sdk_configuration_from_api_response():
    """Test SdkConfiguration.from_api_response static method."""
    api_response = {
        "loginUrl": "https://auth.example.com/login",
        "redirectUri": "https://app.example.com/callback",
        "customApplicationLoginPageUrl": "https://custom.example.com/login",
        "isApplicationCustomDomainActive": True,
        "loginUrlTenantDomainSuffix": "example.com",
    }

    config = SdkConfiguration.from_api_response(api_response)

    assert isinstance(config, SdkConfiguration)
    assert config.login_url == "https://auth.example.com/login"
    assert config.redirect_uri == "https://app.example.com/callback"
    assert config.custom_application_login_page_url == "https://custom.example.com/login"
    assert config.is_application_custom_domain_active is True
    assert config.login_url_tenant_domain_suffix == "example.com"


def test_sdk_configuration_from_api_response_minimal():
    """Test SdkConfiguration.from_api_response with minimal API response."""
    api_response = {
        "loginUrl": "https://auth.example.com/login",
        "redirectUri": "https://app.example.com/callback",
    }

    config = SdkConfiguration.from_api_response(api_response)

    assert config.login_url == "https://auth.example.com/login"
    assert config.redirect_uri == "https://app.example.com/callback"
    assert config.custom_application_login_page_url is None
    assert config.is_application_custom_domain_active is False
    assert config.login_url_tenant_domain_suffix is None


def test_sdk_configuration_from_api_response_with_null_values():
    """Test SdkConfiguration.from_api_response with null values from API."""
    api_response = {
        "loginUrl": "https://auth.example.com/login",
        "redirectUri": "https://app.example.com/callback",
        "customApplicationLoginPageUrl": None,
        "isApplicationCustomDomainActive": False,
        "loginUrlTenantDomainSuffix": None,
    }

    config = SdkConfiguration.from_api_response(api_response)

    assert config.login_url == "https://auth.example.com/login"
    assert config.redirect_uri == "https://app.example.com/callback"
    assert config.custom_application_login_page_url is None
    assert config.is_application_custom_domain_active is False
    assert config.login_url_tenant_domain_suffix is None


def test_sdk_configuration_from_api_response_missing_optional_fields():
    """Test SdkConfiguration.from_api_response when optional fields are missing from API response."""
    api_response = {
        "loginUrl": "https://auth.example.com/login",
        "redirectUri": "https://app.example.com/callback",
        # Optional fields missing entirely
    }

    config = SdkConfiguration.from_api_response(api_response)

    assert config.login_url == "https://auth.example.com/login"
    assert config.redirect_uri == "https://app.example.com/callback"
    assert config.custom_application_login_page_url is None
    assert config.is_application_custom_domain_active is False  # Gets default from .get()
    assert config.login_url_tenant_domain_suffix is None


def test_sdk_configuration_camelcase_to_snake_case_mapping():
    """Test that from_api_response correctly maps camelCase to snake_case."""
    api_response = {
        "loginUrl": "https://test.com/login",
        "redirectUri": "https://test.com/callback",
        "customApplicationLoginPageUrl": "https://custom.test.com/login",
        "isApplicationCustomDomainActive": True,
        "loginUrlTenantDomainSuffix": "test.com",
    }

    config = SdkConfiguration.from_api_response(api_response)

    # Verify all camelCase API keys are correctly mapped to snake_case Python attributes
    assert hasattr(config, "login_url")
    assert hasattr(config, "redirect_uri")
    assert hasattr(config, "custom_application_login_page_url")
    assert hasattr(config, "is_application_custom_domain_active")
    assert hasattr(config, "login_url_tenant_domain_suffix")

    # Verify values are correctly mapped
    assert config.login_url == api_response["loginUrl"]
    assert config.redirect_uri == api_response["redirectUri"]
    assert config.custom_application_login_page_url == api_response["customApplicationLoginPageUrl"]
    assert config.is_application_custom_domain_active == api_response["isApplicationCustomDomainActive"]
    assert config.login_url_tenant_domain_suffix == api_response["loginUrlTenantDomainSuffix"]


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
    assert config.default_tenant_name is None
    assert config.tenant_custom_domain is None
    assert config.tenant_name is None
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
        default_tenant_name="default-tenant",
        tenant_custom_domain="tenant.com",
        tenant_name="my-tenant",
        is_application_custom_domain_active=True,
    )

    assert config.default_tenant_custom_domain == "default.tenant.com"
    assert config.default_tenant_name == "default-tenant"
    assert config.tenant_custom_domain == "tenant.com"
    assert config.tenant_name == "my-tenant"
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


def test_login_state_model_dump():
    """Test LoginState model_dump method."""
    custom_state = {"key": "value"}
    login_state = LoginState(
        state="test_state",
        code_verifier="test_verifier",
        redirect_uri="https://example.com/callback",
        return_url="https://example.com/dashboard",
        custom_state=custom_state,
    )

    result = login_state.model_dump()
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

    result = login_state.model_dump()
    assert result["return_url"] is None
    assert result["custom_state"] is None


def test_login_config_creation():
    """Test LoginConfig creation."""
    custom_state = {"theme": "dark"}
    config = LoginConfig(
        custom_state=custom_state,
        default_tenant_custom_domain="default.com",
        default_tenant_name="default",
        return_url="https://example.com/return",
    )

    assert config.custom_state == custom_state
    assert config.default_tenant_custom_domain == "default.com"
    assert config.default_tenant_name == "default"
    assert config.return_url == "https://example.com/return"


def test_login_config_defaults():
    """Test LoginConfig default values."""
    config = LoginConfig()

    assert config.custom_state is None
    assert config.default_tenant_custom_domain is None
    assert config.default_tenant_name is None
    assert config.return_url is None


def test_login_config_return_url():
    """Test LoginConfig return_url field."""
    config = LoginConfig(return_url="https://example.com/dashboard")

    assert config.return_url == "https://example.com/dashboard"
    assert config.custom_state is None
    assert config.default_tenant_custom_domain is None
    assert config.default_tenant_name is None


########################################
# CALLBACK MODEL TESTS
########################################


def test_callback_result_type_enum():
    """Test CallbackResultType enum values."""
    assert CallbackResultType.COMPLETED.value == "COMPLETED"
    assert CallbackResultType.REDIRECT_REQUIRED.value == "REDIRECT_REQUIRED"


def test_raw_user_info_creation():
    """Test RawUserInfo model creation."""
    user_info = RawUserInfo(
        sub="user123",
        tnt_id="tenant123",
        app_id="app123",
        idp_name="Wristband",
        email="user@example.com",
        name="Test User",
    )

    assert isinstance(user_info, RawUserInfo)
    assert user_info.sub == "user123"
    assert user_info.email == "user@example.com"
    assert user_info.name == "Test User"


def test_callback_data_creation():
    """Test CallbackData creation."""
    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
        email="user@example.com",
        email_verified=True,
    )
    custom_state = {"theme": "dark"}

    callback_data = CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        tenant_name="tenant1",
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
    assert callback_data.tenant_name == "tenant1"
    assert callback_data.user_info == user_info
    assert callback_data.custom_state == custom_state
    assert callback_data.refresh_token == "refresh_token_123"
    assert callback_data.return_url == "https://example.com/dashboard"
    assert callback_data.tenant_custom_domain == "tenant1.example.com"


def test_callback_data_model_dump():
    """Test CallbackData model_dump method."""
    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
        email="user@example.com",
        email_verified=True,
    )
    callback_data = CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        tenant_name="tenant1",
        user_info=user_info,
        custom_state=None,
        refresh_token=None,
        return_url=None,
        tenant_custom_domain=None,
    )

    result = callback_data.model_dump()

    assert isinstance(result, dict)
    assert result["access_token"] == "access_token_123"
    assert isinstance(result["user_info"], dict)  # user_info is dumped to dict
    assert result["user_info"]["userId"] == "user_123"
    assert result["user_info"]["tenantId"] == "tenant_123"
    assert result["custom_state"] is None


def test_callback_data_with_none_optionals():
    """Test CallbackData with None optional values."""
    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
        email="user@example.com",
        email_verified=True,
    )
    callback_data = CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        tenant_name="tenant1",
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
    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
        email="user@example.com",
        email_verified=True,
    )
    callback_data = CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890,
        expires_in=3600,
        tenant_name="tenant1",
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


def test_wristband_token_response_creation():
    """Test WristbandTokenResponse creation."""
    token_response = WristbandTokenResponse(
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


def test_wristband_token_response_from_api_response():
    """Test WristbandTokenResponse.from_api_response static method."""
    api_response = {
        "access_token": "access_token_123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh_token_123",
        "id_token": "id_token_123",
        "scope": "openid email profile",
    }

    token_response = WristbandTokenResponse.from_api_response(api_response)

    assert isinstance(token_response, WristbandTokenResponse)
    assert token_response.access_token == "access_token_123"
    assert token_response.token_type == "Bearer"
    assert token_response.expires_in == 3600
    assert token_response.refresh_token == "refresh_token_123"
    assert token_response.id_token == "id_token_123"
    assert token_response.scope == "openid email profile"


def test_wristband_token_response_from_api_response_exact_mapping():
    """Test that from_api_response maps all fields correctly."""
    api_response = {
        "access_token": "test_access",
        "token_type": "test_type",
        "expires_in": 1800,
        "refresh_token": "test_refresh",
        "id_token": "test_id",
        "scope": "test_scope",
    }

    result = WristbandTokenResponse.from_api_response(api_response)

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
        state="logout_state_123",
        tenant_custom_domain="tenant.example.com",
        tenant_name="my-tenant",
    )

    assert config.redirect_url == "https://example.com/goodbye"
    assert config.refresh_token == "refresh_token_123"
    assert config.state == "logout_state_123"
    assert config.tenant_custom_domain == "tenant.example.com"
    assert config.tenant_name == "my-tenant"


def test_logout_config_defaults():
    """Test LogoutConfig default values."""
    config = LogoutConfig()

    assert config.redirect_url is None
    assert config.refresh_token is None
    assert config.state is None
    assert config.tenant_custom_domain is None
    assert config.tenant_name is None


def test_logout_config_partial():
    """Test LogoutConfig with some parameters."""
    config = LogoutConfig(redirect_url="https://example.com/goodbye", tenant_name="my-tenant")

    assert config.redirect_url == "https://example.com/goodbye"
    assert config.refresh_token is None
    assert config.state is None
    assert config.tenant_custom_domain is None
    assert config.tenant_name == "my-tenant"


def test_logout_config_state_field():
    """Test LogoutConfig state field functionality."""
    config = LogoutConfig(state="custom_logout_state", tenant_name="my-tenant")

    assert config.state == "custom_logout_state"
    assert config.tenant_name == "my-tenant"
    assert config.redirect_url is None
    assert config.refresh_token is None
    assert config.tenant_custom_domain is None


########################################
# INTEGRATION TESTS
########################################


def test_pydantic_model_dump_compatibility():
    """Test that all Pydantic models work with model_dump method."""
    # Test AuthConfig with minimal required fields
    auth_config = AuthConfig(
        client_id="test",
        client_secret="secret",
        wristband_application_vanity_domain="app.wristband.dev",
    )
    auth_dict = auth_config.model_dump()
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
    login_dict = login_state.model_dump()
    assert isinstance(login_dict, dict)
    assert login_dict["state"] == "state"

    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
        email="user@example.com",
        email_verified=True,
    )

    # Test CallbackData
    callback_data = CallbackData(
        access_token="token",
        id_token="id_token",
        expires_at=123456,
        expires_in=3600,
        tenant_name="tenant",
        user_info=user_info,
        custom_state=None,
        refresh_token=None,
        return_url=None,
        tenant_custom_domain=None,
    )
    callback_dict = callback_data.model_dump()
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

    result_dict = login_state.model_dump()
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


########################################
# USERINFO MODEL TESTS
########################################


def test_user_info_creation_minimal():
    """Test UserInfo creation with only required fields."""
    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
    )

    assert user_info.user_id == "user_123"
    assert user_info.tenant_id == "tenant_123"
    assert user_info.application_id == "app_123"
    assert user_info.identity_provider_name == "Wristband"
    assert user_info.email is None
    assert user_info.full_name is None


def test_user_info_creation_with_all_fields():
    """Test UserInfo creation with all optional fields."""
    roles = [UserInfoRole(id="role_123", name="app:app-name:admin", display_name="Admin Role")]

    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
        full_name="John Doe Smith",
        given_name="John",
        family_name="Smith",
        middle_name="Doe",
        nickname="Johnny",
        display_name="jsmith",
        picture_url="https://example.com/pic.jpg",
        email="john@example.com",
        email_verified=True,
        gender="male",
        birthdate="1990-01-01",
        time_zone="America/Los_Angeles",
        locale="en-US",
        phone_number="+16045551234",
        phone_number_verified=True,
        updated_at=1640995200,
        roles=roles,
        custom_claims={"department": "engineering", "level": 5},
    )

    assert user_info.user_id == "user_123"
    assert user_info.full_name == "John Doe Smith"
    assert user_info.given_name == "John"
    assert user_info.family_name == "Smith"
    assert user_info.middle_name == "Doe"
    assert user_info.nickname == "Johnny"
    assert user_info.display_name == "jsmith"
    assert user_info.picture_url == "https://example.com/pic.jpg"
    assert user_info.email == "john@example.com"
    assert user_info.email_verified is True
    assert user_info.gender == "male"
    assert user_info.birthdate == "1990-01-01"
    assert user_info.time_zone == "America/Los_Angeles"
    assert user_info.locale == "en-US"
    assert user_info.phone_number == "+16045551234"
    assert user_info.phone_number_verified is True
    assert user_info.updated_at == 1640995200
    assert user_info.roles is not None and len(user_info.roles) == 1
    assert user_info.custom_claims == {"department": "engineering", "level": 5}


def test_user_info_model_dump_serialization():
    """Test UserInfo serializes to camelCase."""
    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
        full_name="John Smith",
        email="john@example.com",
        email_verified=True,
    )

    result = user_info.model_dump()

    assert isinstance(result, dict)
    # Verify camelCase serialization
    assert result["userId"] == "user_123"
    assert result["tenantId"] == "tenant_123"
    assert result["applicationId"] == "app_123"
    assert result["identityProviderName"] == "Wristband"
    assert result["fullName"] == "John Smith"
    assert result["email"] == "john@example.com"
    assert result["emailVerified"] is True
    # Verify snake_case keys are NOT present
    assert "user_id" not in result
    assert "tenant_id" not in result
    assert "full_name" not in result


def test_user_info_from_camel_case_dict():
    """Test UserInfo can be created from camelCase dict (validation_alias)."""
    camel_case_data = {
        "userId": "user_123",
        "tenantId": "tenant_123",
        "applicationId": "app_123",
        "identityProviderName": "Wristband",
        "fullName": "John Smith",
        "givenName": "John",
        "familyName": "Smith",
        "email": "john@example.com",
        "emailVerified": True,
    }

    user_info = UserInfo(**camel_case_data)

    # Verify internal representation uses snake_case
    assert user_info.user_id == "user_123"
    assert user_info.tenant_id == "tenant_123"
    assert user_info.application_id == "app_123"
    assert user_info.identity_provider_name == "Wristband"
    assert user_info.full_name == "John Smith"
    assert user_info.given_name == "John"
    assert user_info.family_name == "Smith"
    assert user_info.email == "john@example.com"
    assert user_info.email_verified is True


def test_user_info_with_roles():
    """Test UserInfo with roles array."""
    roles = [
        UserInfoRole(id="role_1", name="app:app-name:admin", display_name="Admin"),
        UserInfoRole(id="role_2", name="app:app-name:user", display_name="User"),
    ]

    user_info = UserInfo(
        user_id="user_123",
        tenant_id="tenant_123",
        application_id="app_123",
        identity_provider_name="Wristband",
        roles=roles,
    )

    assert user_info.roles is not None and len(user_info.roles) == 2
    assert user_info.roles[0].id == "role_1"
    assert user_info.roles[1].name == "app:app-name:user"


########################################
# USERINFO ROLE MODEL TESTS
########################################


def test_user_info_role_creation():
    """Test UserInfoRole creation."""
    role = UserInfoRole(id="role_123", name="app:app-name:admin", display_name="Admin Role")

    assert role.id == "role_123"
    assert role.name == "app:app-name:admin"
    assert role.display_name == "Admin Role"


def test_user_info_role_serialization():
    """Test UserInfoRole serializes displayName correctly."""
    role = UserInfoRole(id="role_123", name="app:app-name:admin", display_name="Admin Role")

    result = role.model_dump()

    assert isinstance(result, dict)
    assert result["id"] == "role_123"
    assert result["name"] == "app:app-name:admin"
    assert result["displayName"] == "Admin Role"
    # Verify snake_case key is NOT present
    assert "display_name" not in result


def test_user_info_role_from_camel_case():
    """Test UserInfoRole can be created from camelCase dict."""
    camel_case_data = {"id": "role_123", "name": "app:app-name:admin", "displayName": "Admin Role"}

    role = UserInfoRole(**camel_case_data)

    assert role.id == "role_123"
    assert role.name == "app:app-name:admin"
    assert role.display_name == "Admin Role"


########################################
# RAW USERINFO MODEL TESTS
########################################


def test_raw_user_info_with_all_optional_fields():
    """Test RawUserInfo with all profile, email, phone scopes."""
    roles = [UserInfoRole(id="role_123", name="app:app-name:admin", display_name="Admin")]

    raw_user_info = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        name="John Doe Smith",
        given_name="John",
        family_name="Smith",
        middle_name="Doe",
        nickname="Johnny",
        preferred_username="jsmith",
        picture="https://example.com/pic.jpg",
        email="john@example.com",
        email_verified=True,
        gender="male",
        birthdate="1990-01-01",
        zoneinfo="America/Los_Angeles",
        locale="en-US",
        phone_number="+16045551234",
        phone_number_verified=True,
        updated_at=1640995200,
        roles=roles,
        custom_claims={"department": "engineering"},
    )

    assert raw_user_info.sub == "user_123"
    assert raw_user_info.tnt_id == "tenant_123"
    assert raw_user_info.name == "John Doe Smith"
    assert raw_user_info.given_name == "John"
    assert raw_user_info.preferred_username == "jsmith"
    assert raw_user_info.picture == "https://example.com/pic.jpg"
    assert raw_user_info.zoneinfo == "America/Los_Angeles"
    assert raw_user_info.roles is not None and len(raw_user_info.roles) == 1
    assert raw_user_info.custom_claims == {"department": "engineering"}


def test_raw_user_info_model_dump():
    """Test RawUserInfo model_dump behavior."""
    raw_user_info = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        email="john@example.com",
    )

    result = raw_user_info.model_dump()

    assert isinstance(result, dict)
    assert result["sub"] == "user_123"
    assert result["tnt_id"] == "tenant_123"
    assert result["app_id"] == "app_123"
    assert result["idp_name"] == "Wristband"
    assert result["email"] == "john@example.com"


########################################
# SESSION RESPONSE MODEL TESTS
########################################


def test_session_response_creation():
    """Test SessionResponse creation."""
    session_response = SessionResponse(
        tenant_id="tenant_123",
        user_id="user_123",
        metadata={"role": "admin", "department": "engineering"},
    )

    assert session_response.tenant_id == "tenant_123"
    assert session_response.user_id == "user_123"
    assert session_response.metadata == {"role": "admin", "department": "engineering"}


def test_session_response_serialization():
    """Test SessionResponse serializes to camelCase."""
    session_response = SessionResponse(
        tenant_id="tenant_123",
        user_id="user_123",
        metadata={"role": "admin"},
    )

    result = session_response.model_dump()

    assert isinstance(result, dict)
    assert result["tenantId"] == "tenant_123"
    assert result["userId"] == "user_123"
    assert result["metadata"] == {"role": "admin"}
    # Verify snake_case keys are NOT present
    assert "tenant_id" not in result
    assert "user_id" not in result


def test_session_response_empty_metadata():
    """Test SessionResponse with empty metadata dict."""
    session_response = SessionResponse(
        tenant_id="tenant_123",
        user_id="user_123",
        metadata={},
    )

    assert session_response.metadata == {}

    result = session_response.model_dump()
    assert result["metadata"] == {}


########################################
# TOKEN RESPONSE MODEL TESTS
########################################


def test_token_response_creation():
    """Test TokenResponse creation."""
    token_response = TokenResponse(
        access_token="access_token_123",
        expires_at=1640995200000,
    )

    assert token_response.access_token == "access_token_123"
    assert token_response.expires_at == 1640995200000


def test_token_response_serialization():
    """Test TokenResponse serializes to camelCase."""
    token_response = TokenResponse(
        access_token="access_token_123",
        expires_at=1640995200000,
    )

    result = token_response.model_dump()

    assert isinstance(result, dict)
    assert result["accessToken"] == "access_token_123"
    assert result["expiresAt"] == 1640995200000
    # Verify snake_case keys are NOT present
    assert "access_token" not in result
    assert "expires_at" not in result


def test_token_response_matches_expected_format():
    """Test TokenResponse output matches Wristband SDK expectations."""
    token_response = TokenResponse(
        access_token="eyJhbGc...",
        expires_at=1234567890,
    )

    result = token_response.model_dump()

    # This should match the format documented in the model
    expected_keys = {"accessToken", "expiresAt"}
    assert set(result.keys()) == expected_keys
