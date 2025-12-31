from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException, Request, status
from wristband.python_jwt import JWTPayload, JwtValidationResult

from wristband.fastapi_auth import AuthConfig, JWTAuthResult, WristbandAuth


class TestCreateJwtAuthDependency:
    """Unit tests for WristbandAuth.create_jwt_auth_dependency()"""

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
    def mock_request_with_valid_token(self) -> Request:
        """Create a mock request with valid Authorization header"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.headers = Mock()
        request.headers.get = Mock(return_value="Bearer valid_token_string")
        return request

    @pytest.fixture
    def mock_jwt_payload(self) -> JWTPayload:
        """Create a mock JWT payload"""
        payload_dict = {
            "sub": "user_123",
            "iss": "https://test.wristband.dev",
            "aud": "test_client_id",
            "exp": 9999999999,
            "iat": 1234567890,
        }
        return JWTPayload(payload_dict=payload_dict)

    @pytest.mark.asyncio
    async def test_successful_jwt_authentication(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that dependency successfully validates a valid JWT"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="valid_token_string")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            dependency = wristband_auth.create_jwt_auth_dependency()
            result = await dependency(mock_request_with_valid_token)

            assert isinstance(result, JWTAuthResult)
            assert result.jwt == "valid_token_string"
            assert result.payload == mock_jwt_payload
            assert result.payload.sub == "user_123"

    @pytest.mark.asyncio
    async def test_raises_401_when_authorization_header_missing(self, wristband_auth: WristbandAuth) -> None:
        """Test that 401 is raised when Authorization header is missing"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.headers = Mock()
        request.headers.get = Mock(return_value=None)

        dependency = wristband_auth.create_jwt_auth_dependency()

        with pytest.raises(HTTPException) as exc_info:
            await dependency(request)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_raises_401_when_bearer_token_extraction_fails(self, wristband_auth: WristbandAuth) -> None:
        """Test that 401 is raised when Bearer token cannot be extracted"""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/protected"
        request.headers = Mock()
        request.headers.get = Mock(return_value="Invalid token format")

        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value=None)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            dependency = wristband_auth.create_jwt_auth_dependency()

            with pytest.raises(HTTPException) as exc_info:
                await dependency(request)

            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_raises_401_when_token_validation_fails(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request
    ) -> None:
        """Test that 401 is raised when JWT validation fails"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="invalid_token")
        mock_validation_result = JwtValidationResult(is_valid=False, payload=None)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            dependency = wristband_auth.create_jwt_auth_dependency()

            with pytest.raises(HTTPException) as exc_info:
                await dependency(mock_request_with_valid_token)

            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_jwt_validator_lazy_initialization(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that JWT validator is lazily initialized on first request"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator) as mock_get_validator:
            dependency = wristband_auth.create_jwt_auth_dependency()

            # First request should initialize validator
            await dependency(mock_request_with_valid_token)
            assert mock_get_validator.call_count == 1

            # Second request should reuse validator
            await dependency(mock_request_with_valid_token)
            assert mock_get_validator.call_count == 2

    @pytest.mark.asyncio
    async def test_jwt_validator_caching_across_requests(
        self, wristband_auth: WristbandAuth, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that the same JWT validator instance is reused across requests"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator) as mock_get_validator:
            dependency = wristband_auth.create_jwt_auth_dependency()

            # Create multiple requests
            request1 = Mock(spec=Request)
            request1.method = "GET"
            request1.url = Mock()
            request1.url.path = "/api/endpoint1"
            request1.headers = Mock()
            request1.headers.get = Mock(return_value="Bearer token1")

            request2 = Mock(spec=Request)
            request2.method = "POST"
            request2.url = Mock()
            request2.url.path = "/api/endpoint2"
            request2.headers = Mock()
            request2.headers.get = Mock(return_value="Bearer token2")

            await dependency(request1)
            await dependency(request2)

            # Validator should be retrieved twice (once per request)
            assert mock_get_validator.call_count == 2

    @pytest.mark.asyncio
    async def test_custom_jwks_cache_config(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that custom JWKS cache configuration is passed to validator"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator) as mock_get_validator:
            dependency = wristband_auth.create_jwt_auth_dependency(jwks_cache_max_size=50, jwks_cache_ttl=7200)
            await dependency(mock_request_with_valid_token)

            # Verify custom config was passed
            mock_get_validator.assert_called_once_with(50, 7200)

    @pytest.mark.asyncio
    async def test_default_jwks_cache_config(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that default JWKS cache configuration is used when not specified"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator) as mock_get_validator:
            dependency = wristband_auth.create_jwt_auth_dependency()
            await dependency(mock_request_with_valid_token)

            # Verify None values were passed (defaults will be applied in _get_jwt_validator)
            mock_get_validator.assert_called_once_with(None, None)

    @pytest.mark.asyncio
    async def test_dependency_returns_jwt_auth_result(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that dependency returns JWTAuthResult with both payload and raw token"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="raw_token_string")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            dependency = wristband_auth.create_jwt_auth_dependency()
            result = await dependency(mock_request_with_valid_token)

            # Verify result structure
            assert isinstance(result, JWTAuthResult)
            assert result.jwt == "raw_token_string"
            assert result.payload is mock_jwt_payload
            assert hasattr(result.payload, "sub")
            assert hasattr(result.payload, "iss")
            assert hasattr(result.payload, "aud")

    @pytest.mark.asyncio
    async def test_dependency_is_reusable(self, wristband_auth: WristbandAuth, mock_jwt_payload: JWTPayload) -> None:
        """Test that the same dependency can be used multiple times"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            dependency = wristband_auth.create_jwt_auth_dependency()

            request1 = Mock(spec=Request)
            request1.method = "GET"
            request1.url = Mock()
            request1.url.path = "/api/test"
            request1.headers = Mock()
            request1.headers.get = Mock(return_value="Bearer token")

            result1 = await dependency(request1)
            result2 = await dependency(request1)

            assert result1.payload == mock_jwt_payload
            assert result2.payload == mock_jwt_payload
            assert mock_validator.validate.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_dependencies_with_different_cache_configs(
        self, wristband_auth: WristbandAuth, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that multiple dependencies can be created with different cache configurations"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/test"
        request.headers = Mock()
        request.headers.get = Mock(return_value="Bearer token")

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator) as mock_get_validator:
            # Create two dependencies with different configs
            dependency1 = wristband_auth.create_jwt_auth_dependency(jwks_cache_max_size=10)
            dependency2 = wristband_auth.create_jwt_auth_dependency(jwks_cache_max_size=100, jwks_cache_ttl=3600)

            await dependency1(request)
            await dependency2(request)

            # Verify different configs were used
            assert mock_get_validator.call_count == 2
            mock_get_validator.assert_any_call(10, None)
            mock_get_validator.assert_any_call(100, 3600)

    @pytest.mark.asyncio
    async def test_logs_debug_message(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that debug logging occurs"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
                dependency = wristband_auth.create_jwt_auth_dependency()
                await dependency(mock_request_with_valid_token)

                # Verify debug logging
                assert mock_logger.debug.call_count == 1
                log_message = mock_logger.debug.call_args[0][0]
                assert "Executing JWT auth for:" in log_message
                assert "GET" in log_message
                assert "/api/protected" in log_message

    @pytest.mark.asyncio
    async def test_logs_debug_on_missing_header(self, wristband_auth: WristbandAuth) -> None:
        """Test that debug log is written when Authorization header is missing"""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/api/endpoint"
        request.headers = Mock()
        request.headers.get = Mock(return_value=None)

        with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
            dependency = wristband_auth.create_jwt_auth_dependency()

            with pytest.raises(HTTPException):
                await dependency(request)

            # Verify debug logs
            debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
            assert any("Missing Authorization header" in msg for msg in debug_calls)

    @pytest.mark.asyncio
    async def test_logs_debug_on_invalid_header_format(self, wristband_auth: WristbandAuth) -> None:
        """Test that debug log is written when Authorization header format is invalid"""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/api/endpoint"
        request.headers = Mock()
        request.headers.get = Mock(return_value="NotBearer token")

        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value=None)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
                dependency = wristband_auth.create_jwt_auth_dependency()

                with pytest.raises(HTTPException):
                    await dependency(request)

                # Verify debug logs
                debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
                assert any("Invalid Authorization header format" in msg for msg in debug_calls)

    @pytest.mark.asyncio
    async def test_logs_debug_on_invalid_token(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request
    ) -> None:
        """Test that debug log is written when token validation fails"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="invalid_token")
        mock_validation_result = JwtValidationResult(is_valid=False, payload=None)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            with patch("wristband.fastapi_auth.auth._logger") as mock_logger:
                dependency = wristband_auth.create_jwt_auth_dependency()

                with pytest.raises(HTTPException):
                    await dependency(mock_request_with_valid_token)

                # Verify debug logs
                debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
                assert any("Invalid or expired token" in msg for msg in debug_calls)

    @pytest.mark.asyncio
    async def test_extracts_correct_payload_fields(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request
    ) -> None:
        """Test that all standard JWT payload fields are accessible"""
        payload_dict = {
            "sub": "user_456",
            "iss": "https://auth.example.com",
            "aud": "client_789",
            "exp": 1735689600,
            "iat": 1735603200,
            "custom_claim": "custom_value",
        }
        mock_payload = JWTPayload(payload_dict=payload_dict)

        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            dependency = wristband_auth.create_jwt_auth_dependency()
            result = await dependency(mock_request_with_valid_token)

            # Verify all fields are accessible
            assert result.payload.sub == "user_456"
            assert result.payload.iss == "https://auth.example.com"
            assert result.payload.aud == "client_789"
            assert result.payload.exp == 1735689600
            assert result.payload.iat == 1735603200

    @pytest.mark.asyncio
    async def test_dependency_can_be_used_as_typed_injection(
        self, wristband_auth: WristbandAuth, mock_request_with_valid_token: Request, mock_jwt_payload: JWTPayload
    ) -> None:
        """Test that dependency can be used for typed JWT injection in FastAPI routes"""
        mock_validator = Mock()
        mock_validator.extract_bearer_token = Mock(return_value="token")
        mock_validation_result = JwtValidationResult(is_valid=True, payload=mock_jwt_payload)
        mock_validator.validate = Mock(return_value=mock_validation_result)

        with patch.object(wristband_auth, "_get_jwt_validator", return_value=mock_validator):
            dependency = wristband_auth.create_jwt_auth_dependency()
            auth_result: JWTAuthResult = await dependency(mock_request_with_valid_token)

            # Verify typed access works
            assert hasattr(auth_result, "jwt")
            assert hasattr(auth_result, "payload")
            assert isinstance(auth_result.payload, JWTPayload)
