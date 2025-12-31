from unittest.mock import Mock, patch

import pytest
from fastapi import Request, Response

from wristband.fastapi_auth import CallbackData, SessionMiddleware, UserInfo
from wristband.fastapi_auth.models import SameSiteOption
from wristband.fastapi_auth.session import SessionManager
from wristband.fastapi_auth.utils import DataEncryptor


# Fixtures
@pytest.fixture
def secret_key():
    return "a" * 32


@pytest.fixture
def different_secret_key():
    return "b" * 32


@pytest.fixture
def encryptor(secret_key):
    return DataEncryptor(secret_key)


@pytest.fixture
def callback_data():
    return CallbackData(
        access_token="access_token_123",
        id_token="id_token_123",
        expires_at=1234567890000,
        expires_in=3600,
        tenant_name="test-tenant",
        user_info=UserInfo(
            user_id="user_123",
            tenant_id="tenant_123",
            application_id="app_123",
            identity_provider_name="Wristband",
            email="test@example.com",
        ),
        custom_state={"key": "value"},
        refresh_token="refresh_token_123",
        return_url="/dashboard",
        tenant_custom_domain="custom.example.com",
    )


class TestSessionMiddlewareInitialization:
    """Test SessionMiddleware initialization and validation"""

    def test_init_with_valid_config(self):
        app = Mock()
        middleware = SessionMiddleware(
            app=app,
            secret_key="a" * 32,
            session_cookie_name="session",
            max_age=3600,
        )

        assert middleware._session_cookie_name == "session"
        assert middleware._max_age == 3600

    def test_init_raises_when_secret_key_empty_string(self):
        with pytest.raises(ValueError, match="secret_key at index 0 cannot be empty"):
            SessionMiddleware(app=Mock(), secret_key="")

    def test_init_raises_when_secret_key_empty_list(self):
        with pytest.raises(ValueError, match="secret_key is required"):
            SessionMiddleware(app=Mock(), secret_key=[])

    def test_init_raises_when_secret_key_whitespace(self):
        with pytest.raises(ValueError, match="at least 32 characters"):
            SessionMiddleware(app=Mock(), secret_key="   ")

    def test_init_raises_when_secret_key_too_short(self):
        with pytest.raises(ValueError, match="at least 32 characters"):
            SessionMiddleware(app=Mock(), secret_key="short")

    def test_init_raises_when_key_in_list_too_short(self):
        with pytest.raises(ValueError, match="at least 32 characters"):
            SessionMiddleware(app=Mock(), secret_key=["a" * 32, "short"])

    def test_init_with_exactly_32_chars(self):
        middleware = SessionMiddleware(app=Mock(), secret_key="a" * 32)
        assert middleware._encryptor is not None

    def test_init_with_long_secret_key(self):
        middleware = SessionMiddleware(app=Mock(), secret_key="a" * 256)
        assert middleware._encryptor is not None

    def test_init_with_multiple_keys(self):
        middleware = SessionMiddleware(app=Mock(), secret_key=["a" * 32, "b" * 32, "c" * 32])
        assert middleware._encryptor is not None

    def test_init_raises_when_session_cookie_name_empty(self):
        with pytest.raises(ValueError, match="session_cookie_name cannot be empty"):
            SessionMiddleware(app=Mock(), secret_key="a" * 32, session_cookie_name="")

    def test_init_raises_when_session_cookie_name_whitespace(self):
        with pytest.raises(ValueError, match="session_cookie_name cannot be empty"):
            SessionMiddleware(app=Mock(), secret_key="a" * 32, session_cookie_name="   ")

    def test_init_raises_when_csrf_cookie_name_empty(self):
        with pytest.raises(ValueError, match="csrf_cookie_name cannot be empty"):
            SessionMiddleware(app=Mock(), secret_key="a" * 32, csrf_cookie_name="")

    def test_init_raises_when_csrf_cookie_name_whitespace(self):
        with pytest.raises(ValueError, match="csrf_cookie_name cannot be empty"):
            SessionMiddleware(app=Mock(), secret_key="a" * 32, csrf_cookie_name="   ")

    def test_init_raises_when_max_age_zero(self):
        with pytest.raises(ValueError, match="max_age must be greater than 0"):
            SessionMiddleware(app=Mock(), secret_key="a" * 32, max_age=0)

    def test_init_raises_when_max_age_negative(self):
        with pytest.raises(ValueError, match="max_age must be greater than 0"):
            SessionMiddleware(app=Mock(), secret_key="a" * 32, max_age=-1)

    def test_init_raises_when_path_empty(self):
        with pytest.raises(ValueError, match="path cannot be empty"):
            SessionMiddleware(app=Mock(), secret_key="a" * 32, path="")

    def test_init_raises_when_path_whitespace(self):
        with pytest.raises(ValueError, match="path cannot be empty"):
            SessionMiddleware(app=Mock(), secret_key="a" * 32, path="   ")

    def test_init_defaults(self):
        middleware = SessionMiddleware(app=Mock(), secret_key="a" * 32)

        assert middleware._session_cookie_name == "session"
        assert middleware._csrf_cookie_name == "CSRF-TOKEN"
        assert middleware._max_age == 3600
        assert middleware._path == "/"
        assert middleware._same_site == SameSiteOption.LAX
        assert middleware._secure is True
        assert middleware._enable_csrf_protection is False

    def test_init_csrf_domain_inherits_from_session_domain(self):
        middleware = SessionMiddleware(app=Mock(), secret_key="a" * 32, session_cookie_domain=".example.com")

        assert middleware._csrf_cookie_domain == ".example.com"

    def test_init_csrf_domain_can_override_session_domain(self):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key="a" * 32,
            session_cookie_domain=".example.com",
            csrf_cookie_domain=".csrf.example.com",
        )

        assert middleware._session_cookie_domain == ".example.com"
        assert middleware._csrf_cookie_domain == ".csrf.example.com"

    def test_init_with_all_same_site_options(self):
        same_site_values = [SameSiteOption.LAX, SameSiteOption.STRICT, SameSiteOption.NONE]
        for same_site in same_site_values:
            middleware = SessionMiddleware(app=Mock(), secret_key="a" * 32, same_site=same_site)
            assert middleware._same_site == same_site

    def test_init_with_csrf_protection_enabled(self):
        middleware = SessionMiddleware(app=Mock(), secret_key="a" * 32, enable_csrf_protection=True)
        assert middleware._enable_csrf_protection is True

    def test_init_with_custom_csrf_cookie_name(self):
        middleware = SessionMiddleware(app=Mock(), secret_key="a" * 32, csrf_cookie_name="X-CSRF-TOKEN")
        assert middleware._csrf_cookie_name == "X-CSRF-TOKEN"


class TestSessionMiddlewareDispatch:
    """Test middleware request/response cycle"""

    @pytest.mark.asyncio
    async def test_dispatch_creates_session_and_attaches_to_request(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            assert hasattr(req.state, "session")
            assert isinstance(req.state.session, SessionManager)
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_loads_existing_session(self, secret_key, encryptor):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Create encrypted session cookie
        session_data = {"user_id": "test_user", "is_authenticated": True}
        encrypted = encryptor.encrypt(session_data)

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={encrypted}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert req.state.session["user_id"] == "test_user"
            assert req.state.session["is_authenticated"] is True
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_with_no_session_cookie(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            # Should have empty session
            assert len(req.state.session) == 0
            assert req.state.session.to_dict() == {}
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_with_empty_cookie_value(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", b"session=")],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_with_invalid_encrypted_data(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", b"session=invalid_garbage")],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            # Should fail gracefully and provide empty session
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_with_wrong_secret_key(self, secret_key, different_secret_key):
        # Encrypt with one key
        encryptor1 = DataEncryptor(secret_key)
        session_data = {"user_id": "test_user", "is_authenticated": True}
        encrypted = encryptor1.encrypt(session_data)

        # Try to decrypt with different key
        middleware = SessionMiddleware(app=Mock(), secret_key=different_secret_key)
        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={encrypted}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            # Should fail to decrypt and return empty session
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_with_corrupted_encrypted_data(self, secret_key, encryptor):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Create valid encrypted session
        session_data = {"user_id": "test_user"}
        encrypted = encryptor.encrypt(session_data)

        # Corrupt it by modifying bytes in the middle
        corrupted = encrypted[:10] + "XXXXX" + encrypted[15:]

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={corrupted}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_with_truncated_encrypted_data(self, secret_key, encryptor):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Create valid encrypted session
        session_data = {"user_id": "test_user"}
        encrypted = encryptor.encrypt(session_data)

        # Truncate it
        truncated = encrypted[: len(encrypted) // 2]

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={truncated}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_returns_response_from_handler(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})
        expected_response = Response(content="test content", status_code=201)

        async def call_next(req):
            return expected_response

        response = await middleware.dispatch(request, call_next)

        assert response is expected_response
        assert response.status_code == 201

    @pytest.mark.asyncio
    async def test_dispatch_preserves_response_modifications(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            response = Response(content="custom", status_code=202)
            response.headers["X-Custom-Header"] = "custom-value"
            return response

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 202
        assert response.headers["X-Custom-Header"] == "custom-value"

    @pytest.mark.asyncio
    async def test_dispatch_exception_propagates(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            raise ValueError("Handler error")

        with pytest.raises(ValueError, match="Handler error"):
            await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_with_multiple_cookies(self, secret_key, encryptor):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        session_data = {"user_id": "test_user"}
        encrypted = encryptor.encrypt(session_data)

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"other=value1; session={encrypted}; another=value2".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert req.state.session["user_id"] == "test_user"
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_dispatch_logs_decryption_failure(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", b"session=invalid")],
                "method": "GET",
                "path": "/",
            }
        )

        with patch("wristband.fastapi_auth.middleware.logger") as mock_logger:

            async def call_next(req):
                return Response()

            await middleware.dispatch(request, call_next)

            # Verify logger.debug was called with failure message
            assert mock_logger.debug.called
            call_args = mock_logger.debug.call_args[0][0]
            assert "Failed to decrypt session cookie" in call_args


class TestSessionCookieOperations:
    """Test cookie reading and writing through middleware"""

    @pytest.mark.asyncio
    async def test_session_cookie_written_with_correct_attributes(self, secret_key, callback_data):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)

        assert session_cookie is not None
        assert "Path=/" in session_cookie
        assert "Max-Age=3600" in session_cookie
        assert "HttpOnly" in session_cookie
        assert "SameSite=lax" in session_cookie
        assert "Secure" in session_cookie

    @pytest.mark.asyncio
    async def test_csrf_cookie_not_written_when_protection_disabled(self, secret_key, callback_data):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key, enable_csrf_protection=False)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        has_csrf_cookie = any("CSRF-TOKEN=" in h for h in cookie_headers)

        assert not has_csrf_cookie

    @pytest.mark.asyncio
    async def test_csrf_cookie_written_when_protection_enabled(self, secret_key, callback_data):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key, enable_csrf_protection=True)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        has_session_cookie = any("session=" in h for h in cookie_headers)
        has_csrf_cookie = any("CSRF-TOKEN=" in h for h in cookie_headers)

        assert has_session_cookie
        assert has_csrf_cookie

    @pytest.mark.asyncio
    async def test_csrf_cookie_respects_all_attributes(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            enable_csrf_protection=True,
            path="/api",
            max_age=7200,
            same_site=SameSiteOption.STRICT,
            secure=False,
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        csrf_cookie = next((h for h in cookie_headers if "CSRF-TOKEN=" in h), None)

        assert csrf_cookie is not None
        assert "Path=/api" in csrf_cookie
        assert "Max-Age=7200" in csrf_cookie
        assert "SameSite=strict" in csrf_cookie
        assert "Secure" not in csrf_cookie

    @pytest.mark.asyncio
    async def test_csrf_cookie_with_same_site_none(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            enable_csrf_protection=True,
            same_site=SameSiteOption.NONE,
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        csrf_cookie = next((h for h in cookie_headers if "CSRF-TOKEN=" in h), None)

        assert csrf_cookie is not None
        assert "SameSite=none" in csrf_cookie

    @pytest.mark.asyncio
    async def test_cookies_respect_custom_domains(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            enable_csrf_protection=True,
            session_cookie_domain=".example.com",
            csrf_cookie_domain=".csrf.example.com",
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)
        csrf_cookie = next((h for h in cookie_headers if "CSRF-TOKEN=" in h), None)

        assert session_cookie is not None
        assert csrf_cookie is not None
        assert "Domain=.example.com" in session_cookie
        assert "Domain=.csrf.example.com" in csrf_cookie

    @pytest.mark.asyncio
    async def test_session_cookie_respects_custom_domain_without_csrf(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            enable_csrf_protection=False,
            session_cookie_domain=".example.com",
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)
        csrf_cookie = next((h for h in cookie_headers if "CSRF-TOKEN=" in h), None)

        assert session_cookie is not None
        assert csrf_cookie is None
        assert "Domain=.example.com" in session_cookie

    @pytest.mark.asyncio
    async def test_cookies_respect_custom_path(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            path="/api",
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)

        assert session_cookie is not None
        assert "Path=/api" in session_cookie

    @pytest.mark.asyncio
    async def test_cookies_respect_custom_max_age(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            max_age=7200,
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)

        assert session_cookie is not None
        assert "Max-Age=7200" in session_cookie

    @pytest.mark.asyncio
    async def test_cookies_respect_same_site_strict(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            same_site=SameSiteOption.STRICT,
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)

        assert session_cookie is not None
        assert "SameSite=strict" in session_cookie

    @pytest.mark.asyncio
    async def test_cookies_respect_same_site_none(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            same_site=SameSiteOption.NONE,
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)

        assert session_cookie is not None
        assert "SameSite=none" in session_cookie

    @pytest.mark.asyncio
    async def test_cookies_without_secure_flag(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            secure=False,
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)

        assert session_cookie is not None
        assert "Secure" not in session_cookie

    @pytest.mark.asyncio
    async def test_clear_deletes_session_cookie_only_when_csrf_disabled(self, secret_key, callback_data):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key, enable_csrf_protection=False)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.clear()
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)
        csrf_cookie = next((h for h in cookie_headers if "CSRF-TOKEN=" in h), None)

        assert session_cookie is not None
        assert "Max-Age=0" in session_cookie
        assert csrf_cookie is None

    @pytest.mark.asyncio
    async def test_clear_deletes_both_cookies_when_csrf_enabled(self, secret_key, callback_data):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key, enable_csrf_protection=True)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.clear()
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)
        csrf_cookie = next((h for h in cookie_headers if "CSRF-TOKEN=" in h), None)

        assert session_cookie is not None
        assert csrf_cookie is not None
        assert "Max-Age=0" in session_cookie
        assert "Max-Age=0" in csrf_cookie

    @pytest.mark.asyncio
    async def test_clear_takes_precedence_over_save(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session["user_id"] = "test"
            req.state.session.save()
            # Call clear after save - clear should win
            req.state.session.clear()
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)

        # Should delete, not save
        assert session_cookie is not None
        assert "Max-Age=0" in session_cookie

    @pytest.mark.asyncio
    async def test_custom_cookie_names(self, secret_key, callback_data):
        middleware = SessionMiddleware(
            app=Mock(),
            secret_key=secret_key,
            enable_csrf_protection=True,
            session_cookie_name="custom_session",
            csrf_cookie_name="X-CSRF-TOKEN",
        )
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]

        has_custom_session = any("custom_session=" in h for h in cookie_headers)
        has_custom_csrf = any("X-CSRF-TOKEN=" in h for h in cookie_headers)

        assert has_custom_session
        assert has_custom_csrf

    @pytest.mark.asyncio
    async def test_no_cookies_written_when_session_not_modified(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            # Just read session, don't modify or call save()
            _ = req.state.session.to_dict()
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h for h in response.raw_headers if h[0] == b"set-cookie"]
        assert len(cookie_headers) == 0

    @pytest.mark.asyncio
    async def test_cookies_written_when_save_called(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session["user_id"] = "test"
            req.state.session.save()
            return Response()

        response = await middleware.dispatch(request, call_next)

        cookie_headers = [h for h in response.raw_headers if h[0] == b"set-cookie"]
        assert len(cookie_headers) > 0

    @pytest.mark.asyncio
    async def test_session_cookie_size_limit_exceeded(self, secret_key):
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            # Try to store data that will exceed 4KB after encryption
            large_data = "x" * 10000
            req.state.session["large_field"] = large_data
            req.state.session.save()
            return Response()

        with pytest.raises(ValueError, match="Session cookie exceeds browser limit"):
            await middleware.dispatch(request, call_next)


class TestSessionEncryptionDecryption:
    """Test session encryption and decryption"""

    @pytest.mark.asyncio
    async def test_encryption_decryption_round_trip(self, secret_key, callback_data):
        """Test that session data survives encryption/decryption cycle"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # First request: create and encrypt session
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_create(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response1 = await middleware.dispatch(request1, call_next_create)

        # Extract encrypted session cookie
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None

        # Parse cookie value
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Second request: load and decrypt session
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_verify(req):
            # Verify all data is intact
            assert req.state.session["user_id"] == "user_123"
            assert req.state.session["tenant_id"] == "tenant_123"
            assert req.state.session["is_authenticated"] is True
            assert req.state.session["access_token"] == "access_token_123"
            return Response()

        await middleware.dispatch(request2, call_next_verify)

    @pytest.mark.asyncio
    async def test_decryption_with_wrong_key_fails_gracefully(self, secret_key, different_secret_key, encryptor):
        """Test that wrong decryption key doesn't crash, returns empty session"""
        # Encrypt with first key
        session_data = {"user_id": "test_user"}
        encrypted = encryptor.encrypt(session_data)

        # Try to decrypt with different key
        middleware = SessionMiddleware(app=Mock(), secret_key=different_secret_key)
        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={encrypted}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            # Should get empty session, not crash
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_corrupted_data_fails_gracefully(self, secret_key, encryptor):
        """Test that corrupted encrypted data doesn't crash"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Create valid encrypted session
        session_data = {"user_id": "test_user"}
        encrypted = encryptor.encrypt(session_data)

        # Corrupt by flipping some bits
        corrupted = encrypted[:20] + "CORRUPT" + encrypted[27:]

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={corrupted}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_truncated_data_fails_gracefully(self, secret_key, encryptor):
        """Test that truncated encrypted data doesn't crash"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        session_data = {"user_id": "test_user"}
        encrypted = encryptor.encrypt(session_data)

        # Truncate to half length
        truncated = encrypted[: len(encrypted) // 2]

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={truncated}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_malformed_base64_fails_gracefully(self, secret_key):
        """Test that invalid base64 data doesn't crash"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Invalid base64 characters
        invalid = "this is not base64!!!"

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={invalid}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_empty_json_after_decryption(self, secret_key, encryptor):
        """Test session with empty dict"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Encrypt empty dict
        encrypted = encryptor.encrypt({})

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={encrypted}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            assert len(req.state.session) == 0
            assert req.state.session.to_dict() == {}
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_complex_nested_data_encryption(self, secret_key):
        """Test encryption of complex nested structures"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_create(req):
            req.state.session["complex"] = {
                "nested": {
                    "lists": [1, 2, 3],
                    "dicts": {"key": "value"},
                    "mixed": [{"a": 1}, {"b": 2}],
                }
            }
            req.state.session.save()
            return Response()

        response1 = await middleware.dispatch(request1, call_next_create)

        # Extract cookie
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Reload and verify
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_verify(req):
            assert req.state.session["complex"]["nested"]["lists"] == [1, 2, 3]
            assert req.state.session["complex"]["nested"]["dicts"]["key"] == "value"
            return Response()

        await middleware.dispatch(request2, call_next_verify)

    @pytest.mark.asyncio
    async def test_unicode_data_encryption(self, secret_key):
        """Test encryption of unicode characters"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_create(req):
            req.state.session["unicode"] = "Hello 世界 🎉"
            req.state.session.save()
            return Response()

        response1 = await middleware.dispatch(request1, call_next_create)

        # Extract cookie
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Reload and verify
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_verify(req):
            assert req.state.session["unicode"] == "Hello 世界 🎉"
            return Response()

        await middleware.dispatch(request2, call_next_verify)


class TestSessionPersistence:
    """Test session persistence across requests"""

    @pytest.mark.asyncio
    async def test_full_lifecycle_create_persist_load(self, secret_key, callback_data):
        """Test complete lifecycle: create session, persist to cookie, load in new request"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Request 1: Create session
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_create(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response1 = await middleware.dispatch(request1, call_next_create)

        # Extract session cookie
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Load session
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_load(req):
            assert req.state.session["user_id"] == "user_123"
            assert req.state.session["is_authenticated"] is True
            return Response()

        await middleware.dispatch(request2, call_next_load)

    @pytest.mark.asyncio
    async def test_update_session_and_reload(self, secret_key):
        """Test updating session data persists to next request"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Request 1: Create and update session
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_create(req):
            req.state.session["user_id"] = "user_123"
            req.state.session["counter"] = 1
            req.state.session.save()
            return Response()

        response1 = await middleware.dispatch(request1, call_next_create)

        # Extract cookie
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Load and update
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_update(req):
            assert req.state.session["counter"] == 1
            req.state.session["counter"] = 2
            req.state.session.save()
            return Response()

        response2 = await middleware.dispatch(request2, call_next_update)

        # Extract updated cookie
        cookie_headers = [h[1].decode() for h in response2.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 3: Verify update
        request3 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_verify(req):
            assert req.state.session["counter"] == 2
            return Response()

        await middleware.dispatch(request3, call_next_verify)

    @pytest.mark.asyncio
    async def test_clear_session_and_verify_deleted(self, secret_key, callback_data):
        """Test clearing session removes data in next request"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Request 1: Create session
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_create(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response1 = await middleware.dispatch(request1, call_next_create)

        # Extract cookie
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Clear session
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_clear(req):
            assert req.state.session["user_id"] == "user_123"  # Still loaded
            req.state.session.clear()
            return Response()

        response2 = await middleware.dispatch(request2, call_next_clear)

        # Verify clear cookies set Max-Age=0
        cookie_headers = [h[1].decode() for h in response2.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie is not None
        assert "Max-Age=0" in session_cookie

        # Request 3: Verify empty session (cookie deleted by browser)
        request3 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_verify(req):
            assert len(req.state.session) == 0
            return Response()

        await middleware.dispatch(request3, call_next_verify)

    @pytest.mark.asyncio
    async def test_multiple_request_cycles(self, secret_key):
        """Test session persists correctly across many requests"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        session_cookie_value = None

        # Request 1: Create
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_1(req):
            req.state.session["value"] = 1
            req.state.session.save()
            return Response()

        response1 = await middleware.dispatch(request1, call_next_1)
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Increment
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_2(req):
            assert req.state.session["value"] == 1
            req.state.session["value"] = 2
            req.state.session.save()
            return Response()

        response2 = await middleware.dispatch(request2, call_next_2)
        cookie_headers = [h[1].decode() for h in response2.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 3: Increment again
        request3 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_3(req):
            assert req.state.session["value"] == 2
            req.state.session["value"] = 3
            req.state.session.save()
            return Response()

        response3 = await middleware.dispatch(request3, call_next_3)
        cookie_headers = [h[1].decode() for h in response3.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 4: Verify final value
        request4 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_4(req):
            assert req.state.session["value"] == 3
            return Response()

        await middleware.dispatch(request4, call_next_4)

    @pytest.mark.asyncio
    async def test_session_not_persisted_without_save(self, secret_key):
        """Test that modifications without save() don't persist"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Request 1: Modify without save
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_modify(req):
            req.state.session["user_id"] = "test"
            # Don't call save()
            return Response()

        response1 = await middleware.dispatch(request1, call_next_modify)

        # No cookies should be set
        cookie_headers = [h for h in response1.raw_headers if h[0] == b"set-cookie"]
        assert len(cookie_headers) == 0

    @pytest.mark.asyncio
    async def test_rolling_session_updates_expiry(self, secret_key, callback_data):
        """Test that calling save() refreshes cookie expiry (rolling sessions)"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Request 1: Create session
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_create(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response1 = await middleware.dispatch(request1, call_next_create)

        # Extract cookie
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Just call save() to roll the session
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_roll(req):
            # Just read and save, no modifications
            _ = req.state.session["user_id"]
            req.state.session.save()
            return Response()

        response2 = await middleware.dispatch(request2, call_next_roll)

        # Cookie should be set again (rolling the expiry)
        cookie_headers = [h[1].decode() for h in response2.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        assert "Max-Age=3600" in session_cookie_header


class TestSessionIntegration:
    """Integration tests combining multiple features"""

    @pytest.mark.asyncio
    async def test_full_auth_flow_from_callback(self, secret_key, callback_data):
        """Test complete authentication flow: callback -> create session -> persist -> reload -> verify"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key, enable_csrf_protection=False)

        # Request 1: Simulate callback handler creating session
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/callback"})

        async def call_next_callback(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response1 = await middleware.dispatch(request1, call_next_callback)

        # Verify session cookie was set (no CSRF when disabled)
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        has_session = any("session=" in h for h in cookie_headers)
        has_csrf = any("CSRF-TOKEN=" in h for h in cookie_headers)
        assert has_session
        assert not has_csrf

        # Extract session cookie
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Authenticated request using the session
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/api/protected",
            }
        )

        async def call_next_protected(req):
            # Verify all callback data is accessible
            assert req.state.session["is_authenticated"] is True
            assert req.state.session["user_id"] == "user_123"
            assert req.state.session["tenant_id"] == "tenant_123"
            assert req.state.session["access_token"] == "access_token_123"
            assert req.state.session["refresh_token"] == "refresh_token_123"
            # No CSRF token when protection disabled
            assert "csrf_token" not in req.state.session
            return Response()

        await middleware.dispatch(request2, call_next_protected)

    @pytest.mark.asyncio
    async def test_full_auth_flow_with_csrf_protection(self, secret_key, callback_data):
        """Test auth flow with CSRF protection enabled"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key, enable_csrf_protection=True)

        # Request 1: Simulate callback handler creating session
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/callback"})

        async def call_next_callback(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response1 = await middleware.dispatch(request1, call_next_callback)

        # Verify both cookies were set
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        has_session = any("session=" in h for h in cookie_headers)
        has_csrf = any("CSRF-TOKEN=" in h for h in cookie_headers)
        assert has_session
        assert has_csrf

        # Extract session cookie
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Verify CSRF token in session
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/api/protected",
            }
        )

        async def call_next_protected(req):
            # CSRF token should be present when protection enabled
            assert "csrf_token" in req.state.session
            assert isinstance(req.state.session["csrf_token"], str)
            assert len(req.state.session["csrf_token"]) > 0
            return Response()

        await middleware.dispatch(request2, call_next_protected)

    @pytest.mark.asyncio
    async def test_session_modification_across_requests(self, secret_key):
        """Test modifying session data across multiple requests"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Request 1: Initialize session with cart
        request1 = Request(scope={"type": "http", "headers": [], "method": "POST", "path": "/cart/add"})

        async def call_next_1(req):
            req.state.session["cart"] = [{"item": "apple", "qty": 1}]
            req.state.session.save()
            return Response()

        response1 = await middleware.dispatch(request1, call_next_1)
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Add to cart
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "POST",
                "path": "/cart/add",
            }
        )

        async def call_next_2(req):
            cart = req.state.session["cart"]
            cart.append({"item": "banana", "qty": 2})
            req.state.session["cart"] = cart
            req.state.session.save()
            return Response()

        response2 = await middleware.dispatch(request2, call_next_2)
        cookie_headers = [h[1].decode() for h in response2.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 3: Verify cart contents
        request3 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/cart",
            }
        )

        async def call_next_3(req):
            cart = req.state.session["cart"]
            assert len(cart) == 2
            assert cart[0]["item"] == "apple"
            assert cart[1]["item"] == "banana"
            return Response()

        await middleware.dispatch(request3, call_next_3)

    @pytest.mark.asyncio
    async def test_logout_flow(self, secret_key, callback_data):
        """Test complete logout flow: create session -> clear -> verify gone"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Request 1: Login
        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/login"})

        async def call_next_login(req):
            req.state.session.from_callback(callback_data)
            return Response()

        response1 = await middleware.dispatch(request1, call_next_login)
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Request 2: Use session
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/dashboard",
            }
        )

        async def call_next_dashboard(req):
            assert req.state.session["is_authenticated"] is True
            return Response()

        await middleware.dispatch(request2, call_next_dashboard)

        # Request 3: Logout
        request3 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "POST",
                "path": "/logout",
            }
        )

        async def call_next_logout(req):
            req.state.session.clear()
            return Response()

        response3 = await middleware.dispatch(request3, call_next_logout)

        # Verify session cookie is cleared
        cookie_headers = [h[1].decode() for h in response3.raw_headers if h[0] == b"set-cookie"]
        session_cookie = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie is not None
        assert "Max-Age=0" in session_cookie

        # Request 4: Verify no session (simulate browser deleting cookies)
        request4 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/dashboard"})

        async def call_next_after_logout(req):
            assert len(req.state.session) == 0
            assert req.state.session.get("is_authenticated") is None
            return Response()

        await middleware.dispatch(request4, call_next_after_logout)

    @pytest.mark.asyncio
    async def test_concurrent_session_isolation(self, secret_key):
        """Test that different requests have isolated sessions"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        # Request 1: User A
        request_a = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_a(req):
            req.state.session["user_id"] = "user_a"
            req.state.session.save()
            return Response()

        response_a = await middleware.dispatch(request_a, call_next_a)
        cookie_headers_a = [h[1].decode() for h in response_a.raw_headers if h[0] == b"set-cookie"]
        session_cookie_a = next((h for h in cookie_headers_a if "session=" in h), None)
        assert session_cookie_a is not None
        session_value_a = session_cookie_a.split(";")[0].split("=", 1)[1]

        # Request 2: User B
        request_b = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_b(req):
            req.state.session["user_id"] = "user_b"
            req.state.session.save()
            return Response()

        response_b = await middleware.dispatch(request_b, call_next_b)
        cookie_headers_b = [h[1].decode() for h in response_b.raw_headers if h[0] == b"set-cookie"]
        session_cookie_b = next((h for h in cookie_headers_b if "session=" in h), None)
        assert session_cookie_b is not None
        session_value_b = session_cookie_b.split(";")[0].split("=", 1)[1]

        # Verify sessions are different
        assert session_value_a != session_value_b

        # Verify User A's session
        request_a2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_value_a}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def verify_a(req):
            assert req.state.session["user_id"] == "user_a"
            return Response()

        await middleware.dispatch(request_a2, verify_a)

        # Verify User B's session
        request_b2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_value_b}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def verify_b(req):
            assert req.state.session["user_id"] == "user_b"
            return Response()

        await middleware.dispatch(request_b2, verify_b)

    @pytest.mark.asyncio
    async def test_session_with_custom_fields_persists(self, secret_key, callback_data):
        """Test that custom fields added during from_callback persist"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)

        request1 = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next_create(req):
            custom_fields = {
                "role": "admin",
                "preferences": {"theme": "dark", "language": "en"},
                "last_login": 1234567890,
            }
            req.state.session.from_callback(callback_data, custom_fields)
            return Response()

        response1 = await middleware.dispatch(request1, call_next_create)

        # Extract cookie
        cookie_headers = [h[1].decode() for h in response1.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        session_cookie_value = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Load and verify custom fields
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={session_cookie_value}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next_verify(req):
            assert req.state.session["role"] == "admin"
            assert req.state.session["preferences"]["theme"] == "dark"
            assert req.state.session["last_login"] == 1234567890
            # Core fields also present
            assert req.state.session["user_id"] == "user_123"
            return Response()

        await middleware.dispatch(request2, call_next_verify)


class TestKeyRotation:
    """Test session encryption with key rotation"""

    @pytest.mark.asyncio
    async def test_single_key_as_string(self, secret_key):
        """Test middleware works with single key as string"""
        middleware = SessionMiddleware(app=Mock(), secret_key=secret_key)
        assert middleware._encryptor is not None

    @pytest.mark.asyncio
    async def test_multiple_keys_as_list(self):
        """Test middleware accepts list of keys"""
        keys = ["a" * 32, "b" * 32, "c" * 32]
        middleware = SessionMiddleware(app=Mock(), secret_key=keys)
        assert middleware._encryptor is not None

    @pytest.mark.asyncio
    async def test_key_rotation_decrypts_old_sessions(self, encryptor):
        """Test that sessions encrypted with old key still decrypt with new key list"""
        old_key = "a" * 32
        new_key = "b" * 32

        # Encrypt session with old key
        old_encryptor = DataEncryptor(old_key)
        session_data = {"user_id": "test_user"}
        encrypted = old_encryptor.encrypt(session_data)

        # Middleware with key rotation (new key first, old key second)
        middleware = SessionMiddleware(app=Mock(), secret_key=[new_key, old_key])

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={encrypted}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            # Should decrypt successfully with old key
            assert req.state.session["user_id"] == "test_user"
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_key_rotation_decrypts_with_middle_key(self):
        """Test that sessions encrypted with middle key decrypt correctly"""
        key1 = "a" * 32
        key2 = "b" * 32
        key3 = "c" * 32

        # Encrypt session with middle key
        middle_encryptor = DataEncryptor(key2)
        session_data = {"user_id": "middle_user"}
        encrypted = middle_encryptor.encrypt(session_data)

        # Middleware with 3 keys - middle key should decrypt
        middleware = SessionMiddleware(app=Mock(), secret_key=[key1, key2, key3])

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"cookie", f"session={encrypted}".encode())],
                "method": "GET",
                "path": "/",
            }
        )

        async def call_next(req):
            # Should decrypt successfully with middle key
            assert req.state.session["user_id"] == "middle_user"
            return Response()

        await middleware.dispatch(request, call_next)

    @pytest.mark.asyncio
    async def test_new_sessions_encrypted_with_first_key(self):
        """Test that new sessions are encrypted with the first key in the list"""
        old_key = "a" * 32
        new_key = "b" * 32

        # Middleware with new key first
        middleware = SessionMiddleware(app=Mock(), secret_key=[new_key, old_key])

        request = Request(scope={"type": "http", "headers": [], "method": "GET", "path": "/"})

        async def call_next(req):
            req.state.session["user_id"] = "new_user"
            req.state.session.save()
            return Response()

        response = await middleware.dispatch(request, call_next)

        # Extract encrypted cookie
        cookie_headers = [h[1].decode() for h in response.raw_headers if h[0] == b"set-cookie"]
        session_cookie_header = next((h for h in cookie_headers if "session=" in h), None)
        assert session_cookie_header is not None
        encrypted = session_cookie_header.split(";")[0].split("=", 1)[1]

        # Should decrypt with new key only
        new_encryptor = DataEncryptor(new_key)
        decrypted = new_encryptor.decrypt(encrypted)
        assert decrypted["user_id"] == "new_user"

    def test_init_raises_with_empty_key_list(self):
        """Test that empty key list raises ValueError"""
        with pytest.raises(ValueError, match="secret_key is required"):
            SessionMiddleware(app=Mock(), secret_key=[])

    def test_init_raises_with_short_key_in_list(self):
        """Test that short key in list raises ValueError"""
        with pytest.raises(ValueError, match="at least 32 characters"):
            SessionMiddleware(app=Mock(), secret_key=["a" * 32, "short"])

    def test_init_raises_with_empty_string_in_list(self):
        """Test that empty string in key list raises ValueError"""
        with pytest.raises(ValueError, match="secret_key at index 1 cannot be empty"):
            SessionMiddleware(app=Mock(), secret_key=["a" * 32, ""])
