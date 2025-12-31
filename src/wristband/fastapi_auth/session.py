import json
import logging
from typing import Any, Dict, Iterator, Optional, cast

from fastapi import HTTPException, Request, Response, status

from .csrf import create_csrf_token, delete_csrf_cookie, update_csrf_cookie
from .models import CallbackData, SameSiteOption, Session, SessionResponse, TokenResponse
from .utils import DataEncryptor

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Internal class that handles session operations for a single request.

    This class is created per-request by SessionMiddleware and attached to request.state.
    It manages session state and coordinates persistence to encrypted cookies.

    All cookie operations are deferred until after route execution for optimal performance.

    Usage:
        # Get session value
        user_id = request.state.session.get('user_id')

        # Set session value
        request.state.session['user_id'] = "123"
        request.state.session.save()

        # Check if key exists
        if 'cart' in request.state.session:
            cart = request.state.session['cart']

        # Delete value
        del request.state.session['old_key']
    """

    _max_cookie_size = 4096  # RFC 6265 browser limit

    _encryptor: DataEncryptor
    _session_cookie_name: str
    _session_cookie_domain: Optional[str]
    _max_age: int
    _path: str
    _same_site: SameSiteOption
    _http_only: bool
    _secure: bool
    _enable_csrf_protection: bool
    _csrf_cookie_name: str
    _csrf_cookie_domain: Optional[str]
    _data: Dict[str, Any]
    _needs_clear: bool
    _needs_save: bool

    def __init__(
        self,
        encryptor: DataEncryptor,
        session_cookie_name: str,
        session_cookie_domain: Optional[str],
        max_age: int,
        path: str,
        same_site: SameSiteOption,
        secure: bool,
        enable_csrf_protection: bool,
        csrf_cookie_name: str,
        csrf_cookie_domain: Optional[str],
    ) -> None:
        # Set instance variables directly, bypassing __setattr__
        object.__setattr__(self, "_encryptor", encryptor)
        object.__setattr__(self, "_session_cookie_name", session_cookie_name)
        object.__setattr__(self, "_session_cookie_domain", session_cookie_domain)
        object.__setattr__(self, "_max_age", max_age)
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_same_site", same_site)
        object.__setattr__(self, "_http_only", True)
        object.__setattr__(self, "_secure", secure)
        object.__setattr__(self, "_enable_csrf_protection", enable_csrf_protection)
        object.__setattr__(self, "_csrf_cookie_name", csrf_cookie_name)
        object.__setattr__(self, "_csrf_cookie_domain", csrf_cookie_domain)
        object.__setattr__(self, "_data", {})
        object.__setattr__(self, "_needs_clear", False)
        object.__setattr__(self, "_needs_save", False)

    ####################################
    # INTERNAL METHODS
    ####################################

    def __getattr__(self, key: str) -> Any:
        """
        Allow attribute-style access to session data.

        Example:
            user_id = request.state.session.user_id
        """
        return self._data.get(key)

    def __setattr__(self, key: str, value: Any) -> None:
        """
        Allow attribute-style setting of session data.

        Example:
            request.state.session.user_id = "123"
        """
        # All session data goes through __setitem__ for validation
        self[key] = value

    def __getitem__(self, key: str) -> Any:
        """Get session value by key."""
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Set session value by key."""
        try:
            json.dumps(value)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Session value must be JSON serializable: {e}")

        self._data[key] = value

    def __delitem__(self, key: str) -> None:
        """Delete session value by key."""
        del self._data[key]

    def __contains__(self, key: str) -> bool:
        """Check if key exists in session."""
        return key in self._data

    def __len__(self) -> int:
        """Return number of items in session."""
        return len(self._data)

    def __iter__(self) -> Iterator[str]:
        """Iterate over session keys."""
        return iter(self._data)

    def _load_from_dict(self, data: Dict[str, Any]) -> None:
        """Load session data from dict (internal method used by middleware)."""
        object.__setattr__(self, "_data", data)

    def _persist(self, response: Response) -> None:
        """
        Internal method to apply deferred session operations to response.

        Called by middleware after route execution. Performs cookie operations
        exactly once per request based on what was requested during route execution.

        Args:
            response: The FastAPI Response object to attach cookies to.
        """
        if self._needs_clear:
            self._delete_cookies(response)
        elif self._needs_save:
            self._write_cookies(response)

    def _write_cookies(self, response: Response) -> None:
        """
        Internal method to write session and CSRF cookies to response.

        Args:
            response: The FastAPI Response object to attach cookies to.
        """
        encrypted_value = self._encryptor.encrypt(self._data)

        # Calculate overhead from cookie attributes
        # Format: name=value; Domain=X; Path=X; Secure; HttpOnly; SameSite=X; Max-Age=X
        overhead = len(self._session_cookie_name)
        overhead += len("=")
        overhead += len("; Path=") + len(self._path)
        overhead += len("; Secure; HttpOnly")
        overhead += len("; SameSite=") + len(self._same_site.value)
        overhead += len("; Max-Age=") + len(str(self._max_age))

        if self._session_cookie_domain:
            overhead += len("; Domain=") + len(self._session_cookie_domain)

        # Total cookie size
        total_size = len(encrypted_value) + overhead
        if total_size > self._max_cookie_size:
            raise ValueError(
                f"Session cookie exceeds browser limit: {total_size} bytes (max: {self._max_cookie_size}). "
                f"Encrypted data: {len(encrypted_value)} bytes, overhead: {overhead} bytes. "
                f"Reduce session data or use database-backed sessions."
            )

        # Update the session cookie
        response.set_cookie(
            key=self._session_cookie_name,
            value=encrypted_value,
            domain=self._session_cookie_domain,
            max_age=self._max_age,
            path=self._path,
            secure=self._secure,
            httponly=self._http_only,
            samesite=self._same_site.value,
        )

        # Only update CSRF cookie if protection is enabled
        if self._enable_csrf_protection:
            csrf_token = self._data.get("csrf_token")

            if csrf_token:
                update_csrf_cookie(
                    response=response,
                    cookie_name=self._csrf_cookie_name,
                    csrf_token=csrf_token,
                    domain=self._csrf_cookie_domain,
                    max_age=self._max_age,
                    path=self._path,
                    same_site=self._same_site.value,
                    secure=self._secure,
                )

    def _delete_cookies(self, response: Response) -> None:
        """
        Internal method to delete session and CSRF cookies from response.

        Args:
            response: The FastAPI Response object to clear cookies from.
        """
        # Delete the session cookie
        response.set_cookie(
            key=self._session_cookie_name,
            value="",
            domain=self._session_cookie_domain,
            max_age=0,
            path=self._path,
            secure=self._secure,
            httponly=self._http_only,
            samesite=self._same_site.value,
        )

        # Only delete CSRF cookie if protection is enabled
        if self._enable_csrf_protection:
            delete_csrf_cookie(
                response=response,
                cookie_name=self._csrf_cookie_name,
                domain=self._csrf_cookie_domain,
                path=self._path,
                same_site=self._same_site.value,
                secure=self._secure,
            )

    ####################################
    # PUBLIC METHODS
    ####################################

    def get(self, key: str, default: Any = None) -> Any:
        """Get session value with default."""
        return self._data.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        """
        Return a copy of session data as a dictionary.

        Returns:
            A shallow copy of the session data dict.

        Example:
            session_data = request.state.session.to_dict()
            return {"session": session_data}
        """
        return self._data.copy()

    def from_callback(self, callback_data: CallbackData, custom_fields: Optional[Dict[str, Any]] = None) -> None:
        """
        Create a new session from Wristband auth callback data.

        This is a convenience method that builds session state from authentication
        callback data, optionally merges custom fields, and automatically persists
        the session. It's intended to be called after successful authentication.

        Args:
            callback_data: Callback data containing tokens and user info.
            custom_fields: Optional dict of additional fields to store. All values must be JSON-serializable.

        Raises:
            ValueError: If `callback_data` is None, `user_info` is missing, or `custom_fields` aren't JSON-serializable.

        Example:
            # After successful callback
            callback_result = await wristband_auth.callback(request)

            custom_data = {
                "preferences": {"theme": "dark"},
                "role": "admin"
            }

            request.state.session.from_callback(
                callback_result.callback_data,
                custom_fields=custom_data
            )

        Fields persisted from callback data:
            - is_authenticated (set to True)
            - access_token
            - expires_at
            - user_id
            - tenant_id
            - tenant_name
            - identity_provider_name
            - refresh_token (if "offline_access" scope configured)
            - tenant_custom_domain (if provided during auth request)

        Note:
            - Session is persisted to cookies via save(), which defers until after route completes.
            - Custom fields are merged with core session fields
        """
        if callback_data is None:
            raise ValueError("callback_data is required to create a session")
        if not callback_data.user_info:
            raise ValueError("callback_data.user_info is required to create a session")

        # Build base session data from callback
        session_dict = {
            "is_authenticated": True,
            "access_token": callback_data.access_token,
            "expires_at": callback_data.expires_at,
            "user_id": callback_data.user_info.user_id,
            "tenant_id": callback_data.user_info.tenant_id,
            "tenant_name": callback_data.tenant_name,
            "identity_provider_name": callback_data.user_info.identity_provider_name,
        }

        # Only include optional fields if they have values
        if callback_data.refresh_token:
            session_dict["refresh_token"] = callback_data.refresh_token
        if callback_data.tenant_custom_domain:
            session_dict["tenant_custom_domain"] = callback_data.tenant_custom_domain

        # Add custom fields if provided
        if custom_fields:
            try:
                json.dumps(custom_fields)
                session_dict.update(custom_fields)
            except (TypeError, ValueError) as e:
                raise ValueError(f"Custom fields must be JSON serializable: {e}")

        object.__setattr__(self, "_data", session_dict)
        self.save()

    def save(self) -> None:
        """
        Mark session for persistence (rolling sessions).

        This marks the session to be saved, which causes the session cookie's
        expiry to be refreshed. The actual cookie write happens once after the
        route completes, even if save() is called multiple times.

        If enable_csrf_protection is True and no CSRF token exists in the session,
        a new token will be automatically generated and stored.

        Example:
            # Save after modifying session
            request.state.session['user_id'] = "123"
            request.state.session.save()

            # Or just extend session for authenticated users
            if request.state.session.get('is_authenticated'):
                request.state.session.save()
        """
        # Only add CSRF token if protection is enabled
        if self._enable_csrf_protection and "csrf_token" not in self._data:
            self._data["csrf_token"] = create_csrf_token()

        object.__setattr__(self, "_needs_save", True)

    def clear(self) -> None:
        """
        Delete the session and clear all cookies.

        Resets internal session to empty state and clears session cookie from the response.
        If enable_csrf_protection is True, also clears CSRF cookie.
        Use this when logging out users.

        Example:
            request.state.session.clear()
            return RedirectResponse("/login")
        """
        self._data.clear()  # Clear in-memory session
        object.__setattr__(self, "_needs_clear", True)
        object.__setattr__(self, "_needs_save", False)  # Clear takes precedence

    def get_session_response(self, metadata: Optional[Dict[str, Any]] = None) -> SessionResponse:
        """
        Create a SessionResponse for Wristband frontend SDKs.

        This method extracts tenant_id and user_id from the session and returns them
        in the format expected by Wristband's frontend SDKs.

        Args:
            metadata: Optional custom metadata to include. Must be JSON-serializable.
                    Defaults to an empty dict if not provided.

        Returns:
            SessionResponse containing tenant_id, user_id, and metadata.

        Raises:
            HTTPException: 401 if tenant_id or user_id are missing from session.

        Example:
            @router.get("/api/v1/session", dependencies=[Depends(require_session_auth)])
            async def get_session(request: Request) -> SessionResponse:
                return request.state.session.get_session_response(metadata={"foo": "bar"})
        """
        tenant_id = self._data.get("tenant_id")
        user_id = self._data.get("user_id")

        if not tenant_id or not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        session_metadata = metadata if metadata is not None else {}
        return SessionResponse(tenant_id=tenant_id, user_id=user_id, metadata=session_metadata)

    def get_token_response(self) -> TokenResponse:
        """
        Create a TokenResponse for Wristband frontend SDKs.

        This method extracts access_token and expires_at from the session and returns them
        in the format expected by Wristband's frontend SDKs.

        Returns:
            TokenResponse containing access_token and expires_at timestamp.

        Raises:
            HTTPException: 401 if access_token or expires_at are missing from session.

        Example:
            @router.get("/api/v1/token", dependencies=[Depends(require_session_auth)])
            async def get_token(request: Request) -> TokenResponse:
                return request.state.session.get_token_response()
        """
        access_token = self._data.get("access_token")
        expires_at = self._data.get("expires_at")

        if not access_token or not expires_at:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        return TokenResponse(access_token=access_token, expires_at=expires_at)


def get_session(request: Request) -> Session:
    """
    Get the typed session object from the request.

    This dependency provides type-safe access to the session without performing
    authentication checks. Use with router-level require_session_auth to avoid
    double-execution.

    Args:
        request: The FastAPI request object.

    Returns:
        The typed Session object.

    Raises:
        RuntimeError: If SessionMiddleware is not installed.

    Example:
        from wristband.fastapi_auth import get_session

        # Router-level auth
        router = APIRouter(dependencies=[Depends(require_session_auth)])

        @router.get("/profile")
        async def get_profile(session: Session = Depends(get_session)):
            user_id = session.user_id
            return {"userId": user_id}
    """
    if not hasattr(request.state, "session"):
        raise RuntimeError("Session not found. Ensure SessionMiddleware is registered in your app.")

    return cast(Session, request.state.session)
