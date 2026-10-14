import base64
import json
import re
from typing import Any, Dict, List, Optional, Union, cast
from urllib.parse import urljoin, urlsplit, urlunsplit

from cryptography.fernet import Fernet, MultiFernet

from .models import RawUserInfo, UserInfo

TENANT_NAME_PLACEHOLDER = "{tenant_name}"
TENANT_PLACEHOLDER_PATTERN = re.compile(r"\{tenant_name\}")
LEADING_TENANT_PLACEHOLDER_PATTERN = re.compile(r"^https?://\{tenant_name\}\.")
TENANT_PLACEHOLDER_MSG = '"{tenant_name}" placeholder'

# Browsers strip leading/trailing C0 control characters and spaces from URLs, and remove ASCII tabs and newlines
# anywhere in them. They also treat backslashes as forward slashes for http(s) URLs.
_URL_LEADING_TRAILING_STRIP = "".join(chr(c) for c in range(0x21))
_URL_TAB_OR_NEWLINE_PATTERN = re.compile(r"[\t\n\r]")


def map_userinfo_claims(raw: RawUserInfo) -> UserInfo:
    """
    Maps a RawUserInfo (OIDC claim names) to UserInfo (User entity field names).

    Args:
        raw: RawUserInfo object with OIDC claim names

    Returns:
        UserInfo object with User entity field names
    """
    return UserInfo(
        user_id=raw.sub,
        tenant_id=raw.tnt_id,
        application_id=raw.app_id,
        identity_provider_name=raw.idp_name,
        full_name=raw.name,
        given_name=raw.given_name,
        family_name=raw.family_name,
        middle_name=raw.middle_name,
        nickname=raw.nickname,
        display_name=raw.preferred_username,
        picture_url=raw.picture,
        email=raw.email,
        email_verified=raw.email_verified,
        gender=raw.gender,
        birthdate=raw.birthdate,
        time_zone=raw.zoneinfo,
        locale=raw.locale,
        phone_number=raw.phone_number,
        phone_number_verified=raw.phone_number_verified,
        updated_at=raw.updated_at,
        roles=raw.roles,
        custom_claims=raw.custom_claims,
    )


class DataEncryptor:
    """
    Provides encryption and decryption of data using Fernet symmetric encryption.

    This class is designed to securely encrypt data dictionaries into strings suitable
    for storage in cookies and to decrypt those strings back into dictionaries.

    Supports key rotation by accepting multiple keys. The first key is used for
    encryption, while all keys are tried for decryption (allowing old sessions
    to remain valid during key rotation).

    The secret key(s) must be at least 32 characters to ensure sufficient entropy.
    """

    cipher: Union[Fernet, MultiFernet]

    def __init__(self, secret_key: Union[str, List[str]]) -> None:
        """
        Initialize the DataEncryptor with secret key(s).

        Args:
            secret_key: A secret string or list of strings, each at least 32 characters.
                       If a list, the first key encrypts, all keys can decrypt (key rotation).

        Raises:
            ValueError: If no secret_key is provided, if any key is less than 32 characters,
                       or if the list is empty.
        """
        # Handle single key or list of keys
        keys = [secret_key] if isinstance(secret_key, str) else secret_key

        if not keys:
            raise ValueError("Data Encryptor: secret_key is required")

        # Validate and convert all keys to Fernet format
        fernet_keys: List[Fernet] = []
        for i, key in enumerate(keys):
            if not key:
                raise ValueError(f"Data Encryptor: secret_key at index {i} cannot be empty")
            if len(key) < 32:
                raise ValueError(f"Data Encryptor: secret_key at index {i} must be at least 32 characters long")

            # Convert string to proper Fernet key format (base64 urlsafe-encoded 32 bytes)
            key_bytes: bytes = key.encode("utf-8")[:32].ljust(32, b"\0")  # truncate to 32 bytes if longer
            fernet_key: bytes = base64.urlsafe_b64encode(key_bytes)
            fernet_keys.append(Fernet(fernet_key))

        # Use MultiFernet if multiple keys, otherwise single Fernet
        if len(fernet_keys) > 1:
            self.cipher = MultiFernet(fernet_keys)
        else:
            self.cipher = fernet_keys[0]

    def encrypt(self, data: Dict[str, Any]) -> str:
        """
        Encrypt a dictionary of data into a base64-encoded string.

        Uses the first key for encryption.

        Args:
            data (dict): The data dictionary to encrypt.

        Returns:
            str: The encrypted string representation suitable for use in cookies.

        Raises:
            TypeError: If the input data is not a dictionary.
        """
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary")

        json_data: bytes = json.dumps(data).encode()
        encrypted: bytes = self.cipher.encrypt(json_data)
        return encrypted.decode()

    def decrypt(self, encrypted_str: str, ttl: Optional[int] = None) -> Dict[str, Any]:
        """
        Decrypt an encrypted string back into a dictionary.

        Tries all configured keys for decryption (supports key rotation).

        Args:
            encrypted_str (str): The encrypted string to decrypt.
            ttl (int, optional): The max age of the encrypted string in seconds. When provided, decryption fails
                for strings encrypted longer ago than this.

        Returns:
            dict: The decrypted data dictionary.

        Raises:
            ValueError: If the input string is empty.
            cryptography.fernet.InvalidToken: If decryption fails with all keys.
            json.JSONDecodeError: If decrypted data is not valid JSON.
        """
        if not encrypted_str:
            raise ValueError("Empty encrypted string cannot be decrypted")

        decrypted_bytes: bytes = self.cipher.decrypt(encrypted_str.encode(), ttl=ttl)
        return cast(Dict[str, Any], json.loads(decrypted_bytes.decode()))


def derive_fallback_login_url(login_url: Optional[str]) -> str:
    """
    Derives the fallback login URL from a login URL that uses the {tenant_name} placeholder.

    The placeholder must be the leftmost part of the hostname, e.g. https://{tenant_name}.example.com/auth/login.
    The fallback login URL is the login URL with the placeholder removed, e.g. https://example.com/auth/login.

    Args:
        login_url: The application's login URL.

    Returns:
        The derived fallback login URL, or an empty string when the login URL has no placeholder.
    """
    if not login_url or not TENANT_PLACEHOLDER_PATTERN.search(login_url):
        return ""
    return login_url.replace(f"{TENANT_NAME_PLACEHOLDER}.", "", 1)


def derive_tenant_root_domain(login_url: Optional[str]) -> str:
    """
    Derives the root domain used for parsing tenant subdomains from a login URL that uses the {tenant_name}
    placeholder. The root domain is the hostname with the placeholder removed, without any port.

    Args:
        login_url: The application's login URL.

    Returns:
        The derived root domain (e.g. example.com), or an empty string when the login URL has no placeholder.
    """
    fallback_login_url = derive_fallback_login_url(login_url)
    return (urlsplit(fallback_login_url).hostname or "") if fallback_login_url else ""


def is_tenant_placeholder_position_valid(url: str) -> bool:
    """
    Checks that a URL containing the {tenant_name} placeholder has it exactly once, as the leftmost part of the
    hostname. URLs without the placeholder are always considered valid.

    Args:
        url: The URL to check.

    Returns:
        True if the placeholder is absent or correctly positioned.
    """
    if not TENANT_PLACEHOLDER_PATTERN.search(url):
        return True

    # Removing the leading placeholder should leave no other {tenant_name} anywhere in the URL.
    return bool(LEADING_TENANT_PLACEHOLDER_PATTERN.search(url)) and not TENANT_PLACEHOLDER_PATTERN.search(
        url.replace(f"{TENANT_NAME_PLACEHOLDER}.", "", 1)
    )


def validate_return_url(
    return_url: Optional[str],
    request_scheme: str,
    request_host: str,
    tenant_name: str,
    application_authorization_requests_enabled: bool,
    parse_tenant_from_root_domain: Optional[str] = None,
) -> Optional[str]:
    """
    Validates a user-supplied return URL to prevent open redirects. Without this, an attacker could craft a login
    link with return_url=https://evil.com so that a legitimate login ends with the user being sent to a site they
    don't control.

    Args:
        return_url: The return URL from the login state cookie.
        request_scheme: The scheme of the current request (e.g. "https").
        request_host: The host of the current request, including any port (e.g. "acme.example.com:8000").
        tenant_name: The resolved tenant name for the current callback request.
        application_authorization_requests_enabled: Whether app-level authorization requests are enabled.
        parse_tenant_from_root_domain: The root domain when tenant subdomains are in use, otherwise empty.

    Returns:
        The validated return URL, or None if it is missing, malformed, or points to a host that isn't allowed.
    """
    # Safety check: should never happen.
    if not tenant_name:
        raise ValueError("Tenant name is required to validate return_url")

    # Return URL is optional during login
    if not return_url:
        return None

    try:
        # Normalize the URL the same way a browser would before redirecting to it, so that tricks like
        # "/\\evil.com" or "/\t/evil.com" are checked against the real redirect target.
        normalized_url = _URL_TAB_OR_NEWLINE_PATTERN.sub("", return_url.strip(_URL_LEADING_TRAILING_STRIP))
        normalized_url = normalized_url.replace("\\", "/")

        # Resolve against the current request's origin so relative paths like "/settings" land on the
        # user's current host. Absolute URLs ignore the base.
        url = urlsplit(urljoin(f"{request_scheme}://{request_host}", normalized_url))
        url.port  # Raises ValueError for an invalid port
        url_hostname = url.hostname or ""
        request_hostname = (urlsplit(f"//{request_host}").hostname or "").lower()
        root_domain = (parse_tenant_from_root_domain or "").lower()

        # Only allow redirects to the root domain or the exact host that served this request, over the same
        # protocol. Anything else is treated as untrusted and discarded. The protocol check blocks downgrades
        # like https -> http.
        if url.scheme != request_scheme.lower() or not url_hostname:
            return None
        if url_hostname != request_hostname and (not root_domain or url_hostname != root_domain):
            return None

        if root_domain and application_authorization_requests_enabled and url_hostname == root_domain:
            # The return URL points at the bare root domain, but the app expects tenant subdomains. Prepend the
            # resolved tenant so the user lands on their tenant's host (e.g. myapp.com -> acme.myapp.com).
            # Path, query, fragment, and port are preserved.
            port = f":{url.port}" if url.port else ""
            return urlunsplit(url._replace(netloc=f"{tenant_name}.{url_hostname}{port}"))

        # Allowed host and no tenant rewrite needed. Return the URL unchanged unless normalization changed it,
        # in which case return the normalized absolute URL so the browser lands exactly where we validated.
        return return_url if normalized_url == return_url else urlunsplit(url)
    except ValueError:
        # urlsplit() raises on malformed input (e.g. an invalid port). Treat anything unparseable as unsafe.
        return None
