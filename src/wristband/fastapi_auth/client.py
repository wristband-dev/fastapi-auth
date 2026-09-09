import base64
from typing import Optional, Tuple

import httpx

from .exceptions import InvalidGrantError, WristbandError
from .models import RawUserInfo, SdkConfiguration, UserInfo, ValidateTenantCustomDomainResponse, WristbandTokenResponse
from .retry import with_retry
from .utils import map_userinfo_claims


def _parse_error_body(response: httpx.Response) -> Tuple[str, Optional[str]]:
    """
    Safely extracts an OAuth-style error code and description from an error response body.

    Falls back to a generic error code and no description if the body isn't valid JSON
    (e.g. a plain-text or HTML error page from a proxy/CDN) so that error handling never
    raises a JSON decoding error of its own -- otherwise a 4xx with a non-JSON body would
    surface as an unrelated exception instead of a WristbandError/InvalidGrantError, and
    the retry logic in retry.py would misread it as a transient failure and retry it.

    Callers are responsible for applying a context-appropriate default when the
    description comes back empty (e.g. "Invalid grant" vs "Unknown error").
    """
    try:
        data = response.json()
        return data.get("error", "unknown_error"), data.get("error_description")
    except Exception:
        return "unknown_error", None


class WristbandApiClient:
    def __init__(self, wristband_application_vanity_domain: str, client_id: str, client_secret: str) -> None:
        if not wristband_application_vanity_domain or not wristband_application_vanity_domain.strip():
            raise ValueError("Wristband application vanity domain is required")
        if not client_id or not client_id.strip():
            raise ValueError("Client ID is required")
        if not client_secret or not client_secret.strip():
            raise ValueError("Client secret is required")

        credentials: str = f"{client_id}:{client_secret}"
        encoded_credentials: str = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

        self.client_id = client_id
        self._base_url: str = f"https://{wristband_application_vanity_domain}/api/v1"
        self._basic_auth_headers: dict[str, str] = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self._json_headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        self.client = httpx.AsyncClient()

    async def get_sdk_configuration(self) -> SdkConfiguration:
        """
        Retrieves the SDK configuration from Wristband's SDK Auto-Configuration Endpoint.

        Automatically retries on transient failures (5xx responses, network errors).

        Returns:
            SdkConfiguration: The SDK configuration containing auto-configurable values.

        Raises:
            WristbandError: If the request fails or returns an error response.
        """

        async def _do_request() -> httpx.Response:
            response: httpx.Response = await self.client.get(
                f"{self._base_url}/clients/{self.client_id}/sdk-configuration",
                headers=self._json_headers,
            )
            response.raise_for_status()
            return response

        try:
            response = await with_retry(_do_request)
            return SdkConfiguration.from_api_response(response.json())
        except Exception as e:
            raise WristbandError("unexpected_error", str(e))

    async def get_tokens(self, code: str, redirect_uri: str, code_verifier: str) -> WristbandTokenResponse:
        """
        Automatically retries on transient failures (5xx responses, network errors).
        4xx errors (including invalid_grant) are never retried.
        """
        if not code or not code.strip():
            raise ValueError("Authorization code is required")
        if not redirect_uri or not redirect_uri.strip():
            raise ValueError("Redirect URI is required")
        if not code_verifier or not code_verifier.strip():
            raise ValueError("Code verifier is required")

        async def _do_request() -> httpx.Response:
            response: httpx.Response = await self.client.post(
                self._base_url + "/oauth2/token",
                headers=self._basic_auth_headers,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": code_verifier,
                },
            )
            if response.status_code >= 500:
                response.raise_for_status()
            return response

        try:
            response = await with_retry(_do_request)
        except httpx.HTTPStatusError as e:
            # Retries were exhausted on a persistent 5xx -- fall through to the same
            # error-body handling used for any other non-200 response.
            response = e.response

        if response.status_code != 200:
            error_code, error_description = _parse_error_body(response)
            if error_code == "invalid_grant":
                raise InvalidGrantError(error_description or "Invalid grant")
            raise WristbandError(error_code, error_description or "Unknown error", status_code=response.status_code)

        return WristbandTokenResponse.from_api_response(response.json())

    async def get_userinfo(self, access_token: str) -> UserInfo:
        """
        Automatically retries on transient failures (5xx responses, network errors).
        """

        async def _do_request() -> httpx.Response:
            response: httpx.Response = await self.client.get(
                self._base_url + "/oauth2/userinfo", headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            return response

        try:
            response = await with_retry(_do_request)
            raw_userinfo: RawUserInfo = RawUserInfo(**response.json())
            userinfo: UserInfo = map_userinfo_claims(raw_userinfo)
            return userinfo
        except Exception as e:
            raise WristbandError("unexpected_error", str(e))

    async def refresh_token(self, refresh_token: str) -> WristbandTokenResponse:
        """
        Automatically retries on transient failures (5xx responses, network errors).
        4xx errors (including invalid_grant) are never retried.
        """

        async def _do_request() -> httpx.Response:
            response: httpx.Response = await self.client.post(
                self._base_url + "/oauth2/token",
                headers=self._basic_auth_headers,
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
            if response.status_code >= 500:
                response.raise_for_status()
            return response

        try:
            response = await with_retry(_do_request)
        except httpx.HTTPStatusError as e:
            response = e.response

        if response.status_code != 200:
            error_code, error_description = _parse_error_body(response)
            if error_code == "invalid_grant":
                raise InvalidGrantError(error_description or "Invalid grant")
            raise WristbandError(error_code, error_description or "Unknown error", status_code=response.status_code)

        return WristbandTokenResponse.from_api_response(response.json())

    async def revoke_refresh_token(self, refresh_token: str) -> None:
        """
        Automatically retries on transient failures (5xx responses, network errors).
        Callers are expected to treat revocation failures as non-fatal (e.g. during
        logout), so errors are simply raised after retries are exhausted rather than
        mapped to a specific exception type.
        """

        async def _do_request() -> httpx.Response:
            response: httpx.Response = await self.client.post(
                self._base_url + "/oauth2/revoke",
                headers=self._basic_auth_headers,
                data={"token": refresh_token},
            )
            response.raise_for_status()
            return response

        await with_retry(_do_request)

    async def validate_tenant_custom_domain(self, tenant_custom_domain: str) -> bool:
        """
        Validates that a tenant custom domain is verified and belongs to your Wristband
        application. Automatically retries on transient failures (5xx responses, network
        errors).

        Args:
            tenant_custom_domain: The tenant custom domain to validate.

        Returns:
            True if the tenant custom domain is verified and belongs to your application.

        Raises:
            ValueError: When tenant_custom_domain is missing or empty.
            WristbandError: If the request fails or returns an error response.
        """
        if not tenant_custom_domain or not tenant_custom_domain.strip():
            raise ValueError("Tenant custom domain is required")

        async def _do_request() -> httpx.Response:
            response: httpx.Response = await self.client.post(
                self._base_url + "/custom-domains/validate",
                headers=self._json_headers,
                json={"tenantCustomDomain": tenant_custom_domain},
            )
            response.raise_for_status()
            return response

        response = await with_retry(_do_request)
        return ValidateTenantCustomDomainResponse.from_api_response(response.json()).valid
