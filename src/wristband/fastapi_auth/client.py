import base64

import httpx

from .exception import InvalidGrantError, WristbandError
from .models import TokenResponse, UserInfo


class WristbandApiClient:
    def __init__(self, wristband_application_vanity_domain: str, client_id: str, client_secret: str) -> None:
        if not wristband_application_vanity_domain or not wristband_application_vanity_domain.strip():
            raise ValueError("Wristband application vanity domain is required")
        if not client_id or not client_id.strip():
            raise ValueError("Client ID is required")
        if not client_secret or not client_secret.strip():
            raise ValueError("Client secret is required")

        credentials: str = f"{client_id}:{client_secret}"
        encoded_credentials: str = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

        self.base_url: str = f'https://{wristband_application_vanity_domain}/api/v1'
        self.headers: dict[str, str] = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        self.client = httpx.AsyncClient()

    async def get_tokens(self, code: str, redirect_uri: str, code_verifier: str) -> TokenResponse:
        if not code or not code.strip():
            raise ValueError("Authorization code is required")
        if not redirect_uri or not redirect_uri.strip():
            raise ValueError("Redirect URI is required")
        if not code_verifier or not code_verifier.strip():
            raise ValueError("Code verifier is required")

        response: httpx.Response = await self.client.post(
            self.base_url + '/oauth2/token',
            headers=self.headers,
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
                'code_verifier': code_verifier,
            },
        )

        if response.status_code != 200:
            data = response.json()
            if data.get("error") == "invalid_grant":
                raise InvalidGrantError(data.get("error_description", "Invalid grant"))

            raise WristbandError(data.get("error", "unknown_error"), data.get("error_description", "Unknown error"))

        return TokenResponse.from_api_response(response.json())

    async def get_userinfo(self, access_token: str) -> UserInfo:
        response: httpx.Response = await self.client.get(
            self.base_url + '/oauth2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        return response.json()

    async def refresh_token(self, refresh_token: str) -> TokenResponse:
        response: httpx.Response = await self.client.post(
            self.base_url + '/oauth2/token',
            headers=self.headers,
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token
            },
        )

        if response.status_code != 200:
            data = response.json()
            if data.get("error") == "invalid_grant":
                raise InvalidGrantError(data.get("error_description", "Invalid grant"))

            # Raises for 4xx or 5xx
            response.raise_for_status()

        return TokenResponse.from_api_response(response.json())

    async def revoke_refresh_token(self, refresh_token: str) -> None:
        await self.client.post(
            self.base_url + '/oauth2/revoke',
            headers=self.headers,
            data={
                'token': refresh_token
            },
        )
