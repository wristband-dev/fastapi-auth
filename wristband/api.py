import base64
from typing import Any
import requests

from wristband.models import TokenResponse

class WristbandError(Exception):
    def __init__(self, error_code: str, error_description: str) -> None:
        self.error_code: str = error_code
        self.error_description: str = error_description
        super().__init__(f"{error_code}: {error_description}")


class Api:
    def __init__(self, wristband_application_vanity_domain: str, client_id: str, client_secret: str) -> None:
        credentials: str = f"{client_id}:{client_secret}"
        encoded_credentials: str = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        self.base_url: str = f'https://{wristband_application_vanity_domain}/api/v1'
        self.headers: dict[str, str] = { 
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def get_tokens(self, code: str, redirect_uri: str, code_verifier: str) -> TokenResponse:
        form_data: dict[str, str] = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'code_verifier': code_verifier,
        }

        response: requests.Response = requests.post(
            self.base_url + '/oauth2/token', 
            data=form_data,
            headers=self.headers
        )

        if response.status_code != 200:
            raise WristbandError(response.json()['error'], response.json()['error_description'])

        return TokenResponse.from_api_response(response.json())
    
    def revoke_refresh_token(self, refresh_token: str) -> None:
        form_data: dict[str, str] = {
            'token': refresh_token
        }

        requests.post(
            self.base_url + '/oauth2/revoke',
            data=form_data,
            headers=self.headers
        )

    def refresh_token(self, refresh_token: str) -> TokenResponse:
        form_data: dict[str, str] = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }

        response: requests.Response = requests.post(
            self.base_url + '/oauth2/token',
            data=form_data, 
            headers=self.headers
        )

        return TokenResponse.from_api_response(response.json())


    def get_userinfo(self, access_token: str) -> dict[str, Any]:

        response: requests.Response = requests.get(
            self.base_url + '/oauth2/userinfo',
            headers={ 'Authorization': f'Bearer {access_token}' }
        )

        return response.json()