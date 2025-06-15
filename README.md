<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> • 
      <a href="https://docs.wristband.dev/">Documentation</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Wristband Multi-Tenant Authentication SDK for FastAPI

This module facilitates seamless interaction with Wristband for user authentication within multi-tenant [FastAPI applications](https://fastapi.tiangolo.com). It follows OAuth 2.1 and OpenID standards.

Key functionalities encompass the following:

- Initiating a login request by redirecting to Wristband.
- Receiving callback requests from Wristband to complete a login request.
- Retrieving all necessary JWT tokens and userinfo to start an application session.
- Logging out a user from the application by revoking refresh tokens and redirecting to Wristband.
- Checking for expired access tokens and refreshing them automatically, if necessary.

You can learn more about how authentication works in Wristband in our documentation:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

---

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [1) Initialize the SDK](#1-initialize-the-sdk)
  - [2) Set Up Session Storage](#2-set-up-session-storage)
  - [3) Add Auth Endpoints](#3-add-auth-endpoints)
    - [Login Endpoint](#login-endpoint)
    - [Callback Endpoint](#callback-endpoint)
    - [Logout Endpoint](#logout-endpoint)
  - [4) Guard Your Non-Auth APIs and Handle Token Refresh](#4-guard-your-non-auth-apis-and-handle-token-refresh)
  - [5) Pass Your Access Token to Downstream APIs](#5-pass-your-access-token-to-downstream-apis)
- [Wristband Auth Configuration Options](#wristband-auth-configuration-options)
- [API](#api)
- [Questions](#questions)

<br/>

## Installation

**Install the package from PyPI**
```sh
pip install wristband-fastapi-auth
```

**Or if using poetry**
```sh
poetry add wristband-fastapi-auth
```

**Or if using pipenv**
```sh
pipenv install wristband-fastapi-auth
```

<br>

## Usage

### 1) Initialize the SDK
First, create an instance of `WristbandAuth` in your FastAPI project structure in any location of your choice (i.e. `src/auth/wristband_auth.py`). Then, you can import this instance and use it across your project. When creating an instance, you provide all necessary configurations for your application to correlate with how you've set it up in Wristband.

```python
# src/auth/wristband_auth.py
from wristband_fastapi_auth import WristbandAuth, AuthConfig

# Configure Wristband authentication; your config values may vary.
# You can generate a login state secret by running:
#
# > python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"
auth_config = AuthConfig(
    client_id="<your_client_id>",
    client_secret="<your_client_secret>",
    login_state_secret="<your-login-state-secret>",
    login_url="https://{tenant_domain}.yourapp.io/auth/login",
    redirect_uri="https://{tenant_domain}.yourapp.io/auth/callback",
    parse_tenant_from_root_domain="yourapp.io",
    is_application_custom_domain_active=True,
    wristband_application_vanity_domain="auth.yourapp.io",
)

# Initialize Wristband auth instance
wristband_auth = WristbandAuth(auth_config)
```

<br>

### 2) Set Up Session Storage

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. We typically recommend cookie-based sessions due to it being lighter-weight and not requiring a backend session store like Redis or other technologies. We are big fans of encrypted cookie-based sessions for this reason.

> [!NOTE]
> <ins>You can use a 3rd party library such as [starsessions](https://github.com/alex-oleshkevich/starsessions)</ins> for FastAPI applications that need server-side sessions with Redis or other backend stores.

You can borrow this example below to see how one might establish cookie-based session middleware to manage your application's session data using the SDK's `SessionEncryptor` utility:

#### a) Create a class for your session data
```python
# src/models/session_data.py
from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class SessionData:
    is_authenticated: bool = False
    access_token: str = ""
    expires_at: int = 0
    refresh_token: str | None = None
    user_id: str = ""
    tenant_id: str = ""
    idp_name: str = ""
    tenant_domain_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, str] = asdict(self)
        return data

    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'SessionData':
        return SessionData(**data)
    
    @staticmethod
    def empty() -> 'SessionData':
        return SessionData()
```

#### b) Create an encrypted session middleware
```python
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Literal, cast
import logging
from wristband.fastapi_auth import SessionEncryptor
from models.session_data import SessionData

__all__ = ['EncryptedSessionMiddleware']
logger = logging.getLogger(__name__)
SameSiteOptions = Literal["lax", "strict", "none"]

class _SessionManager:
    def __init__(
        self,
        encryptor: SessionEncryptor,
        cookie_name: str,
        max_age: int,
        path: str,
        same_site: SameSiteOptions,
        secure: bool
    ):
        self.encryptor = encryptor
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.path = path
        self.same_site: SameSiteOptions = same_site
        self.http_only = True
        self.secure = secure
        self._session_data: SessionData = SessionData.empty()
    
    def get(self) -> SessionData:
        return self._session_data
    
    def set_data(self, session_data: SessionData) -> None:
        self._session_data = session_data
    
    def update(self, response: Response, session_data: SessionData) -> None:
        self._session_data = session_data
        encrypted_value = self.encryptor.encrypt(session_data.to_dict())
        response.set_cookie(
            key=self.cookie_name,
            value=encrypted_value,
            max_age=self.max_age,
            path=self.path,
            secure=self.secure,
            httponly=self.http_only,
            samesite=self.same_site
        )
    
    def delete(self, response: Response) -> None:
        self._session_data = SessionData.empty()
        response.set_cookie(
            key=self.cookie_name,
            value='',
            max_age=0,
            path=self.path,
            secure=self.secure,
            httponly=self.http_only,
            samesite=self.same_site
        )

class EncryptedSessionMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        cookie_name: str = "session",
        secret_key: str = "",
        max_age: int = 1800,
        path: str = "/",
        same_site: Literal["lax", "strict", "none"] = "lax",
        secure: bool = True,
    ):
        super().__init__(app)
        if not secret_key:
            raise ValueError("secret_key is required for session encryption")
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.path = path
        self.same_site: SameSiteOptions = same_site
        self.secure = secure
        self.encryptor = SessionEncryptor(secret_key)
    
    async def dispatch(self, request: Request, call_next) -> Response:
        session_manager = _SessionManager(
            encryptor=self.encryptor,
            cookie_name=self.cookie_name,
            max_age=self.max_age,
            path=self.path,
            same_site=self.same_site,
            secure=self.secure
        )

        try:
            session_cookie = request.cookies.get(self.cookie_name)
            if session_cookie:
                session_data_dict = self.encryptor.decrypt(session_cookie)
                session_data = SessionData.from_dict(session_data_dict)
                session_manager.set_data(session_data)
            else:
                session_manager.set_data(SessionData.empty())
        except Exception as e:
            logger.error(f"Failed to decrypt session cookie: {str(e)}")
            session_manager.set_data(SessionData.empty())

        request.state.session = cast(_SessionManager, session_manager)
        response = await call_next(request)
        return response
```

#### c) Add the middleware your FastAPI app
```python
# src/run.py
from fastapi import FastAPI
import logging
import uvicorn
from middleware.session_middleware import EncryptedSessionMiddleware
from routes import router

def create_app() -> FastAPI:
    app = FastAPI()

    # ...

    # Add session middleware.
    # You can generate a secret key by running:
    #
    # > python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"
    app.add_middleware(
        EncryptedSessionMiddleware,
        cookie_name="session",
        secret_key="<your-secret-key>",
        max_age=1800,  # 30 minutes
        path="/",
        same_site="lax",
        secure=True,  # Set to True in production
    )
    
    # API routes
    app.include_router(router)
    return app

# Uvicorn
app = create_app()
if __name__ == '__main__':
    uvicorn.run("run:app", host="localhost", port=6001, reload=True)
```

<br>

### 3) Add Auth Endpoints

There are <ins>three core API endpoints</ins> your FastAPI server should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to wherever your FastAPI routes are.

#### Login Endpoint

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```python
# src/routes/routes.py
from datetime import datetime, timedelta
from fastapi import APIRouter, Request
from fastapi.responses import Response
from wristband.fastapi_auth import CallbackResult, CallbackData, LogoutConfig, CallbackResultType
from auth.wristband import wristband_auth
from models.session_data import SessionData

router = APIRouter()

# Login Endpoint - Route path can be whatever you prefer
@router.get('/api/auth/login')
async def login(request: Request) -> Response:
    resp: Response = await wristband_auth.login(req=request)
    return resp

# ...
```

<br>

#### Callback Endpoint

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```python
# src/routes/routes.py

# ...

@router.get('/api/auth/callback')
async def callback(request: Request) -> Response:
    callback_result: CallbackResult = await wristband_auth.callback(req=request)

    # For certain edge cases, the SDK will require you to redirect back to login.
    if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
        return await wristband_auth.create_callback_response(request, callback_result.redirect_url)
    
    # Create session data for the authenticated user
    callback_data: CallbackData = callback_result.callback_data
    session_data: SessionData = SessionData(
        is_authenticated=True,
        access_token=callback_data.access_token,
        # Convert the "expiresIn" seconds into milliseconds from the epoch.
        expires_at=int((datetime.now() + timedelta(seconds=callback_data.expires_in)).timestamp() * 1000),
        refresh_token=callback_data.refresh_token or None,
        user_id=callback_data.user_info['sub'],
        tenant_id=callback_data.user_info['tnt_id'],
        idp_name=callback_data.user_info['idp_name'],
        tenant_domain_name=callback_data.tenant_domain_name,
    )

    # Create the callback response that sets the session cookie.
    response: Response = await wristband_auth._create_callback_response(request, "http://yourapp.io/home")
    request.state.session.update(response, session_data)
    return response

# ...
```

#### Logout Endpoint

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).


```python
# src/routes/routes.py

# ...

@router.get('/api/auth/logout')
def logout(request: Request) -> Response:
    session_data: SessionData = request.state.session.get()

    # Delete the session cookie and redirect to the Wristband Logout Endpoint.
    response: Response = await wristband_auth.logout(
        req=request,
        config=LogoutConfig(
            refresh_token=session_data.refresh_token if session_data else None,
            tenant_custom_domain=session_data.tenant_custom_domain if session_data else None,
            tenant_domain_name=session_data.tenant_domain_name if session_data else None,
        )
    )
    request.state.session.delete(response)
    return response

# ...
```

<br>

### 4) Guard Your Non-Auth APIs and Handle Token Refresh

> [!NOTE]
> There may be applications that do not want to utilize access tokens and/or refresh tokens. If that applies to your application, then you can ignore using the `refresh_token_if_expired()` functionality.

Create an auth middleware somewhere in your project to check that your session is still valid. It must check if the access token is expired and perform a token refresh if necessary. The Wristband SDK will make 3 attempts to refresh the token and return the latest JWTs to your server.

```python
# src/middleware/auth_middleware.py
from datetime import datetime, timedelta
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
import logging
from wristband.fastapi_auth import TokenData
from auth.wristband import wristband_auth
from models.session_data import SessionData

logger = logging.getLogger(__name__)

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path: str = request.url.path

        # -> Skip authentication for any public routes <-
        # You can add any other routes that makes sense for your app.
        if path.startswith("/api/auth/"):
            return await call_next(request)

        # Validate the user's authenticated session
        session_data: SessionData = request.state.session.get()
        if not session_data.is_authenticated:
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)

        try:
            # Check if token is expired and refresh if necessary
            new_token_data: TokenData | None = await wristband_auth.refresh_token_if_expired(
                session_data.refresh_token,
                session_data.expires_at
            )
            if new_token_data:
                # Update session with new token data
                session_data.access_token = new_token_data.access_token
                session_data.refresh_token = new_token_data.refresh_token
                session_data.expires_at = int(
                    (datetime.now() + timedelta(seconds=new_token_data.expires_in))
                    .timestamp() * 1000
                )

            # "Touch" the session cookie. Saves new token data if refresh occured.
            response: Response = await call_next(request)
            request.state.session.update(response, session_data)
            return response
        except Exception as e:
            logger.exception(f"Auth middleware error during token refresh: {str(e)}")
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)
```

Now add your auth middleware to your FastAPI application.

```python
# src/run.py
from fastapi import FastAPI
import logging
import uvicorn
from middleware.auth_middleware import AuthMiddleware
from middleware.session_middleware import EncryptedSessionMiddleware
from routes import router

def create_app() -> FastAPI:
    app = FastAPI()

    # Add the auth middleware to the app.
    # IMPORTANT: Middleware gets invoked in REVERSE order, so auth must come here
    # before the session middleware, otherwise it won't have access to the session.
    app.add_middleware(AuthMiddleware)

    # session middleware
    app.add_middleware(
        EncryptedSessionMiddleware,
        cookie_name="session",
        secret_key="<your-secret-key>",
        max_age=1800,  # 30 minutes
        path="/",
        same_site="lax",
        secure=True,  # Set to True in production
    )
    
    # API routes
    app.include_router(router)
    return app

app = create_app()
if __name__ == '__main__':
    uvicorn.run("run:app", host="localhost", port=6001, reload=True)
```

<br>

### 5) Pass Your Access Token to Downstream APIs

> [!NOTE]
> This is only applicable if you wish to call Wristband's APIs directly or protect your application's other downstream backend APIs.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```
Authorization: Bearer <access_token_value>
```

For example, if you were using Axios to make API calls to other services, you would pass the access token from your application session into the `Authorization` header as follows:

```python
# src/routes/routes.py
import httpx

# ...

client = httpx.AsyncClient()

@router.post('/api/nickname')
async def generate_new_nickname(request: Request) -> Response:
    try:
        session_data: SessionData = request.state.session.get()
        
        # Update User API - https://docs.wristband.dev/reference/patchuserv1
        response: httpx.Response = await client.patch(
            f'https://{'<your-wristband-app-vanity-domain>'}/api/v1/users/{session_data.user_id}',
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {session_data.access_token}'
            },
            json={
                'nickname': 'Smooth Criminal'
            },
        )
        
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
```

<br>

## Wristband Auth Configuration Options

The `WristbandAuth()` constructor is used to instantiate the Wristband SDK. It takes an `AuthConfig` type as an argument.

```python
def __init__(self, auth_config: AuthConfig) -> None:
```

| AuthConfig Field | Type | Required | Description |
| ---------------- | ---- | -------- | ----------- |
| client_id | str | Yes | The ID of the Wristband client. |
| client_secret | str | Yes | The client's secret. |
| custom_application_login_page_url | Optional[str] | No | Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value only needs to be provided if you are self-hosting the application login page. By default, the SDK will use your Wristband-hosted Application-Level Login page URL. If this value is provided, the SDK will redirect to this URL in certain cases where it cannot resolve a proper Tenant-Level Login URL. |
| dangerously_disable_secure_cookies | bool | No | USE WITH CAUTION: If set to `True`, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development environments that don't have HTTPS enabed.  If not provided, this value defaults to `False`. |
| is_application_custom_domain_active | bool | No | Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `default_tenant_custom_domain` config.  Defaults to `False`. |
| login_state_secret | str | Yes | A 32 byte (or longer) secret used for encryption and decryption of login state cookies. You can run `python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"` to create a secret from your CLI. |
| login_url | str | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow. If you intend to use tenant subdomains in your Login Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/login`. |
| parse_tenant_from_root_domain | str | Only if using tenant subdomains in your application | The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `default_tenant_custom_domain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL. |
| redirect_uri | str | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint. If you intend to use tenant subdomains in your Callback Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/callback`. |
| scopes | List[str] | No | The scopes required for authentication. Refer to the docs for [currently supported scopes](https://docs.wristband.dev/docs/oauth2-and-openid-connect-oidc#supported-openid-scopes). The default value is `["openid", "offline_access", "email"]`. |
| wristband_application_vanity_domain | str | Yes | The vanity domain of the Wristband application. |

## API

### `async def login(self, req: Request, config: LoginConfig = LoginConfig()) -> Response:`

```python
response: Response = await wristband_auth.login(req=request)
```

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When the frontend of your application redirects the user to your FastAPI Login Endpoint, there are two ways to accomplish getting the `tenant_domain_name` information: passing a query parameter or using tenant subdomains.

The `login()` method can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| custom_state | Optional[dict[str, Any]] | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| default_tenant_domain_name | str | No | An optional default tenant domain name to use for the login request in the event the tenant domain cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| default_tenant_custom_domain | str | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |

#### Which Domains Are Used in the Authorize URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if `parse_tenant_from_root_domain` is specified and there is a subdomain present in the host.
3. `tenant_domain` query parameter: Evaluated if no tenant subdomain is found in the host.
4. `default_tenant_custom_domain` in LoginConfig: Used if none of the above are present.
5. `default_tenant_domain` in LoginConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Tenant Domain Query Param

If your application does not wish to utilize subdomains for each tenant, you can pass the `tenant_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_domain=customer01
```

Your AuthConfig would look like the following when creating an SDK instance without any subdomains:

```python
auth_config = AuthConfig(
   client_id="ic6saso5hzdvbnof3bwgccejxy",
   client_secret="30e9977124b13037d035be10d727806f",
   login_state_secret="7ffdbecc-ab7d-4134-9307-2dfcc52f7475",
   login_url="https://yourapp.io/auth/login",
   redirect_uri="https://yourapp.io/auth/callback",
   wristband_application_vanity_domain="yourapp-yourcompany.us.wristband.dev",
)
```

#### Tenant Subdomains

If your application wishes to utilize tenant subdomains, then you do not need to pass a query param when redirecting to your FastAPI Login Endpoint. The SDK will parse the tenant subdomain from the host in order to make the redirection to the Wristband Authorize Endpoint. You will also need to tell the SDK what your application's root domain is in order for it to correctly parse the subdomain.

```sh
GET https://customer01.yourapp.io/auth/login
```

Your AuthConfig would look like the following when creating an SDK instance when using subdomains:

```python
auth_config = AuthConfig(
    client_id="ic6saso5hzdvbnof3bwgccejxy",
    client_secret="30e9977124b13037d035be10d727806f",
    login_state_secret="7ffdbecc-ab7d-4134-9307-2dfcc52f7475",
    login_url="https://{tenant_domain}.yourapp.io/auth/login",
    redirect_uri="https://{tenant_domain}.yourapp.io/auth/callback",
    parse_tenant_from_root_domain="yourapp.io",
    wristband_application_vanity_domain="yourapp-yourcompany.us.wristband.dev",
)
```

#### Default Tenant Domain Name

For certain use cases, it may be useful to specify a default tenant domain in the event that the `login()` method cannot find a tenant domain in either the query parameters or in the URL subdomain. You can specify a fallback default tenant domain via a `LoginConfig` object:

```python
response: Response = await wristband_auth.login(
    req=request, 
    config=LoginConfig(default_tenant_domain_name="default")
)
```

#### Tenant Custom Domain Query Param

If your application wishes to utilize tenant custom domains, you can pass the `tenant_custom_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_custom_domain=mytenant.com
```

The tenant custom domain takes precedence over all other possible domains else when present.

#### Default Tenant Custom Domain

For certain use cases, it may be useful to specify a default tenant custom domain in the event that the `login()` method cannot find a tenant custom domain in the query parameters. You can specify a fallback default tenant custom domain via a `LoginConfig` object:

```python
response: Response = await wristband_auth.login(
    req=request, 
    config=LoginConfig(default_tenant_custom_domain="mytenant.com")
)
```

The default tenant custom domain takes precedence over all other possible domain configurations when present except for the case where the `tenant_custom_domain` query parameter exists in the request.

#### Custom State

Before your Login Endpoint redirects to Wristband, it will create a Login State Cookie to cache all necessary data required in the Callback Endpoint to complete any auth requests. You can inject additional state into that cookie via a `LoginConfig` object:

```python
response: Response = await wristband_auth.login(
    req=request, 
    config=LoginConfig(custom_state={"test": "abc"})
)
```

> [!WARNING]
> Injecting custom state is an advanced feature, and it is recommended to use `custom_state` sparingly. Most applications may not need it at all. The max cookie size is 4kB. From our own tests, passing a `custom_state` JSON of at most 1kB should be a safe ceiling.

#### Login Hints

Wristband will redirect to your FastAPI Login Endpoint for workflows like Application-Level Login (Tenant Discovery) and can pass the `login_hint` query parameter as part of the redirect request:

```sh
GET https://customer01.yourapp.io/auth/login?login_hint=user@wristband.dev
```

If Wristband passes this parameter, it will be appended as part of the redirect request to the Wristband Authorize Endpoint. Typically, the email form field on the Tenant-Level Login page is pre-filled when a user has previously entered their email on the Application-Level Login Page.

#### Return URLs

It is possible that users will try to access a location within your application that is not some default landing page. In those cases, they would expect to immediately land back at that desired location after logging in.  This is a better experience for the user, especially in cases where they have application URLs bookmarked for convenience.  Given that your frontend will redirect users to your FastAPI Login Endpoint, you can pass a `return_url` query parameter when redirecting to your Login Endpoint, and that URL will be available to you upon completion of the Callback Endpoint.

```sh
GET https://customer01.yourapp.io/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and you can choose to send users to that return URL (if necessary) after the SDK's `callback()` method is done executing.

### `async def callback(self, req: Request) -> CallbackResult:`

```python
callback_result: CallbackResult = await wristband_auth.callback(req=request)
response: Response = await wristband_auth.create_callback_response(request, redirect_url="https://yourapp.io/home")
```

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your FastAPI Callback Endpoint with an authorization code which can be used to exchange for an access token. It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration. The return type of the callback method is a CallbackResult type containing the result of what happened during callback execution as well as any accompanying data:

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| callback_data | `CallbackData` | The callback data received after authentication (`COMPLETED` result only). |
| redirect_url | str | A URL that you need to redirect to (`REDIRECT_REQUIRED` result only). For some edge cases, the SDK will require a redirect to restart the login flow. |
| type | `CallbackResultType`  | Enum representing the type of the callback result. |

The following are the possible `CallbackResultType` enum values that can be returned from the callback execution:

| CallbackResultType  | Description |
| ------------------- | ----------- |
| `COMPLETED`  | Indicates that the callback is successfully completed and data is available for creating a session. |
| `REDIRECT_REQUIRED`  | Indicates that a redirect to the login endpoint is required. |

When the callback returns a `COMPLETED` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application. The `CallbackData` is defined as follows:


| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| access_token | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| custom_state | Optional[dict[str, Any]] | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| expires_in | int | The durtaion from the current time until the access token is expired (in seconds). |
| id_token | str | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refresh_token | Optional[str] | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| return_url | Optional[str] | The URL to return to after authentication is completed. |
| tenant_custom_domain | Optional[str] | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenant_domain_name | str | The domain name of the tenant the user belongs to. |
| user_info | dict[str, Any] | Data for the current user retrieved from the Wristband Userinfo Endpoint. The data returned in this object follows the format laid out in the [Wristband Userinfo Endpoint documentation](https://docs.wristband.dev/reference/userinfov1). The exact fields that get returned are based on the scopes you configured in the SDK. |


#### Redirect Responses

There are certain scenarios where a redirect URL is returned by the SDK. The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of where the user gets redirected to in these scenarios depends on if the application is using tenant subdomains and if the SDK is able to determine which tenant the user is currently attempting to log in to. The resolution happens in the following order:

1. If the tenant domain can be determined, then the user will get redirected back to your FastAPI Login Endpoint.
2. Otherwise, the user will be sent to the Wristband-hosted Tenant-Level Login Page URL.

For the case of the `COMPLETED` result type, there is a second method called `createCallbackResponse()` you must use to create the appropriate redirect response to your application's destination URL while ensuring the proper response headers are set.

```python
const appUrl = callback_result.callback_data.returnUrl or 'https://yourapp.io/home'
response: Response = await wristband_auth.create_callback_response(req, appUrl)
```

#### Error Parameters

Certain edge cases are possible where Wristband encounters an error during the processing of an auth request. These are the following query parameters that are sent for those cases to your Callback Endpoint:

| Query Parameter | Description |
| --------------- | ----------- |
| error | Indicates an error that occurred during the Login Workflow. |
| error_description | A human-readable description or explanation of the error to help diagnose and resolve issues more effectively. |

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&error=login_required&error_description=User%20must%20re-authenticate%20because%20the%20specified%20max_age%20value%20has%20elapsed
```

The error types that get automatically resolved in the SDK are:

| Error | Description |
| ----- | ----------- |
| login_required | Indicates that the user needs to log in to continue. This error can occur in scenarios where the user's session has expired, the user is not currently authenticated, or Wristband requires the user to explicitly log in again for security reasons. |

For all other error types, the SDK will throw a `WristbandError` object (containing the error and description) that your application can catch and handle. Most errors come from SDK configuration issues during development that should be addressed before release to production.


### `async def logout(self, req: Request, config: LogoutConfig = LogoutConfig()) -> Response:`

```python
response: Response = await wristband_auth.logout(
    req=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
return response
```

When users of your application are ready to log out or their application session expires, your frontend should redirect the user to your FastAPI Logout Endpoint.

```sh
GET https://customer01.yourapp.io/auth/logout
```

If your application created a session, it should destroy it before invoking the `logout()` method.  This method can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ------------------ | ---- | -------- | ----------- |
| redirect_url | Optional[str] | No | Optional URL that Wristband will redirect to after the logout operation has completed. This will also take precedence over the `custom_application_login_page_url` (if specified) in the SDK AuthConfig if the tenant domain cannot be determined when attempting to redirect to the Wristband Logout Endpoint. |
| refresh_token | Optional[str] | No | The refresh token to revoke. |
| tenant_custom_domain | Optional[str] | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenant_domain_name | Optional[str] | No | The domain name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your login endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `tenant_custom_domain` in LogoutConfig: If provided, this takes top priority.
2. `tenant_domain_name` in LogoutConfig: This takes the next priority if `tenant_custom_domain` is not present.
3. `tenant_custom_domain` query parameter: Evaluated if present and there is also no LogoutConfig provided for either `tenant_custom_domain` or `tenant_domain_name`.
4. Tenant subdomain in the URL: Used if none of the above are present, and `parse_tenant_from_root_domain` is specified, and the subdomain is present in the host.
5. `tenant_domain` query parameter: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `logout()` method, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domain Names

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you can either explicitly pass it into the LogoutConfig:

```python
response: Response = await wristband_auth.logout(
    req=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_domain_name="customer01"
    )
)
```

...or you can alternatively pass the `tenant_domain` query parameter in your redirect request to Logout Endpoint:

```python
# Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_domain=customer01"
response: Response = await wristband_auth.logout(
    req=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
```

If your application uses tenant subdomains, then passing the `tenant_domain_name` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL as long as the `parse_tenant_from_root_domain` SDK config is set.

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you can either explicitly pass it into the LogoutConfig:

```python
response: Response = await wristband_auth.logout(
    req=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_custom_domain="customer01.com"
    )
)
```

...or you can alternatively pass the `tenant_custom_domain` query parameter in your redirect request to Logout Endpoint:

```python
# Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_custom_domain=customer01.com"
response: Response = await wristband_auth.logout(
    req=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then you should consider passing both the tenant domain names and tenant custom domains (either via LogoutConfig or by query parameters) to ensure all use cases are handled by the SDK.

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `redirect_url` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```python
response: Response = await wristband_auth.logout(
    req=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_domain_name="customer01",
        redirect_url="https://custom-logout.com"
    )
)
```

### `async def refresh_token_if_expired(self, refresh_token: Optional[str], expires_at: Optional[int]) -> TokenData | None:`

```python
token_data: TokenData | None = await wristband_auth.refresh_token_if_expired(
    refresh_token="98yht308hf902hc90wh09",
    expires_at=1710707503788
)
```

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| expires_at | int | Yes | Unix timestamp in milliseconds at which the token expires. |
| refresh_token | str | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If the `refresh_token_if_expired()` method finds that your token has not expired yet, it will return `null` as the value, which means your auth middleware can simply continue forward as usual.

<br>

## Wristband Multi-Tenant FastAPI Demo App

You can check out the [Wristband FastAPI demo app](https://github.com/wristband-dev/fastapi-demo-app) to see this SDK in action. Refer to that GitHub repository for more information.

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
