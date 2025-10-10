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

Enterprise-ready authentication for multi-tenant [FastAPI applications](https://fastapi.tiangolo.com) using OAuth 2.1 and OpenID Connect standards.

<br>

## Overview

This SDK provides complete authentication integration with Wristband, including:

- **Login flow** - Redirect to Wristband and handle OAuth callbacks
- **Session management** - Encrypted cookie-based sessions with CSRF protection
- **Token handling** - Automatic access token refresh and validation
- **Logout flow** - Token revocation and session cleanup
- **Multi-tenancy** - Support for tenant subdomains and custom domains

Learn more about Wristband's authentication patterns:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

<br>

---

<br>

## Table of Contents

- [Requirements](#requirements)
- [Migrating From Older SDK Versions](#migrating-from-older-sdk-versions)
- [Installation](#installation)
- [Usage](#usage)
  - [1) Initialize the SDK](#1-initialize-the-sdk)
  - [2) Set Up Session Middleware](#2-set-up-session-middleware)
  - [3) Add Auth Endpoints](#3-add-auth-endpoints)
    - [Login Endpoint](#login-endpoint)
    - [Callback Endpoint](#callback-endpoint)
    - [Logout Endpoint](#logout-endpoint)
    - [Session Endpoint](#session-endpoint)
    - [Token Endpoint (Optional)](#token-endpoint-optional)
  - [4) Guard Your Protected APIs and Handle Token Refresh](#4-guard-your-protected-apis-and-handle-token-refresh)
  - [5) Pass Your Access Token to Downstream APIs](#5-pass-your-access-token-to-downstream-apis)
- [Auth Configuration Options](#auth-configuration-options)
  - [WristbandAuth()](#wristbandauth)
  - [WristbandAuth.discover()](#wristbandauthdiscover)
- [Auth API](#auth-api)
  - [login()](#login)
  - [callback()](#callback)
  - [create_callback_response()](#create_callback_response)
  - [logout()](#logout)
  - [refresh_token_if_expired()](#refresh_token_if_expired)
- [Session Management](#session-management)
  - [Session Configuration](#session-configuration)
  - [The Session Object](#the-session-object)
  - [Session Dependencies](#session-dependencies)
    - [require_session_auth (created by create_session_auth_dependency())](#require_session_auth-created-by-create_session_auth_dependency)
    - [get_session](#get_session)
  - [Session Access Patterns](#session-access-patterns)
  - [Session API](#session-api)
    - [session.get()](#sessiongetkey-defaultnone)
    - [session.to_dict()](#sessionto_dict)
    - [session.from_callback()](#sessionfrom_callbackcallback_data-custom_fieldsnone)
    - [session.save()](#sessionsave)
    - [session.clear()](#sessionclear)
    - [session.get_session_response()](#sessionget_session_responsemetadatanone)
    - [session.get_token_response()](#sessionget_token_response)
  - [CSRF Protection](#csrf-protection)
- [Debug Logging](#debug-logging)
- [JWT Token Validation](#jwt-token-validation)
- [Demo Application](#wristband-multi-tenant-fastapi-demo-app)
- [Questions](#questions)

<br>

---

<br>

## Getting Started

Follow the [Wristband Auth Quick Start Guides](https://docs.wristband.dev/docs/auth-quick-start) for step-by-step integration instructions.

<br/>

## Requirements

This SDK is designed to work for Python version 3.9+ and FastAPI version 0.100.0+.

<br/>

## Migrating From Older SDK Versions

On an older version of our SDK? Check out our migration guide:

- [Instructions for migrating to Version 1.x](migration/v1/README.md)

<br>

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

Create an instance of the SDK to use across your project. This centralizes all authentication configuration and provides the core SDK instance across your FastAPI application.

<br>

#### SDK Instance

Create a `WristbandAuth` instance in a central location (e.g., `src/auth/wristband.py`):

```python
# src/auth/wristband.py
from wristband_fastapi_auth import WristbandAuth, AuthConfig

# Configure Wristband authentication
auth_config = AuthConfig(
    client_id="<your_client_id>",
    client_secret="<your_client_secret>",
    wristband_application_vanity_domain="<your_wristband_app_vanity_domain>",
)

# Initialize Wristband auth instance
wristband_auth = WristbandAuth(auth_config)
```

<br>

#### Session Auth Dependency

In the same file, you'll also create a reusable dependency for protecting authenticated routes in FastAPI.

```python
# src/auth/wristband.py (continued)

# ...

# Creates a dependency that validates sessions, handles CSRF protection,
# and automatically refreshes expired tokens.
require_session_auth = wristband_auth.create_session_auth_dependency()

# Export for use across your application
__all__ = ["wristband_auth", "require_session_auth"]
```

<br>

### 2) Set Up Session Middleware

This SDK is unopinionated about session management after authentication. For convenience, we provide encrypted cookie-based sessions: a lightweight approach that requires no backend infrastructure like Redis or databases.

> [!NOTE]
> For applications requiring server-side session storage, consider [starsessions](https://github.com/alex-oleshkevich/starsessions), which supports Redis and other backends.

Add the SDK's `SessionMiddleware` to your FastAPI application:

```python
# src/main.py
import logging
import uvicorn
from fastapi import FastAPI
from routes.auth_routes import router as auth_router
from wristband.fastapi_auth import SessionMiddleware


def create_app() -> FastAPI:
    app = FastAPI()

    # ...

    # Add session middleware.
    # You can generate a secret key by running:
    # > python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"
    app.add_middleware(SessionMiddleware, secret_key="<your-secret>")
    
    # Include auth routes - path prefix can be whatever you prefer.
    app.include_router(auth_router, prefix="/api/auth")

    return app

# Uvicorn
app = create_app()
if __name__ == '__main__':
    uvicorn.run("run:app", host="localhost", port=6001, reload=True)
```

Once configured, the middleware automatically attaches a session object to every request at `request.state.session`. You can read and write session data using dictionary-style access (`request.state.session["key"]`), attribute access (`request.state.session.key`), or helper methods like `get()`, `save()`, and `clear()`. All session modifications are automatically encrypted and persisted to cookies after your route handler completes.

<br>

### 3) Add Auth Endpoints

There are <ins>four core API endpoints</ins> your FastAPI server should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to wherever your FastAPI routes are.

<br>

#### Login Endpoint

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```python
# src/routes/auth_routes.py
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from wristband.fastapi_auth import (
    CallbackResult,
    CallbackResultType,
    get_session,
    LogoutConfig,
    Session,
    SessionResponse,
    TokenResponse
)

from auth.wristband import require_session_auth, wristband_auth

router = APIRouter()

# Login Endpoint - Route path can be whatever you prefer
@router.get('/login')
async def login(request: Request) -> Response:
    # Construct the authorize request URL and redirect to the Wristband Authorize Endpoint
    return await wristband_auth.login(request)

# ...
```

<br>

#### Callback Endpoint

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

**Make sure to use the `get_session` dependency to get access to the user's session!**

```python
# src/routes/auth_routes.py (continued)

# ...

# Callback Endpoint - Route path can be whatever you prefer
@router.get('/callback')
async def callback(request: Request, session: Session = Depends(get_session)) -> Response:
    # Get the result of the callback
    callback_result: CallbackResult = await wristband_auth.callback(request)

    # For certain edge cases, the SDK will require you to redirect back to login.
    if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
        assert callback_result.redirect_url is not None
        return await wristband_auth.create_callback_response(request, callback_result.redirect_url)

    # Create a session for the authenticated user in FastAPI.
    assert callback_result.callback_data is not None
    session.from_callback(callback_result.callback_data)

    # Return the callback response that redirects to your app.
    return await wristband_auth.create_callback_response(request, "http://yourapp.io/home")

# ...
```

#### Logout Endpoint

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).

**Make sure to use the `get_session` dependency to get access to the user's session!**

```python
# src/routes/auth_routes.py (continued)

# ...

# Logout Endpoint - Route path can be whatever you prefer
@router.get('/logout')
def logout(request: Request, session: Session = Depends(get_session)) -> Response:
    # Get all the necessary session data needed to perform the logout operation.
    logout_config = LogoutConfig(
        refresh_token=session.refresh_token,
        tenant_custom_domain=session.tenant_custom_domain,
        tenant_name=session.tenant_name,
    )

    # Clear the user's session in FastAPI.
    session.clear()

    # Return the redirect response that send the user to the Wristband Logout Endpoint.
    return await wristband_auth.logout(request, logout_config)

# ...
```

<br>

#### Session Endpoint

> [!NOTE]
> This endpoint is required for Wristband frontend SDKs to function. For more details, see the [Wristband Session Management documentation](https://docs.wristband.dev/docs/session-management-backend-server).

Wristband frontend SDKs require a Session Endpoint in your backend to verify authentication status and retrieve session metadata. Create a protected session endpoint that uses `get_session_response()` to return the session response format expected by Wristband's frontend SDKs. The response model will always have a `user_id` and a `tenant_id` in it. You can include any additional data for your frontend by customizing the `metadata` parameter (optional), which requires JSON-serializable values.

**Make sure to protect this endpoint using the `require_session_auth` dependency you created!**

```python
# src/routes/auth_routes.py (continued)

# ...

# Session Endpoint - Route path can be whatever you prefer
# Inject the "require_session_auth" dependency to make this a protected endpoint.
@router.get("/session")
async def get_session_response(session: Session = Depends(require_session_auth)) -> SessionResponse:
    try:
        return session.get_session_response(metadata={ "foo": "bar" })
    except Exception as e:
        logger.exception(f"Session endpoint error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
```

The Session Endpoint returns a `SessionResponse` model to your frontend:

```json
{
  "tenantId": "tenant_abc123",
  "userId": "user_xyz789",
  "metadata": {
    "foo": "bar",
    // Any other optional data you provide...
  }
}
```

<br>

#### Token Endpoint (Optional)

> [!NOTE]
> This endpoint is required when your frontend needs to make authenticated API requests directly to Wristband or other protected services. For more details, see the [Wristband documentation on using access tokens from the frontend](https://docs.wristband.dev/docs/authenticating-api-requests-with-bearer-tokens#using-access-tokens-from-the-frontend).
>
> If your application doesn't need frontend access to tokens (e.g., all API calls go through your backend), you can skip this endpoint.

Some applications require the frontend to make direct API calls to Wristband or other protected services using the user's access token. The Token Endpoint provides a secure way for your frontend to retrieve the current access token and its expiration time without exposing it in the session cookie or in browser storage.

Create a protected token endpoint that uses `get_token_response()` to return the token data expected by Wristband's frontend SDKs.

**Make sure to protect this endpoint using the `require_session_auth` dependency you created!**

```python
# src/routes/auth_routes.py (continued)

# ...

# Token Endpoint - Route path can be whatever you prefer
# Inject the "require_session_auth" dependency to make this a protected endpoint.
@router.get("/token")
async def get_token_response(session: Session = Depends(require_session_auth)) -> TokenResponse:
    try:
        return session.get_token_response()
    except Exception as e:
        logger.exception(f"Token endpoint error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
```

The Token Endpoint returns a `TokenResponse` model to your frontend:

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": 1735689600000
}
```

Your frontend can then use the `accessToken` in the Authorization header when making API requests:

```typescript
const tokenResponse = await fetch('/api/auth/token');
const { accessToken } = await tokenResponse.json();

// Use token to call Wristband API
const userResponse = await fetch('https://<your-wristband-app-vanity_domain>/api/v1/users/123', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});
```

<br>

### 4) Guard Your Protected APIs and Handle Token Refresh

> [!NOTE]
> If you only need JWT validation without the full authenticated session flow, check out the standalone [Wristband python-jwt](https://github.com/wristband-dev/python-jwt) library.

The SDK provides `create_session_auth_dependency()` (as shown in the [Initialize the SDK](#1-initialize-the-sdk) section) which returns a reusable FastAPI Dependency that:

- Validates the user's authenticated session
- Checks CSRF tokens to prevent [cross-site request forgery](https://docs.wristband.dev/docs/csrf-protection-for-backend-servers) attacks
- Automatically refreshes expired access tokens
- Updates session cookies with new token data when refresh occurs

You can apply it to protect any route necessary, much like the Session Endpoint or Token Endpoint.

```python
# Example Usage
from fastapi import APIRouter, Depends
from auth.wristband import require_session_auth

router = APIRouter()

# Router-level protection
protected_router = APIRouter(dependencies=[Depends(require_session_auth)])

# ...or...

# Endpoint-level protection with implicit session access via request.state
@router.get("/protected", dependencies=[Depends(require_session_auth)])
async def protected_endpoint(request: Request):
    return {"message": f"Hello, {request.state.session.user_id}"}

# ...or...

# Endpoint-level protection with explicit, typed Session injection
@router.get("/protected")
async def protected_endpoint(session: Session = Depends(require_session_auth)):
    return {"message": f"Hello, {session.user_id}"}
```

<br>

### 5) Pass Your Access Token to Downstream APIs

> [!NOTE]
> This is only applicable if you wish to call Wristband's APIs directly or protect your application's other downstream backend APIs.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```
Authorization: Bearer <access_token_value>
```

For example, if you were making API calls to other services, you would pass the access token from your application session into the `Authorization` header as follows:

```python
# src/routes/example_routes.py
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from wristband.fastapi_auth import Session
from auth.wristband import require_session_auth

router = APIRouter()
client = httpx.AsyncClient()

@router.post("/api/nickname", status_code=status.HTTP_204_NO_CONTENT)
async def update_nickname(session: Session = Depends(require_session_auth)):
    try:
        # Update User API: https://docs.wristband.dev/reference/patchuserv1
        response: httpx.Response = await client.patch(
            f"https://<your-wristband-app-vanity-domain>/api/v1/users/{session.user_id}",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                # Add access token to Authorization header
                "Authorization": f"Bearer {session.access_token}",
            },
            json={"nickname": "Smooth Criminal"},
        )

        response.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
```

<br>

## Auth Configuration Options

The `WristbandAuth()` constructor is used to instantiate the Wristband SDK. It takes an `AuthConfig` type as an argument.

```python
def __init__(self, auth_config: AuthConfig) -> None:
```

| AuthConfig Field | Type | Required | Auto-Configurable | Description |
| ---------------- | ---- | -------- | ----------------- | ----------- |
| auto_configure_enabled | bool | No | _N/A_ | Flag that tells the SDK to automatically set some of the SDK configuration values by calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default. When disabled, if manual configurations are not provided, then an error will be thrown. |
| client_id | str | Yes | No | The ID of the Wristband client. |
| client_secret | str | Yes | No | The client's secret. |
| custom_application_login_page_url | Optional[str] | No | Yes | Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value only needs to be provided if you are self-hosting the application login page. By default, the SDK will use your Wristband-hosted Application-Level Login page URL. If this value is provided, the SDK will redirect to this URL in certain cases where it cannot resolve a proper Tenant-Level Login URL. |
| dangerously_disable_secure_cookies | bool | No | No | USE WITH CAUTION: If set to `True`, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development environments that don't have HTTPS enabed.  If not provided, this value defaults to `False`. |
| is_application_custom_domain_active | Optional[bool] | No | Yes | Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `default_tenant_custom_domain` config.  Defaults to `False`. |
| login_state_secret | Optional[str] | No | No | A 32 character (or longer) secret used for encryption and decryption of login state cookies. If not provided, it will default to using the client secret. For enhanced security, it is recommended to provide a value that is unique from the client secret. You can run `python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"` to create a secret from your CLI. |
| login_url | Optional[str] | Only when `auto_configure_enabled` is set to `False` | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow. If you intend to use tenant subdomains in your Login Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/login`. |
| parse_tenant_from_root_domain | Optional[str] | Only if using tenant subdomains in your application | Yes | The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `default_tenant_custom_domain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL. |
| redirect_uri | Optional[str] | Only when `auto_configure_enabled` is set to `False` | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint. If you intend to use tenant subdomains in your Callback Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/callback`. |
| scopes | List[str] | No | No | The scopes required for authentication. Refer to the docs for [currently supported scopes](https://docs.wristband.dev/docs/oauth2-and-openid-connect-oidc#supported-openid-scopes). The default value is `["openid", "offline_access", "email"]`. |
| token_expiration_buffer | int | No | No | Buffer time (in seconds) to subtract from the access token’s expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls. Defaults to 60 seconds. |
| wristband_application_vanity_domain | str | Yes | No | The vanity domain of the Wristband application. |

<br>

### `WristbandAuth()`

```ts
wristband_auth: WristbandAuth = WristbandAuth(auth_config: AuthConfig)
```

This constructor creates an instance of `WristbandAuth` using lazy auto-configuration. Auto-configuration is enabled by default and will fetch any missing configuration values from the Wristband SDK Configuration Endpoint when any auth function is first called (i.e. `login`, `callback`, etc.). Set `auto_configure_enabled` to `False` disable to prevent the SDK from making an API request to the Wristband SDK Configuration Endpoint. In the event auto-configuration is disabled, you must manually configure all required values. Manual configuration values take precedence over auto-configured values.

| Method | When Config is Fetched | Use When |
| ------ | ---------------------- | -------- |
| WristbandAuth() (default) | Lazily, on first auth method call (login, callback, etc.) | Standard usage - allows your app to start without waiting for config |
| WristbandAuth.discover() | Eagerly, immediately when called | You want to fail fast at startup if auto-config is unavailable |

**Minimal config with auto-configure (default behavior)**
```python
wristband_auth: WristbandAuth = WristbandAuth(AuthConfig(
    client_id="your-client-id",
    client_secret="your-client-secret",
    wristband_application_vanity_domain="auth.yourapp.io"
))
```

**Manual override with partial auto-configure for some fields**
```python
wristband_auth: WristbandAuth = WristbandAuth(AuthConfig(
    client_id="your-client-id",
    client_secret="your-client-secret",
    wristband_application_vanity_domain="auth.yourapp.io",
    login_url="https://yourapp.io/auth/login",  # Manually override "login_url"
    # "redirect_uri" will be auto-configured
))
```

**Auto-configure disabled**
```python
wristband_auth: WristbandAuth = WristbandAuth(AuthConfig(
    auto_configure_enabled=False,
    client_id="your-client-id",
    client_secret="your-client-secret",
    wristband_application_vanity_domain="auth.custom.com",
    # Must manually configure non-auto-configurable fields
    is_application_custom_domain_active=True,
    login_url="https://{tenant_domain}.custom.com/auth/login",
    redirect_uri="https://{tenant_domain}.custom.com/auth/callback",
    parse_tenant_from_root_domain="custom.com",
))
```

<br>

### `WristbandAuth.discover()`

This method performs eager auto-configuration on an existing `WristbandAuth` instance. Unlike the default lazy auto-configuration behavior, this method immediately fetches and resolves all auto-configuration values from the Wristband SDK Configuration Endpoint during the call. This is useful when you want to fail fast if auto-configuration is unavailable, or when you need configuration values resolved before making any auth method calls. Manual configuration values take precedence over auto-configured values.

> [!WARNING]
> NOTE: This method can only be called when `auto_configure_enabled` is `True`. If auto-configuration is disabled, a `WristbandError` will be raised.

**Eager auto-configure with error handling**
```python
try:
    wristband_auth: WristbandAuth = WristbandAuth(AuthConfig(
        client_id="your-client-id",
        client_secret="your-client-secret",
        wristband_application_vanity_domain="auth.yourapp.io"
    ))
    
    await wristband_auth.discover()
    
    #
    # ...Configuration is now resolved and validated...
    #
except WristbandError as error:
    print(f'Auto-configuration failed: {error.error_description}')
```

<br>

## Auth API

### login()

```python
async def login(self, request: Request, config: LoginConfig = LoginConfig()) -> Response:
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | Request | Yes | The FastAPI request object. |
| config | LoginConfig | No | Optional configuration if your application needs custom behavior. |

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When the frontend of your application redirects the user to your FastAPI Login Endpoint, there are two ways to accomplish getting the `tenant_name` information: passing a query parameter or using tenant subdomains.

```python
response: Response = await wristband_auth.login(request)
```

The `login()` method can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| custom_state | Optional[dict[str, Any]] | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| default_tenant_name | str | No | An optional default tenant name to use for the login request in the event the tenant name cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| default_tenant_custom_domain | str | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |
| return_url | str | No | The URL to return to after authentication is completed. If a value is provided, then it takes precedence over the `return_url` request query parameter. |

#### Which Domains Are Used in the Authorize URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if `parse_tenant_from_root_domain` is specified and there is a subdomain present in the host.
3. `tenant_domain` query parameter: Evaluated if no tenant subdomain is found in the host.
4. `default_tenant_custom_domain` in LoginConfig: Used if none of the above are present.
5. `default_tenant_name` in LoginConfig: Used as the final fallback.

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

#### Default Tenant Name

For certain use cases, it may be useful to specify a default tenant name in the event that the `login()` method cannot find a tenant name in either the query parameters or in the URL subdomain. You can specify a fallback default tenant name via a `LoginConfig` object:

```python
response: Response = await wristband_auth.login(
    request=request, 
    config=LoginConfig(default_tenant_name="default")
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
    request=request, 
    config=LoginConfig(default_tenant_custom_domain="mytenant.com")
)
```

The default tenant custom domain takes precedence over all other possible domain configurations when present except for the case where the `tenant_custom_domain` query parameter exists in the request.

#### Custom State

Before your Login Endpoint redirects to Wristband, it will create a Login State Cookie to cache all necessary data required in the Callback Endpoint to complete any auth requests. You can inject additional state into that cookie via a `LoginConfig` object:

```python
response: Response = await wristband_auth.login(
    request=request, 
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

It is possible that users will try to access a location within your application that is not some default landing page. In those cases, they would expect to immediately land back at that desired location after logging in.  This is a better experience for the user, especially in cases where they have application URLs bookmarked for convenience.

Given that your frontend will redirect users to your Login Endpoint, you can either include it in your Login Config:

```python
response: Response = await wristband_auth.login(
    request=request, 
    config=LoginConfig(return_url="test")
)
```

...or you can pass a `return_url` query parameter when redirecting to your Login Endpoint:

```sh
GET https://customer01.yourapp.io/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and it is available to you in your Callback Endpoint after the SDK's `callback()` method is done executing. You can choose to send users to that return URL (if necessary). The Login Config takes precedence over the query parameter in the event a value is provided for both.

##### Return URL Preservation During Tenant Discovery

When the `login()` method cannot resolve a tenant domain from the request (subdomain, query parameters, or defaults), the SDK redirects users to the Application-Level Login (Tenant Discovery) Page. To ensure a seamless user experience, any provided return URL values are automatically preserved by appending them to the `state` query parameter. This allows the return URL to be propagated back to the Login Endpoint once tenant discovery is complete, ensuring users land at their originally intended destination after authentication.

<br>

### callback()

```python
async def callback(self, request: Request) -> CallbackResult:
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | Request | Yes | The FastAPI request object. |

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your FastAPI Callback Endpoint with an authorization code which can be used to exchange for an access token.

```python
callback_result: CallbackResult = await wristband_auth.callback(request)
```

It will also pass the state parameter that was generated during the Login Endpoint.

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
| access_token | str | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| custom_state | Optional[dict[str, Any]] | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| expires_at | int | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| expires_in | int | The durtaion from the current time until the access token is expired (in seconds). The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| id_token | str | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refresh_token | Optional[str] | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| return_url | Optional[str] | The URL to return to after authentication is completed. |
| tenant_custom_domain | Optional[str] | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenant_name | str | The name of the tenant the user belongs to. |
| user_info | `UserInfo` | User information that is retrieved from the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) and transformed to user-friendly field names that match the Wristband User entity naming convention. The exact fields that get returned are based on the scopes you configured in the SDK. |

The `UserInfo` model is defined as follows:

| UserInfo Field | Type | Always Returned | Description |
| -------------- | ---- | --------------- | ----------- |
| user_id | str | Yes | ID of the user. |
| tenant_id | str | Yes | ID of the tenant that the user belongs to. |
| application_id | str | Yes | ID of the application that the user belongs to. |
| identity_provider_name | str | Yes | Name of the identity provider. |
| full_name | Optional[str] | No | End-User's full name in displayable form (requires `profile` scope). |
| given_name | Optional[str] | No | Given name(s) or first name(s) of the End-User (requires `profile` scope). |
| family_name | Optional[str] | No | Surname(s) or last name(s) of the End-User (requires `profile` scope). |
| middle_name | Optional[str] | No | Middle name(s) of the End-User (requires `profile` scope). |
| nickname | Optional[str] | No | Casual name of the End-User (requires `profile` scope). |
| display_name | Optional[str] | No | Shorthand name by which the End-User wishes to be referred (requires `profile` scope). |
| picture_url | Optional[str] | No | URL of the End-User's profile picture (requires `profile` scope). |
| email | Optional[str] | No | End-User's preferred email address (requires `email` scope). |
| email_verified | Optional[bool] | No | True if the End-User's email address has been verified (requires `email` scope). |
| gender | Optional[str] | No | End-User's gender (requires `profile` scope). |
| birthdate | Optional[str] | No | End-User's birthday in YYYY-MM-DD format (requires `profile` scope). |
| time_zone | Optional[str] | No | End-User's time zone (requires `profile` scope). |
| locale | Optional[str] | No | End-User's locale as BCP47 language tag, e.g., "en-US" (requires `profile` scope). |
| phone_number | Optional[str] | No | End-User's telephone number in E.164 format (requires `phone` scope). |
| phone_number_verified | Optional[bool] | No | True if the End-User's phone number has been verified (requires `phone` scope). |
| updated_at | Optional[int] | No | Time the End-User's information was last updated as Unix timestamp (requires `profile` scope). |
| roles | Optional[List[UserInfoRole]] | No | The roles assigned to the user (requires `roles` scope). |
| custom_claims | Optional[dict[str, Any]] | No | Object containing any configured custom claims. |

The `UserInfoRole` model is defined as follows:

| UserInfoRole Field | Type | Description |
| ------------------ | ---- | ----------- |
| id | str | Globally unique ID of the role. |
| name | str | The role name (e.g., "app:app-name:admin"). |
| display_name | str | The human-readable display name for the role. |

<br>

#### Redirect Responses

There are certain scenarios where a redirect URL is returned by the SDK. The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of where the user gets redirected to in these scenarios depends on if the application is using tenant subdomains and if the SDK is able to determine which tenant the user is currently attempting to log in to. The resolution happens in the following order:

1. If the tenant domain can be determined, then the user will get redirected back to your FastAPI Login Endpoint.
2. Otherwise, the user will be sent to the Wristband-hosted Tenant-Level Login Page URL.

**In both scenarios** (`COMPLETED` and `REDIRECT_REQUIRED`), you must use `create_callback_response()` to create the appropriate redirect response.

<br>

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

<br>

### create_callback_response()

```python
async def create_callback_response(self, request: Request, redirect_url: str) -> Response:
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | Request | Yes | The FastAPI request object. |
| redirect_url | str | Yes | The URL to redirect the user to after authentication completes. |

Your Callback Endpoint will call `create_callback_response()` after the `callback()` method is finished in order to complete the authentication flow. This will return a FastAPI `Response` object with the appropriate response headers and cookie handling set.

```python
callback_result = await wristband_auth.callback(request)

# Handle redirect required scenario
if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
    return await wristband_auth.create_callback_response(
        request, 
        callback_result.redirect_url
    )

# Handle successful authentication
app_url = callback_result.callback_data.return_url or "https://yourapp.io/home"
response = await wristband_auth.create_callback_response(request, app_url)

# Create session before returning response
session.from_callback(callback_result.callback_data)
return response
```

<br>

### logout()

```python
async def logout(self, request: Request, config: LogoutConfig = LogoutConfig()) -> Response:
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| request | Request | Yes | The FastAPI request object. |
| config | LogoutConfig | No | Optional configuration if your application needs custom behavior. |

When users of your application are ready to log out or their application session expires, your frontend should redirect the user to your FastAPI Logout Endpoint.

```python
response: Response = await wristband_auth.logout(
    request=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
return response
```

```sh
GET https://customer01.yourapp.io/auth/logout
```

If your application created a session, it should destroy it before invoking the `logout()` method.  This method can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ------------------ | ---- | -------- | ----------- |
| redirect_url | Optional[str] | No | Optional URL that Wristband will redirect to after the logout operation has completed. This will also take precedence over the `custom_application_login_page_url` (if specified) in the SDK AuthConfig if the tenant domain cannot be determined when attempting to redirect to the Wristband Logout Endpoint. |
| refresh_token | Optional[str] | No | The refresh token to revoke. |
| state | Optional[str] | No | Optional value that will be appended as a query parameter to the resolved logout URL, if provided. Maximum length of 512 characters. |
| tenant_custom_domain | Optional[str] | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenant_name | Optional[str] | No | The name of the tenant the user belongs to. |

<br>

#### Which Domains Are Used in the Logout URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your login endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `tenant_custom_domain` in LogoutConfig: If provided, this takes top priority.
2. `tenant_name` in LogoutConfig: This takes the next priority if `tenant_custom_domain` is not present.
3. `tenant_custom_domain` query parameter: Evaluated if present and there is also no LogoutConfig provided for either `tenant_custom_domain` or `tenant_name`.
4. Tenant subdomain in the URL: Used if none of the above are present, and `parse_tenant_from_root_domain` is specified, and the subdomain is present in the host.
5. `tenant_domain` query parameter: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

<br>

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `logout()` method, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

<br>

#### Resolving Tenant Domains

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you can either explicitly pass a tenant name into the LogoutConfig:

```python
response: Response = await wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_name="customer01"
    )
)
```

...or you can alternatively pass the `tenant_domain` query parameter in your redirect request to Logout Endpoint:

```python
# Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_domain=customer01"
response: Response = await wristband_auth.logout(
    request=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
```

If your application uses tenant subdomains, then passing the `tenant_name` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL as long as the `parse_tenant_from_root_domain` SDK config is set.

<br>

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you can either explicitly pass it into the LogoutConfig:

```python
response: Response = await wristband_auth.logout(
    request=request,
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
    request=request,
    config=LogoutConfig(refresh_token="98yht308hf902hc90wh09")
)
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then you should consider passing both the tenant names and tenant custom domains (either via LogoutConfig or by query parameters) to ensure all use cases are handled by the SDK.

<br>

#### Preserving State After Logout

The `state` field in the `LogoutConfig` allows you to preserve application state through the logout flow.

```python
response: Response = await wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_name="customer01",
        state="user_initiated_logout"
    )
)
```

The state value gets appended as a query parameter to the Wristband Logout Endpoint URL:

```sh
https://customer01.auth.yourapp.io/api/v1/logout?client_id=123&state=user_initiated_logout
```

After logout completes, Wristband will redirect to your configured redirect URL (either your Login Endpoint by default, or a custom logout redirect URL if configured) with the `state` parameter included:

```sh
https://yourapp.io/auth/login?tenant_domain=customer01&state=user_initiated_logout
```

This is useful for tracking logout context, displaying post-logout messages, or handling different logout scenarios. The state value is limited to 512 characters and will be URL-encoded automatically.

<br>

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `redirect_url` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```python
response: Response = await wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
        tenant_name="customer01",
        redirect_url="https://custom-logout.com"
    )
)
```

<br>

### refresh_token_if_expired()

```python
async def refresh_token_if_expired(self, refresh_token: str, expires_at: int) -> Optional[TokenData]:
```

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| expires_at | int | Yes | Unix timestamp in milliseconds at which the token expires. |
| refresh_token | str | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

```python
token_data: Optional[TokenData] = await wristband_auth.refresh_token_if_expired(
    refresh_token="98yht308hf902hc90wh09",
    expires_at=1710707503788
)
```

If the `refresh_token_if_expired()` method finds that your token has not expired yet, it will return `null` as the value, which means your auth middleware can simply continue forward as usual.

The `TokenData` is defined as follows:

| TokenData Field | Type | Description |
| --------------- | ---- | ----------- |
| access_token | str | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| expires_at | int | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| expires_in | int | The durtaion from the current time until the access token is expired (in seconds). The `token_expiration_buffer` SDK configuration is accounted for in this value. |
| id_token | str | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refresh_token | Optional[str] | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |

<br>

## Session Management

The SDK provides encrypted cookie-based session management via the `SessionMiddleware`. Sessions are automatically attached to `request.state.session` on every request and provide a dict-like interface for storing user data. All session data is encrypted using AES-256-GCM before being stored in cookies.

<br>

### Session Configuration

Configure session behavior when adding the middleware:

```python
app.add_middleware(
    SessionMiddleware,
    secret_key="your-secret-key",
    session_cookie_name="session",
    session_cookie_domain=".example.com",
    csrf_cookie_name="CSRF-TOKEN",
    csrf_cookie_domain=".example.com",
    max_age=3600,
    path="/",
    same_site="lax",
    secure=True,
)
```

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| secret_key | str | Yes | N/A | Secret key for session encryption (minimum 32 characters) |
| session_cookie_name | str | No | "session" | Name of the session cookie |
| session_cookie_domain | Optional[str] | No | None | Domain for the session cookie |
| csrf_cookie_name | str | No | "CSRF-TOKEN" | Name of the CSRF cookie |
| csrf_cookie_domain | Optional[str] | No | None | Domain for CSRF cookie (defaults to session_cookie_domain) |
| max_age | int | No | 3600 (1 hour) | Cookie expiration time in seconds |
| path | str | No | "/" | Cookie path |
| same_site | Literal["lax", "strict", "none"] | No | "lax" | Cookie SameSite attribute |
| secure | bool | No | True | Require HTTPS for cookies. **Set `secure=True` in production to ensure cookies are only sent over HTTPS.** |

> [!TIP]
> **Cross-Origin Requests**: If your frontend makes requests from a different subdomain (e.g., `app.example.com` calling APIs on `api.example.com`), you may need to set `csrf_cookie_domain=".example.com"` (with the leading dot) to allow the CSRF cookie to be accessible across subdomains. The session cookie should typically remain more restrictive.

<br>

### The Session Object

Once `SessionMiddleware` is configured, every request automatically has a session object attached at `request.state.session`. You can access this session object in two ways:

1. Via the `Session` Protocol (**preferred**) - Provides IDE autocomplete and type checking
2. Directly via `request.state.session` - Standard, untyped access to the session

#### Understanding Session State

Sessions start empty. All base session fields are Optional because the session begins with no data. Session fields are only populated when you either:

- Call `session.from_callback(callback_data)` after successful authentication (automatically sets all auth-related fields)
- Manually set fields and call `session.save()` to persist them

This means before authentication, fields like `user_id`, `access_token`, etc. will be set to `None`.

#### Base Session Fields

These fields are automatically populated when you call `session.from_callback()` after successful Wristband authentication:

| Session Field | Type | Description |
| ------------- | ---- | ----------- |
| is_authenticated | Optional[bool] | Whether the user is authenticated (set to `True` by `from_callback()`). |
| access_token | Optional[str] | JWT access token for making authenticated API calls to Wristband and other services. |
| expires_at | Optional[int] | Token expiration timestamp (milliseconds since Unix epoch). Accounts for `token_expiration_buffer` from SDK config. |
| user_id | Optional[str] | Unique identifier for the authenticated user. |
| tenant_id | Optional[str] | Unique identifier for the tenant that the user belongs to. |
| tenant_name | Optional[str] | Name of the tenant that the user belongs to. |
| identity_provider_name | Optional[str] | Name of the identity provider that the user belongs to. |
| csrf_token | Optional[str] | CSRF token for request validation. Token value is automatically generated by `from_callback()`. |
| refresh_token | Optional[str] | Refresh token for obtaining new access tokens when they expire. Only present if `offline_access` scope was requested during authentication. |
| tenant_custom_domain | Optional[str] | Custom domain for the tenant, if configured. Only present if a tenant custom domain was used during authentication. |

#### Extending the Session Protocol

You can extend the `Session` Protocol to add type hints for any custom session fields you want to include in the user's session. This gives you full IDE autocomplete and type checking for both base and custom fields:

```python
# src/models.py
from typing import Optional, Protocol
from wristband.fastapi_auth import Session

class MySession(Session, Protocol):
    """Extended session with custom fields."""
    role: Optional[str]
    preferences: Optional[dict]
    last_login: Optional[int]
```

Then use your custom session type in route handlers:

```python
from fastapi import Depends, Request
from wristband.fastapi_auth import get_session

from .models import MySession

# Using typed dependency injection
@router.get("/profile")
async def get_profile(session: MySession = Depends(get_session)):
    return {
        "userId": session.user_id,  # Base field - fully typed
        "role": session.role  # Custom field - fully typed
    }
```

<br>

### Session Dependencies

The SDK provides two [FastAPI dependencies](https://fastapi.tiangolo.com/tutorial/dependencies/) for working with sessions in your route handlers:

- `require_session_auth` - created by `create_session_auth_dependency()`
- `get_session`

<br>

#### require_session_auth (created by `create_session_auth_dependency()`)

```python
def create_session_auth_dependency(
    self,
    csrf_header_name: str = "X-CSRF-TOKEN"
) -> Callable[[Request, Response], Awaitable[Session]]:
```

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| csrf_header_name | str | No | `X-CSRF-TOKEN` | The HTTP request header name to read the CSRF token from. Must match the header name your frontend uses when sending CSRF tokens. |

The `create_session_auth_dependency()` method on `WristbandAuth` generates a reusable FastAPI dependency for securing routes with session-based authentication. It validates the user’s session, enforces CSRF protection, and automatically refreshes expired access tokens when needed. This method must be called on the `WristbandAuth` instance because it depends on the instance’s `refresh_token_if_expired()` method and the configured `token_expiration_buffer` SDK configuration.

```python
require_session_auth = wristband_auth.create_session_auth_dependency()
```

The returned function can be used with FastAPI's `Depends()` to protect routes. When the dependency is invoked on a request, it performs the following steps:

1. Verifies the session exists and the user is authenticated
2. Validates the CSRF token from the specified header matches the session token
3. Checks if the access token has expired and refreshes it if necessary
4. Updates the session with new token data when refresh occurs
5. Saves the session to persist changes (implements rolling sessions)

<br>

##### Using the Session Auth Dependency

You can apply the session auth dependency in two ways:

- At the router level to protect all routes within a router
- At the individual endpoint level for more granular control

Both approaches offer different granularity of control depending on your application's needs.

> [!WARNING]
> Avoid combining router-level and route-level protection within the same router. Doing so will trigger authentication and CSRF validation twice for every request.
>
> If you want to apply router-level protection but still need typed access to the user's session inside endpoints, inject the `get_session` dependency at the endpoint level instead of using `require_session_auth` twice.

**Router-Level Authentication**
```python
# src/routes/protected_routes.py
from fastapi import APIRouter, Depends
from auth.wristband import require_session_auth

# All routes in this router will require authentication
router = APIRouter(dependencies=[Depends(require_session_auth)])

@router.get("/protected-resource-01")
async def get_protected_resource_01():
    pass

@router.get("/protected-resource-02")
async def get_protected_resource_02():
    pass
```

**Endpoint-Level Authentication**
```python
# src/routes/mixed_routes.py
from fastapi import APIRouter, Depends
from auth.wristband import require_session_auth

router = APIRouter()

@router.get("/public-resource")
async def get_public_resource():
    # No authentication required
    pass

@router.get("/protected-resource", dependencies=[Depends(require_session_auth)])
async def get_protected_resource():
    # Authentication required; No Session access needed
    pass

@router.get("/another-protected-resource")
async def get_another_protected_resource(session: Session = Depends(require_session_auth)):
    # Authentication required; Session access from dependency injection
    print(f"User ID --> {session.user_id}")
```

##### Custom CSRF Header

If your frontend uses a different CSRF header name, specify it when creating the dependency:

```python
# Frontend sends CSRF token in X-CUSTOM-XSRF-TOKEN header
require_session_auth = wristband_auth.create_session_auth_dependency(
    csrf_header_name="X-CUSTOM-XSRF-TOKEN"
)
```

##### Dependency Exceptions

The `require_session_auth` dependency can raise an exception for the following scenarios:

| Exception Type | Condition |
| -------------- | --------- |
| RuntimeError | If `SessionMiddleware` is not registered in the application. |
| HTTPException (401) | If the session is not authenticated or token refresh fails. |
| HTTPException (403) | If CSRF token validation fails |

Your frontend should treat 401 and 403 responses as signals that the user must re-authenticate before continuing.

**Handling Auth Errors in Your Frontend:**
```typescript
async function makeAuthenticatedRequest(url: string, options: RequestInit = {}) {
  try {
    const response = await fetch(url, {
      ...options,
      credentials: 'include', // Include cookies
      headers: {
        'X-CSRF-TOKEN': getCsrfToken(), // Your function to read CSRF cookie
        ...options.headers,
      },
    });

    // Handle authentication errors
    if (response.status === 401 || response.status === 403) {
      // Redirect to login - user needs to re-authenticate
      window.location.href = '/api/auth/login';
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Request failed:', error);
    throw error;
  }
}
```

<br> 

#### get_session

```python
def get_session(request: Request) -> Session:
```

Get the typed session object from a request. Use this dependency when you need typed access to session data without performing any validation.

> [!WARNING]
> This dependency does not perform authentication or CSRF validation. Use it only when you've already protected the route with `require_session_auth` at the router level, or when you need access to session data for non-protected routes.

```python
from fastapi import Depends
from wristband.fastapi_auth import get_session, Session

@router.get("/profile")
async def get_profile(session: Session = Depends(get_session)):
    return { "userId": session.user_id }
```

##### Exceptions

The `get_session` dependency can raise an exception for the following scenarios:

| Exception Type | Condition |
| -------------- | --------- |
| RuntimeError | If `SessionMiddleware` is not registered in the application. |

<br>

### Session Access Patterns

Sessions support standard dictionary operations **and** attribute-style access for getting, setting, checking, and deleting values. These examples work with both `request.state.session` and the typed `Session` dependency obtained via `Depends(get_session)` or `Depends(require_session_auth)`.

```python
# Set values (dict-style)
session["user_id"] = "123"
session["cart"] = {"items": [], "total": 0}

# Set values (attribute-style)
session.user_id = "123"
session.cart = {"items": [], "total": 0}

# Get values (dict-style)
user_id = session["user_id"]
cart = session.get("cart")  # Returns None if missing
role = session.get("role", "guest")  # With default

# Get values (attribute-style)
user_id = session.user_id
cart = session.cart  # Returns None if missing

# Check existence
if "cart" in session:
    cart = session["cart"]

# Delete values (dict-style)
del session["old_key"]

# Iterate over keys
for key in session:
    print(f"{key}: {session[key]}")

# Get number of items
item_count = len(session)
```

<br>

#### Limitations

**JSON Serialization:** All values stored in the session must be JSON-serializable. Attempting to store non-serializable values (like functions, file objects, or custom class instances) will raise a `ValueError`.

**Size Limit:** Sessions are limited to 4KB total, including encryption overhead and cookie attributes. This limit is enforced by the browser per [RFC 6265](https://datatracker.ietf.org/doc/html/rfc6265). If your session data exceeds this limit, a `ValueError` is raised with details about the data size and overhead. If you need to store larger amounts of data, consider:
- Storing only essential data in the session (IDs, tokens, minimal user info)
- Using a database-backed session library (like starsessions)
- Storing large data in a database and keeping only a reference ID in the session

<br>

### Session API

#### `session.get(key, default=None)`

Get a session value with an optional default.

```python
user_id = session.get("user_id")
role = session.get("role", "guest")
```

<br>

#### `session.to_dict()`

Get a shallow copy of all session data as a dictionary.

```python
session_data = session.to_dict()
# Returns: {"user_id": "123", "tenant_id": "abc", ...}
```

<br>

#### `session.from_callback(callback_data, custom_fields=None)`

Create a session from Wristband callback data after successful authentication. This is a convenience method that automatically:

- Extracts a core subset of user and tenant info from callback data
- Generates a CSRF token to store in both the session and CSRF cookies
- Marks the session for persistence in an encrypted session cookie

| Parameters | Type | Required | Default | Description |
| ---------- | ---- | -------- | ------- | ----------- |
| callback_data | `CallbackData` | Yes | N/A | The callback data from `wristband_auth.callback()`. A `ValueError` is raised if `callback_data` is None or `callback_data.user_info` is missing. |
| custom_fields | Optional[Dict[str, Any]] | No | None | Additional fields to store. A `ValueError` is raised if `custom_fields` aren't JSON-serializable. |

```python
# Basic usage
callback_result = await wristband_auth.callback(request)
session.from_callback(callback_result.callback_data)

# With custom fields
session.from_callback(
    callback_data=callback_result.callback_data,
    custom_fields={
        "role": "admin",
        "preferences": {"theme": "dark"},
        "last_login": 1735689600000
    }
)
```

The following fields from the callback data are automatically stored in the session:

- `is_authenticated` (always set to `True`)
- `access_token`
- `expires_at`
- `user_id` (from `callback_data.user_info.user_id`)
- `tenant_id` (from `callback_data.user_info.tenant_id`)
- `tenant_name`
- `identity_provider_name` (from `callback_data.user_info.identity_provider_name`)
- `csrf_token` (auto-generated CSRF token)
- `refresh_token` (only if `offline_access` scope was requested)
- `tenant_custom_domain` (only if a tenant custom domain was used during authentication)

<br>

#### `session.save()`

Mark the session for persistence. This refreshes the cookie expiration time (implementing rolling sessions - extending session expiration on each request) and saves any modifications made to session data. Use `save()` when manually modifying session data or when you want to keep sessions alive based on user activity.

```python
# After modifying session
session.last_activity = time.time()
session.save()

# Extend session without modification (rolling sessions)
if session.get("is_authenticated"):
    session.save()
```

<br>

#### `session.clear()`

Delete the session and clear all cookies (both session and CSRF). Use this when logging users out.

```python
@router.get("/logout")
async def logout(session: Session = Depends(get_session)):
    # Destroy session and CSRF cookies
    session.clear()

    # ...
```

<br>

#### `session.get_session_response(metadata=None)`

Create a `SessionResponse` for Wristband frontend SDKs. This method is typically used in your Session Endpoint.  An `HTTPException` with 401 status is raised if `tenant_id` or `user_id` are missing from the session.

| Parameters | Type | Required | Default | Description |
| ---------- | ---- | -------- | ------- | ----------- |
| metadata | Optional[Dict[str, Any]] | No | None | Custom metadata to include **(must be JSON-serializable)**. |

```python
from fastapi import APIRouter, Depends
from wristband.fastapi_auth import Session, SessionResponse

from auth.wristband import require_session_auth

@router.get("/api/auth/session")
async def get_session_response(session: Session = Depends(require_session_auth)) -> SessionResponse:
    return session.get_session_response(
        metadata={
            "name": session.full_name,
            "preferences": session.preferences
        }
    )
```

##### `SessionResponse`

Returned by `get_session_response()`. The response format matches what Wristband frontend SDKs expect from Session Endpoints.

| SessionResponse Field | Type | Description | Serialized As |
| --------------------- | ---- | ----------- | ------------- |
| user_id | str | The ID of the user who authenticated. | `userId` |
| tenant_id | str | The ID of the tenant that the authenticated user belongs to. | `tenantId` |
| metadata | Optional[Dict[str, Any]] | Any included custom session metadata. Defaults to an empty dict if none was provided. | `metadata` |

<br>

#### `session.get_token_response()`

Create a `TokenResponse` for Wristband frontend SDKs. This method is typically used in your Token Endpoint. An `HTTPException` with 401 status is raised if `access_token` or `expires_at` are missing from the session.

```python
from fastapi import APIRouter, Depends
from wristband.fastapi_auth import Session, TokenResponse

from auth.wristband import require_session_auth

@router.get("/api/auth/token")
async def get_token_response(session: Session = Depends(require_session_auth)) -> TokenResponse:
    return session.get_token_response()
```

##### `TokenResponse`

Returned by `get_token_response()`. The response format matches what Wristband frontend SDKs expect from Token Endpoints.

| TokenResponse Field | Type | Description | Serialized As |
| ------------------- | ---- | ----------- | ------------- |
| access_token | str | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. | `accessToken` |
| expires_at | int | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `token_expiration_buffer` SDK configuration is accounted for in this value. | `expiresAt` |

<br>

### CSRF Protection

When you create a session using `from_callback()`, the SDK automatically generates a CSRF token and stores it in two locations:

1. **Session cookie** (encrypted, HttpOnly): Contains the CSRF token as part of the encrypted session data
2. **CSRF cookie** (unencrypted, readable by JavaScript): Contains the same CSRF token in plaintext

This dual-cookie approach follows the [Synchronizer Token Pattern](https://docs.wristband.dev/docs/csrf-protection-for-backend-servers):
- The session cookie proves the user is authenticated (server-side validation)
- The CSRF cookie must be read by your frontend and sent in request headers (client-side participation)

**Frontend Implementation:**

Your frontend must read the CSRF token from the CSRF cookie and include it in a CSRF header (i.e., `X-CSRF-TOKEN`) for all state-changing requests. For example:

```javascript
// Read CSRF token from cookie
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('CSRF-TOKEN='))
  ?.split('=')[1];

// Include in requests
fetch('/api/protected-endpoint', {
  method: 'POST',
  headers: {
    'X-CSRF-TOKEN': csrfToken,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ data: 'example' })
});
```

<br>

#### Automatic Validation

When you use the `require_session_auth` dependency created by `wristband_auth.create_session_auth_dependency()`, CSRF validation happens automatically on every request. If CSRF validation fails, an `HTTPException` with 403 Forbidden status is raised.

> [!NOTE]
> CSRF validation is primarily for state-changing operations (POST, PUT, DELETE). GET requests can use `require_session_auth` for authentication without CSRF concerns, though the CSRF token will still be validated if present in the request headers.

```python
# CSRF is validated automatically when using require_session_auth
@router.post("/api/v1/data")
async def update_data(session: Session = Depends(require_session_auth)):
    # By the time your handler runs, CSRF has been validated
    session.data = "new_data"
    session.save()
    return {"status": "success"}
```

<br>

## Debug Logging

The SDK includes some debug-level logging for troubleshooting authentication and session issues. To enable debug logs in your FastAPI application, configure the logger for the Wristband SDK:

```python
# src.main.py
import logging

# Configure your app's logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(name)s: %(message)s"
)

# Enable DEBUG logs for Wristband SDK
logging.getLogger("wristband.fastapi_auth").setLevel(logging.DEBUG)
```

<br>

## JWT Token Validation

If you only need to validate JWT access tokens issued by Wristband (without the full authentication flow), use the standalone [python-jwt](https://github.com/wristband-dev/python-jwt) library. This is useful for:

- Microservices that receive tokens from your main application
- Backend services that only need to verify tokens, not issue them
- APIs that validate tokens in the `Authorization` header

The `python-jwt` library provides lightweight JWT validation with public key caching and is designed specifically for Wristband tokens.

<br>

## Wristband Multi-Tenant FastAPI Demo App

You can check out the [Wristband FastAPI demo app](https://github.com/wristband-dev/fastapi-demo-app) to see this SDK in action. Refer to that GitHub repository for more information.

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
