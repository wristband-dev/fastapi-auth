<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instructions from version 1.x to version 2.x
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

# Migration Instructions from Version 1.x to Version 2.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 2.x

<br>

## Table of Contents

- [Overview of Changes](#overview-of-changes)
- [Breaking Changes](#breaking-changes)
  - [CallbackResult Structure Changes](#callbackresult-structure-changes)
  - [Query Parameter and URL Placeholder Naming Changes](#query-parameter-and-url-placeholder-naming-changes)
  - [Session Middleware Configuration Changes](#session-middleware-configuration-changes)
  - [Session Auth Dependency Creation Changes](#session-auth-dependency-creation-changes)
- [Recommended Updates](#recommended-updates)
  - [Session Endpoint Response Headers](#session-endpoint-response-headers)
  - [Token Endpoint Response Headers](#token-endpoint-response-headers)

<br>

---

<br>

## Overview of Changes

Version 2.0 is a major release that:

- ✅ Adds JWT bearer token authentication support
- ✅ Adds multi-strategy authentication (SESSION + JWT)
- ✅ Introduces discriminated union pattern for `CallbackResult`
- ✅ Changes query parameter naming for consistency (`tenant_domain` → `tenant_name`)
- ✅ Updates session middleware configuration with new CSRF options
- ✅ Reorganizes session auth dependency creation

<br>

## Breaking Changes

### CallbackResult Structure Changes

The `CallbackResult` model in v2.x now uses a discriminated union pattern with explicit variant types and a new `reason` field for redirect cases.

#### Type Checking Pattern

**v1.x:**
```python
callback_result: CallbackResult = await wristband_auth.callback(request)

- if callback_result.type == CallbackResultType.REDIRECT_REQUIRED:
-     assert callback_result.redirect_url is not None
-     return await wristband_auth.create_callback_response(request, callback_result.redirect_url)

- assert callback_result.callback_data is not None
- session.from_callback(callback_result.callback_data)
```

**v2.x:**
```python
callback_result: CallbackResult = await wristband_auth.callback(request)

+ if isinstance(callback_result, RedirectRequiredCallbackResult):
+     return await wristband_auth.create_callback_response(
+         request,
+         callback_result.redirect_url
+     )

+ # callback_result is now guaranteed to be CompletedCallbackResult
+ session.from_callback(callback_result.callback_data)
```

**Key Changes:**
- Use `isinstance()` checks instead of comparing `callback_result.type`
- No more `assert` statements needed - type narrowing is automatic
- Import the new result types: `CompletedCallbackResult`, `RedirectRequiredCallbackResult`

#### New Import Required

```python
- from wristband.fastapi_auth import CallbackResult, CallbackResultType
+ from wristband.fastapi_auth import (
+     CallbackResult,
+     CompletedCallbackResult,
+     RedirectRequiredCallbackResult,
+ )
```

#### New `reason` Field

v2.x adds a `reason` field to `RedirectRequiredCallbackResult` that indicates why the redirect is required:

```python
if isinstance(callback_result, RedirectRequiredCallbackResult):
    # You can now inspect why redirect is needed
    print(f"Redirect reason: {callback_result.reason}")
    # Possible values: MISSING_LOGIN_STATE, INVALID_LOGIN_STATE, 
    #                  LOGIN_REQUIRED, INVALID_GRANT
```

See the [callback() documentation](../../README.md#callback) for the complete `CallbackFailureReason` enum values.

<br>

### Query Parameter and URL Placeholder Naming Changes

To improve consistency across the SDK, query parameter names have changed from `tenant_domain` to `tenant_name`.

#### Login Endpoint Query Parameters

**v1.x:**
```python
# Login with tenant domain query parameter
- GET https://yourapp.io/auth/login?tenant_domain=customer01
```

**v2.x:**
```python
# Login with tenant name query parameter
+ GET https://yourapp.io/auth/login?tenant_name=customer01
```

#### Logout Endpoint Query Parameters

**v1.x:**
```python
# Logout with tenant domain query parameter
- GET https://yourapp.io/auth/logout?tenant_domain=customer01
```

**v2.x:**
```python
# Logout with tenant name query parameter
+ GET https://yourapp.io/auth/logout?tenant_name=customer01
```

> **💡 Note:** The `tenant_custom_domain` query parameter name remains unchanged in both versions.

#### URL Placeholder Changes

**v1.x:**
```python
auth_config = AuthConfig(
    # ... other config
-   login_url="https://{tenant_domain}.yourapp.com/auth/login",
-   redirect_uri="https://{tenant_domain}.yourapp.com/auth/callback",
)
```

**v2.x:**
```python
auth_config = AuthConfig(
    # ... other config
+   login_url="https://{tenant_name}.yourapp.com/auth/login",
+   redirect_uri="https://{tenant_name}.yourapp.com/auth/callback",
)
```

> **⚠️ Important:**
>
> The old `{tenant_domain}` placeholder still works for backwards compatibility, but it is now deprecated and will be removed in a future major version. All new code should use `{tenant_name}`.

<br>

### Session Middleware Configuration Changes

The session middleware configuration has been updated with new CSRF-related parameters and a change to the `same_site` parameter type.

#### SameSite Parameter Type

**v1.x:**
```python
app.add_middleware(
    SessionMiddleware,
    secret_key="your-secret-key",
-   same_site="lax",  # String literal
)
```

**v2.x:**
```python
+ from wristband.fastapi_auth import SessionMiddleware, SameSiteOption

app.add_middleware(
    SessionMiddleware,
    secret_key="your-secret-key",
+   same_site=SameSiteOption.LAX,  # Enum value
)
```

**Import Required:**
```python
+ from wristband.fastapi_auth import SameSiteOption
```

**Available Values:**
- `SameSiteOption.LAX` (default)
- `SameSiteOption.STRICT`
- `SameSiteOption.NONE`

#### New CSRF Configuration Options

v2.x introduces explicit CSRF configuration options:

**v2.x:**
```python
app.add_middleware(
    SessionMiddleware,
    secret_key="your-secret-key",
+   enable_csrf_protection=True,  # <-- NEW (Default: False)
    csrf_cookie_name="CSRF-TOKEN",
    csrf_cookie_domain=".example.com",
)
```

**Key Points:**
- `enable_csrf_protection` is new and defaults to `False` in v2.x
- CSRF tokens are only generated when `enable_csrf_protection=True`
- In v1.x, CSRF tokens were always generated
- If you rely on CSRF protection, explicitly set `enable_csrf_protection=True`

<br>

### Session Auth Dependency Creation Changes

The method signature for creating session auth dependencies has changed.

#### Method Signature

**v1.x:**
```python
require_session_auth = wristband_auth.create_session_auth_dependency(
    csrf_header_name="X-CSRF-TOKEN"
)
```

**v2.x:**
```python
require_session_auth = wristband_auth.create_session_auth_dependency(
+   enable_csrf_protection=True,  # Default: False
    csrf_header_name="X-CSRF-TOKEN"
)
```

**Key Changes:**
- `enable_csrf_protection` parameter added (default: `False`)
- If you want CSRF protection (recommended), you must explicitly enable it

## Recommended Updates

### Session Endpoint Response Headers

While not a breaking change, it's recommended to add no-cache headers to your session endpoint:

**v1.x:**
```python
@router.get("/session")
async def get_session_response(session: Session = Depends(require_session_auth)) -> SessionResponse:
-   return session.get_session_response(metadata={ "foo": "bar" })
```

**v2.x:**
```python
@router.get("/session")
async def get_session_response(
+   response: Response,
    session: Session = Depends(require_session_auth)
) -> SessionResponse:
+   response.headers["Cache-Control"] = "no-store"
+   response.headers["Pragma"] = "no-cache"
    return session.get_session_response(metadata={ "foo": "bar" })
```

<br>

### Token Endpoint Response Headers

Similarly, add no-cache headers to your token endpoint:

**v1.x:**
```python
@router.get("/token")
async def get_token_response(session: Session = Depends(require_session_auth)) -> TokenResponse:
-   return session.get_token_response()
```

**v2.x:**
```python
@router.get("/token")
async def get_token_response(
+   response: Response,
    session: Session = Depends(require_session_auth)
) -> TokenResponse:
+   response.headers["Cache-Control"] = "no-store"
+   response.headers["Pragma"] = "no-cache"
    return session.get_token_response()
```

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
