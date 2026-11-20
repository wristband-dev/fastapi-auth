<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instructions from version 2.x to version 3.x
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> • 
      <a href="https://docs.wristband.dev/">Documentation</a> • 
      <a href="https://docs.wristband.dev/llms.txt">LLMs.txt</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Migration Instructions from Version 2.x to Version 3.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 3.x

<br>

## Table of Contents

- [Overview of Changes](#overview-of-changes)
- [Breaking Changes](#breaking-changes)
  - [Minimum Python Version](#minimum-python-version)
  - [Tenant Domain URL Placeholder Removed](#tenant-domain-url-placeholder-removed)
  - [Application-Level Authorization Requests](#application-level-authorization-requests)
  - [parse_tenant_from_root_domain and fallback_login_url Configs Removed](#parse_tenant_from_root_domain-and-fallback_login_url-configs-removed)
  - [callback() Changes](#callback-changes)
  - [Return URL Validation in callback()](#return-url-validation-in-callback)
  - [CSRF Protection Is Configured Only on SessionMiddleware](#csrf-protection-is-configured-only-on-sessionmiddleware)
  - [Multi-Strategy Auth Stops at the First Credential](#multi-strategy-auth-stops-at-the-first-credential)
  - [Session and Login State Cookie Encryption](#session-and-login-state-cookie-encryption)
  - [Tenant Name and Tenant Custom Domain Validation](#tenant-name-and-tenant-custom-domain-validation)
  - [refresh_token_if_expired() Changes](#refresh_token_if_expired-changes)
  - [Other Behavior Changes](#other-behavior-changes)
- [Recommended Updates](#recommended-updates)
  - [Automatic No-Cache Headers](#automatic-no-cache-headers)

<br>

---

<br>

## Overview of Changes

Version 3.0 is a major release that:

- ✅ Raises the minimum supported Python version to 3.11
- ✅ Removes the deprecated `{tenant_domain}` URL placeholder
- ✅ Adds application-level authorization requests, controlled by the new `application_authorization_requests_enabled` config
- ✅ Removes the `parse_tenant_from_root_domain` and `fallback_login_url` configs, which are now derived from `login_url`
- ✅ Replaces `create_callback_response()` with a redirect response returned directly by `callback()`
- ✅ Validates the return URL in `callback()` to prevent open redirects
- ✅ Adds the `trust_proxy_headers` config for applications running behind a reverse proxy
- ✅ Sets `Cache-Control: no-store` and `Pragma: no-cache` automatically on responses that write or delete session cookies
- ✅ Turns on CSRF protection with one setting on `SessionMiddleware`, for both token generation and validation
- ✅ Makes multi-strategy auth use the first credential the request carries, instead of trying every strategy
- ✅ Derives session and Login State Cookie keys from the whole secret, and expires both cookies server-side
- ✅ Ignores tenant names and tenant custom domains that aren't valid DNS names, preventing open redirects

<br>

## Breaking Changes

### Minimum Python Version

The minimum supported Python version is now 3.11. Python 3.9 and 3.10 have reached end of life (Python 3.10 on October 1, 2026).

The SDK's `pyproject.toml` now declares:

**v2.x:**
```toml
- requires-python = ">=3.9"
```

**v3.x:**
```toml
+ requires-python = ">=3.11"
```

**Key Changes:**
- Upgrade your app's runtime to Python 3.11 or later
- Update anything still pinned to Python 3.9 or 3.10, such as CI workflows, Dockerfiles, `.python-version` files, or hosting platform settings

<br>

### Tenant Domain URL Placeholder Removed

The `{tenant_domain}` placeholder, deprecated in v2.x, has been removed. `{tenant_name}` is now the only supported tenant placeholder in `login_url` and `redirect_uri`.

**v2.x:**
```python
auth_config = AuthConfig(
    # ... other config
-   login_url="https://{tenant_domain}.yourapp.com/auth/login",
-   redirect_uri="https://{tenant_domain}.yourapp.com/auth/callback",
)
```

**v3.x:**
```python
auth_config = AuthConfig(
    # ... other config
+   login_url="https://{tenant_name}.yourapp.com/auth/login",
+   redirect_uri="https://{tenant_name}.yourapp.com/auth/callback",
)
```

<br>

### Application-Level Authorization Requests

v3.x adds support for application-level authorization requests, controlled by the new `application_authorization_requests_enabled` config. When enabled, Wristband accepts authorization requests through your application's vanity domain in addition to tenant vanity domains, which gives your application one fixed, static Authorization Endpoint URL (required by some third-party platforms, such as Supabase).

This changes what the SDK does when it cannot resolve a tenant from the request. When auto-configure is enabled (the default), the value comes from the setting on your Application in the Wristband Dashboard, which is enabled by default. So unless you set `application_authorization_requests_enabled` yourself, upgrading to v3.x can change these redirects:

| Scenario | v2.x | v3.x (enabled) |
| -------- | ---- | -------------- |
| `login()` cannot resolve a tenant | Redirects to the Application-Level Login (Tenant Discovery) Page, or to `custom_application_login_page_url` | Redirects to the Wristband Authorize Endpoint using your application's vanity domain, with a Login State Cookie, and Wristband handles tenant discovery as part of the same authorization flow |
| `logout()` cannot resolve a tenant and no `redirect_url` is set | Redirects to the Application-Level Login (Tenant Discovery) Page, or to `custom_application_login_page_url` | Redirects to your Login Endpoint (with the `{tenant_name}` subdomain removed if your `login_url` contains it) to start a new application-level authorization flow |

To keep the v2.x behavior, set `application_authorization_requests_enabled` to `False`:

**v3.x:**
```python
auth_config = AuthConfig(
    # ... other config
+   application_authorization_requests_enabled=False,
)
```

**Key Changes:**
- Requests where the tenant can be resolved (tenant subdomain, `tenant_name` or `tenant_custom_domain` query parameter, or a default tenant in `LoginConfig`) are unaffected and always use the tenant-level flow
- `custom_application_login_page_url` is now only used when `application_authorization_requests_enabled` is `False`
- When enabled and your `login_url` contains the `{tenant_name}` placeholder, the Login State Cookie is scoped to your root domain (e.g. `Domain=.yourapp.com`), since the login starts on your root domain and Wristband redirects back to the tenant's Callback Endpoint
- When auto-configure is disabled and the config isn't set, it defaults to `False`, which matches the v2.x behavior

See [Application-Level Authorization Requests](../../README.md#application-level-authorization-requests) in the README for more details.

<br>

### parse_tenant_from_root_domain and fallback_login_url Configs Removed

The `parse_tenant_from_root_domain` and `fallback_login_url` configs have been removed from `AuthConfig`. Tenant subdomain parsing is now enabled whenever `login_url` contains the `{tenant_name}` placeholder, and the SDK derives both values from `login_url` by removing the `{tenant_name}` subdomain:

- The root domain for parsing tenant subdomains (e.g. `https://{tenant_name}.yourapp.com/auth/login` gives a root domain of `yourapp.com`)
- The non-tenant-specific Login Endpoint URL that `logout()` redirects to when the tenant can't be resolved and application-level authorization requests are enabled (e.g. `https://{tenant_name}.yourapp.com/auth/login` gives `https://yourapp.com/auth/login`)

**v2.x:**
```python
auth_config = AuthConfig(
    # ... other config
    login_url="https://{tenant_name}.yourapp.com/auth/login",
    redirect_uri="https://{tenant_name}.yourapp.com/auth/callback",
-   parse_tenant_from_root_domain="yourapp.com",
    application_authorization_requests_enabled=True,
-   fallback_login_url="https://yourapp.com/auth/login",
)
```

**v3.x:**
```python
auth_config = AuthConfig(
    # ... other config
    login_url="https://{tenant_name}.yourapp.com/auth/login",
    redirect_uri="https://{tenant_name}.yourapp.com/auth/callback",
    application_authorization_requests_enabled=True,
)
```

**Key Changes:**
- Remove `parse_tenant_from_root_domain` and `fallback_login_url` from your SDK config
- If your app relies on auto-configuration and never set either value, no change is needed
- If you previously set a `fallback_login_url` that differs from your `login_url` with the `{tenant_name}` subdomain removed, `logout()` now redirects to the derived URL instead

> **⚠️ Important:**
>
> The `{tenant_name}` placeholder must appear exactly once in `login_url` and `redirect_uri`, as the leftmost part of the hostname. Either both URLs contain the placeholder or neither does.
>
> `AuthConfig` ignores unknown fields, so passing `parse_tenant_from_root_domain` or `fallback_login_url` does not raise an error. Remove them anyway, since they no longer have any effect.

<br>

### callback() Changes

`create_callback_response()` has been removed. `callback()` now takes a second argument, `resolve_redirect_url`: a function that receives the request and the callback data, and returns the URL to send the user to after a successful login. The callback result always contains a ready-made redirect `response` with the Login State Cookie already cleared, so the Callback Endpoint returns it instead of building one.

**v2.x:**
```python
@router.get('/callback')
async def callback(request: Request, session: Session = Depends(get_session)) -> Response:
-   callback_result: CallbackResult = await wristband_auth.callback(request)

    if isinstance(callback_result, RedirectRequiredCallbackResult):
-       return await wristband_auth.create_callback_response(
-           request,
-           callback_result.redirect_url
-       )

    session.from_callback(callback_result.callback_data)

-   app_url = callback_result.callback_data.return_url or "<your_app_home_url>"
-   return await wristband_auth.create_callback_response(request, app_url)
```

**v3.x:**
```python
@router.get('/callback')
async def callback(request: Request, session: Session = Depends(get_session)) -> Response:
+   callback_result = await wristband_auth.callback(
+       request,
+       lambda req, data: data.return_url or "<your_app_home_url>",
+   )

    if isinstance(callback_result, RedirectRequiredCallbackResult):
+       return callback_result.response

    session.from_callback(callback_result.callback_data)

+   return callback_result.response
```

**Key Changes:**
- Replace every `create_callback_response()` call. For completed results, move the redirect logic into the `resolve_redirect_url` function passed to `callback()`. For redirect required results, return `callback_result.response`.
- `resolve_redirect_url` runs only when the callback completes successfully. It can be a regular function or an `async` function (for example, to look up data in your own database).
- `resolve_redirect_url` can return an absolute URL or a relative path (e.g. `/home`). Returning an empty value raises a `TypeError`, and so does passing something other than a function.
- `RedirectRequiredCallbackResult` no longer contains `redirect_url`. Its `response` already redirects to the Login Endpoint.
- `CompletedCallbackResult` and `RedirectRequiredCallbackResult` both contain the new `response` field. The session you create with `session.from_callback()` is still saved onto the returned response by the `SessionMiddleware`.

<br>

### Return URL Validation in callback()

`callback()` now validates the return URL before including it in the returned callback data. In v2.x, the return URL was passed through unchanged. A return URL that fails validation is now left out of the callback data (`return_url` is `None`), and the flow continues without it.

**v2.x:**
```python
# Login request: /auth/login?return_url=https://otherapp.com/dashboard
callback_result: CallbackResult = await wristband_auth.callback(request)

if isinstance(callback_result, CompletedCallbackResult):
-   # return_url == "https://otherapp.com/dashboard"
-   return_url = callback_result.callback_data.return_url
-   return await wristband_auth.create_callback_response(request, return_url)
```

**v3.x:**
```python
# Login request: /auth/login?return_url=https://otherapp.com/dashboard
callback_result = await wristband_auth.callback(
    request,
+   # data.return_url is None (the host does not match the request's host or the root domain)
+   lambda req, data: data.return_url or "/home",
)

if isinstance(callback_result, CompletedCallbackResult):
+   return callback_result.response
```

**Key Changes:**
- Relative paths (e.g. `/settings`) resolve against the callback request's host
- The protocol must match the callback request's protocol, which blocks downgrades like `https` to `http`. The protocol comes from the request URL, so when TLS terminates at a reverse proxy, configure your ASGI server to trust the proxy's forwarded protocol (e.g. Uvicorn's `--forwarded-allow-ips`).
- The hostname must be either the root domain (when `login_url` contains the `{tenant_name}` placeholder) or the callback request's host
- When application-level authorization requests are enabled and `login_url` contains the `{tenant_name}` placeholder, a return URL on the bare root domain is rewritten to the tenant's subdomain (e.g. `yourapp.com` to `acme.yourapp.com`)
- If your app runs behind a reverse proxy that sets `X-Forwarded-Host`, set the new `trust_proxy_headers=True` config so the request's host is read from that header

> **⚠️ Important:**
>
> Make sure your `resolve_redirect_url` function has a default redirect location for when `return_url` is not present, since a return URL that worked in v2.x may now be left out.

<br>

### CSRF Protection Is Configured Only on SessionMiddleware

In v2.x, CSRF protection needed two separate settings: `enable_csrf_protection` on `SessionMiddleware` generated tokens, and `enable_csrf_protection` on the auth dependency validated them. Turning on only the first generated tokens that were never checked. Turning on only the second rejected every request with a 403, because no token was ever generated.

In v3.x, `SessionMiddleware(enable_csrf_protection=True)` turns on both. The `enable_csrf_protection` parameter has been removed from `create_session_auth_dependency()` and from `SessionAuthConfig`. `csrf_header_name` is unchanged.

**v2.x:**
```python
app.add_middleware(SessionMiddleware, secret_key="...", enable_csrf_protection=True)

require_session_auth = wristband_auth.create_session_auth_dependency(
-   enable_csrf_protection=True,
    csrf_header_name="X-CSRF-TOKEN",
)

require_auth = wristband_auth.create_auth_dependency(
    strategies=[AuthStrategy.SESSION, AuthStrategy.JWT],
-   session_config=SessionAuthConfig(enable_csrf_protection=True, csrf_header_name="X-CSRF-TOKEN"),
)
```

**v3.x:**
```python
# One setting turns CSRF on for both generation and validation
app.add_middleware(SessionMiddleware, secret_key="...", enable_csrf_protection=True)

+require_session_auth = wristband_auth.create_session_auth_dependency(csrf_header_name="X-CSRF-TOKEN")

require_auth = wristband_auth.create_auth_dependency(
    strategies=[AuthStrategy.SESSION, AuthStrategy.JWT],
+   session_config=SessionAuthConfig(csrf_header_name="X-CSRF-TOKEN"),  # optional, this is the default
)
```

**Key Changes:**
- Remove `enable_csrf_protection` from every `create_session_auth_dependency()` call and `SessionAuthConfig`. Passing it raises a `TypeError` in `create_session_auth_dependency()`.
- If you had `enable_csrf_protection=True` on `SessionMiddleware` but not on your dependencies, your routes now validate CSRF tokens. Make sure your frontend sends the CSRF header, or turn the setting off on `SessionMiddleware`.
- CSRF tokens are now 32 random bytes (64 hex characters), and are compared in constant time.

<br>

### Multi-Strategy Auth Stops at the First Credential

In v2.x, `create_auth_dependency()` tried every strategy until one succeeded, and raised the last strategy's exception if none did. A `SESSION` CSRF failure (403) followed by a failed `JWT` strategy returned 401 (or 500 for a non-Bearer `Authorization` header) instead of 403.

In v3.x, the strategies are meant for requests that carry one credential or the other. A strategy is skipped only when its credential is missing: no `Authorization` header for `JWT`, or no session cookie for `SESSION`. When a credential is present and fails, the request is rejected right away, and later strategies aren't tried. With a single strategy, nothing changes.

| Configured strategies | Request sent | v2.x | v3.x |
| --------------------- | ------------ | ---- | ---- |
| `SESSION`, `JWT` | Session only, CSRF header wrong | 401 | 403 |
| `SESSION`, `JWT` | Both, CSRF header wrong, token valid | 200 | 403 |
| `JWT`, `SESSION` | Both, token expired, session valid | 200 | 401 |
| Any including `JWT` | `Authorization: Basic ...` only | 500 | 401 |
| Either order | Neither | 401 | 401 |

**Key Changes:**
- A request that carries a failing credential no longer falls back to another strategy. If a client sends both a session cookie and a bearer token, the first strategy in your list decides the result.
- Unexpected errors (anything other than an `HTTPException`) are no longer swallowed while trying the next strategy.
- A non-Bearer or malformed `Authorization` header now returns 401 instead of 500, with both `create_jwt_auth_dependency()` and `create_auth_dependency()`.

<br>

### Session and Login State Cookie Encryption

In v2.x, only the first 32 bytes of each secret were used as the encryption key, so characters past 32 added nothing. In v3.x, each key is derived from the whole secret with HKDF-SHA256.

> **⚠️ Important:**
>
> Because the keys change, session cookies and Login State Cookies created by v2.x can't be decrypted by v3.x. When you upgrade, every user is logged out once, and any login in progress during the deploy is sent back to your Login Endpoint.

**Key Changes:**
- `SessionMiddleware` raises a `ValueError` at startup when more than 3 secrets are passed to `secret_key`, which the README already documented as the maximum.
- Session cookies older than the `SessionMiddleware` `max_age` are now rejected, even if a browser still sends them, so a copied session cookie stops working when the session would have expired. Rolling sessions (each `session.save()`) still extend the session.
- Login State Cookies older than 1 hour are now rejected. A Login State Cookie that's too old, tampered with, or encrypted with a different secret now makes `callback()` return a `RedirectRequiredCallbackResult` with the `invalid_login_state` reason, instead of raising `cryptography.fernet.InvalidToken`.

<br>

### Tenant Name and Tenant Custom Domain Validation

In v2.x, the `tenant_name` query parameter was used as-is to build the Wristband host (`https://{tenant_name}-{vanity domain}`). A link like `/auth/login?tenant_name=evil.com%23` redirected the browser straight to `evil.com`, without ever reaching Wristband.

In v3.x, `login()`, `callback()`, and `logout()` ignore any tenant name that isn't a single DNS label (letters, digits, and inner hyphens, up to 63 characters), as if no tenant name was passed. Tenant custom domains must be a valid hostname with no port, path, or credentials. This applies to:
- The `tenant_name` query parameter and the tenant subdomain
- `LoginConfig.default_tenant_name` and `LoginConfig.default_tenant_custom_domain`
- `LogoutConfig.tenant_name` and `LogoutConfig.tenant_custom_domain`
- The `tenant_custom_domain` query parameter, which now skips the Validate Custom Domain API call when it fails the check

**Key Changes:**
- No change is needed if your tenant names and tenant custom domains are valid DNS names, which Wristband requires.
- An invalid value falls through to the next option in the domain priority order, and eventually to the application-level flow. In `callback()`, an invalid `tenant_name` raises the existing `missing_tenant_name` error.

<br>

### refresh_token_if_expired() Changes

**Key Changes:**
- When Wristband rejects the refresh token with `invalid_grant`, `refresh_token_if_expired()` now raises `WristbandError` with the `invalid_refresh_token` error code, like every other 4xx error. In v2.x it re-raised `InvalidGrantError`. If you catch `InvalidGrantError` around this method, catch `WristbandError` and check for `invalid_refresh_token` instead.
- The token is refreshed once the current time reaches `expires_at` (`now >= expires_at`). In v2.x it was only refreshed 1ms later.
- An `expires_at` of `0` is now treated as an expiration in the past, so the token is refreshed. In v2.x it raised a `TypeError`. A missing or negative value still raises a `TypeError`.

<br>

### Other Behavior Changes

**Key Changes:**
- **Return URL length:** The 450-character limit on return URLs has been removed. Return URLs are kept in the Login State Cookie at any length. A return URL is only dropped when it's over 512 characters and has to go in the Application-Level Login (Tenant Discovery) Page `state` query parameter, which Wristband limits to 512 characters.
- **Logout URL encoding:** `LogoutConfig.redirect_url` and `LogoutConfig.state` are now URL-encoded in the Wristband Logout URL. In v2.x, a `redirect_url` with its own query string broke the URL. Remove any manual encoding you added to work around it, or the value will be encoded twice.
- **Logout state validation:** A `LogoutConfig.state` over 512 characters still raises a `ValueError`, but now before anything else happens. In v2.x the refresh token was revoked first.
- **JWKS cache TTL:** `jwks_cache_ttl` is in milliseconds. The v2.x README documented it in seconds, so a value of `3600` cached keys for 3.6 seconds. Multiply your value by 1000 if you followed the README (e.g. `3600000` for 1 hour), or leave it unset to keep keys cached until they're evicted by size.

<br>

## Recommended Updates

### Automatic No-Cache Headers

Any response that writes or deletes a session cookie now automatically includes `Cache-Control: no-store` and `Pragma: no-cache`. This prevents browsers and shared caches (such as CDNs and proxies) from storing a response that carries a user's session cookie and serving it to someone else. In v2.x, apps were solely responsible for setting these headers. For security, the SDK now sets them itself, so a forgotten header can no longer leave a session cookie cacheable.

The no-cache headers that v2.x recommended adding to your Session Endpoint and Token Endpoint can now be removed.

**v2.x:**
```python
@router.get("/session")
async def get_session_response(
-   response: Response,
    session: Session = Depends(require_session_auth)
) -> SessionResponse:
-   response.headers["Cache-Control"] = "no-store"
-   response.headers["Pragma"] = "no-cache"
    return session.get_session_response(metadata={ "foo": "bar" })
```

**v3.x:**
```python
@router.get("/session")
async def get_session_response(session: Session = Depends(require_session_auth)) -> SessionResponse:
    return session.get_session_response(metadata={ "foo": "bar" })
```

The same applies to your Token Endpoint:

**v2.x:**
```python
@router.get("/token")
async def get_token_response(
-   response: Response,
    session: Session = Depends(require_session_auth)
) -> TokenResponse:
-   response.headers["Cache-Control"] = "no-store"
-   response.headers["Pragma"] = "no-cache"
    return session.get_token_response()
```

**v3.x:**
```python
@router.get("/token")
async def get_token_response(session: Session = Depends(require_session_auth)) -> TokenResponse:
    return session.get_token_response()
```

**Key Changes:**
- `require_session_auth` (and the `AuthStrategy.SESSION` strategy of `require_auth`) saves the session on every request it authenticates (rolling sessions), so those responses always include the headers
- `session.save()` and `session.clear()` set the headers on the response when the `SessionMiddleware` writes or deletes the session cookies
- Requests authenticated with the JWT strategy do not write cookies, so those responses do not get the headers automatically
- Manually set `Cache-Control` and `Pragma` headers can be removed only from routes that save or clear the session on every request, such as routes protected by `require_session_auth`. Keep them on any route that only sometimes saves or clears the session, or that never does, since those responses do not get the headers automatically.

> **⚠️ Important:**
>
> Existing `Cache-Control` and `Pragma` values on the response are replaced, not merged. If your app sets a custom `Cache-Control` value on a response that also saves or clears the session, that value is now replaced with `no-store`.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
