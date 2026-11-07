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
