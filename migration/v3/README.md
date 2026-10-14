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
      <a href="https://docs.wristband.dev/">Documentation</a>
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

- [Application-Level Authorization Requests Enabled by Default](#application-level-authorization-requests-enabled-by-default)
- [Tenant Domain URL Placeholder Removed](#tenant-domain-url-placeholder-removed)
- [parse_tenant_from_root_domain Config Removed](#parse_tenant_from_root_domain-config-removed)
- [Return URL Validation in callback()](#return-url-validation-in-callback)
- [Login State Cookie Changes](#login-state-cookie-changes)

<br>

## Application-Level Authorization Requests Enabled by Default

The SDK now supports Application-Level Authorization Requests through the `application_authorization_requests_enabled` config. It is auto-configured from your Application's settings in the Wristband Dashboard, and it defaults to `True`. This lets third-party platforms and SDKs that require a single, static Authorization Endpoint URL (e.g. Supabase) use one fixed URL in addition to per-tenant URLs.

This only changes behavior when `login()` or `logout()` cannot resolve a tenant from the request (no tenant subdomain, `tenant_name` or `tenant_custom_domain` query parameter, or default tenant):

- `login()` redirects to the Wristband Authorize Endpoint on your application's vanity domain, and Wristband handles tenant discovery within that same authorization flow. The return URL is preserved in the Login State Cookie. In 2.x, `login()` redirected to the Application-Level Login (Tenant Discovery) Page.
- `logout()`, when no `redirect_url` is set in `LogoutConfig`, redirects back to your application's own Login Endpoint to start a new app-level flow. That is your `login_url` with the `{tenant_name}` subdomain removed if it contains the placeholder, or your `login_url` as is otherwise.
- `custom_application_login_page_url` has no effect on `login()` or `logout()`.
- When `login_url` contains the `{tenant_name}` placeholder, the Login State Cookie is set on your root domain (e.g. `.yourapp.io`) in both the app-level and tenant-level login flows, and `create_callback_response()` clears it with the same domain.

To keep the 2.x behavior, turn the setting off on your Application's Settings page in the Wristband Dashboard, or set it in your SDK config:

```python
auth_config = AuthConfig(
    # ... other config
+   application_authorization_requests_enabled=False,
)
```

<br>

## Tenant Domain URL Placeholder Removed

The `{tenant_domain}` placeholder has been removed. `{tenant_name}` is now the only supported tenant placeholder in `login_url` and `redirect_uri`.

**Before (2.x):**
```python
auth_config = AuthConfig(
    # ... other config
-   login_url="https://{tenant_domain}.yourapp.com/auth/login",
-   redirect_uri="https://{tenant_domain}.yourapp.com/auth/callback",
)
```

**After (3.x):**
```python
auth_config = AuthConfig(
    # ... other config
+   login_url="https://{tenant_name}.yourapp.com/auth/login",
+   redirect_uri="https://{tenant_name}.yourapp.com/auth/callback",
)
```

<br>

## parse_tenant_from_root_domain Config Removed

The `parse_tenant_from_root_domain` config has been removed from `AuthConfig`. Tenant subdomain parsing is now enabled whenever `login_url` contains the `{tenant_name}` placeholder, and the SDK determines the root domain from `login_url` by removing the `{tenant_name}` subdomain.

**Before (2.x):**
```python
auth_config = AuthConfig(
    # ... other config
    login_url="https://{tenant_name}.yourapp.com/auth/login",
    redirect_uri="https://{tenant_name}.yourapp.com/auth/callback",
-   parse_tenant_from_root_domain="yourapp.com",
)
```

**After (3.x):**
```python
auth_config = AuthConfig(
    # ... other config
    login_url="https://{tenant_name}.yourapp.com/auth/login",
    redirect_uri="https://{tenant_name}.yourapp.com/auth/callback",
)
```

**Key Changes:**
1. Remove `parse_tenant_from_root_domain` from your SDK config
2. The root domain is derived from `login_url` (e.g. `https://{tenant_name}.yourapp.com/auth/login` gives a root domain of `yourapp.com`)
3. If your app relies on auto-configuration and never set `parse_tenant_from_root_domain`, no change is needed

> **⚠️ Important:**
>
> The `{tenant_name}` placeholder must appear exactly once in `login_url` and `redirect_uri`, as the leftmost part of the hostname. Either both URLs contain the placeholder or neither does.

<br>

## Return URL Validation in callback()

`callback()` now validates the return URL before including it in the returned callback data. In 2.x, the return URL was passed through unchanged. A return URL that fails validation is now left out of the callback data, and the flow continues without it.

**Before (2.x):**
```python
# Login request: /auth/login?return_url=https://otherapp.com/dashboard
callback_result = await wristband_auth.callback(request)

if callback_result.type == CallbackResultType.COMPLETED:
    return_url = callback_result.callback_data.return_url
-   # return_url == "https://otherapp.com/dashboard"
-   return await wristband_auth.create_callback_response(request, return_url)
```

**After (3.x):**
```python
# Login request: /auth/login?return_url=https://otherapp.com/dashboard
callback_result = await wristband_auth.callback(request)

if callback_result.type == CallbackResultType.COMPLETED:
    return_url = callback_result.callback_data.return_url
+   # return_url is None (the host does not match the request host or the root domain)
+   return await wristband_auth.create_callback_response(request, return_url or "/home")
```

**Key Changes:**
1. Relative paths (e.g. `/settings`) resolve against the current request's host
2. The scheme must match the request's scheme, which blocks downgrades like `https` to `http`
3. The hostname must be either the root domain (when `login_url` contains the `{tenant_name}` placeholder) or the request's host
4. When application-level authorization requests are enabled and `login_url` contains the `{tenant_name}` placeholder, a return URL on the bare root domain is rewritten to the tenant's subdomain (e.g. `yourapp.com` to `acme.yourapp.com`)

> **⚠️ Important:**
>
> Make sure your Callback Endpoint has a default redirect location for when `return_url` is not present, since a return URL that worked in 2.x may now be left out.

<br>

## Login State Cookie Changes

No code or config changes are needed for the following:

1. The Login State Cookie's 1-hour lifetime is now also enforced when decrypting, with a 60-second clock skew tolerance.
2. When the Login State Cookie cannot be decrypted (tampered, expired, or encrypted with a different secret), `callback()` no longer raises an exception. It returns a `REDIRECT_REQUIRED` result with the `INVALID_LOGIN_STATE` reason, and `create_callback_response()` clears the cookie.

> **⚠️ Important:**
>
> If your Callback Endpoint already handles the `REDIRECT_REQUIRED` result type, no change is needed.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
