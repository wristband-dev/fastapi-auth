<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instructions from version 0.x to version 1.x
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

# Migration Instructions from Version 0.x to Version 1.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 1.x

<br>

## Table of Contents

- [Model Field Name Changes](#model-field-name-changes)
  - [default_tenant_domain_name renamed to default_tenant_name](#default_tenant_domain_name-renamed-to-default_tenant_name)
  - [tenant_domain_name renamed to tenant_name](#tenant_domain_name-renamed-to-tenant_name)
- [UserInfo Model Changes](#userinfo-model-changes)

<br>

## Model Field Name Changes

### `default_tenant_domain_name` renamed to `default_tenant_name`

The field `default_tenant_domain_name` has been renamed to `default_tenant_name` in the `LoginConfig` model.

```python
from wristband_fastapi_auth import LoginConfig

response = await wristband_auth.login(
    request=request,
-   config=LoginConfig(default_tenant_domain_name="default")
+   config=LoginConfig(default_tenant_name="default")
)
```

<br>

### `tenant_domain_name` renamed to `tenant_name`

The field `tenant_domain_name` has been renamed to `tenant_name` in the `CallbackData` and `LogoutConfig` models.

**CallbackData:**
```python
callback_result = await wristband_auth.callback(request)

if callback_result.type == CallbackResultType.COMPLETED:
-   tenant_name = callback_result.callback_data.tenant_domain_name
+   tenant_name = callback_result.callback_data.tenant_name
```

**LogoutConfig:**
```python
from wristband_fastapi_auth import LogoutConfig

response = await wristband_auth.logout(
    request=request,
    config=LogoutConfig(
        refresh_token="98yht308hf902hc90wh09",
-       tenant_domain_name="customer01"
+       tenant_name="customer01"
    )
)
```

<br>

## UserInfo Model Changes

The `user_info` field in `CallbackData` is now a fully typed Pydantic model (`UserInfo`) instead of a dictionary. Field names are mapped from Wristband UserInfo API claim names to match the User entity field names in Wristband's Resource Management API.

```python
callback_result = await wristband_auth.callback(request)

if callback_result.type == CallbackResultType.COMPLETED:
-   # Dictionary access with OIDC claim names (v0.x)
-   user_id = callback_result.callback_data.user_info["sub"]
-   tenant_id = callback_result.callback_data.user_info["tnt_id"]
-   email = callback_result.callback_data.user_info["email"]
-   full_name = callback_result.callback_data.user_info.get("name")
-   roles = callback_result.callback_data.user_info.get("tnt_roles", [])

+   # Typed model access with User entity field names (v1.x)
+   user_id = callback_result.callback_data.user_info.user_id
+   tenant_id = callback_result.callback_data.user_info.tenant_id
+   email = callback_result.callback_data.user_info.email
+   full_name = callback_result.callback_data.user_info.full_name
+   roles = callback_result.callback_data.user_info.roles  # List[UserInfoRole]
+
+   # Access role fields
+   if roles:
+       role_id = roles[0].id
+       role_name = roles[0].name
+       display_name = roles[0].display_name
```

Key mapping changes:

- `sub` → `user_id`
- `tnt_id` → `tenant_id`
- `app_id` → `application_id`
- `idp_name` → `identity_provider_name`
- `name` → `full_name`
- `preferred_username` → `display_name`
- `picture` → `picture_url`
- `zoneinfo` → `time_zone`

See the [callback() documentation](../../README.md#async-def-callbackself-request-request---callbackresult) for the complete `UserInfo` and `UserInfoRole` model definitions.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
