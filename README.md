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

# Wristband Multi-Tenant Authentication SDK for Express

[![npm package](https://img.shields.io/badge/npm%20i-express--auth-brightgreen)](https://www.npmjs.com/package/@wristband/express-auth)
[![version number](https://img.shields.io/github/v/release/wristband-dev/express-auth?color=green&label=version)](https://github.com/wristband-dev/express-auth/releases)
[![Actions Status](https://github.com/wristband-dev/express-auth/workflows/Test/badge.svg)](https://github.com/wristband-dev/express-auth/actions)
[![License](https://img.shields.io/github/license/wristband-dev/express-auth)](https://github.com/wristband-dev/express-auth/blob/main/LICENSE.md)

This module facilitates seamless interaction with Wristband for user authentication within multi-tenant [Express applications](https://expressjs.com). It follows OAuth 2.1 and OpenID standards. It supports both CommonJS and ES Modules and includes TypeScript declaration files.

Key functionalities encompass the following:

- Initiating a login request by redirecting to Wristband.
- Receiving callback requests from Wristband to complete a login request.
- Retrieving all necessary JWT tokens and userinfo to start an application session.
- Logging out a user from the application by revoking refresh tokens and redirecting to Wristband.
- Checking for expired access tokens and refreshing them automatically, if necessary.

You can learn more about how authentication works in Wristband in our documentation:

- [Auth Flows Walkthrough](https://docs.wristband.dev/docs/auth-flows-and-diagrams)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

---

## Table of Contents

- [Migrating From Older SDK Versions](#migrating-from-older-sdk-versions)
- [Installation](#installation)
- [Usage](#usage)
  - [1) Initialize the SDK](#1-initialize-the-sdk)
  - [2) Choose Your Session Storage](#2-choose-your-session-storage)
  - [3) Add Auth Endpoints](#3-add-auth-endpoints)
    - [Login Endpoint](#login-endpoint)
    - [Callback Endpoint](#callback-endpoint)
    - [Logout Endpoint](#logout-endpoint)
  - [4) Guard Your Non-Auth APIs and Handle Token Refresh](#4-guard-your-non-auth-apis-and-handle-token-refresh)
  - [5) Pass Your Access Token to Downstream APIs](#5-pass-your-access-token-to-downstream-apis)
- [Wristband Auth Configuration Options](#wristband-auth-configuration-options)
- [API](#api)
  - [Login](#loginreq-request-res-response-config-loginconfig-promisestring)
  - [Callback](#callbackreq-request-res-response-promisecallbackresult)
  - [Logout](#logoutreq-request-res-response-config-logoutconfig-promisestring)
  - [RefreshTokenIfExpired](#refreshtokenifexpiredrefreshtoken-string-expiresat-number-promisetokendata--null)
- [Questions](#questions)

<br/>

## Migrating From Older SDK Versions

On an older version of our SDK? Check out our migration guide:

- [Instructions for migrating to Version 4.x](migration/v4/README.md)
- [Instructions for migrating to Version 3.x](migration/v3/README.md)

<br>

## Installation

```sh
npm install @wristband/express-auth
```

or 

```sh
yarn add @wristband/express-auth
```

## Usage

### 1) Initialize the SDK
First, create an instance of `WristbandAuth` in your Express directory structure in any location of your choice (i.e. `src/wristband-auth.js`). Then, you can export this instance and use it across your project. When creating an instance, you provide all necessary configurations for your application to correlate with how you've set it up in Wristband. 

```typescript
// ESModules
import { createWristbandAuth } from '@wristband/express-auth';
// CommonJS
// const { createWristbandAuth } = require('@wristband/express-auth');

const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://{tenant_domain}.yourapp.io/auth/login",
  redirectUri: "https://{tenant_domain}.yourapp.io/auth/callback",
  parseTenantFromRootDomain: "yourapp.io",
  isApplicationCustomDomainActive: true,
  wristbandApplicationVanityDomain: "auth.yourapp.io",
});

// ESModules
export default wristbandAuth;
// CommonJS
// module.exports = wristbandAuth; 
```

### 2) Choose Your Session Storage

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. We typically recommend cookie-based sessions due to it being lighter-weight and not requiring a backend session store like Redis or other technologies.  We are big fans of <ins>[Iron Session](https://github.com/vvo/iron-session)</ins> for this reason. Examples below show what it might look like when using such a library to manage your application's session data.

> [!NOTE]
> <ins>[Express Session](https://github.com/expressjs/session)</ins> is typically the choice for Express applications that need server-side sessions.

Wherever you initialize your Express application, add your session framework:

```typescript
import express from 'express';
import { getIronSession } from 'iron-session';

// Initialize Express app
const app = express();

// Middleware to initialize Iron Session cookie-based sessions for the application (can be moved to its own file).
const ironSession = function (sessionOptions) {
  return async function ironSessionMiddleware(req, res, next) {
    req.session = await getIronSession(req, res, sessionOptions);
    next();
  };
};

// 30 minute cookie-based session
app.use(
  ironSession({
    cookieName: 'my-session-cookie-name',
    password: '983hr8f9rbgu9bfi9ewbefd8ewhf89ew',
    cookieOptions: {
      httpOnly: true,
      maxAge: 1800,
      path: '/',
      sameSite: true,
      secure: true,
    },
  })
);

...
...
```

### 3) Add Auth Endpoints

There are <ins>three core API endpoints</ins> your Express server should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to wherever your Express routes/controllers are.

#### [Login Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#login-endpoint)

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```typescript
import { wristbandAuth } from './wristband-auth.js';

// Login Endpoint - Route path can be whatever you prefer
app.get('/auth/login', async (req, res) => {
  try {
    const loginUrl = await wristbandAuth.login(req, res, { /* Optional login configs */ });
    res.redirect(loginUrl);
  } catch (error) {
    // Handle error
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
```

#### [Callback Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#callback-endpoint)

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```typescript
import type { CallbackResultType } from '@wristband/express-auth';
import { wristbandAuth } from './wristband-auth.js';

// Callback Endpoint - Route path can be whatever you prefer
app.get('/auth/callback', async (req, res) => {
  try {
    const callbackResult = await wristbandAuth.callback(req, res);
    const { callbackData, redirectUrl, type } = callbackResult;
    
    // For certain edge cases, the SDK will require you to redirect back to login.
    if (type === CallbackResultType.REDIRECT_REQUIRED) {
      return res.redirect(redirectUrl);
    }

    // If the SDK determines no redirect is required, then we can save any necessary fields for the user's app session into a session cookie.
    // Store a simple flag to indicate the user has successfully authenticated.
    req.session.isAuthenticated = true;
    req.session.accessToken = callbackData.accessToken;
    // Convert the "expiresIn" seconds into a Unix timestamp in milliseconds at which the token expires.
    req.session.expiresAt = Date.now() + callbackData.expiresIn * 1000;
    req.session.refreshToken = callbackData.refreshToken;
    req.session.userId = callbackData.userinfo.sub;
    req.session.tenantId = callbackData.userinfo.tnt_id;
    req.session.identityProviderName = callbackData.userinfo.idp_name;
    req.session.tenantDomainName = callbackData.tenantDomainName;

    await req.session.save();

    // Send the user back to the application.
    return res.redirect(callbackData.returnUrl || `https://${callbackData.tenantDomainName}.yourapp.io/`);
  } catch (error) {
    // Handle error
    console.error(error);
    return res.status(500).send('Internal Server Error');
  }
});
```

#### [Logout Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#logout-endpoint-1)

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).


```typescript
import { wristbandAuth } from './wristband-auth.js';

// Logout Endpoint - Route path can be whatever you prefer
app.get('/auth/logout', async (req, res) => {
  const { refreshToken, tenantDomainName } = session;

  // Always destroy your application's session.
  res.clearCookie('my-session-cookie-name');
  req.session.destroy();

  try {
    const logoutUrl = await wristbandAuth.logout(req, res, { tenantDomainName, refreshToken });
    res.redirect(logoutUrl);
  } catch (error) {
    // Handle error
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
```

### 4) Guard Your Non-Auth APIs and Handle Token Refresh

> [!NOTE]
> There may be applications that do not want to utilize access tokens and/or refresh tokens. If that applies to your application, then you can ignore using the `refreshTokenIfExpired()` functionality.

Create a middleware somewhere in your project to check that your session is still valid. It must check if the access token is expired and perform a token refresh if necessary. The Wristband SDK will make 3 attempts to refresh the token and return the latest JWTs to your server.


```typescript
import { wristbandAuth } from './wristband-auth.js';

// Middleware that ensures there is an authenticated user session and JWTs are not expired.
const authMiddleware = async function (req, res, next) {
  const { expiresAt, isAuthenticated, refreshToken } = req.session;
  if (!isAuthenticated) {
    return res.status(401).send();
  }

  try {
    const tokenData = await wristbandAuth.refreshTokenIfExpired(refreshToken, expiresAt);
    if (tokenData) {
      req.session.accessToken = tokenData.accessToken;
      // Convert the "expiresIn" seconds into a Unix timestamp in milliseconds at which the token expires.
      req.session.expiresAt = Date.now() + tokenData.expiresIn * 1000;
      req.session.refreshToken = tokenData.refreshToken;
    }

    // Save the session in order to "touch" it (even if there is no new token data).
    await req.session.save();
    return next();
  } catch (error) {
    console.error(`Failed to refresh token due to: ${error}`);
    return res.status(401).send();
  }
};

export default authMiddleware;
```

Now import your auth middleware and use it for any routes that must be protected with an authenticated session.

```typescript
import { authMiddleWare } from './auth-middleware.js';

// All APIs that are called from an unauthenticated state.
app.get('/auth/login', () => { ... });
app.get('/auth/callback', () => { ... });
app.get('/auth/logout', () => { ... });

// Protect any routes that require an authenticated session.
app.use('/api', authMiddleware, apiRoutes);
```

### 5) Pass Your Access Token to Downstream APIs

> [!NOTE]
> This is only applicable if you wish to call Wristband's APIs directly or protect your application's other downstream backend APIs.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```
Authorization: Bearer <access_token_value>
```

For example, if you were using Axios to make API calls to other services, you would pass the access token from your application session into the `Authorization` header as follows:

```typescript
// You could pull this function into a utils file and use it across your project.
const bearerToken = function(req) {
  return { headers: { Authorization: `Bearer ${req.session.accessToken}` } };
};

// Pass your access token in the request to downstream APIs
app.post('/orders', async (req, res, next) => {
  try {
    // Fictional example + pseudocode
    const newOrder = { ...req.body };
    db.save(newOrder)
    await axios.post('/email-receipt', newOrder, bearerToken(req));
    return res.status(200).send();
  } catch (error) {
    // Handle error
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
```

## Wristband Auth Configuration Options

The `createWristbandAuth()` function is used to instatiate the Wristband SDK.  It takes an `AuthConfig` type as an argument.

```ts
function createWristbandAuth(authConfig: AuthConfig): WristbandAuth {}
```

| AuthConfig Field | Type | Required | Description |
| ---------------- | ---- | -------- | ----------- |
| clientId | string | Yes | The ID of the Wristband client. |
| clientSecret | string | Yes | The client's secret. |
| customApplicationLoginPageUrl | string | No | Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value only needs to be provided if you are self-hosting the application login page. By default, the SDK will use your Wristband-hosted Application-Level Login page URL. If this value is provided, the SDK will redirect to this URL in certain cases where it cannot resolve a proper Tenant-Level Login URL.               |
| dangerouslyDisableSecureCookies | boolean | No | USE WITH CAUTION: If set to `true`, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development environments that don't have HTTPS enabed.  If not provided, this value defaults to `false`. |
| isApplicationCustomDomainActive | boolean | No | Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `defaultTenantCustomDomain` config.  Defaults to `false`. |
| loginStateSecret | string | Yes | A 32 byte (or longer) secret used for encryption and decryption of login state cookies. You can run `openssl rand -base64 32` to create a secret from your CLI. |
| loginUrl | string | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow. If you intend to use tenant subdomains in your Login Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/login`. |
| parseTenantFromRootDomain | string | Only if using tenant subdomains in your application | The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `defaultTenantCustomDomain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL. |
| redirectUri | string | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint. If you intend to use tenant subdomains in your Callback Endpoint URL, then this value must contain the `{tenant_domain}` token. For example: `https://{tenant_domain}.yourapp.com/auth/callback`. |
| scopes | string[] | No | The scopes required for authentication. Refer to the docs for [currently supported scopes](https://docs.wristband.dev/docs/oauth2-and-openid-connect-oidc#supported-openid-scopes). The default value is `[openid, offline_access, email]`. |
| wristbandApplicationVanityDomain | string | Yes | The vanity domain of the Wristband application. |

## API

### `login(req: Request, res: Response, config?: LoginConfig): Promise<string>`

```ts
await login(req, res);
```

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When the frontend of your application redirects the user to your Express Login Endpoint, there are two ways to accomplish getting the `tenantDomainName` information: passing a query parameter or using tenant subdomains.

The `login()` function can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| customState | JSON | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| defaultTenantDomainName | string | No | An optional default tenant domain name to use for the login request in the event the tenant domain cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| defaultTenantCustomDomain | string | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |

#### Which Domains Are Used in the Authorize URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if `parseTenantFromRootDomain` is specified and there is a subdomain present in the host.
3. `tenant_domain` query parameter: Evaluated if no tenant subdomain is found in the host.
4. `defaultTenantCustomDomain` in LoginConfig: Used if none of the above are present.
5. `defaultTenantDomain` in LoginConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Tenant Domain Query Param

If your application does not wish to utilize subdomains for each tenant, you can pass the `tenant_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_domain=customer01
```

Your AuthConfig would look like the following when creating an SDK instance without any subdomains:

```ts
const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://yourapp.io/auth/login",
  redirectUri: "https://yourapp.io/auth/callback",
  wristbandApplicationVanityDomain: "yourapp-yourcompany.us.wristband.dev",
});
```

#### Tenant Subdomains

If your application wishes to utilize tenant subdomains, then you do not need to pass a query param when redirecting to your Express Login Endpoint. The SDK will parse the tenant subdomain from the host in order to make the redirection to the Wristband Authorize Endpoint. You will also need to tell the SDK what your application's root domain is in order for it to correctly parse the subdomain.

```sh
GET https://customer01.yourapp.io/auth/login
```

Your AuthConfig would look like the following when creating an SDK instance when using subdomains:

```ts
const wristbandAuth = createWristbandAuth({
  clientId: "ic6saso5hzdvbnof3bwgccejxy",
  clientSecret: "30e9977124b13037d035be10d727806f",
  loginStateSecret: '7ffdbecc-ab7d-4134-9307-2dfcc52f7475',
  loginUrl: "https://{tenant_domain}.yourapp.io/auth/login",
  redirectUri: "https://{tenant_domain}.yourapp.io/auth/callback",
  parseTenantFromRootDomain: "yourapp.io",
  wristbandApplicationVanityDomain: "yourapp-yourcompany.us.wristband.dev",
});
```

#### Default Tenant Domain Name

For certain use cases, it may be useful to specify a default tenant domain in the event that the `login()` function cannot find a tenant domain in either the query parameters or in the URL subdomain. You can specify a fallback default tenant domain via a `LoginConfig` object:

```ts
const loginUrl = await wristbandAuth.login(req, res, { defaultTenantDomainName: 'default' });
res.redirect(loginUrl);
```

#### Tenant Custom Domain Query Param

If your application wishes to utilize tenant custom domains, you can pass the `tenant_custom_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_custom_domain=mytenant.com
```

The tenant custom domain takes precedence over all other possible domains else when present.

#### Default Tenant Custom Domain

For certain use cases, it may be useful to specify a default tenant custom domain in the event that the `login()` function cannot find a tenant custom domain in the query parameters. You can specify a fallback default tenant custom domain via a `LoginConfig` object:

```ts
const loginUrl = await wristbandAuth.login(req, res, { defaultTenantCustomDomain: 'mytenant.com' });
res.redirect(loginUrl);
```

The default tenant custom domain takes precedence over all other possible domain configurations when present except for the case where the `tenant_custom_domain` query parameter exists in the request.

#### Custom State

Before your Login Endpoint redirects to Wristband, it will create a Login State Cookie to cache all necessary data required in the Callback Endpoint to complete any auth requests. You can inject additional state into that cookie via a `LoginConfig` object:

```ts
const loginUrl = await wristbandAuth.login(req, res, { customState: { test: 'abc' } });
res.redirect(loginUrl);
```

> [!WARNING]
> Injecting custom state is an advanced feature, and it is recommended to use `customState` sparingly. Most applications may not need it at all. The max cookie size is 4kB. From our own tests, passing a `customState` JSON of at most 1kB should be a safe ceiling.

#### Login Hints

Wristband will redirect to your Express Login Endpoint for workflows like Application-Level Login (Tenant Discovery) and can pass the `login_hint` query parameter as part of the redirect request:

```sh
GET https://customer01.yourapp.io/auth/login?login_hint=user@wristband.dev
```

If Wristband passes this parameter, it will be appended as part of the redirect request to the Wristband Authorize Endpoint. Typically, the email form field on the Tenant-Level Login page is pre-filled when a user has previously entered their email on the Application-Level Login Page.

#### Return URLs

It is possible that users will try to access a location within your application that is not some default landing page. In those cases, they would expect to immediately land back at that desired location after logging in.  This is a better experience for the user, especially in cases where they have application URLs bookmarked for convenience.  Given that your frontend will redirect users to your Express Login Endpoint, you can pass a `return_url` query parameter when redirecting to your Login Endpoint, and that URL will be available to you upon completion of the Callback Endpoint.

```sh
GET https://customer01.yourapp.io/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and you can choose to send users to that return URL (if necessary) after the SDK's `callback()` funciton is done executing.

### `callback(req: Request, res: Response): Promise<CallbackResult>`

```ts
const callbackResult = await callback(req, res);
```

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your Express Callback Endpoint with an authorization code which can be used to exchange for an access token. It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration. The return type of the callback function is a CallbackResult object containing the result of what happened during callback execution as well as any accompanying data:

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| callbackData | `CallbackData` | The callback data received after authentication (`COMPLETED` result only). |
| redirectUrl | string | A URL that you need to redirect to (`REDIRECT_REQUIRED` result only). For some edge cases, the SDK will require a redirect to restart the login flow. |
| type | `CallbackResultType`  | Enum representing the type of the callback result. |

The following are the possible `CallbackResultType` enum values that can be returned from the callback execution:

| CallbackResultType  | Description |
| ------------------- | ----------- |
| `COMPLETED`  | Indicates that the callback is successfully completed and data is available for creating a session. |
| `REDIRECT_REQUIRED`  | Indicates that a redirect to the login endpoint is required. |

When the callback returns a `COMPLETED` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application. The `CallbackData` is defined as follows:


| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| accessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| customState | JSON or `undefined` | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| expiresIn | number | The durtaion from the current time until the access token is expired (in seconds). |
| idToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| refreshToken | string or `undefined` | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| returnUrl | string or `undefined` | The URL to return to after authentication is completed. |
| tenantCustomDomain | string | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenantDomainName | string | The domain name of the tenant the user belongs to. |
| userinfo | JSON | Data for the current user retrieved from the Wristband Userinfo Endpoint. The data returned in this object follows the format laid out in the [Wristband Userinfo Endpoint documentation](https://docs.wristband.dev/reference/userinfov1). The exact fields that get returned are based on the scopes you configured in the SDK. |


#### Redirect Responses

There are certain scenarios where a redirect URL is returned by the SDK. The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of where the user gets redirected to in these scenarios depends on if the application is using tenant subdomains and if the SDK is able to determine which tenant the user is currently attempting to log in to. The resolution happens in the following order:

1. If the tenant domain can be determined, then the user will get redirected back to your Express Login Endpoint.
2. Otherwise, the user will be sent to the Wristband-hosted Tenant-Level Login Page URL.

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


### `logout(req: Request, res: Response, config?: LogoutConfig): Promise<string>`

```ts
const logoutUrl = await logout(req, res, { refreshToken: '98yht308hf902hc90wh09' });
res.redirect(logoutUrl);
```

When users of your application are ready to log out or their application session expires, your frontend should redirect the user to your Express Logout Endpoint.

```sh
GET https://customer01.yourapp.io/auth/logout
```

If your application created a session, it should destroy it before invoking the `logout()` function.  This function can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ------------------ | ---- | -------- | ----------- |
| redirectUrl | string | No | Optional URL that Wristband will redirect to after the logout operation has completed. This will also take precedence over the `customApplicationLoginPageUrl` (if specified) in the SDK AuthConfig if the tenant domain cannot be determined when attempting to redirect to the Wristband Logout Endpoint. |
| refreshToken | string | No | The refresh token to revoke. |
| tenantCustomDomain | string | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| tenantDomainName | string | No | The domain name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your login endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `tenantCustomDomain` in LogoutConfig: If provided, this takes top priority.
2. `tenantDomainName` in LogoutConfig: This takes the next priority if `tenantCustomDomain` is not present.
3. `tenant_custom_domain` query parameter: Evaluated if present and there is also no LogoutConfig provided for either `tenantCustomDomain` or `tenantDomainName`.
4. Tenant subdomain in the URL: Used if none of the above are present, and `parseTenantFromRootDomain` is specified, and the subdomain is present in the host.
5. `tenant_domain` query parameter: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `logout()` function, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domain Names

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you can either explicitly pass it into the LogoutConfig:

```ts
const logoutUrl = await logout(req, res, config: { refreshToken: '98yht308hf902hc90wh09', tenantDomainName: 'customer01' });
res.redirect(logoutUrl);
```

...or you can alternatively pass the `tenant_domain` query parameter in your redirect request to Logout Endpoint:

```ts
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_domain=customer01"
//
const logoutUrl = await logout(req, res, config: { refreshToken: '98yht308hf902hc90wh09' });
res.redirect(logoutUrl);
```

If your application uses tenant subdomains, then passing the `tenantDomainName` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL as long as the `parseTenantFromRootDomain` SDK config is set.

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you can either explicitly pass it into the LogoutConfig:

```ts
const logoutUrl = await logout(req, res, { refreshToken: '98yht308hf902hc90wh09', tenantCustomDomain: 'mytenant.com' });
res.redirect(logoutUrl);
```

...or you can alternatively pass the `tenant_custom_domain` query parameter in your redirect request to Logout Endpoint:

```ts
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_custom_domain=customer01.com"
//
const logoutUrl = await logout(req, res, config: { refreshToken: '98yht308hf902hc90wh09' });
res.redirect(logoutUrl);
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then you should consider passing both the tenant domain names and tenant custom domains (either via LogoutConfig or by query parameters) to ensure all use cases are handled by the SDK.

**Pass tenant domains and custom domains in LogoutConfig**
```ts
const { refreshToken, tenantCustomDomain, tenantDomainName } = session;

const logoutUrl = await logout(req, res, { refreshToken, tenantCustomDomain, tenantDomainName });
res.redirect(logoutUrl);
```

**Pass tenant domains and custom domains in LogoutConfig**
```ts
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_custom_domain=customer01.com&tenant_domain=customer01"
//
const { refreshToken } = session;

const logoutUrl = await logout(req, res, { refreshToken });
res.redirect(logoutUrl);
```

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `redirectUrl` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```ts
const logoutConfig = {
  redirectUrl: 'https://custom-logout.com',
  refreshToken: '98yht308hf902hc90wh09',
  tenantDomainName: 'customer01'
};
const logoutUrl = await logout(req, res, logoutConfig);
res.redirect(logoutUrl);
```

### `refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null>`

```ts
const tokenData = await refreshTokenIfExpired('98yht308hf902hc90wh09', 1710707503788);
```

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| expiresAt | number | Yes | Unix timestamp in milliseconds at which the token expires. |
| refreshToken | string | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If the `refreshTokenIfExpired()` functions finds that your token has not expired yet, it will return `null` as the value, which means your auth middleware can simply continue forward as usual.

<br>

## Wristband Multi-Tenant Express Demo App

You can check out the [Wristband B2B Express demo app](https://github.com/wristband-dev/b2b-expressjs-demo-app) to see this SDK in action. Refer to that GitHub repository for more information.

<br/>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
