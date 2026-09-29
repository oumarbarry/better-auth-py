---
title: OAuth Provider
---

# OAuth Provider

Turns your app into an OAuth 2.1 / OIDC authorization server: client
registration and management, authorize and consent, every token grant,
introspection, userinfo, revocation, end-session and back-channel logout.
Covers RFC 6749, 7009, 7523 (`private_key_jwt`), 7591, 7636, 7662, 8707
(resource indicators) and 9449 (DPoP). Mirrors the TS
`@better-auth/oauth-provider` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import JWTPlugin, OAuthProviderPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[
        JWTPlugin(),
        OAuthProviderPlugin(login_page="/login", consent_page="/consent"),
    ],
)
```

`JWTPlugin` is required alongside it. Without it, initialization raises
`ValueError: oauth-provider requires the jwt plugin to be installed`. The
alternative is `disable_jwt_plugin=True`, which HS256-signs id tokens with each
client's secret and stores client secrets encrypted (recoverable) instead of
hashed.

::: warning Changed in 1.1
Several defaults are stricter, as in better-auth 1.7.6. Run your migrations
(new tables and columns), then check these before upgrading:

- A client must authenticate with the method it registered (default
  `client_secret_basic`). `bind_client_auth_method=False` keeps the 1.0
  leniency between Basic and post.
- ID tokens carry protocol claims only. Profile and email claims come from
  UserInfo. `legacy_id_token_profile_claims=True` (deprecated) restores them.
- A requested `resource` must be a configured resource, linked to the client.
  The base URL is no longer accepted as an audience: configure `resources`,
  or list legacy audiences in `valid_audiences` (deprecated).
- Redirect URIs follow the client application type. A client using an HTTP
  loopback redirect must be updated with `application_type: "native"`.
- A client is public only when its `token_endpoint_auth_method` is `none`.
- The `client_credentials` grant uses the client's
  `client_credentials_scopes`.

See [Upgrade from 1.0](/migrate/from-1-0).
:::

## Options

All options are keyword arguments of `OAuthProviderPlugin`.

### Scopes and lifetimes

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `scopes` | `list[str] \| None` | `["openid", "profile", "email", "offline_access"]` | Supported scopes advertised in discovery. |
| `code_expires_in` | `int` | `600` | Authorization-code lifetime (seconds). |
| `access_token_expires_in` | `int` | `3600` | Access-token lifetime. |
| `m2m_access_token_expires_in` | `int` | `3600` | Client-credentials token lifetime. |
| `id_token_expires_in` | `int` | `36000` | Id-token lifetime. |
| `refresh_token_expires_in` | `int` | `2592000` | Refresh-token lifetime (30 days). |
| `refresh_token_reuse_interval` | `int` | `0` | Seconds during which a rotated refresh token can be sent again and gets the same response. `0` keeps strict replay detection. |
| `scope_expirations` | `dict[str, int] \| None` | `None` | Per-scope token lifetimes. |
| `grant_types` | `list[str] \| None` | `authorization_code`, `client_credentials`, `refresh_token` | Enabled grants. `refresh_token` needs `authorization_code`. |
| `client_credential_grant_default_scopes` | `list[str] \| None` | `None` | When set, clients without `client_credentials_scopes` keep the 1.0 scope rules for the `client_credentials` grant. |

### Client authentication

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `bind_client_auth_method` | `bool` | `True` | A client must use its registered `token_endpoint_auth_method`. `False` lets `client_secret_basic` and `client_secret_post` stand in for each other. |
| `assertion_max_lifetime` | `int` | `300` | Maximum seconds between now and a `private_key_jwt` assertion's `exp` or `iat`. |
| `dpop` | `dict \| None` | `None` | DPoP proof settings: `proofMaxAgeSeconds` (default `300`) and `signingAlgorithms` (default `EdDSA`, `ES256`, `ES512`, `PS256`, `RS256`). |

### Client registration

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_dynamic_client_registration` | `bool` | `False` | Enable RFC 7591 `/oauth2/register`. |
| `allow_unauthenticated_client_registration` | `bool` | `False` | Registration without a session or an initial access token. Such clients cannot use `client_credentials`. |
| `validate_initial_access_token` | `callable \| None` | `None` | Protects registration with an RFC 7591 initial access token (`Authorization: Bearer ...`). Receives `{"initialAccessToken", "headers", "clientMetadata"}` and returns `{"referenceId": ...}` to allow or `False` to refuse (may be async). |
| `client_registration_default_scopes` | `list[str] \| None` | `None` | Scopes of dynamically registered clients, together with the allowed ones below. Defaults to `scopes`. |
| `client_registration_allowed_scopes` | `list[str] \| None` | `None` | Extra scopes for dynamically registered clients. Every value must be in `scopes`. |
| `client_registration_default_resources` | `list[str] \| None` | `None` | Resources linked to every registered client. Every value must be in `resources`. |
| `client_registration_allowed_resources` | `list[str] \| None` | `None` | Extra resources a registered client may request. Every value must be in `resources`. |
| `client_registration_require_pkce` | `bool` | `True` | `False` lets confidential registered clients skip PKCE. |
| `client_registration_client_secret_expiration` | `int \| str \| datetime \| None` | `None` | Expiry of dynamically registered client secrets. A duration string (`"30d"`) is added to the issue time. A number or `datetime` is the expiry time itself. |
| `client_privileges` | `callable \| None` | `None` | Gate for client management actions. |
| `client_reference` | `callable \| None` | `None` | `(session) -> reference id` stored on created clients (for example an organization id). |
| `allow_public_client_prelogin` | `bool` | `False` | Enable `/oauth2/public-client-prelogin`. |

### Authorization pages

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `login_page` | `str \| None` | `None` | Where an unauthenticated `/oauth2/authorize` redirects. |
| `consent_page` | `str \| None` | `None` | Where consent is collected. |
| `signup`, `select_account`, `post_login` | `dict \| None` | `None` | Extra screens in the authorize flow. |
| `cached_trusted_clients` | `set[str] \| None` | `None` | Client ids cached in memory. They cannot be changed through the client endpoints. |
| `request_uri_resolver` | `callable \| None` | `None` | Resolves a `request_uri` authorization parameter. |

### Protected resources

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `resources` | `list[str \| dict] \| None` | `None` | Resources this server issues access tokens for. See [Protected resources](#protected-resources). |
| `enforce_per_client_resources` | `bool \| None` | `True` when unset | A requested resource must be linked to the client. |
| `resource_seed_mode` | `str \| None` | `"insertOnly"` | How `resources` is written to the `oauthResource` table: `"insertOnly"`, `"merge"` (writes the fields present in the config) or `"overwrite"`. |
| `cached_resources` | `set[str] \| None` | `None` | Resource identifiers kept in memory. |
| `identifier_validator` | `callable \| None` | `None` | `(identifier) -> bool` that replaces the default RFC 8707 check (absolute URI, no fragment). |
| `resource_privileges` | `callable \| None` | `None` | Gate for the admin resource methods. Receives `{"headers", "action", "session", "user", "resourceId"}`. Without it, any signed-in user may manage resources. |

### Claims, storage and generators

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `custom_id_token_claims`, `custom_access_token_claims`, `custom_user_info_claims` | `callable \| None` | `None` | Extra claims. Custom ID token claims cannot replace protocol claims. |
| `custom_token_response_fields` | `callable \| None` | `None` | Extra token response fields. |
| `pairwise_secret` | `str \| None` | `None` | Enables pairwise subject identifiers. At least 32 characters. |
| `advertised_metadata` | `dict \| None` | `None` | Overrides advertised discovery values (`scopes_supported` must be a subset of `scopes`). |
| `store_tokens` | `str \| dict` | `"hashed"` | How access and refresh tokens are stored. |
| `store_client_secret` | `str \| dict \| None` | `None` (hashed with jwt; encrypted without) | How client secrets are stored. |
| `prefix`, `generate_client_id`, `generate_client_secret`, `generate_refresh_token`, `generate_opaque_access_token`, `format_refresh_token` | various | `None` | Token and id formats. |
| `disable_jwt_plugin` | `bool` | `False` | Run without the JWT plugin (see [Enable](#enable)). |
| `rate_limit` | `dict \| None` | `None` | Per-endpoint `{"window", "max"}` or `False`, keyed by `register`, `authorize`, `token`, `introspect`, `revoke`, `userinfo`. |

### Deprecated

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `valid_audiences` | `list[str] \| None` | `None` | Audiences accepted as resources with no policy and no client link. Use `resources`. |
| `legacy_id_token_profile_claims` | `bool` | `False` | Put the scope-based profile and email claims back in the ID token. |
| `silence_warnings` | `dict \| None` | `None` | Accepted and ignored. |

## Clients

Clients are created with `/oauth2/create-client`, `/oauth2/register` or the
server-side `admin_create_client` method. The body uses RFC 7591 names:

| Field | Description |
| --- | --- |
| `redirect_uris`, `post_logout_redirect_uris` | Registered redirect URIs. |
| `token_endpoint_auth_method` | `client_secret_basic` (default), `client_secret_post`, `private_key_jwt` or `none` (public client, PKCE required). |
| `application_type` | `web` (default) or `native`. Sets the redirect URI rules below. |
| `grant_types`, `response_types`, `scope` | Allowed grants, response types and scopes. |
| `jwks`, `jwks_uri` | The client's public keys, required for `private_key_jwt`. Use one or the other. `jwks_uri` must be HTTPS on a public host. |
| `backchannel_logout_uri`, `backchannel_logout_session_required` | [Back-channel logout](#logout) target. HTTPS on a public host. Needs the JWT plugin. |
| `dpop_bound_access_tokens` | Always issue DPoP-bound tokens to this client. |
| `client_name`, `client_uri`, `logo_uri`, `contacts`, `tos_uri`, `policy_uri`, `software_id`, `software_version`, `software_statement` | Display and software metadata. |

`/oauth2/register` also accepts `subject_type`, `resources` and
`skip_consent`. The admin method also accepts `client_credentials_scopes`,
`client_secret_expires_at`, `skip_consent`, `enable_end_session`,
`require_pkce`, `subject_type` and `metadata`. Unknown fields are dropped.

Redirect URI rules:

- `web` clients need HTTPS on a host that is not loopback.
- `native` clients may use HTTPS on a public host, HTTP on `localhost`,
  `127.0.0.1` or `[::1]` (any port), or a reverse-domain private scheme such
  as `com.example.app:/callback`.
- A redirect URI never carries credentials or a fragment.

Clients stored by 1.0 keep working until they are updated.

## Token endpoint

- Client authentication: `client_secret_basic`, `client_secret_post`,
  `private_key_jwt` (a `client_assertion` signed with a key from the client's
  `jwks` or `jwks_uri`; each assertion `jti` is accepted once) or `none`.
  Sending two methods at once is refused.
- ID tokens carry `at_hash`. JWT access tokens carry `typ: at+jwt`,
  `client_id` and `jti`, and the resource as `aud`.
- DPoP (RFC 9449): a `DPoP` proof header at the token endpoint binds the
  tokens to the client key. The response has `token_type: DPoP` and the
  access token a `cnf.jkt` claim. UserInfo and introspection check the
  binding. A client or resource can require it.
- Refresh tokens rotate on every use. With `refresh_token_reuse_interval`,
  the previous token sent again within the interval returns the cached
  response, for the same client, scopes, resources and DPoP key.
- Resource indicators are bound to the authorization grant: token and refresh
  requests can narrow them, never widen them.
- Reusing an authorization code revokes the tokens already issued for it.

## Authorize endpoint

`/oauth2/authorize` takes the request as a GET query or a form POST. It
supports the OIDC `claims` parameter and enforces `max_age`. An invalid
request redirects to the client's registered redirect URI with an RFC 6749
error. `state` is optional.

## Protected resources

A protected resource is an API that accepts your access tokens. Its
identifier is the RFC 8707 `resource` value and becomes the access token
`aud`. Configure resources as strings or dicts (camelCase keys, as stored):

```python
OAuthProviderPlugin(
    resources=[
        "https://api.example.com",
        {
            "identifier": "https://api.example.com/mcp",
            "allowedScopes": ["mcp:read", "mcp:write"],
            "accessTokenTtl": 300,
            "dpopBoundAccessTokensRequired": True,
        },
    ],
)
```

Policy keys: `name`, `accessTokenTtl`, `refreshTokenTtl`, `signingAlgorithm`
(`EdDSA`, `ES256`, `ES512`, `PS256` or `RS256`), `signingKeyId`,
`allowedScopes`, `customClaims`, `dpopBoundAccessTokensRequired`, `disabled`,
`metadata`. Configured resources are written to the `oauthResource` table on
first use. Deleting a resource row makes tokens issued for it invalid.

By default a client may only request resources linked to it
(`oauthClientResource`). Link them with the admin methods below, or through
registration with `client_registration_default_resources` and
`client_registration_allowed_resources`.

## Logout

- `/oauth2/end-session` (RP-initiated logout) accepts GET and POST, for
  clients created with `enable_end_session`. `id_token_hint` is optional:
  without a usable hint the user is asked to confirm, and the confirmation
  posts to `/oauth2/end-session/confirm`.
- Back-channel logout: when a session ends (sign-out, end-session, admin
  revoke), the server sends a signed logout token to each client with a
  `backchannel_logout_uri` and active tokens for that session (5 seconds per
  client, no retry), after the session deletion commits. It then revokes the
  session's access tokens, and its refresh tokens unless `offline_access`
  was granted. Delivery runs inline, before the sign-out response returns.
- Introspection and UserInfo report tokens of an ended session as inactive.

## Device authorization grant

`OAuthDeviceAuthorizationPlugin` adds the RFC 8628 device grant for OAuth
clients: the device requests codes at `/device/code`, the user approves them
as with [Device Authorization](./device-authorization), and the client polls
`/oauth2/token` with
`grant_type=urn:ietf:params:oauth:grant-type:device_code` for a regular OAuth
token set. Discovery advertises `device_authorization_endpoint`.

```python
from better_auth.plugins_ext import (
    JWTPlugin,
    OAuthDeviceAuthorizationPlugin,
    OAuthProviderPlugin,
)

plugins = [
    JWTPlugin(),
    OAuthProviderPlugin(login_page="/login", consent_page="/consent"),
    OAuthDeviceAuthorizationPlugin(expires_in="10m", interval="5s"),
]
```

- It takes the same options as `DeviceAuthorizationPlugin` and replaces it:
  installing both raises `ValueError`. It also needs `OAuthProviderPlugin`.
- The client must list the device code grant in its `grant_types`.
- At `/device/code` a confidential client authenticates with its registered
  method, a public client (`none`) sends `client_id`. A `resource` parameter
  binds the code to protected resources.
- An unknown `client_id` is refused with `invalid_client`, unless
  `validate_client` accepts it. Such codes follow the session flow and are
  redeemed at `/device/token`. Codes issued to an OAuth client are refused
  there and must go to `/oauth2/token`.
- `GET /device` also shows the `resource` to the code owner.
- It adds the `oauthClientId` and `resources` columns to `deviceCode`.

## Endpoints

25 routes under `/oauth2/`:

| Method | Path |
| --- | --- |
| POST | `/oauth2/register` |
| POST | `/oauth2/create-client` |
| GET | `/oauth2/get-client` |
| GET | `/oauth2/public-client` |
| POST | `/oauth2/public-client-prelogin` |
| GET | `/oauth2/get-clients` |
| POST | `/oauth2/update-client` |
| POST | `/oauth2/client/rotate-secret` |
| POST | `/oauth2/delete-client` |
| GET/POST | `/oauth2/authorize` |
| POST | `/oauth2/token` |
| POST | `/oauth2/introspect` |
| POST | `/oauth2/revoke` |
| GET/POST | `/oauth2/userinfo` |
| GET/POST | `/oauth2/end-session` |
| POST | `/oauth2/end-session/confirm` |
| POST | `/oauth2/consent` |
| POST | `/oauth2/continue` |
| GET | `/oauth2/get-consent` |
| GET | `/oauth2/get-consents` |
| POST | `/oauth2/update-consent` |
| POST | `/oauth2/delete-consent` |

Discovery documents (`/.well-known/...`) are served through the plugin's
request hooks. Registration, client creation, secret rotation and the device
endpoints answer with `Cache-Control: no-store`, errors included. UserInfo
responses are no-store too.

### Server-side methods

These are methods on the plugin instance, not HTTP routes. Each takes a `Ctx`
whose request carries the admin's session cookie and a JSON body.

| Method | Purpose |
| --- | --- |
| `admin_create_client(ctx)` | Create a client with server-owned fields such as `client_credentials_scopes`. |
| `admin_update_client(ctx)` | Update a client, including `client_credentials_scopes`. |
| `admin_create_oauth_resource(ctx)` | Create a resource (201). |
| `admin_list_oauth_resources(ctx)` | List resources. |
| `admin_get_oauth_resource(ctx, identifier)` | Read one resource. |
| `admin_update_oauth_resource(ctx, identifier)` | Update a resource's policy. |
| `admin_delete_oauth_resource(ctx, identifier)` | Delete a resource. |
| `admin_link_client_resource(ctx, identifier, client_id)` | Allow a client to request a resource. |
| `admin_unlink_client_resource(ctx, identifier, client_id)` | Remove that link. |
| `get_oauth_server_config()` | The authorization server metadata. |
| `get_openid_config()` | The OIDC discovery document. |

```python
import json

from better_auth.plugins_ext import OAuthProviderPlugin
from better_auth.types import AuthRequest, Ctx

provider = next(p for p in auth.plugins if isinstance(p, OAuthProviderPlugin))
request = AuthRequest(
    method="POST",
    path="/admin/oauth2/resources",
    headers={"cookie": admin_cookie},
    body=json.dumps({"identifier": "https://api.example.com"}).encode(),
)
ctx = Ctx(auth=auth, request=request)
response = await provider.admin_create_oauth_resource(ctx)
```

## Schema

| Table | Columns |
| --- | --- |
| `oauthClient` | `clientId`, `clientSecret`, `clientDiscoveryId`, `disabled`, `skipConsent`, `enableEndSession`, `subjectType`, `scopes`, `clientCredentialsScopes`, `userId`, `createdAt`, `updatedAt`, `name`, `uri`, `icon`, `contacts`, `tos`, `policy`, `softwareId`, `softwareVersion`, `softwareStatement`, `redirectUris`, `postLogoutRedirectUris`, `backchannelLogoutUri`, `backchannelLogoutSessionRequired`, `tokenEndpointAuthMethod`, `applicationType`, `jwks`, `jwksUri`, `grantTypes`, `responseTypes`, `requirePKCE`, `dpopBoundAccessTokens`, `referenceId`, `metadata` |
| `oauthConsent` | `clientId`, `userId`, `referenceId`, `resources`, `requestedUserInfoClaims`, `scopes`, `createdAt`, `updatedAt` |
| `oauthResource` | `identifier`, `name`, `accessTokenTtl`, `refreshTokenTtl`, `signingAlgorithm`, `signingKeyId`, `allowedScopes`, `customClaims`, `dpopBoundAccessTokensRequired`, `disabled`, `createdAt`, `updatedAt`, `policyVersion`, `metadata` |
| `oauthClientResource` | `clientId`, `resourceId`, `metadata`, `createdAt` |
| `oauthRefreshToken` | `token`, `clientId`, `sessionId`, `userId`, `referenceId`, `authorizationCodeId`, `resources`, `requestedUserInfoClaims`, `expiresAt`, `createdAt`, `revoked`, `rotatedAt`, `rotationReplayResponse`, `rotationReplayExpiresAt`, `authTime`, `confirmation`, `scopes` |
| `oauthAccessToken` | `token`, `clientId`, `sessionId`, `userId`, `referenceId`, `authorizationCodeId`, `resources`, `requestedUserInfoClaims`, `refreshId`, `expiresAt`, `createdAt`, `revoked`, `confirmation`, `scopes` |
| `oauthClientAssertion` | `expiresAt` (the row id is a digest of the assertion `jti`) |

The 1.0 `oauthClient.public` and `oauthClient.type` columns are no longer
used. Run your migrations after upgrading.

## Notes

- For the "enter this code on your TV" flow in your own app, use
  [Device Authorization](./device-authorization). For OAuth clients, use the
  [device authorization grant](#device-authorization-grant).
- To *consume* someone else's OAuth server instead of being one, see
  [Generic OAuth](./generic-oauth) or the [providers](/providers/) registry.
