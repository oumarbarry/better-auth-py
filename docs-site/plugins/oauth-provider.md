---
title: OAuth Provider
---

# OAuth Provider

Turns your app into an OAuth 2.1 / OIDC authorization server: client
registration and management, authorize and consent, every token grant,
introspection, userinfo, revocation and end-session — RFC 6749, 7009, 7636 and
7662. Mirrors the TS `@better-auth/oauth-provider` plugin.

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

`JWTPlugin` is required alongside it — without it, initialization raises
`ValueError: oauth-provider requires the jwt plugin to be installed`. The
alternative is `disable_jwt_plugin=True`, which HS256-signs id tokens with each
client's secret and stores client secrets encrypted (recoverable) instead of
hashed.

## Options

The most-used options (the full TS option surface is ported; all snake_case):

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `scopes` | `list[str] \| None` | `None` | Supported scopes advertised in discovery. |
| `code_expires_in` | `int` | `600` | Authorization-code lifetime (seconds). |
| `access_token_expires_in` | `int` | `3600` | Access-token lifetime. |
| `m2m_access_token_expires_in` | `int` | `3600` | Client-credentials token lifetime. |
| `id_token_expires_in` | `int` | `36000` | ID-token lifetime. |
| `refresh_token_expires_in` | `int` | `2592000` | Refresh-token lifetime (30 days). |
| `allow_dynamic_client_registration` | `bool` | `False` | Enable RFC 7591 `/oauth2/register`. |
| `allow_unauthenticated_client_registration` | `bool` | `False` | Registration without a session. |
| `grant_types` | `list[str] \| None` | `None` | Restrict the enabled grants. |
| `login_page` | `str \| None` | `None` | Where an unauthenticated `/oauth2/authorize` redirects. |
| `consent_page` | `str \| None` | `None` | Where consent is collected. |
| `store_tokens` | `str \| dict` | `"hashed"` | How access/refresh tokens are stored. |
| `store_client_secret` | `str \| dict \| None` | `None` (hashed with jwt; encrypted without) | How client secrets are stored. |
| `valid_audiences` | `list[str] \| None` | `None` | Accepted `aud` values on introspection. |
| `scope_expirations` | `dict[str, int] \| None` | `None` | Per-scope token lifetimes. |
| `trusted clients / claims / generators` | various | `None` | `cached_trusted_clients`, `custom_id_token_claims`, `custom_access_token_claims`, `custom_user_info_claims`, `custom_token_response_fields`, `generate_client_id`, `generate_client_secret`, `generate_refresh_token`, `generate_opaque_access_token`, `prefix`, `pairwise_secret`, `client_reference`, `client_privileges`, `request_uri_resolver`, `signup`, `select_account`, `post_login`, `format_refresh_token`, `client_registration_*`, `allow_public_client_prelogin`, `disable_jwt_plugin`, `silence_warnings`, `rate_limit`. |

## Endpoints

22 routes under `/oauth2/`:

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
| GET | `/oauth2/authorize` |
| POST | `/oauth2/token` |
| POST | `/oauth2/introspect` |
| POST | `/oauth2/revoke` |
| GET/POST | `/oauth2/userinfo` |
| GET | `/oauth2/end-session` |
| POST | `/oauth2/consent` |
| POST | `/oauth2/continue` |
| GET | `/oauth2/get-consent` |
| GET | `/oauth2/get-consents` |
| POST | `/oauth2/update-consent` |
| POST | `/oauth2/delete-consent` |

Discovery documents (`/.well-known/...`) are served through the plugin's
request hooks.

## Schema

| Table | Key columns |
| --- | --- |
| `oauthClient` | `clientId`, `clientSecret`, `disabled`, `skipConsent`, `enableEndSession`, `subjectType`, `scopes`, `userId`, `redirectUris`, `postLogoutRedirectUris`, `tokenEndpointAuthMethod`, `grantTypes`, `responseTypes`, `public`, `type`, `requirePKCE`, `referenceId`, `metadata`, registration metadata (`name`, `uri`, `icon`, `contacts`, `tos`, `policy`, `softwareId`, `softwareVersion`, `softwareStatement`), `createdAt`, `updatedAt` |
| `oauthConsent` | `clientId`, `userId`, `referenceId`, `scopes`, `createdAt`, `updatedAt` |
| `oauthAccessToken` | `token`, `clientId`, `sessionId`, `userId`, `referenceId`, `refreshId`, `expiresAt`, `createdAt`, `scopes` |
| `oauthRefreshToken` | `token`, `clientId`, `sessionId`, `userId`, `referenceId`, `expiresAt`, `createdAt`, `revoked`, `authTime`, `scopes` |

## Notes

- For the "enter this code on your TV" flow, add
  [device-authorization](./device-authorization).
- To *consume* someone else's OAuth server instead of being one, see
  [generic-oauth](./generic-oauth) or the [providers](/providers/) registry.
