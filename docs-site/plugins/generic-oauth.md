---
title: Generic OAuth
---

# Generic OAuth

Sign in with any OAuth2/OIDC provider that is not in the built-in registry,
configured at runtime: point it at a discovery URL or spell out the endpoints.
Each configured provider becomes a regular social provider. Mirrors the TS
`genericOAuth()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import GenericOAuthPlugin
from better_auth.plugins_ext.generic_oauth import GenericOAuthConfig

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[
        GenericOAuthPlugin(
            config=[
                GenericOAuthConfig(
                    provider_id="keycloak",
                    client_id="my-client",
                    client_secret="my-secret",
                    discovery_url=(
                        "https://sso.example.com/realms/main"
                        "/.well-known/openid-configuration"
                    ),
                    scopes=["openid", "email", "profile"],
                )
            ]
        )
    ],
)
```

Register `<base URL><base path>/callback/<provider_id>` as the redirect URI
with the provider (for example `https://app.example.com/api/auth/callback/keycloak`),
then start the sign-in like any social provider, with `POST /sign-in/social`:

```json
{
  "provider": "keycloak",
  "callbackURL": "/dashboard"
}
```

::: warning Changed in 1.1
Providers now use the social routes (`/sign-in/social`, `/callback/<id>`,
`/link-social`) and the default redirect URI is `<base>/callback/<id>`.
Update the redirect URI registered with each provider, or pass
`legacy_routes=True` to keep the 1.0 routes. PKCE is on by default, and
`map_profile_to_user` can no longer change the account id. See
[Upgrade from 1.0](/migrate/from-1-0).
:::

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `config` | `list[GenericOAuthConfig]` | required | One entry per provider. |
| `legacy_routes` | `bool` | `False` | Keep the 1.0 routes `/sign-in/oauth2`, `/oauth2/callback/<id>` and `/oauth2/link` as aliases of the social routes. The default redirect URI goes back to `/oauth2/callback/<id>`. |

Two providers with the same `provider_id` log a warning. A generic provider
with the id of a built-in social provider replaces it and logs a warning.

### Provider configuration

`GenericOAuthConfig` is a dataclass. `provider_id` and `client_id` are
required. The endpoints come from `discovery_url`, or from
`authorization_url` plus `token_url` (or a `get_token` callback).

**Endpoints and discovery**

| Field | Default | Description |
| --- | --- | --- |
| `discovery_url` | `None` | OIDC discovery document. Fills the endpoints, the issuer and, when it lists `jwks_uri`, ID token verification. Explicit endpoint fields win. |
| `discovery_headers` | `None` | Headers sent with the discovery request. |
| `authorization_url` | `None` | Authorization endpoint. |
| `token_url` | `None` | Token endpoint. |
| `user_info_url` | `None` | UserInfo endpoint. |
| `end_session_endpoint` | `None` | Provider logout endpoint (also read from discovery). Sign-out returns the provider logout URL built from it. |
| `post_logout_redirect_uri` | `None` | Where the provider sends the user after logout. A relative path is resolved against the auth base URL. |
| `disable_provider_logout` | `False` | Never build a provider logout URL on sign-out. |

**Authorization request**

| Field | Default | Description |
| --- | --- | --- |
| `client_secret` | `""` | Client secret. Leave it empty for `private_key_jwt` or `none` authentication. |
| `name` | `None` | Display name. Defaults to the provider id. |
| `scopes` | `[]` | Requested scopes. `openid` is added when discovery says the provider is OIDC. |
| `redirect_uri` | `None` | Overrides the default `<base>/callback/<id>`. |
| `pkce` | `True` | Send a PKCE challenge. Set `False` for providers that reject PKCE. |
| `response_type` | `"code"` | OAuth `response_type`. |
| `response_mode` | `None` | OAuth `response_mode`. |
| `prompt` | `None` | OAuth `prompt`. |
| `access_type` | `None` | For example `"offline"`. |
| `authorization_url_params` | `None` | Extra query parameters on the authorization URL (a dict). |

**Token endpoint**

| Field | Default | Description |
| --- | --- | --- |
| `authentication` | `"post"` | Client credentials in the body (`"post"`) or an HTTP Basic header (`"basic"`). |
| `token_endpoint_auth` | `None` | `TokenEndpointAuth(method=...)` from `better_auth.oauth.machinery`. Methods: `"client_secret_basic"`, `"client_secret_post"`, `"private_key_jwt"` (with `get_client_assertion`), `"none"`, `"custom"` (with `customize_request`). Overrides `authentication`. |
| `authorization_headers` | `None` | Extra headers on the token request. |
| `token_url_params` | `None` | Extra body parameters on the code exchange (a dict). |
| `refresh_token_params` | `None` | Extra body parameters on refresh: a dict, or a callable that receives the request context (may be async). |
| `access_token_expires_in` | `None` | Seconds to assume when the provider omits `expires_in`. |
| `get_token` | `None` | Custom code exchange. Receives `{"code", "redirectURI", "codeVerifier", "deviceId"}`, returns `OAuthTokens` or a token response dict (may be async). |

The plugin refuses to start when `client_secret` is set with the
`private_key_jwt` or `none` method, or missing for a `client_secret_*` method
or `authentication="basic"`.

**Profile and account**

| Field | Default | Description |
| --- | --- | --- |
| `get_user_info` | `None` | Custom profile fetch: `(tokens) -> dict or None` (may be async). |
| `map_profile_to_user` | `None` | `(profile) -> dict` of local user fields (may be async). It cannot change the account id. |
| `account_subject` | `None` | `({"tokens", "profile"}) -> str or int` (may be async): the stable account id. Defaults to the profile `sub` for OIDC providers and `id` otherwise. An empty result refuses the sign-in. |
| `require_id_token_verification` | `False` | Skip the provider unless discovery gives an issuer and a JWKS URI. Needs `discovery_url`. |
| `disable_id_token_nonce_binding` | `False` | Do not bind the verified ID token to a nonce sent in the authorization request. |
| `override_user_info` | `False` | Update the user from the provider profile on every sign-in. |
| `disable_sign_up` | `False` | Never create a user from this provider. |
| `disable_implicit_sign_up` | `False` | Create a user only when the sign-in request sends `requestSignUp: true`. |
| `require_email_verification` | `False` | An unverified email gets no session, and a verification email is sent. |
| `allow_idp_initiated` | `False` | Accept a callback the provider starts without a prior sign-in request, by restarting the flow. |

**Deprecated**

| Field | Default | Description |
| --- | --- | --- |
| `issuer` | `None` | Issuer used for the RFC 9207 `iss` check when discovery gives none. |
| `require_issuer_validation` | `False` | Refuse a callback without `iss` (`issuer_missing`) once an issuer is known. |

## Presets

Functions in `better_auth.plugins_ext.generic_oauth` return a ready
`GenericOAuthConfig`. Each takes `client_id` and the shared options
(`client_secret`, `token_endpoint_auth`, `scopes`, `redirect_uri`,
`end_session_endpoint`, `post_logout_redirect_uri`,
`disable_provider_logout`, `pkce`, `disable_implicit_sign_up`,
`disable_sign_up`, `override_user_info`).

| Function | Provider id | Extra argument | Default scopes |
| --- | --- | --- | --- |
| `okta` | `okta` | `issuer` | `openid profile email` |
| `auth0` | `auth0` | `domain` | `openid profile email` |
| `keycloak` | `keycloak` | `issuer` (realm URL) | `openid profile email` |
| `slack` | `slack` | none | `openid profile email` |
| `line` | `line` | `provider_id` (optional) | `openid profile email` |
| `hubspot` | `hubspot` | none | `oauth` |
| `gumroad` | `gumroad` | none | `view_profile` |
| `patreon` | `patreon` | none | `identity[email]` |
| `yandex` | `yandex` | none | `login:info login:email login:avatar` |
| `microsoft_entra_id` | `microsoft-entra-id` | `tenant_id` (a tenant GUID) | `openid profile email` |

```python
from better_auth.plugins_ext.generic_oauth import microsoft_entra_id, slack

GenericOAuthPlugin(
    config=[
        slack(client_id="...", client_secret="..."),
        microsoft_entra_id(
            tenant_id="00000000-0000-0000-0000-000000000000",
            client_id="...",
            client_secret="...",
        ),
    ]
)
```

`microsoft_entra_id` uses the `oid` claim as the account id and requires a
verified ID token. For the `common`, `organizations` or `consumers` tenants,
use the built-in [Microsoft provider](/providers/microsoft).

## Endpoints

The plugin adds no route of its own. Providers use the core social routes:

| Method | Path |
| --- | --- |
| POST | `/sign-in/social` (`provider` is the `provider_id`) |
| GET/POST | `/callback/{providerId}` |
| POST | `/link-social` |

With `legacy_routes=True`, these aliases are also mounted:

| Method | Path |
| --- | --- |
| POST | `/sign-in/oauth2` |
| GET/POST | `/oauth2/callback/{providerId}` |
| POST | `/oauth2/link` |

## Errors

| Code | Status | Message |
| --- | --- | --- |
| `INVALID_OAUTH_CONFIGURATION` | 400 | Invalid OAuth configuration |
| `TOKEN_URL_NOT_FOUND` | 400 | Invalid OAuth configuration. Token URL not found. |

The callback redirects with the same `error` codes as other social
providers, for example `invalid_code`, `unable_to_get_user_info`,
`email_not_found`, `email_does_not_match`, `state_not_found` and
`state_mismatch`.

## Notes

- Discovery runs on the provider's first use and is cached once it
  succeeds. A failed fetch is retried on the next request. A provider whose
  discovery gives no usable authorization or token endpoint is skipped.
- When discovery publishes a `jwks_uri`, the ID token from the code exchange
  is verified against it (issuer, audience and nonce), and the provider
  accepts ID token sign-in (`POST /sign-in/social` with `idToken`).
  Without a JWKS URI the ID token is only decoded.
- Configured providers also work with the other social routes, such as
  `/refresh-token` and sign-out with provider logout.
- For providers in the built-in registry, configure them directly. See
  [providers](/providers/).
