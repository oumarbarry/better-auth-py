---
title: Facebook
---

# Facebook

Facebook Login (Graph API v24.0). OAuth2 without PKCE, plus a separate **Limited Login** path whose JWTs are verified against Facebook's dedicated JWKS.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Facebook

auth = BetterAuth(
    secret=...,
    social_providers={
        "facebook": Facebook(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "facebook": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | The app id. Also used (with `client_secret`) to app-bind opaque tokens via `debug_token`. |
| `client_secret` | `str` | required | |
| `fields` | `list[str]` | `[]` | Extra Graph profile fields appended to the `/me` request (beyond `id,name,email,picture`). |
| `config_id` | `str \| None` | `None` | Facebook login configuration id, sent as the `config_id` authorize param. |
| `disable_id_token_sign_in` | `bool` | `False` | Refuse direct token sign-in (both JWT and opaque paths). |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `email public_profile`.
- Register `{base_url}{base_path}/callback/facebook` as a valid OAuth redirect URI in the Meta developer console.
- Two token paths on direct sign-in: a 3-segment JWT is a **Limited Login** token, verified against `https://limited.facebook.com/.well-known/oauth/openid/jwks/` (issuer `https://www.facebook.com`, RS256 only); anything else is treated as opaque, and the identity comes from the access token sent as `idToken.accessToken`: it is validated through Graph `debug_token` (must be valid, bound to a configured app id, and carry a `user_id`), then the Graph profile is read. A missing or rejected access token answers `401 FAILED_TO_GET_USER_INFO`.

::: warning Changed in 1.1
Opaque token sign-in reads the identity from `idToken.accessToken`, not from `idToken.token`. Clients that sent only the opaque token must also send it as `accessToken`. See [Upgrade from 1.0](/migrate/from-1-0).
:::
- The Graph `/me` endpoint is not app-bound, so the access token is app-verified via `debug_token` before its profile is trusted, and the returned profile `id` must match the token's `user_id`.
- Limited-Login id tokens carry no `email_verified` claim, mapped as `False`.
