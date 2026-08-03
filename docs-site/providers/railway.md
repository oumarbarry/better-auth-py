---
title: Railway
---

# Railway

Railway OAuth2 (OIDC-shaped) with PKCE (S256) and basic token-endpoint auth. No id-token direct sign-in.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Railway

auth = BetterAuth(
    secret=...,
    social_providers={
        "railway": Railway(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "railway": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `openid email profile`.
- Register `{base_url}{base_path}/callback/railway` as the redirect URI on the Railway OAuth app.
- Token-endpoint client auth is **basic** (`Authorization: Basic`) for both exchange and refresh.
- Railway's userinfo never returns an `email_verified` claim — always mapped as `False` (TS: "default to false for security consistency").
