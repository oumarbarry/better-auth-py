---
title: Polar
---

# Polar

Polar OAuth2 (OIDC-shaped) with PKCE (S256). No id-token direct sign-in.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Polar

auth = BetterAuth(
    secret=...,
    social_providers={
        "polar": Polar(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "polar": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply — TS's `prompt` option maps to `authorize_params={"prompt": "…"}`.

## Notes

- Default scopes: `openid profile email`.
- Register `{base_url}{base_path}/callback/polar` as the redirect URI on the Polar OAuth client.
- Profile mapping: id from `id`, name prefers `public_name` then `username`, avatar from `avatar_url`; `email_verified` defaults to `False` when Polar omits it.
