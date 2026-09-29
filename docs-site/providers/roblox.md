---
title: Roblox
---

# Roblox

Roblox OAuth2 (OIDC-shaped userinfo). No PKCE, no id-token direct sign-in.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Roblox

auth = BetterAuth(
    secret=...,
    social_providers={
        "roblox": Roblox(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "roblox": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `openid profile`.
- Register `{base_url}{base_path}/callback/roblox` as the redirect URL on the Roblox OAuth app.
- The authorize URL carries `prompt=select_account consent` by default (default `authorize_params`).
- Roblox never returns an email: `email` is the placeholder `{sub}@roblox.placeholder.invalid` and `email_verified` is always `False`. Display name prefers `nickname`.

::: warning Changed in 1.1
The email of a new Roblox user was the `preferred_username` and is now the placeholder `{sub}@roblox.placeholder.invalid`. Existing users keep the address stored at sign-up.
See [Upgrade from 1.0](/migrate/from-1-0).
:::
