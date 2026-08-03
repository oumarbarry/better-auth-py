---
title: Figma
---

# Figma

Figma OAuth2 with PKCE (S256). No id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Figma

auth = BetterAuth(
    secret=...,
    social_providers={
        "figma": Figma(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "figma": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `current_user:read`.
- Register `{base_url}{base_path}/callback/figma` as the redirect URI in your Figma app settings.
- Token-endpoint client auth is **basic** (`Authorization: Basic`), not the default body-post — for both code exchange and refresh.
- Profile mapping: name comes from `handle`, avatar from `img_url`; `email_verified` is always `False` (Figma exposes no verification flag).
