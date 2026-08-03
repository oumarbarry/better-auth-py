---
title: Notion
---

# Notion

Notion public-integration OAuth2. No PKCE, no id token, and no OAuth scopes — permissions live in the integration's capabilities.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Notion

auth = BetterAuth(
    secret=...,
    social_providers={
        "notion": Notion(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "notion": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: none (Notion's permission model is the integration's capabilities, not OAuth scopes).
- Register `{base_url}{base_path}/callback/notion` as the redirect URI on the public integration.
- `owner=user` is always sent on the authorize URL (default `authorize_params`).
- Token-endpoint client auth is **basic** (RFC 7617) — Notion rejects the body-post form.
- Userinfo is `GET /v1/users/me` with a `Notion-Version: 2022-06-28` header; the actual user profile is nested at `bot.owner.user`. `email` can be absent, and `email_verified` is always `False`.
