---
title: Vercel
---

# Vercel

Sign in with Vercel. OAuth2 with **required** PKCE (S256); no default scopes.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Vercel

auth = BetterAuth(
    secret=...,
    social_providers={
        "vercel": Vercel(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "vercel": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: none — a `scope` param is only sent when you configure `scopes` explicitly.
- Register `{base_url}{base_path}/callback/vercel` as the redirect URI on the Vercel integration.
- PKCE is mandatory — building the authorize URL without a code verifier raises (matching TS, where every other PKCE provider just omits the challenge silently).
- Display name prefers `name`, falling back to `preferred_username`.
