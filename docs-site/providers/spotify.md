---
title: Spotify
---

# Spotify

Spotify OAuth2 with PKCE (S256). No id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Spotify

auth = BetterAuth(
    secret=...,
    social_providers={
        "spotify": Spotify(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "spotify": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `user-read-email`.
- Register `{base_url}{base_path}/callback/spotify` as the redirect URI in the Spotify developer dashboard.
- Avatar: Spotify's `images` is a size-ordered array — the first entry's `url` is used, `None` when empty.
- `email_verified` is always `False` — Spotify's userinfo has no such claim.
