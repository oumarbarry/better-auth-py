---
title: Kick
---

# Kick

Kick OAuth2 with PKCE (S256). No id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Kick

auth = BetterAuth(
    secret=...,
    social_providers={
        "kick": Kick(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "kick": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `user:read`.
- Register `{base_url}{base_path}/callback/kick` as the redirect URI in the Kick developer settings.
- The userinfo endpoint (`https://api.kick.com/public/v1/users`) returns `{"data": [...]}` — the first entry is the profile; an empty array rejects the sign-in.
- Kick never returns an `email_verified` claim — mapped as `False`.
