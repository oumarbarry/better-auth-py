---
title: Dropbox
---

# Dropbox

Dropbox OAuth2 with PKCE (S256). No id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Dropbox

auth = BetterAuth(
    secret=...,
    social_providers={
        "dropbox": Dropbox(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "dropbox": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |
| `access_type` | `str` | `""` | `"offline"`, `"online"` or `"legacy"` — forwarded as the Dropbox-specific `token_access_type` authorize param. Set `"offline"` to get a refresh token. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `account_info.read`.
- Register `{base_url}{base_path}/callback/dropbox` as a redirect URI in the Dropbox App Console.
- User info is a **POST** to `/2/users/get_current_account` (Dropbox requires POST, not GET, with no body).
