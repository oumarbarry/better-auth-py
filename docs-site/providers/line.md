---
title: LINE
---

# LINE

LINE Login v2.1 with PKCE (S256). Id tokens are verified through LINE's own `/verify` endpoint — not JWKS.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Line

auth = BetterAuth(
    secret=...,
    social_providers={
        "line": Line(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "line": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | The LINE channel ID. |
| `client_secret` | `str` | required | The channel secret. |
| `disable_id_token_sign_in` | `bool` | `False` | Refuse direct id-token sign-in. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `openid profile email`.
- Register `{base_url}{base_path}/callback/line` as a callback URL on the LINE Login channel.
- Id-token verification POSTs to `https://api.line.me/oauth2/v2.1/verify` and checks `aud` (must equal the channel ID) and `nonce` — there is no JWKS.
- User info prefers the decoded `id_token` (no network call); the userinfo endpoint is the fallback.
- LINE exposes no email-verification flag — `email_verified` is always `False`.
