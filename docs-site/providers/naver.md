---
title: Naver
---

# Naver

Naver Login OAuth2. No PKCE, no id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Naver

auth = BetterAuth(
    secret=...,
    social_providers={
        "naver": Naver(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "naver": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `profile email`.
- Register `{base_url}{base_path}/callback/naver` as the callback URL in the Naver developers console.
- The userinfo payload is wrapped in a `{resultcode, message, response}` envelope; sign-in is rejected unless `resultcode == "00"`, then the nested `response` object is mapped.
- `email_verified` is always `False` — Naver exposes no verification flag.
