---
title: LinkedIn
---

# LinkedIn

LinkedIn OIDC sign-in. No PKCE; standard bearer-token userinfo, no id-token direct sign-in.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import LinkedIn

auth = BetterAuth(
    secret=...,
    social_providers={
        "linkedin": LinkedIn(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "linkedin": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `profile email openid`.
- Register `{base_url}{base_path}/callback/linkedin` as an authorized redirect URL in the LinkedIn developer portal.
- Userinfo is the OIDC endpoint `https://api.linkedin.com/v2/userinfo`; `email_verified` defaults to `False` when LinkedIn omits the claim.
