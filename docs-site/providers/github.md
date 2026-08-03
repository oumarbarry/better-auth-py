---
title: GitHub
---

# GitHub

GitHub OAuth2. Pure OAuth2 — no PKCE, no id token.

## Configure

```python
from better_auth import BetterAuth, GitHub

auth = BetterAuth(
    secret=...,
    social_providers={
        "github": GitHub(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "github": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `read:user user:email`.
- Register `{base_url}{base_path}/callback/github` as the authorization callback URL in the GitHub OAuth app settings.
- `GitHub` is re-exported at the package root (`from better_auth import GitHub`).
- User info takes **two** API calls: `GET /user` for the profile, then `GET /user/emails` to resolve the primary email and its `verified` flag (the profile's public email can be absent or unverified).
- Display name prefers `name`, falling back to `login`.
