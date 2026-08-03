---
title: Salesforce
---

# Salesforce

Salesforce OAuth2 with PKCE (S256), for production, sandbox, or a My Domain host. No id-token direct sign-in.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Salesforce

auth = BetterAuth(
    secret=...,
    social_providers={
        "salesforce": Salesforce(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "salesforce": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | The connected app's consumer key. |
| `client_secret` | `str` | required | |
| `environment` | `str` | `"production"` | `"production"` (`login.salesforce.com`) or `"sandbox"` (`test.salesforce.com`). |
| `login_url` | `str \| None` | `None` | My Domain host (e.g. `acme.my.salesforce.com`) — overrides `environment`. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `openid email profile` (applied only when you pass no `scopes`).
- Register `{base_url}{base_path}/callback/salesforce` as the callback URL on the connected app.
- All endpoints live under `https://{host}/services/oauth2/` on the selected host.
- Profile mapping: the user id comes from `user_id` (not `sub`); the avatar from `photos.picture` or `photos.thumbnail`.
