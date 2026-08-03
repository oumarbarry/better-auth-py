---
title: Atlassian
---

# Atlassian

Atlassian account OAuth2 with PKCE (S256). Pure OAuth2 — no id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Atlassian

auth = BetterAuth(
    secret=...,
    social_providers={
        "atlassian": Atlassian(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "atlassian": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `read:jira-user offline_access`.
- Register `{base_url}{base_path}/callback/atlassian` as the callback URL in the Atlassian developer console.
- The authorize URL always carries `audience=api.atlassian.com` (default `authorize_params`).
- User info is a bearer-token GET on `https://api.atlassian.com/me`; `email_verified` is always `False` — Atlassian's `/me` exposes no verification flag.
