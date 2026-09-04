---
title: GitLab
---

# GitLab

GitLab OAuth2 with PKCE (S256), for gitlab.com or self-hosted instances. No id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Gitlab

auth = BetterAuth(
    secret=...,
    social_providers={
        "gitlab": Gitlab(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "gitlab": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |
| `issuer` | `str` | `""` | Self-hosted GitLab base URL; empty means `https://gitlab.com`. All three endpoints derive from it (double slashes are collapsed, so a trailing-slash issuer is safe). |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `read_user`.
- Register `{base_url}{base_path}/callback/gitlab` as the redirect URI in the GitLab application settings.
- The class is `Gitlab` (lowercase `l`), matching the TS export.
- Sign-in is rejected when the GitLab account `state` is not `"active"` or the account is `locked`.
