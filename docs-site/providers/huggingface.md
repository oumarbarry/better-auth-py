---
title: Hugging Face
---

# Hugging Face

Hugging Face OAuth (OIDC-shaped) with PKCE (S256). Standard bearer-token userinfo; no id-token direct sign-in.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Huggingface

auth = BetterAuth(
    secret=...,
    social_providers={
        "huggingface": Huggingface(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "huggingface": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `openid profile email`.
- Register `{base_url}{base_path}/callback/huggingface` as the redirect URL in your Hugging Face OAuth app.
- Profile mapping: display name prefers `name`, falling back to `preferred_username`.
