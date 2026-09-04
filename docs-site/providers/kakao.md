---
title: Kakao
---

# Kakao

Kakao Login OAuth2. No PKCE, no id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Kakao

auth = BetterAuth(
    secret=...,
    social_providers={
        "kakao": Kakao(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "kakao": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | The Kakao REST API key. |
| `client_secret` | `str` | required | |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `account_email profile_image profile_nickname`.
- Register `{base_url}{base_path}/callback/kakao` as the redirect URI in the Kakao developers console.
- The profile is nested under `kakao_account` (and `kakao_account.profile`): nickname, `profile_image_url`/`thumbnail_image_url`, email.
- `email_verified` is the AND of Kakao's `is_email_valid` and `is_email_verified` flags.
