---
title: VK
---

# VK

VK ID OAuth2 with PKCE (S256). No id-token direct sign-in.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import VK

auth = BetterAuth(
    secret=...,
    social_providers={
        "vk": VK(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "vk": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | The VK ID app id. |
| `client_secret` | `str` | required | |
| `scheme` | `str \| None` | `None` | Parity field from TS's `VkOption` surface (UI hint); not read by the flow. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `email phone`.
- Register `{base_url}{base_path}/callback/vk` as the redirect URI in the VK ID app settings.
- User info is a **POST** to `https://id.vk.com/oauth2/user_info` with a form body (`access_token` + `client_id`), not a bearer header; the profile is nested under `user`, and the name is `first_name last_name`.
- No email on the account means the sign-in is rejected by the callback's email-required gate (TS returns `null`); `email_verified` is always `False`.
