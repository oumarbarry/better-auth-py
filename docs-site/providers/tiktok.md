---
title: TikTok
---

# TikTok

TikTok Login Kit. OAuth2 with no PKCE and comma-joined scopes; TikTok uses `client_key` instead of `client_id` everywhere.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import TikTok

auth = BetterAuth(
    secret=...,
    social_providers={
        "tiktok": TikTok(client_key="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "tiktok": {"client_key": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_key` | `str` | required | Replaces `client_id` on the authorize URL, token exchange and refresh (TS types `clientId` as `never`). |
| `client_secret` | `str` | required | |
| `client_id` | `str \| list[str]` | `""` | Unused — TikTok never uses `client_id`; leave it empty. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `user.info.profile`, joined with a **comma** in the authorize URL.
- Register `{base_url}{base_path}/callback/tiktok` as the redirect URI in the TikTok developer portal.
- The authorize URL is hand-built with TikTok's non-standard param ordering; token refresh sends `client_key` as an extra POST param.
- User info requests the fields `open_id, avatar_large_url, display_name, username`; the profile is nested at `data.user`. TikTok returns no email — `email` falls back to `username` and `email_verified` is always `False`.
