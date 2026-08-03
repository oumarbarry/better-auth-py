---
title: Twitter (X)
---

# Twitter (X)

X (Twitter) OAuth2 with PKCE (S256) and basic token-endpoint auth. Registry key stays `twitter`. No id token.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Twitter

auth = BetterAuth(
    secret=...,
    social_providers={
        "twitter": Twitter(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "twitter": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `users.read tweet.read offline.access users.email`.
- Register `{base_url}{base_path}/callback/twitter` as the callback URI in the X developer portal.
- Token-endpoint client auth is **basic** (standard RFC 7617 base64 — X rejects base64url).
- The profile takes **two** calls to `/2/users/me`: one with `user.fields=profile_image_url`, one with `user.fields=confirmed_email` (X only returns email under that separate field query). A confirmed email sets `email_verified=True`; otherwise `email` falls back to the username, unverified.
