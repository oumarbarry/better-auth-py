---
title: Reddit
---

# Reddit

Reddit OAuth2. No PKCE, no id token; basic token-endpoint auth and a mandatory custom `User-Agent`.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Reddit

auth = BetterAuth(
    secret=...,
    social_providers={
        "reddit": Reddit(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "reddit": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply — Reddit's `duration` authorize param (refresh-token issuance) is `authorize_params={"duration": "permanent"}`.

## Notes

- Default scopes: `identity`.
- Register `{base_url}{base_path}/callback/reddit` as the redirect URI in the Reddit app preferences.
- Reddit blocks generic HTTP clients: the token exchange sends `accept: text/plain` and a non-default `User-Agent` (`better-auth-py`); userinfo (`GET /api/v1/me`) carries the same `User-Agent`.
- The `identity` scope never returns an email, so a stable non-routable placeholder is synthesized — `{id}@reddit.invalid` (RFC 2606) — always unverified. Avatar URLs are stripped of their query string.
