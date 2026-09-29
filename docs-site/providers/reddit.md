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

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply. Reddit's `duration` authorize param (refresh-token issuance) is `authorize_params={"duration": "permanent"}`.

## Notes

- Default scopes: `identity`.
- Register `{base_url}{base_path}/callback/reddit` as the redirect URI in the Reddit app preferences.
- Token requests use `client_secret_basic` (HTTP Basic) client authentication.
- Reddit blocks generic HTTP clients: the code exchange sends `accept: text/plain` and a non-default `User-Agent` (`better-auth`); userinfo (`GET /api/v1/me`) carries the same `User-Agent`. Token refresh sends neither header.
- The `identity` scope never returns an email, so a stable non-routable placeholder is synthesized: `{id}@reddit.placeholder.invalid` (RFC 6761), always unverified. Avatar URLs are stripped of their query string.

::: warning Changed in 1.1
The placeholder email for new users was `{id}@reddit.invalid` and is now `{id}@reddit.placeholder.invalid`. Existing users keep the address stored at sign-up.
See [Upgrade from 1.0](/migrate/from-1-0).
:::
