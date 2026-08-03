---
title: Twitch
---

# Twitch

Twitch OIDC-flavored OAuth2. No PKCE; user info comes from the decoded id token — no userinfo call.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Twitch

auth = BetterAuth(
    secret=...,
    social_providers={
        "twitch": Twitch(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "twitch": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |
| `claims` | `list[str]` | `["email", "email_verified", "preferred_username", "picture"]` | Extra OIDC id-token claims requested via the `claims` authorize param — Twitch is the only provider that sends one. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `user:read:email openid`.
- Register `{base_url}{base_path}/callback/twitch` as an OAuth redirect URL in the Twitch developer console.
- User info is the decoded (unverified, per TS `decodeJwt`) `id_token` — there is no network userinfo call, and no JWKS-backed direct id-token sign-in.
- Display name comes from `preferred_username`.
