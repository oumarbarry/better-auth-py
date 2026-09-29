---
title: Discord
---

# Discord

Discord OAuth2. Pure OAuth2 (no PKCE, no id token).

## Configure

```python
from better_auth import BetterAuth, Discord

auth = BetterAuth(
    secret=...,
    social_providers={
        "discord": Discord(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "discord": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |
| `prompt` | `str \| None` | `None` | Sent as the `prompt` authorize param. `None` sends `"none"` (skip the consent screen for a returning user); `"consent"` always shows it. |
| `permissions` | `int \| None` | `None` | Bot permission bitfield, sent as `permissions` only when the scopes include `bot`. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `identify email`.
- Register `{base_url}{base_path}/callback/discord` as a redirect in the Discord developer portal.
- `Discord` is re-exported at the package root (`from better_auth import Discord`).
- Authorize endpoint: `https://discord.com/api/oauth2/authorize`. No PKCE, and no login hint.
- Avatar mapping: users with a custom avatar get the CDN URL (`.gif` for animated avatars, whose hash starts with `a_`, `.png` otherwise); otherwise the default-avatar CDN fallback is computed: `(id >> 22) % 6` for new usernames, `discriminator % 5` for legacy discriminator accounts.
- The display name prefers `global_name`, falling back to `username`.
