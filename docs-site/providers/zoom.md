---
title: Zoom
---

# Zoom

Zoom OAuth2. PKCE is optional (on by default) — the only provider with a PKCE toggle. No id token, and no `scope` param ever.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Zoom

auth = BetterAuth(
    secret=...,
    social_providers={
        "zoom": Zoom(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "zoom": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |
| `use_pkce` | `bool` | `True` | TS's `pkce` option — `Zoom(..., use_pkce=False)` drops the challenge from the authorize URL. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: none — the hand-built authorize URL never carries a `scope` param, even if you set `scopes` (matching TS, which ignores them for Zoom; scopes are configured on the Zoom app itself).
- Register `{base_url}{base_path}/callback/zoom` as the redirect URL on the Zoom OAuth app.
- The token exchange forwards the PKCE `code_verifier` unconditionally when present, even with `use_pkce=False` — only the authorize-URL side is gated (matching TS).
- `email_verified` maps from Zoom's `verified` flag; the avatar from `pic_url`.
