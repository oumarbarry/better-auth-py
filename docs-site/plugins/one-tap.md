---
title: One Tap
---

# One Tap

Google One Tap: the browser posts a Google ID token to `/one-tap/callback` and
gets a session back, running the same find/register/link decision tree as the
redirect OAuth flow. Mirrors the TS `oneTap()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import OneTapPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[OneTapPlugin(client_id="xxx.apps.googleusercontent.com")],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `disable_signup` | `bool` | `False` | Only sign in existing users. |
| `client_id` | `str \| list[str] \| None` | `None` | Accepted `aud` value(s); falls back to the registered Google provider's client id. |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/one-tap/callback` |

## Notes

- The ID token is verified against Google's JWKS (RS256/ES256) with the same
  machinery as the core Google provider.
- Also honours the registered [Google provider](/providers/)'s
  `disable_sign_up` and its `authorize_params["hd"]` hosted-domain restriction.
