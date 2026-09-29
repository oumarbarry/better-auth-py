---
title: Google One Tap
---

# Google One Tap

Google One Tap: the browser posts a Google id token to `/one-tap/callback` and
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

- The id token is verified against Google's JWKS (RS256 only) with the same
  machinery as the core Google provider.
- A token without an email is refused with a 400 (`Email not available in
  token`). In 1.0 the endpoint answered 200 with an error body.
- Also honors the registered [Google provider](/providers/)'s
  `disable_sign_up` and its `hd` hosted-domain restriction
  (`authorize_params["hd"]` still works).
- When `user.validate_user_info` is set, it runs for One Tap sign-ins with
  `source["method"]` set to `"oauth"` and `source["oauth"]["providerId"]` set
  to `"google"`.
