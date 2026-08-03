---
title: One-Time Token
---

# One-Time Token

Mints a short-lived, single-use token from an existing session and exchanges it
back for that session — the standard cross-domain or SSR handoff. Mirrors the
TS `oneTimeToken()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import OneTimeTokenPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[OneTimeTokenPlugin(expires_in=3)],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `expires_in` | `int` | `3` | Token lifetime in **minutes**. |
| `disable_client_request` | `bool` | `False` | Reject `/one-time-token/generate` over HTTP. |
| `generate_token` | `callable \| None` | `None` | Custom token generator, `(session, ctx) -> str`. |
| `disable_set_session_cookie` | `bool` | `False` | Don't set the session cookie on verify (return the session JSON only). |
| `store_token` | `str \| dict` | `"plain"` | `"plain"`, `"hashed"`, or a custom-hasher config. |
| `set_ott_header_on_new_session` | `bool` | `False` | Attach a one-time token header whenever a new session is created. |

## Endpoints

| Method | Path |
| --- | --- |
| GET | `/one-time-token/generate` |
| POST | `/one-time-token/verify` |

## Schema

No extra tables — tokens live in the core `verification` table.

## Notes

- Verification consumes the token atomically; expired tokens are rejected
  before any cookie is queued (TS checks expiry after queueing — a TS-side
  quirk this port deliberately does not reproduce).
- `ponytail`: this port is HTTP-only, so `disable_client_request=True` rejects
  the generate endpoint outright — there is no separate `auth.api` server-call
  surface. TS exports no error codes for this plugin; the error bodies here
  carry the generic `BAD_REQUEST` code with TS's exact message text.
