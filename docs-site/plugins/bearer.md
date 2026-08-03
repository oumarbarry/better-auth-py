---
title: Bearer
---

# Bearer

Echoes the session token back on a `set-auth-token` response header so
cookieless clients can store it. Mirrors the TS `bearer()` plugin — with one
difference: reading `Authorization: Bearer ...` on requests is already built
into this port's core session layer, so the plugin is only needed for the
response side (and for `require_signature`).

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import BearerPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[BearerPlugin()],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `require_signature` | `bool` | `False` | Only accept signed tokens in the `Authorization` header; raw session tokens are stripped before core sees them. |

## Endpoints

None — the plugin is request/response hooks only. It also merges
`set-auth-token` into `Access-Control-Expose-Headers` so CORS clients can read
it.

## Notes

- Pair with [oauth-popup](./oauth-popup) so the popup page can hand the token
  back to the opener.
- See the [getting started guide](/guide/getting-started) for when you need
  this at all — pure cookie clients don't.
