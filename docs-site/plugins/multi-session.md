---
title: Multi-Session
---

# Multi-Session

Several accounts signed in at once, each with its own device-session cookie,
plus endpoints to list, switch and revoke them. Mirrors the TS `multiSession()`
plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import MultiSessionPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[MultiSessionPlugin(maximum_sessions=5)],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `maximum_sessions` | `int` | `5` | Cap on concurrent device-session cookies. Once exceeded, a fresh sign-in still gets its main session cookie but no additional per-device slot (silently, as in TS). |

## Endpoints

| Method | Path |
| --- | --- |
| GET | `/multi-session/list-device-sessions` |
| POST | `/multi-session/set-active` |
| POST | `/multi-session/revoke` |

## Notes

- Cookie scheme (TS parity): one additional signed cookie per device session,
  named `<sessionCookieName>_multi-<token.lower()>`.
- `set-active` and `revoke` act on the token proven by the signed cookie value,
  never on the request-body value itself — a request cannot pair a
  validly-signed cookie with an unrelated token.
- [custom-session](./custom-session) can opt into reshaping
  `list-device-sessions` via `should_mutate_list_device_sessions_endpoint`.
