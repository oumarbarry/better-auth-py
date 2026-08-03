---
title: Custom Session
---

# Custom Session

Wraps `GET /get-session` so you can reshape or enrich what clients receive —
joining a subscription, a role, a tenant. Mirrors the TS `customSession()`
plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import CustomSessionPlugin

async def with_plan(session, ctx):
    return {**session, "plan": "pro"}

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[CustomSessionPlugin(with_plan)],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `fn` | `callable` | required (positional) | `(session, ctx) -> dict`, returns the payload clients receive. |
| `should_mutate_list_device_sessions_endpoint` | `bool` | `False` | Also apply `fn` to each entry of [multi-session](./multi-session)'s `list-device-sessions`. |

## Endpoints

Overrides the existing route:

| Method | Path |
| --- | --- |
| GET | `/get-session` |

## Notes

- `ponytail`: TS's `fn` also receives a third `options` argument used only for
  type inference; the Python callable takes `(session, ctx)`.
