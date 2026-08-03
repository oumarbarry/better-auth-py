---
title: Last Login Method
---

# Last Login Method

Records which method was used on the most recent successful sign-in, in a
cookie and optionally in the database — the "you last signed in with GitHub"
hint. Mirrors the TS `lastLoginMethod()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import LastLoginMethodPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[LastLoginMethodPlugin(store_in_database=True)],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `cookie_name` | `str` | `"better-auth.last_used_login_method"` | Cookie carrying the hint. |
| `max_age` | `int` | `2592000` | Cookie lifetime in seconds (30 days). |
| `custom_resolve_method` | `callable \| None` | `None` | `(ctx) -> str \| None`, override how the method name is derived. |
| `store_in_database` | `bool` | `False` | Also persist on the `user` row. |
| `before_store_cookie` | `callable \| None` | `None` | `(ctx, method) -> bool`, gate the cookie (consent). |
| `schema` | `dict \| None` | `None` | Field-name override for the database column. |

## Endpoints

None — the plugin is hooks only.

## Schema

Only when `store_in_database=True`:

| Table | Added columns |
| --- | --- |
| `user` | `lastLoginMethod` |

## Notes

- The default resolver derives the method from the sign-in path (e.g.
  `email`, a social provider id, `siwe`); `custom_resolve_method` replaces it.
