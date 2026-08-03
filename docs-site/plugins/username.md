---
title: Username
---

# Username

Sign in with a username instead of an email, with configurable validation and
normalization. Mirrors the TS `username()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import UsernamePlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[UsernamePlugin(min_username_length=3, max_username_length=30)],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `min_username_length` | `int` | `3` | Minimum length. |
| `max_username_length` | `int` | `30` | Maximum length. |
| `username_validator` | `callable \| None` | `None` | `(username) -> bool` extra format check. |
| `display_username_validator` | `callable \| None` | `None` | Validator for `displayUsername`. |
| `username_normalization` | `callable \| bool \| None` | `None` | Normalizer applied on write (default lowercases); `False` disables. |
| `display_username_normalization` | `callable \| bool` | `False` | Normalizer for `displayUsername`. |
| `validation_order` | `dict \| None` | `None` | Run validation before or after normalization. |
| `schema` | `dict \| None` | `None` | Field-name overrides for the added columns. |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/sign-in/username` |
| POST | `/is-username-available` |

## Schema

| Table | Added columns |
| --- | --- |
| `user` | `username` (unique), `displayUsername` |

## Notes

- `/sign-in/username` equalizes timing — a wrong username still runs a dummy
  password hash — and never leaks `EMAIL_NOT_VERIFIED` before a correct
  password.
- Validation errors are 400s on `/sign-up/email` and `/update-user` (HTTP
  before-hooks) and 422s on `/sign-in/username` and `/is-username-available`,
  matching TS.
